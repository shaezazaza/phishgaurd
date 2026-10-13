"""Optional: use the fine-tuned transformer together with the TF-IDF model.

If models/transformer/ exists and torch + transformers are installed, PhishGuard
averages the two probabilities. Explanations (key words) still come from the
TF-IDF model because its weights are easy to read.
"""

import json
import os
import re

from .features import clean_text


class EnsembleTextModel:
    def __init__(self, tfidf_model, transformer_dir, weight=0.5):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.torch = torch
        self.base = tfidf_model
        self.weight = weight
        self.tok = AutoTokenizer.from_pretrained(transformer_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(transformer_dir).eval()
        cfg = json.load(open(os.path.join(transformer_dir, "phishguard.json")))
        self.max_len = cfg.get("max_len", 256)
        names = cfg.get("names", [])
        self.pat = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\b") if names else None

    def _transformer_proba(self, subjects, bodies):
        texts = [clean_text(s, b, max_chars=3000) for s, b in zip(subjects, bodies)]
        if self.pat:
            texts = [self.pat.sub("name", t) for t in texts]
        enc = self.tok(texts, truncation=True, max_length=self.max_len, padding=True, return_tensors="pt")
        with self.torch.no_grad():
            logits = self.model(**enc).logits
        return self.torch.softmax(logits, -1)[:, 1].numpy()

    def predict_proba(self, subjects, bodies):
        p1 = self.base.predict_proba(subjects, bodies)
        p2 = self._transformer_proba(list(subjects), list(bodies))
        return (1 - self.weight) * p1 + self.weight * p2

    def explain(self, subject, body, k=6):
        return self.base.explain(subject, body, k)


def maybe_ensemble(tfidf_model, transformer_dir):
    if not transformer_dir or not os.path.isdir(transformer_dir):
        return tfidf_model
    try:
        return EnsembleTextModel(tfidf_model, transformer_dir)
    except Exception as ex:  # torch missing etc.
        print(f"[phishguard] transformer not used ({ex}); using TF-IDF model only")
        return tfidf_model
