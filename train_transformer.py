"""Fine-tune a small transformer (DistilBERT by default) on the same data + same split as train.py.

Run this on a machine with a GPU (e.g. your WSL2 + CUDA setup). On CPU it works but is slow.

  pip install torch transformers accelerate
  python train_transformer.py                         # distilbert-base-uncased, 2 epochs
  python train_transformer.py --model microsoft/deberta-v3-small --epochs 3
  python train_transformer.py --max-train 3000        # quick test run

Output: models/transformer/  and  reports/metrics_transformer.json
After that, phishguard automatically averages it with the TF-IDF model (see phishguard/transformer_model.py).
"""

import argparse
import json
import os
import re

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset
from transformers import (AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments,
                          DataCollatorWithPadding)

from phishguard.features import clean_text
from train import EN_MIN, enron_names, metrics, split


def mask_names(texts, names):
    """Replace Enron staff names with 'name' so the model can't use them as a shortcut."""
    pat = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\b") if names else None
    return [pat.sub("name", t) if pat else t for t in texts]


class EmailSet(Dataset):
    def __init__(self, enc, labels):
        self.enc, self.labels = enc, labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, i):
        item = {k: torch.tensor(v[i]) for k, v in self.enc.items()}
        item["labels"] = torch.tensor(int(self.labels[i]))
        return item


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="distilbert-base-uncased")
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--max-train", type=int, default=0, help="subsample training set (0 = all)")
    ap.add_argument("--out", default="models/transformer")
    a = ap.parse_args()

    df = pd.read_parquet("data/emails.parquet")
    df = df[df.english >= EN_MIN].reset_index(drop=True)
    names = enron_names(df)
    train, test = split(df)
    if a.max_train:
        train = train.sample(min(a.max_train, len(train)), random_state=42)
    print("train", len(train), "test", len(test), "device", "cuda" if torch.cuda.is_available() else "cpu")

    tok = AutoTokenizer.from_pretrained(a.model)
    def encode(d):
        texts = mask_names([clean_text(s, b, max_chars=3000) for s, b in zip(d.subject, d.body)], names)
        return tok(texts, truncation=True, max_length=a.max_len)

    tr = EmailSet(encode(train), train.label.values)
    te = EmailSet(encode(test), test.label.values)

    model = AutoModelForSequenceClassification.from_pretrained(a.model, num_labels=2)
    # class weights: legit emails outnumber phishing ~3:1
    w = torch.tensor([1.0, (train.label == 0).sum() / max((train.label == 1).sum(), 1)], dtype=torch.float)

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            loss = torch.nn.functional.cross_entropy(out.logits, labels, weight=w.to(out.logits.device))
            return (loss, out) if return_outputs else loss

    steps = int(np.ceil(len(tr) / a.batch) * a.epochs)
    args = TrainingArguments(output_dir=a.out + "_ckpt", num_train_epochs=a.epochs,
                             per_device_train_batch_size=a.batch, per_device_eval_batch_size=a.batch * 2,
                             learning_rate=a.lr, weight_decay=0.01, warmup_steps=max(1, int(0.06 * steps)),
                             fp16=torch.cuda.is_available(), logging_steps=50, save_strategy="no",
                             report_to=[], seed=42)
    trainer = WeightedTrainer(model=model, args=args, train_dataset=tr,
                              data_collator=DataCollatorWithPadding(tok))
    trainer.train()

    logits = trainer.predict(te).predictions
    p = torch.softmax(torch.tensor(logits), -1)[:, 1].numpy()
    rep = {"model": a.model, "main_test": metrics(test.label.values, p), "per_source": {}}
    for src in test.source.unique():
        m = (test.source == src).values
        rep["per_source"][src] = {"n": int(m.sum()), "flagged": round(float((p[m] >= 0.5).mean()), 4)}
    print(json.dumps(rep, indent=2))

    os.makedirs(a.out, exist_ok=True)
    trainer.save_model(a.out)
    tok.save_pretrained(a.out)
    json.dump({"names": names, "max_len": a.max_len}, open(os.path.join(a.out, "phishguard.json"), "w"))
    os.makedirs("reports", exist_ok=True)
    json.dump(rep, open("reports/metrics_transformer.json", "w"), indent=2)
    print("saved", a.out)


if __name__ == "__main__":
    main()
