"""Export the trained text model + rule settings to JSON for the Chrome extension.

  python export_extension_model.py            -> extension/model/model.json
                                               + extension/model/blocklist-domains.txt (if feeds/ exists)
Run this again after you retrain, then reload the extension.
"""

import json
import os
import shutil

import joblib

from phishguard import features as F
from phishguard.rules import RULES
from phishguard.scorer import HIGH, INTEL_POINTS, MEDIUM, TACTIC_NAMES, TEXT_WEIGHT

OUT = "extension/model"


def main():
    m = joblib.load("models/text_model.joblib")
    vocab = m.tfidf.vocabulary_
    n_text = len(vocab)
    coef = m.clf.coef_[0]
    terms = [None] * n_text
    for t, i in vocab.items():
        terms[i] = t
    model = {
        "version": 1,
        "terms": terms,
        "idf": [round(float(x), 5) for x in m.tfidf.idf_],
        "coef": [round(float(x), 5) for x in coef[:n_text]],
        "cue_coef": [round(float(x), 5) for x in coef[n_text:]],
        "cue_names": F.CUE_NAMES,
        "cue_weight": m.cue_weight,
        "intercept": float(m.clf.intercept_[0]),
        "stop_words": sorted(m.tfidf.get_stop_words()),
        "ngram_max": m.tfidf.ngram_range[1],
        "cues": F.CUES,
        "shorteners": sorted(F.SHORTENERS), "risky_tlds": sorted(F.RISKY_TLDS),
        "risky_ext": list(F.RISKY_EXT), "archive_ext": list(F.ARCHIVE_EXT),
        "free_mail": sorted(F.FREE_MAIL), "brands": F.BRANDS,
        "rules": {k: {"points": p, "reason": r} for k, (p, r) in RULES.items()},
        "text_weight": TEXT_WEIGHT, "intel_points": INTEL_POINTS, "high": HIGH, "medium": MEDIUM,
        "tactic_names": TACTIC_NAMES,
    }
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "model.json"), "w") as f:
        json.dump(model, f, separators=(",", ":"))
    print("model.json", round(os.path.getsize(os.path.join(OUT, "model.json")) / 1e6, 2), "MB,", n_text, "terms")

    src = "feeds/phishing-domains-ACTIVE.txt"
    if os.path.exists(src):
        shutil.copy(src, os.path.join(OUT, "blocklist-domains.txt"))
        print("blocklist-domains.txt copied")
    else:
        print("no feeds/ folder - run `python -m phishguard feeds --update` first to bundle the blocklist")


if __name__ == "__main__":
    main()
