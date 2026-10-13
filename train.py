"""Train the text model on real data and evaluate it honestly.

Tests:
  A. Main test     - newest 20% of phishing_pot + random 20% of the rest (never seen in training)
  B. Era shift     - train only on old data (Nazario 2005-07 + Enron), test on recent phishing_pot
  C. Other legit   - SpamAssassin sample emails (not Enron) -> false alarms?
  D. Shortcut check- top words, so you can see what the model actually learned
Also compares 3 classic models (Logistic Regression, Linear SVM, Naive Bayes).

Usage: python train.py            (needs data/emails.parquet from build_dataset.py)
"""

import glob
import json
import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC

from phishguard.emailparse import parse_file
from phishguard.textmodel import TextModel

EN_MIN = 0.08          # english score cut-off (see build_dataset.py)
SEED = 42
os.makedirs("models", exist_ok=True)
os.makedirs("reports", exist_ok=True)


def metrics(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": round(precision_score(y, pred, zero_division=0), 4),
            "recall": round(recall_score(y, pred, zero_division=0), 4),
            "f1": round(f1_score(y, pred, zero_division=0), 4),
            "roc_auc": round(roc_auc_score(y, p), 4) if len(set(y)) > 1 else None,
            "pr_auc": round(average_precision_score(y, p), 4) if len(set(y)) > 1 else None,
            "false_positive_rate": round(fp / max(fp + tn, 1), 4),
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def enron_names(df):
    """First/last names of Enron staff (from their e-mail addresses), so the model
    can't learn 'mentions Vince Kaminski = safe'."""
    import re
    from collections import Counter
    leg = df[df.source.str.startswith("enron")]
    txt = " ".join(leg["from"].tolist()) + " " + " ".join(leg["body"].str[:3000].tolist())
    c = Counter()
    for local in re.findall(r"([a-z]+(?:\.[a-z]+)+)\s*@\s*enron", txt.lower()):
        c.update(p for p in local.split(".") if len(p) > 2)
    for local in re.findall(r"([a-z]+)\s+([a-z]+)\s*/\s*(?:hou|corp|na|enron)", txt.lower()):
        c.update(p for p in local if len(p) > 2)
    # keep only real names: drop words that also show up a lot in phishing text (e.g. "address")
    phish = " ".join((df[df.label == 1].subject + " " + df[df.label == 1].body.str[:3000]).tolist()).lower()
    pc = Counter(re.findall(r"[a-z]+", phish))
    return sorted(n for n, k in c.items() if k >= 3 and pc[n] < 5)


def split(df):
    rng = np.random.RandomState(SEED)
    test = np.zeros(len(df), bool)
    pot = (df.source == "phishing_pot").values
    cut = np.nanpercentile(df.loc[pot, "order"], 80)
    test[pot] = df.loc[pot, "order"].values > cut            # newest 20% of recent phishing
    test[~pot] = rng.rand((~pot).sum()) < 0.2                # random 20% of the rest
    return df[~test], df[test]


def main():
    df = pd.read_parquet("data/emails.parquet")
    df = df[df.english >= EN_MIN].reset_index(drop=True)
    print("English emails used:\n", df.groupby(["source", "label"]).size(), "\n")
    names = enron_names(df)
    print(len(names), "Enron staff names blocked, e.g.", names[:12])
    TM = lambda **kw: TextModel(extra_stop=names, **kw)
    train, test = split(df)
    report = {"data": {"train": train.groupby("source").size().to_dict(),
                       "test": test.groupby("source").size().to_dict()}}

    # ---------------- compare models (test A)
    candidates = {
        "logistic_regression": TM(),
        "linear_svm": TM(classifier=LinearSVC(C=0.5, class_weight="balanced")),
        "naive_bayes": TM(classifier=ComplementNB(alpha=0.3)),
    }
    report["A_main_test"] = {}
    for name, m in candidates.items():
        t = time.time()
        m.fit(train.subject, train.body, train.label)
        p = m.predict_proba(test.subject, test.body)
        r = metrics(test.label.values, p)
        r["train_seconds"] = round(time.time() - t, 1)
        report["A_main_test"][name] = r
        print(f"[A] {name:20s} P={r['precision']} R={r['recall']} F1={r['f1']} AUC={r['roc_auc']} FPR={r['false_positive_rate']}")

    model = candidates["logistic_regression"]  # explainable, so it is the one we ship
    p = model.predict_proba(test.subject, test.body)
    report["A_per_source"] = {}
    for src in test.source.unique():
        msk = (test.source == src).values
        pred = p[msk] >= 0.5
        lab = test.label.values[msk][0]
        rate = pred.mean() if lab == 1 else 1 - pred.mean()
        report["A_per_source"][src] = {"n": int(msk.sum()),
                                       ("detected" if lab else "correctly_passed"): round(float(rate), 4)}
    print("[A] per source:", report["A_per_source"])

    # ---------------- era shift (test B)
    old = df[df.source.isin(["nazario", "enron_mbox", "enron_ham"])]
    old_train, _ = split(old)
    recent = df[df.source == "phishing_pot"]
    m_old = TM().fit(old_train.subject, old_train.body, old_train.label)
    pr = m_old.predict_proba(recent.subject, recent.body)
    report["B_era_shift"] = {"trained_on": "Nazario 2005-07 + Enron only",
                             "tested_on": f"{len(recent)} recent phishing_pot emails",
                             "detected": round(float((pr >= 0.5).mean()), 4),
                             "compare_model_trained_with_recent": report["A_per_source"].get("phishing_pot")}
    print("[B] old-only model catches", report["B_era_shift"]["detected"], "of recent phishing")

    # ---------------- other legit (test C)
    sa = [f for f in sorted(glob.glob("../data/sa/t/data/nice/0*"))]
    rows = []
    for f in sa:
        try:
            e = parse_file(f)
            if len(e["body"]) > 30:
                rows.append((os.path.basename(f), e["subject"], e["body"]))
        except Exception:
            pass
    if rows:
        ps = model.predict_proba([r[1] for r in rows], [r[2] for r in rows])
        report["C_spamassassin_legit"] = {"n": len(rows), "false_alarms": int((ps >= 0.5).sum()),
                                          "scores": {r[0]: round(float(x), 3) for r, x in zip(rows, ps)}}
        print("[C] SpamAssassin legit:", report["C_spamassassin_legit"]["false_alarms"], "false alarms of", len(rows))

    # ---------------- shortcut check (test D)
    pos, neg = model.top_features(30)
    report["D_top_phishing_words"] = [(str(w), float(c)) for w, c in pos]
    report["D_top_legit_words"] = [(str(w), float(c)) for w, c in neg]
    print("[D] phishing words:", [str(w) for w, _ in pos])
    print("[D] legit words:   ", [str(w) for w, _ in neg])

    # ---------------- final model on ALL data, save
    final = TM().fit(df.subject, df.body, df.label)
    joblib.dump(final, "models/text_model.joblib", compress=3)
    json.dump(report, open("reports/metrics.json", "w"), indent=2)
    np.save("reports/test_scores.npy", np.vstack([test.label.values, p]))
    print("\nsaved models/text_model.joblib and reports/metrics.json")


if __name__ == "__main__":
    main()
