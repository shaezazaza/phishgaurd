"""Build one clean dataset file from the raw sources.

Sources (all public, downloaded from GitHub):
  phishing  nazario      - Nazario phishing corpus (2005-2007), mbox      [diegoocampoh/MachineLearningPhishing]
  phishing  phishing_pot - recent real phishing .eml (2022-2026)          [rf-peixoto/phishing_pot]
  legit     enron_mbox   - Enron business email, mbox                     [diegoocampoh/MachineLearningPhishing]
  legit     enron_ham    - Enron-Spam "ham" (text only, used for extra FP testing) [MWiechmann/enron_spam_data]

Output: data/emails.parquet with one row per email.
Usage:  python build_dataset.py --data ../data
"""

import argparse
import glob
import hashlib
import mailbox
import os
import re
from multiprocessing import Pool

import pandas as pd

from phishguard.emailparse import parse_bytes, parse_message, from_text
from email import policy
import email

MAX_BODY = 20000

EN_STOP = set("the and to of a in is you your for that this on with are be it as at we have from or by our not will can please if an".split())


def english_score(text):
    words = re.findall(r"[a-zA-Z']+", text.lower())[:400]
    if len(words) < 5:
        return 1.0  # too short to judge, keep
    return sum(w in EN_STOP for w in words) / len(words)


def slim(d, source, label):
    return {
        "source": source, "label": label,
        "from": d["from"][:300], "reply_to": d["reply_to"][:300], "return_path": d["return_path"][:300],
        "subject": d["subject"][:500], "body": d["body"][:MAX_BODY],
        "urls": d["urls"][:50], "html_links": [list(x) for x in d["html_links"][:50]],
        "attachments": d["attachments"][:20], "auth_results": d["auth_results"][:3000],
        "has_headers": d["has_headers"],
    }


def load_mbox(path, source, label):
    rows = []
    for msg in mailbox.mbox(path, factory=lambda f: email.message_from_binary_file(f, policy=policy.default)):
        try:
            rows.append(slim(parse_message(msg), source, label))
        except Exception:
            pass
    return rows


def _eml(path):
    try:
        with open(path, "rb") as f:
            r = slim(parse_bytes(f.read()), "phishing_pot", 1)
        r["file"] = os.path.basename(path)
        return r
    except Exception:
        return None


def main(data_dir, out):
    rows = []
    res = os.path.join(data_dir, "MachineLearningPhishing/code/resources")
    rows += load_mbox(os.path.join(res, "emails-phishing.mbox"), "nazario", 1)
    print("nazario", len(rows))
    n = len(rows)
    rows += load_mbox(os.path.join(res, "emails-enron.mbox"), "enron_mbox", 0)
    print("enron_mbox", len(rows) - n)

    files = sorted(glob.glob(os.path.join(data_dir, "phishing_pot/email/*.eml")))
    with Pool(2) as p:
        pot = [r for r in p.imap(_eml, files, chunksize=50) if r]
    rows += pot
    print("phishing_pot", len(pot), "of", len(files))

    ham = pd.read_csv(os.path.join(data_dir, "enron_spam_data/enron_spam_data.csv"))
    ham = ham[ham["Spam/Ham"] == "ham"].fillna("")
    for s, b in zip(ham["Subject"], ham["Message"]):
        rows.append(slim(from_text(s, b), "enron_ham", 0))
    print("enron_ham", len(ham))

    df = pd.DataFrame(rows)
    df["file"] = df.get("file", pd.Series(dtype=str)).fillna("")
    # phishing_pot samples are numbered roughly in arrival order -> use for a time-based split
    df["order"] = df["file"].str.extract(r"(\d+)", expand=False).astype(float)
    df["text_len"] = (df["subject"] + " " + df["body"]).str.len()
    df["english"] = [english_score(s + " " + b) for s, b in zip(df["subject"], df["body"])]

    # remove exact duplicates (same subject+body), keep first
    norm = (df["subject"].str.lower() + "|" + df["body"].str.lower()).str.replace(r"\s+", " ", regex=True)
    df["hash"] = [hashlib.md5(x.encode("utf-8", "ignore")).hexdigest() for x in norm]
    before = len(df)
    df = df.drop_duplicates("hash")
    # a text that appears with both labels would be noise - drop it
    print(f"dropped {before - len(df)} duplicates")
    df = df[df["text_len"] > 20]

    os.makedirs(os.path.dirname(out), exist_ok=True)
    df.to_parquet(out, index=False)
    print(df.groupby(["source", "label"]).agg(n=("hash", "size"),
                                             english_share=("english", lambda s: round((s >= 0.12).mean(), 2))))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data")
    ap.add_argument("--out", default="data/emails.parquet")
    a = ap.parse_args()
    main(a.data, a.out)
