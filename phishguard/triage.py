"""Batch triage: scan a folder of .eml files -> prioritized analyst queue with campaign grouping.

Campaign = suspicious emails that share a link domain, a near-identical subject,
or very similar text. Seeing 30 copies of one lure as ONE campaign cuts triage time.
"""

import csv
import glob
import json
import os
import re
from collections import defaultdict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .emailparse import base_domain, parse_file
from .features import clean_text
from .intel import _host, _is_shared

SIMILAR_TEXT = 0.8


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, i):
        while self.p[i] != i:
            self.p[i] = self.p[self.p[i]]
            i = self.p[i]
        return i

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def group_campaigns(items):
    """items: list of (parsed_email, result). Returns campaign id per item (None if not suspicious)."""
    idx = [i for i, (_, r) in enumerate(items) if r["level"] != "LOW"]
    uf = _UF(len(items))
    by_key = defaultdict(list)
    for i in idx:
        e = items[i][0]
        for u in e["urls"]:
            h = _host(u)
            if h and not _is_shared(h):
                by_key["dom:" + base_domain(h)].append(i)
        subj = re.sub(r"[\d#]+", "#", (e["subject"] or "").lower()).strip()
        if len(subj) > 8:
            by_key["subj:" + subj].append(i)
    for members in by_key.values():
        for m in members[1:]:
            uf.union(members[0], m)
    if len(idx) > 1:
        texts = [clean_text(items[i][0]["subject"], items[i][0]["body"]) for i in idx]
        try:
            X = TfidfVectorizer(min_df=1).fit_transform(texts)
            S = cosine_similarity(X)
            for a in range(len(idx)):
                for b in range(a + 1, len(idx)):
                    if S[a, b] >= SIMILAR_TEXT:
                        uf.union(idx[a], idx[b])
        except ValueError:
            pass
    roots = {}
    out = [None] * len(items)
    sizes = defaultdict(int)
    for i in idx:
        sizes[uf.find(i)] += 1
    for i in idx:
        r = uf.find(i)
        if sizes[r] > 1:
            out[i] = roots.setdefault(r, f"C{len(roots) + 1:03d}")
    return out, {roots[r]: s for r, s in sizes.items() if r in roots}


def triage_folder(guard, folder, out_csv=None, out_json=None):
    files = sorted(glob.glob(os.path.join(folder, "**", "*.eml"), recursive=True))
    items = []
    for f in files:
        try:
            e = parse_file(f)
            items.append((e, guard.scan(e), f))
        except Exception as ex:
            print(f"skip {f}: {ex}")
    camp, sizes = group_campaigns([(e, r) for e, r, _ in items])

    rows = []
    for (e, r, f), c in zip(items, camp):
        rows.append({
            "risk": r["risk"], "level": r["level"], "action": r["action"],
            "campaign": c or "", "campaign_size": sizes.get(c, 1) if c else 1,
            "file": os.path.relpath(f, folder), "from": e["from"][:120], "subject": e["subject"][:150],
            "tactics": "; ".join(r["tactics"]),
            "top_reasons": " | ".join(x["reason"] for x in r["reasons"][:3]),
        })
    # priority: risk first, bigger campaigns first among equals
    rows.sort(key=lambda x: (-x["risk"], -x["campaign_size"]))

    if out_csv:
        with open(out_csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["risk"])
            w.writeheader()
            w.writerows(rows)
    if out_json:
        json.dump(rows, open(out_json, "w"), indent=2)

    summary = {"scanned": len(rows),
               "high": sum(r["level"] == "HIGH" for r in rows),
               "medium": sum(r["level"] == "MEDIUM" for r in rows),
               "low": sum(r["level"] == "LOW" for r in rows),
               "campaigns": len(sizes),
               "emails_in_campaigns": sum(sizes.values()),
               "analyst_items": sum(r["level"] != "LOW" for r in rows) - sum(sizes.values()) + len(sizes)}
    return rows, summary
