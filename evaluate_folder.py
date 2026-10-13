"""Test the full system (text model + rules + threat intel) on YOUR OWN emails.

This is the most important test, because the legit training mail is old Enron
corporate mail. Export ~200 normal emails from your inbox and any phishing you
have as .eml files (Gmail: open mail -> 3 dots -> "Download message";
Outlook: drag mail to a folder / "Save as").

  python evaluate_folder.py --legit my_mail/legit --phish my_mail/phish [--offline]

Prints precision / recall / false-alarm rate at the MEDIUM and HIGH cut-offs,
and lists every legit email that got flagged so you can see why.
"""

import argparse
import glob
import os

from train import metrics
from phishguard.scorer import PhishGuard, HIGH, MEDIUM


def scan_dir(g, d, label):
    out = []
    for f in sorted(glob.glob(os.path.join(d, "**", "*.eml"), recursive=True)):
        try:
            r = g.scan_file(f)
            out.append((f, label, r))
        except Exception as ex:
            print("skip", f, ex)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--legit", required=True)
    ap.add_argument("--phish")
    ap.add_argument("--offline", action="store_true")
    a = ap.parse_args()
    g = PhishGuard(online=not a.offline)
    rows = scan_dir(g, a.legit, 0) + (scan_dir(g, a.phish, 1) if a.phish else [])
    y = [l for _, l, _ in rows]
    risk = [r["risk"] / 100 for _, _, r in rows]
    import numpy as np
    for name, cut in (("MEDIUM+ (review)", MEDIUM), ("HIGH (quarantine)", HIGH)):
        m = metrics(np.array(y), np.array(risk), thr=cut / 100)
        print(f"{name:18s} precision={m['precision']} recall={m['recall']} false-alarm rate={m['false_positive_rate']} "
              f"(fp={m['fp']} of {m['fp'] + m['tn']} legit)")
    print("\nLegit emails that were flagged:")
    for f, l, r in sorted(rows, key=lambda x: -x[2]["risk"]):
        if l == 0 and r["risk"] >= MEDIUM:
            print(f"  {r['risk']:3d} {os.path.basename(f)[:40]:40s} {r['email']['subject'][:50]}")
            for x in r["reasons"][:3]:
                print(f"        {x['points']:+5.1f} {x['reason'][:110]}")


if __name__ == "__main__":
    main()
