"""Command line.

  python -m phishguard scan  mail.eml [--json]
  python -m phishguard text  "subject" "body" [--from x@y.com]
  python -m phishguard triage folder_of_emls/ [--csv queue.csv] [--json queue.json]
  python -m phishguard feeds  [--update]
"""

import argparse
import json

from .intel import ThreatIntel, update_feeds


def main():
    ap = argparse.ArgumentParser(prog="phishguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("files", nargs="+"); s.add_argument("--json", action="store_true")
    t = sub.add_parser("text"); t.add_argument("subject"); t.add_argument("body")
    t.add_argument("--from", dest="sender", default=""); t.add_argument("--json", action="store_true")
    q = sub.add_parser("triage"); q.add_argument("folder"); q.add_argument("--csv"); q.add_argument("--json")
    f = sub.add_parser("feeds"); f.add_argument("--update", action="store_true")
    for p in (s, t, q):
        p.add_argument("--offline", action="store_true", help="skip online threat-intel APIs")
    a = ap.parse_args()

    if a.cmd == "feeds":
        if a.update:
            update_feeds()
        print(ThreatIntel(online=False).status())
        return

    from .scorer import PhishGuard, pretty
    g = PhishGuard(online=not a.offline)
    if a.cmd == "scan":
        for path in a.files:
            r = g.scan_file(path)
            print(json.dumps(r, indent=2) if a.json else pretty(r) + "\n")
    elif a.cmd == "text":
        r = g.scan_text(a.subject, a.body, sender=a.sender)
        print(json.dumps(r, indent=2) if a.json else pretty(r))
    elif a.cmd == "triage":
        from .triage import triage_folder
        rows, summary = triage_folder(g, a.folder, a.csv, a.json)
        print(json.dumps(summary, indent=2))
        print("\nTop of the analyst queue:")
        for r in rows[:15]:
            print(f"{r['risk']:3d} {r['level']:6s} {r['campaign'] or '-':5s} {r['subject'][:70]}")


if __name__ == "__main__":
    main()
