"""Combine text model + rules + threat intel into one explainable risk score (0-100)."""

import os

import joblib

from .emailparse import parse_bytes, parse_file, from_text
from .features import clean_text, text_cues
from .intel import ThreatIntel
from .rules import score_rules, verified_brand_sender

HERE = os.path.dirname(__file__)
DEFAULT_MODEL = os.path.join(HERE, "..", "models", "text_model.joblib")

TEXT_WEIGHT = 75        # text model alone can reach "HIGH" only when very sure (p >= 0.93)
INTEL_POINTS = 40       # a link on a phishing blocklist
HIGH, MEDIUM = 70, 40

TACTIC_NAMES = {
    "cue_urgency": "Urgency / pressure", "cue_threat": "Fear / threat", "cue_credentials": "Credential request",
    "cue_money": "Money / payment request", "cue_authority": "Authority impersonation",
    "cue_secrecy": "Secrecy request (BEC style)", "cue_action": "Pushes a click / download",
    "cue_generic_greeting": "Generic greeting",
}


class PhishGuard:
    def __init__(self, model_path=DEFAULT_MODEL, intel=None, online=True,
                 transformer_dir=os.environ.get("PHISHGUARD_TRANSFORMER", os.path.join(HERE, "..", "models", "transformer"))):
        from .transformer_model import maybe_ensemble
        self.text_model = maybe_ensemble(joblib.load(model_path), transformer_dir)
        self.intel = intel if intel is not None else ThreatIntel(online=online)

    def scan_file(self, path):
        return self.scan(parse_file(path))

    def scan_bytes(self, raw):
        return self.scan(parse_bytes(raw))

    def scan_text(self, subject, body, sender="", reply_to="", attachments=None):
        return self.scan(from_text(subject, body, sender, reply_to, attachments))

    def scan(self, e):
        p = float(self.text_model.predict_proba([e["subject"]], [e["body"]])[0])
        rule_pts, rule_hits, signs = score_rules(e)
        intel_hits = self.intel.check_urls(e["urls"]) if self.intel else []

        text_pts = TEXT_WEIGHT * p
        calmed = False
        if verified_brand_sender(e, signs) and not intel_hits:
            text_pts *= 0.4   # genuine, authenticated mail from the real brand
            calmed = True

        risk = text_pts + rule_pts + (INTEL_POINTS if intel_hits else 0)
        risk = int(round(max(0, min(100, risk))))
        level = "HIGH" if risk >= HIGH else "MEDIUM" if risk >= MEDIUM else "LOW"
        action = {"HIGH": "Quarantine + send to analyst queue (priority)",
                  "MEDIUM": "Deliver with warning banner + analyst review",
                  "LOW": "Deliver"}[level]

        cues = text_cues(clean_text(e["subject"], e["body"]))
        tactics = [TACTIC_NAMES[k] for k, v in cues.items() if v > 0]

        reasons = []
        for n, h in enumerate(intel_hits):   # points counted once, every hit listed
            reasons.append({"points": INTEL_POINTS if n == 0 else 0,
                            "reason": f"Threat intel ({h['source']}): {h['detail']} [{h['url'][:60]}]"})
        reasons += sorted(({"points": h["points"], "reason": h["reason"]} for h in rule_hits),
                          key=lambda r: -r["points"])
        words = [w for w, _ in self.text_model.explain(e["subject"], e["body"], k=8) if not w.startswith("cue_")]
        reasons.append({"points": round(text_pts, 1),
                        "reason": f"Text model says {p:.0%} phishing-like" +
                                  (f" (key words: {', '.join(words[:6])})" if words and p >= 0.3 else "") +
                                  (" - lowered because sender is the verified real brand" if calmed else "")})

        return {
            "risk": risk, "level": level, "action": action,
            "text_probability": round(p, 4),
            "tactics": tactics,
            "reasons": reasons,
            "intel_hits": intel_hits,
            "email": {"from": e["from"], "reply_to": e["reply_to"], "subject": e["subject"],
                      "urls": e["urls"][:10], "attachments": e["attachments"],
                      "auth": {k: signs[k] for k in ("spf", "dkim", "dmarc")}},
        }


def pretty(result):
    r = result
    bar = "#" * (r["risk"] // 5) + "." * (20 - r["risk"] // 5)
    lines = [f"Subject : {r['email']['subject'][:90]}",
             f"From    : {r['email']['from'][:90]}",
             f"Risk    : {r['risk']:3d}/100 [{bar}] {r['level']}",
             f"Action  : {r['action']}",
             f"Auth    : SPF={r['email']['auth']['spf']} DKIM={r['email']['auth']['dkim']} DMARC={r['email']['auth']['dmarc']}"]
    if r["tactics"]:
        lines.append("Tactics : " + ", ".join(r["tactics"]))
    lines.append("Why     :")
    for x in r["reasons"]:
        lines.append(f"   {x['points']:+6.1f}  {x['reason']}")
    return "\n".join(lines)
