"""Rule layer: header authentication, sender, links and attachments.

Each rule adds (or removes) points and gives a plain-English reason.
Points are hand-set (not learned) because our training data has no
modern headers / links for legit mail. Tune them on your own labelled mail.
"""

from .features import attachment_signs, auth_signs, link_signs, sender_signs, BRANDS
from .emailparse import base_domain, domain_of

# (points, reason). Positive = more suspicious.
RULES = {
    "spf_fail":            (15, "SPF check failed - server not allowed to send for this domain"),
    "spf_softfail":        (8,  "SPF soft-fail - sender server is not clearly allowed"),
    "dkim_fail":           (12, "DKIM signature failed - message may be altered or forged"),
    "dmarc_fail":          (20, "DMARC failed - sender domain is likely spoofed"),
    "auth_all_pass":       (-15, "SPF, DKIM and DMARC all passed"),
    "reply_to_mismatch":   (12, "Replies go to a different domain than the sender"),
    "return_path_mismatch": (5, "Bounce address domain differs from sender"),
    "display_name_has_email": (8, "Display name contains an e-mail address (classic spoof trick)"),
    "brand_impersonation": (25, "Mentions brand '{v}' but is not sent from its real domain"),
    "lookalike_sender":    (12, "Sender domain looks like a look-alike (digits / 'rn' / '-secure' etc.)"),
    "sender_risky_tld":    (8,  "Sender uses a cheap / high-abuse domain ending"),
    "free_mail_sender":    (4,  "Sent from a free webmail account"),
    "link_ip_address":     (15, "Link points to a raw IP address"),
    "link_shortener":      (8,  "Link uses a URL shortener that hides the real target"),
    "link_risky_tld":      (8,  "Link goes to a high-abuse domain ending"),
    "link_punycode":       (12, "Link uses punycode (possible look-alike characters)"),
    "link_has_at":         (12, "Link contains '@' to hide the real host"),
    "link_many_subdomains": (6, "Link has an unusually long chain of subdomains"),
    "link_text_mismatch":  (18, "Link text shows one site but actually goes to another"),
    "link_http_only":      (3,  "Link is not HTTPS"),
    "risky_attachment":    (25, "Dangerous attachment type (script / html / macro / exe)"),
    "archive_attachment":  (8,  "Compressed attachment (often used to hide malware)"),
    "double_extension":    (20, "Attachment uses a double extension (e.g. invoice.pdf.exe)"),
}


def _add(hits, key, value=None):
    pts, why = RULES[key]
    hits.append({"rule": key, "points": pts, "reason": why.format(v=value)})


def score_rules(e):
    """Return (points, hits, raw_signs)."""
    hits = []
    auth = auth_signs(e)
    snd = sender_signs(e, "")
    lnk = link_signs(e)
    att = attachment_signs(e)

    if auth["has_auth_results"]:
        if auth["spf"] == "fail":
            _add(hits, "spf_fail")
        elif auth["spf"] == "softfail":
            _add(hits, "spf_softfail")
        if auth["dkim"] == "fail":
            _add(hits, "dkim_fail")
        if auth["dmarc"] == "fail":
            _add(hits, "dmarc_fail")
        if auth["spf"] == auth["dkim"] == auth["dmarc"] == "pass":
            _add(hits, "auth_all_pass")

    for k in ("reply_to_mismatch", "return_path_mismatch", "display_name_has_email",
              "lookalike_sender", "sender_risky_tld", "free_mail_sender"):
        if snd[k]:
            _add(hits, k)
    if snd["brand_impersonation"]:
        _add(hits, "brand_impersonation", snd["brand_impersonation"])

    for k in ("link_ip_address", "link_shortener", "link_risky_tld", "link_punycode", "link_has_at",
              "link_many_subdomains", "link_text_mismatch", "link_http_only"):
        if lnk[k]:
            _add(hits, k)
    for k in ("risky_attachment", "archive_attachment", "double_extension"):
        if att[k]:
            _add(hits, k)

    return sum(h["points"] for h in hits), hits, {**auth, **snd, **lnk, **att}


def verified_brand_sender(e, signs):
    """True if mail is DMARC/DKIM-pass AND really comes from a known brand's domain.
    Used to calm down the text model for genuine PayPal / bank / Amazon mail."""
    sbase = base_domain(domain_of(e.get("from", "")))
    real = set(BRANDS.values())
    passed = signs.get("dmarc") == "pass" or (signs.get("dkim") == "pass" and signs.get("spf") == "pass")
    return passed and sbase in real
