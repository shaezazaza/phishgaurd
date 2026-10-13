"""Features.

Two groups, on purpose:
  * TEXT features (words + social-engineering cues) -> learned by the ML model.
  * LINK / ATTACHMENT / SENDER features -> scored by hand-set rules (rules.py).

Why split? The legit training mail (Enron) has no links, attachments or real
sender headers, so a model trained on those would just learn "has a link = phish".
Keeping them out of the ML model stops that shortcut.
"""

import re
from urllib.parse import urlparse

from .emailparse import base_domain, domain_of

# ---------------------------------------------------------------- text cleaning
_URL = re.compile(r"(https?://|www\.)\S+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)*", re.I)
_LONG_JUNK = re.compile(r"\b\w{25,}\b")              # random filler / tracking tokens
_DATASET_WORDS = re.compile(r"\b(enron|ect|hou|phishing[\s_@]*pot|example\.com)\b", re.I)


def clean_text(subject, body, max_chars=6000):
    """Lower-case text with URLs, e-mail addresses and dataset-specific words removed."""
    t = f"{subject} \n {body[:max_chars]}"
    t = _URL.sub(" ", t)
    t = _EMAIL.sub(" ", t)
    t = _DATASET_WORDS.sub(" ", t)
    t = _LONG_JUNK.sub(" ", t)
    t = t.lower()
    return re.sub(r"\s+", " ", t).strip()


# ---------------------------------------------------------------- social-engineering cues
CUES = {
    "urgency": ["urgent", "immediately", "within 24 hours", "within 48 hours", "act now", "final notice",
                "last warning", "expire", "expires", "expired", "asap", "right away", "as soon as possible",
                "deadline", "today only", "limited time", "suspended", "suspension", "terminated",
                "will be closed", "will be deleted", "will be blocked", "locked", "disabled"],
    "threat": ["unauthorized", "unusual activity", "suspicious activity", "security alert", "breach",
               "compromised", "legal action", "penalty", "fraud alert", "restricted", "violation"],
    "credentials": ["password", "login", "log in", "sign in", "sign-in", "verify your", "confirm your",
                    "update your", "validate", "credentials", "username", "otp", "one-time", "pin",
                    "security question", "account information", "billing information"],
    "money": ["wire transfer", "gift card", "invoice", "payment", "bank details", "bank account", "refund",
              "credit card", "card details", "prize", "winner", "lottery", "inheritance", "bitcoin",
              "crypto", "transfer", "claim", "reward", "bonus", "free"],
    "authority": ["ceo", "director", "it department", "helpdesk", "help desk", "administrator", "irs",
                  "income tax", "government", "police", "court", "customer service", "support team"],
    "secrecy": ["confidential", "keep this between", "don't tell", "do not share", "private matter",
                "discreet", "i am in a meeting", "can't talk"],
    "action": ["click here", "click the link", "click below", "open the attachment", "download",
               "enable macros", "enable content", "follow the link", "visit the link"],
    "generic_greeting": ["dear customer", "dear user", "dear member", "dear client", "dear account holder",
                         "dear sir/madam", "dear valued", "hello user"],
}


def text_cues(clean):
    """Counts of each cue group in already-cleaned text."""
    return {f"cue_{k}": sum(clean.count(w) for w in words) for k, words in CUES.items()}


CUE_NAMES = list(text_cues("").keys())


# ---------------------------------------------------------------- link / attachment / sender signs
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy", "ow.ly", "cutt.ly",
              "shorturl.at", "tiny.cc", "s.id", "rebrand.ly", "buff.ly"}
RISKY_TLDS = {"xyz", "top", "ru", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link", "work", "zip",
              "mov", "rest", "icu", "cyou", "sbs", "cfd", "monster", "shop", "online", "site", "live"}
RISKY_EXT = (".exe", ".scr", ".js", ".jse", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img",
             ".lnk", ".html", ".htm", ".shtml", ".svg", ".docm", ".xlsm", ".pptm", ".jar", ".msi")
ARCHIVE_EXT = (".zip", ".rar", ".7z", ".gz", ".tar", ".ace", ".cab")
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "proton.me",
             "protonmail.com", "icloud.com", "gmx.com", "mail.com", "yandex.com", "rediffmail.com",
             "zoho.com"}
BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "office 365": "microsoft.com",
          "outlook": "microsoft.com", "amazon": "amazon.com", "apple": "apple.com", "icloud": "apple.com",
          "google": "google.com", "netflix": "netflix.com", "facebook": "facebook.com",
          "instagram": "instagram.com", "linkedin": "linkedin.com", "dhl": "dhl.com", "fedex": "fedex.com",
          "docusign": "docusign.net", "dropbox": "dropbox.com", "wells fargo": "wellsfargo.com",
          "chase": "chase.com", "bank of america": "bankofamerica.com", "sbi": "sbi.co.in",
          "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axis bank": "axisbank.com",
          "paytm": "paytm.com", "phonepe": "phonepe.com", "irctc": "irctc.co.in",
          "income tax": "incometax.gov.in", "metamask": "metamask.io", "coinbase": "coinbase.com"}
_LOOKALIKE = re.compile(r"(\d(?=[a-z])|(?<=[a-z])\d|rn|vv|-secure|-security|-verify|-login|-update|-support|-account)")


def _host(u):
    try:
        return (urlparse(u if "://" in u else "http://" + u).hostname or "").lower()
    except ValueError:
        return ""


def _display_name(addr):
    m = re.match(r'\s*"?([^"<]*)"?\s*<', addr or "")
    return (m.group(1) if m else "").strip().lower()


def link_signs(e):
    urls = e.get("urls", [])
    hosts = [h for h in (_host(u) for u in urls) if h]
    sender_base = base_domain(domain_of(e.get("from", "")))
    link_bases = {base_domain(h) for h in hosts}

    # <a> text shows one domain but href goes to another
    text_mismatch = 0
    for href, txt in e.get("html_links", []):
        shown = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", (txt or "").lower())
        if shown and href.lower().startswith("http"):
            if base_domain(shown.group(0)) != base_domain(_host(href)):
                text_mismatch += 1

    return {
        "num_links": len(urls),
        "num_link_domains": len(link_bases),
        "link_ip_address": int(any(re.fullmatch(r"[\d.]+", h) for h in hosts)),
        "link_shortener": int(any(base_domain(h) in SHORTENERS or h in SHORTENERS for h in hosts)),
        "link_risky_tld": int(any(h.rsplit(".", 1)[-1] in RISKY_TLDS for h in hosts)),
        "link_punycode": int(any("xn--" in h for h in hosts)),
        "link_has_at": int(any("@" in (urlparse(u).netloc if "://" in u else "") for u in urls)),
        "link_many_subdomains": int(any(h.count(".") >= 4 for h in hosts)),
        "link_text_mismatch": text_mismatch,
        "link_not_sender_domain": int(bool(sender_base) and bool(link_bases) and sender_base not in link_bases),
        "link_http_only": int(any(u.lower().startswith("http://") for u in urls)),
    }


def sender_signs(e, clean):
    sender = domain_of(e.get("from", ""))
    sbase = base_domain(sender)
    reply = domain_of(e.get("reply_to", ""))
    rpath = domain_of(e.get("return_path", ""))
    name = _display_name(e.get("from", ""))

    impersonated = ""
    for brand, real in BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", name + " " + e.get("subject", "").lower()):
            if sbase and sbase != real and not sbase.endswith("." + real):
                impersonated = brand
                break
    return {
        "reply_to_mismatch": int(bool(reply) and base_domain(reply) != sbase),
        "return_path_mismatch": int(bool(rpath) and bool(sbase) and base_domain(rpath) != sbase),
        "free_mail_sender": int(sbase in FREE_MAIL),
        "display_name_has_email": int("@" in name),
        "brand_impersonation": impersonated,
        "lookalike_sender": int(bool(sbase) and bool(_LOOKALIKE.search(sbase.split(".")[0]))),
        "sender_risky_tld": int(sbase.rsplit(".", 1)[-1] in RISKY_TLDS if sbase else 0),
    }


def attachment_signs(e):
    names = [a.lower() for a in e.get("attachments", [])]
    return {
        "num_attachments": len(names),
        "risky_attachment": int(any(n.endswith(RISKY_EXT) for n in names)),
        "archive_attachment": int(any(n.endswith(ARCHIVE_EXT) for n in names)),
        "double_extension": int(any(re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.\w{2,4}$", n) for n in names)),
    }


def auth_signs(e):
    a = (e.get("auth_results") or "").lower()
    def res(key):
        m = re.search(rf"\b{key}\s*=\s*(\w+)", a)
        return m.group(1) if m else "none"
    spf, dkim, dmarc = res("spf"), res("dkim"), res("dmarc")
    if spf == "none":
        m = re.search(r"\b(pass|fail|softfail|neutral|permerror|temperror)\b", a)
        spf = m.group(1) if m and "spf" in a else "none"
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "has_auth_results": int(bool(a))}
