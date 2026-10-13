"""Turn a raw email (.eml bytes / mbox message) into a simple dict the rest of the code uses."""

import email
import re
from email import policy
from email.utils import getaddresses, parseaddr
from html import unescape

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)

# second-level suffixes so "mail.sbi.co.in" -> "sbi.co.in"
_TWO_PART = {"co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "nic.in", "firm.in",
             "co.uk", "org.uk", "ac.uk", "gov.uk", "com.br", "net.br", "org.br", "gov.br",
             "com.au", "net.au", "org.au", "co.jp", "co.za", "com.mx", "com.cn", "com.sg",
             "com.tr", "co.kr", "com.ar", "com.pk", "com.ng", "co.id", "com.my"}


def base_domain(host):
    """Registered domain of a host name: 'login.paypal.com' -> 'paypal.com'."""
    host = (host or "").lower().strip(". ").split(":")[0]
    if not host or re.fullmatch(r"[\d.]+", host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_PART:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


_ADDR_ANGLE = re.compile(r"<([^<>\s]+@[^<>\s]+)>")
_ADDR_BARE = re.compile(r"[^\s<>\"',;:]+@[^\s<>\"',;:]+")


def addr_of(address):
    """'Name <a@b.com>' -> 'a@b.com'. Works on messy real-world From headers too
    (e.g. '"Microsoft account team", _ <x@y.com>') where email.utils.parseaddr gives up."""
    s = str(address or "")
    m = _ADDR_ANGLE.search(s) or _ADDR_BARE.search(s)
    return (m.group(1) if m.re is _ADDR_ANGLE else m.group(0)).strip() if m else ""


def domain_of(address):
    addr = addr_of(address)
    return addr.split("@")[-1].lower() if "@" in addr else ""


def html_to_text(html):
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["style", "script", "head", "title", "meta", "noscript"]):
            tag.decompose()   # CSS / JS is not text the reader sees
        return soup.get_text(" ")
    except Exception:
        html = re.sub(r"(?is)<(style|script)[^>]*>.*?</\1>", " ", html)
        return re.sub(r"<[^>]+>", " ", html)


def html_links(html):
    """[(href, visible text)] for every <a> tag."""
    out = []
    try:
        for a in BeautifulSoup(html, "lxml").find_all("a", href=True):
            out.append((a["href"].strip(), a.get_text(" ", strip=True)))
    except Exception:
        pass
    return out


def _part_text(part):
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "latin-1", errors="replace")


def _header(msg, name):
    try:
        v = msg.get(name)
        return str(v) if v is not None else ""
    except Exception:  # badly formed headers in real phishing mail
        raw = msg.get_all(name, failobj=[]) if hasattr(msg, "get_all") else []
        return str(raw[0]) if raw else ""


def parse_message(msg):
    """msg: email.message.Message (policy.default preferred)."""
    plain, html, attachments = [], [], []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        try:
            fname = part.get_filename()
        except Exception:
            fname = None
        disp = (part.get("Content-Disposition") or "").lower()
        if fname or "attachment" in disp:
            attachments.append(fname or f"unnamed.{ctype.split('/')[-1]}")
            continue
        if ctype == "text/plain":
            plain.append(_part_text(part))
        elif ctype == "text/html":
            html.append(_part_text(part))

    html_src = "\n".join(h for h in html if isinstance(h, str))
    body = "\n".join(p for p in plain if isinstance(p, str)).strip()
    if not body and html_src:
        body = html_to_text(html_src)
    body = unescape(body)

    links = html_links(html_src)
    urls = [h for h, _ in links if h.lower().startswith("http")]
    urls += URL_RE.findall(body)
    urls = list(dict.fromkeys(urls))  # unique, keep order

    received = msg.get_all("Received", failobj=[]) if hasattr(msg, "get_all") else []
    auth = " ".join(str(h) for h in (msg.get_all("Authentication-Results", failobj=[]) or []))
    auth += " " + " ".join(str(h) for h in (msg.get_all("ARC-Authentication-Results", failobj=[]) or []))
    auth += " " + _header(msg, "Received-SPF")

    return {
        "from": _header(msg, "From"),
        "reply_to": _header(msg, "Reply-To"),
        "return_path": _header(msg, "Return-Path"),
        "to": _header(msg, "To"),
        "subject": _header(msg, "Subject"),
        "date": _header(msg, "Date"),
        "body": body,
        "html": html_src,
        "html_links": links,
        "urls": urls,
        "attachments": attachments,
        "auth_results": auth.strip(),
        "num_received": len(received),
        "has_headers": len(received) > 0 or bool(auth.strip()),
    }


def parse_bytes(raw: bytes):
    return parse_message(email.message_from_bytes(raw, policy=policy.default))


def parse_file(path):
    with open(path, "rb") as f:
        return parse_bytes(f.read())


def from_text(subject, body, sender="", reply_to="", attachments=None):
    """Build the same dict from plain fields (e.g. a CSV row or pasted text)."""
    return {
        "from": sender, "reply_to": reply_to, "return_path": "", "to": "", "subject": subject or "",
        "date": "", "body": body or "", "html": "", "html_links": [],
        "urls": list(dict.fromkeys(URL_RE.findall(body or ""))), "attachments": attachments or [],
        "auth_results": "", "num_received": 0, "has_headers": False,
    }
