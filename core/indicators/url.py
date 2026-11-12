"""
url.py - URL / network indicators.   [Member 1]

Every link is checked; each check produces at most ONE indicator with all
offending links as evidence (so 20 bad links do not count 20 times).
"""
import math
import re
from collections import Counter
from urllib.parse import urlparse

from core.indicators.common import Indicator, lookalike, registered_domain

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "buzz", "icu",
                   "cyou", "sbs", "zip", "loan", "win", "support", "online", "site", "ru", "cn"}
FILE_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "zip", "jpg", "png", "txt", "html", "php", "exe"}

# id -> (name, weight, reason)
CHECKS = {
    "URL_HTTP_INSECURE": ("Unencrypted HTTP link", 5, "http:// has no TLS encryption; real login pages use HTTPS."),
    "URL_IP_HOST": ("IP address instead of domain", 15, "Links to a raw IP address avoid domain reputation checks."),
    "URL_SHORTENER": ("URL shortener", 8, "A shortener hides where the link really goes."),
    "URL_LOOKALIKE_DOMAIN": ("Lookalike / typosquatted domain", 20, "The domain imitates a well-known brand."),
    "URL_PUNYCODE": ("Punycode (IDN homograph)", 15, "xn-- domains can show letters that look identical to a real brand."),
    "URL_EXCESSIVE_SUBDOMAINS": ("Excessive subdomains", 6, "A trusted name is placed on the left; the real domain is on the right."),
    "URL_SUSPICIOUS_TLD": ("Suspicious top-level domain", 8, "Cheap TLDs are heavily abused for phishing."),
    "URL_AT_SYMBOL": ("'@' trick in URL", 12, "Browsers ignore everything before '@': bank.com@evil.com opens evil.com."),
    "URL_TEXT_MISMATCH": ("Link text does not match destination", 15, "The visible text shows one domain, the link goes to another."),
    "URL_LONG_OR_RANDOM": ("Very long or random-looking URL", 4, "Long/random URLs hide the target and evade filters."),
}


def entropy(s: str) -> float:
    """Shannon entropy in bits per character: random tokens ~5, normal words ~3-4."""
    return -sum(c / len(s) * math.log2(c / len(s)) for c in Counter(s).values()) if s else 0.0


def analyze(email) -> list:
    hits = {id_: [] for id_ in CHECKS}
    for link in email.links:
        url = link.url
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        reg = registered_domain(host)
        is_ip = re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host) is not None
        subdomains = [s for s in host[: -len(reg)].split(".") if s and s != "www"]

        if url.lower().startswith("http://"):
            hits["URL_HTTP_INSECURE"].append(url)
        if is_ip:
            hits["URL_IP_HOST"].append(url)
        if reg in SHORTENERS:
            hits["URL_SHORTENER"].append(url)
        if not is_ip and (reason := lookalike(host)):
            hits["URL_LOOKALIKE_DOMAIN"].append(reason)
        if "xn--" in host:
            hits["URL_PUNYCODE"].append(host)
        if len(subdomains) >= 3:
            hits["URL_EXCESSIVE_SUBDOMAINS"].append(host)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            hits["URL_SUSPICIOUS_TLD"].append(host)
        if "@" in parsed.netloc:
            hits["URL_AT_SYMBOL"].append(url)
        shown = re.search(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", link.text.lower())
        if shown and shown.group().rsplit(".", 1)[-1] not in FILE_EXTENSIONS \
                and registered_domain(shown.group()) != reg:
            hits["URL_TEXT_MISMATCH"].append(f"shows '{link.text}' but goes to {host}")
        tail = parsed.path + parsed.query
        if len(url) > 100 or (len(tail) >= 40 and entropy(tail) > 4.5):
            hits["URL_LONG_OR_RANDOM"].append(url[:80])

    found = []
    for id_, evidence in hits.items():
        if evidence:
            name, weight, reason = CHECKS[id_]
            found.append(Indicator(id_, name, "url", weight, reason, evidence[:5]))
    return found
