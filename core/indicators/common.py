"""
Shared pieces for all detectors (Member 1): the Indicator record and a few
helpers for reasoning about domain names. Everything is offline.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field


@dataclass
class Indicator:
    id: str            # key into knowledge_base.json, e.g. "URL_IP_HOST"
    name: str          # short title shown in the UI
    category: str      # "content" | "url" | "header" | "attachment"
    weight: int        # points this indicator adds to the risk score
    reason: str        # plain-English explanation
    evidence: list = field(default_factory=list)   # the exact text that matched

    def to_dict(self) -> dict:
        return asdict(self)


# Brands phishers like to imitate -> their official domains.
MICROSOFT = ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"]
APPLE = ["apple.com", "icloud.com"]
BRANDS = {
    "paypal": ["paypal.com"], "google": ["google.com", "gmail.com"], "amazon": ["amazon.com", "amazon.in"],
    "microsoft": MICROSOFT, "office365": MICROSOFT, "outlook": MICROSOFT, "onedrive": MICROSOFT,
    "apple": APPLE, "icloud": APPLE,
    "netflix": ["netflix.com"], "dropbox": ["dropbox.com"], "dhl": ["dhl.com"], "flipkart": ["flipkart.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"], "hdfc": ["hdfcbank.com", "hdfcbank.net"], "icici": ["icicibank.com"],
    "paytm": ["paytm.com"], "phonepe": ["phonepe.com"], "irctc": ["irctc.co.in"],
    "income tax": ["incometax.gov.in"], "uidai": ["uidai.gov.in"],
}

FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com",
            "rediffmail.com", "aol.com", "icloud.com", "protonmail.com", "zoho.com"}

# Suffixes like "co.in" belong to the registry, not the organisation.
TWO_PART_SUFFIXES = {"co.in", "gov.in", "ac.in", "org.in", "net.in", "co.uk", "com.au"}


def registered_domain(host: str) -> str:
    """'login.paypal.com' -> 'paypal.com';  'alerts.sbi.co.in' -> 'sbi.co.in'."""
    parts = host.lower().strip(".").split(".")
    n = 3 if ".".join(parts[-2:]) in TWO_PART_SUFFIXES else 2
    return ".".join(parts[-n:])


def domain_of(address: str) -> str:
    """'Bob <bob@Example.com>' -> 'example.com'."""
    return address.rsplit("@", 1)[-1].strip(" <>").lower() if "@" in address else ""


def is_official(host: str, domains: list) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def levenshtein(a: str, b: str) -> int:
    """Edit distance: how many single-letter changes turn a into b."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Digits and Cyrillic letters that look like Latin letters (paypa1, аpple).
LOOKALIKE_CHARS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a",
                                 "а": "a", "е": "e", "о": "o", "р": "p", "с": "c"})


def lookalike(host: str) -> str | None:
    """Return a reason if `host` imitates a known brand, else None."""
    try:
        host = host.encode("ascii").decode("idna")       # punycode xn--... -> real characters
    except UnicodeError:
        pass
    host = host.lower()
    if any(is_official(host, domains) for domains in BRANDS.values()):
        return None
    for brand in BRANDS:
        key = brand.replace(" ", "")
        for token in re.split(r"[.\-]", host):
            if token == key:
                return f"'{host}' contains '{brand}' but is not an official {brand} domain"
            if token.translate(LOOKALIKE_CHARS) == key:
                return f"'{token}' imitates '{brand}' using look-alike characters"
            # Edit distance only for longer names ('apple' vs 'apply' would be a false alarm).
            if len(key) >= 6 and levenshtein(token, key) == 1:
                return f"'{token}' is one typo away from '{brand}' (typosquatting)"
    return None
