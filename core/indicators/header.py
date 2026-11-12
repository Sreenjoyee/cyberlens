"""
header.py - sender / header authentication checks.   [Member 1]

The From line is just text the sender typed; SMTP does not verify it.
These checks compare the identity the email CLAIMS with the technical facts.

SPF   = was the sending server allowed to send for this domain?
DKIM  = does the domain's digital signature over the message verify?
DMARC = is the visible From domain backed by SPF or DKIM?
"""
import re

from core.indicators.common import BRANDS, FREEMAIL, Indicator, domain_of, is_official, lookalike, registered_domain

ORG_WORDS = r"\b(bank|department|support|team|helpdesk|security|ceo|md|hr|payroll|finance|official|admin|" \
            r"service|government|tax|police|lottery|rewards?|billing|kyc|board|officer)\b"


def analyze(email) -> list:
    found = []
    sender = domain_of(email.from_email)
    name = email.from_name.lower()

    def add(id_, title, weight, reason, evidence):
        found.append(Indicator(id_, title, "header", weight, reason, evidence))

    # 1. Display name claims a brand the sending domain does not belong to.
    claimed = [b for b, domains in BRANDS.items()
               if re.search(rf"\b{b}\b", name) and not is_official(sender, domains)]
    if sender and claimed:
        add("HDR_DISPLAY_NAME_MISMATCH", "Display name / sender mismatch", 12,
            "The display name claims a brand, but the real sending domain is not that brand's.",
            [f"'{email.from_name}' sent from {sender}"])

    # 2. The sender domain itself is a lookalike (paypa1-security.com).
    if sender and (reason := lookalike(sender)):
        add("HDR_LOOKALIKE_SENDER", "Lookalike sender domain", 16, "The sender's domain imitates a known brand.", [reason])

    # 3/4. Replies or bounces go to a different domain than From.
    for id_, title, weight, other in [
        ("HDR_REPLY_TO_MISMATCH", "Reply-To differs from sender", 10, email.reply_to),
        ("HDR_RETURN_PATH_MISMATCH", "Return-Path differs from sender", 5, email.return_path),
    ]:
        if sender and domain_of(other) and registered_domain(domain_of(other)) != registered_domain(sender):
            add(id_, title, weight, "This address belongs to a different domain than the visible sender.",
                [f"From: {email.from_email}", f"Other: {other}"])

    # 5. SPF / DKIM / DMARC failures recorded by the receiving mail server.
    auth = email.auth_results.lower()
    for proto, weight in [("spf", 10), ("dkim", 8), ("dmarc", 12)]:
        if m := re.search(rf"\b{proto}=(fail|softfail)\b", auth):
            add(f"HDR_{proto.upper()}_FAIL", f"{proto.upper()} check failed", weight,
                f"The receiving server reported {proto.upper()}={m.group(1)}: the sender is likely spoofed.", [m.group(0)])

    # 6. Free webmail account pretending to be an organisation.
    who = f"{name} {email.from_email.split('@')[0].replace('.', ' ')}"
    if sender in FREEMAIL and (re.search(ORG_WORDS, who) or any(re.search(rf"\b{b}\b", who) for b in BRANDS if b != "google")):
        add("HDR_FREEMAIL_ORG", "Free-mail account posing as organisation", 10,
            "Claims to be an organisation but uses a free webmail account anyone can create.",
            [f"{email.from_name} <{email.from_email}>"])
    return found
