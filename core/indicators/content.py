"""
content.py - language-based (social-engineering) indicators.   [Member 1]

Each check is one row in CHECKS: a list of phrases (regular expressions).
Phrases are wrapped in \b word boundaries so 'pin' does not match 'spinning'.
The matched phrases are kept as evidence.
"""
import re

from core.indicators.common import Indicator, domain_of, is_official

# A request preceded by "never", "do not" ... is a warning, not a request:
# "We will never ask you to share your OTP."
NEGATION = re.compile(r"\b(never|not|don't|won't|avoid)\b[^.!?]{0,30}$", re.IGNORECASE)

REQUEST = r"(?:send|share|provide|enter|confirm|update|verify|submit|reply with|link|give)"
SECRETS = (r"(?:aadhaa?r|pan (?:card|number)|bank account|(?:credit |debit )?card (?:number|details)|cvv"
           r"|otp|(?:upi |atm )?pin|kyc|ifsc)")

# (id, name, weight, phrases, ignore negated matches?, reason)
CHECKS = [
    ("CNT_URGENCY", "Urgency / threat language", 10, [
        r"urgent(?:ly)?", r"immediately", r"right away", r"act now", r"asap", r"within \d+ hours",
        r"(?:account|service|connection) (?:has been|will be|is) (?:suspended|blocked|locked|limited|disconnected)",
        r"expires? today", r"final (?:notice|warning)", r"legal action", r"arrest", r"penalty",
        r"failure to \w+", r"unusual activity", r"suspicious (?:activity|login)", r"permanently (?:deleted|blocked)",
     ], False, "Pressure and threats rush you into acting before thinking."),
    ("CNT_CREDENTIAL_REQUEST", "Credential request", 20, [
        r"verify your (?:account|identity|login)", r"confirm your (?:account|password|identity|details)",
        r"(?:update|validate) your (?:login|account|password|billing)",
        r"(?:log ?in|sign ?in) (?:to|and) (?:verify|confirm|unlock|restore|view|avoid)",
        r"click (?:here|below) to (?:verify|log ?in|sign ?in|unlock)", r"enter your (?:password|username|credentials)",
        r"unlock your account", r"restore (?:your )?access",
     ], True, "Asks you to log in or confirm your account - real organisations do not do this by email."),
    ("CNT_PERSONAL_DATA", "Sensitive data request", 20, [
        REQUEST + r"\b[^.!?]{0,40}?\b" + SECRETS,
     ], True, "Asks for identity or payment secrets (Aadhaar, PAN, card, CVV, OTP, PIN, KYC)."),
    ("CNT_REWARD_BAIT", "Reward / lottery bait", 14, [
        r"you(?:'ve| have)? won", r"winner", r"lottery", r"lucky draw", r"prize", r"congratulations",
        r"cash ?back", r"claim your", r"refund of", r"tax refund", r"kbc", r"selected as",
     ], False, "Prizes, cashback or refunds exploit greed and curiosity."),
    ("CNT_PAYMENT_REQUEST", "Payment / money-transfer request", 15, [
        r"wire transfer", r"bank transfer", r"gift cards", r"processing fee", r"(?:customs|registration|delivery) fee",
        r"pay (?:a|the) (?:small )?(?:fee|fine|dues|penalty)", r"outstanding (?:payment|invoice)",
        r"new bank account", r"bank details (?:have )?changed",
     ], False, "Asks you to send money or change bank details - typical of scams and BEC."),
    ("CNT_GENERIC_GREETING", "Generic greeting", 5, [
        r"dear (?:valued )?(?:customer|user|client|member|winner|taxpayer|citizen|consumer|employee)", r"hello user",
     ], False, "A mass-mailed message: the sender does not know your name."),
]

# Authorities -> domains allowed to use that name ([] = never trust it by email alone).
AUTHORITIES = {
    r"state bank of india|sbi": ["sbi.co.in", "onlinesbi.sbi"],
    r"hdfc bank": ["hdfcbank.com", "hdfcbank.net"],
    r"reserve bank of india|rbi": ["rbi.org.in"],
    r"income tax department|it department": ["incometax.gov.in"],
    r"uidai|government of india|police|cyber cell": ["gov.in", "nic.in"],
    r"ceo|md|managing director|it support|helpdesk|mail administrator": [],
}


def find(pattern: str, text: str, skip_negated: bool = False) -> list:
    """All distinct matches of pattern in text (lower-case)."""
    hits = []
    for m in re.finditer(r"\b(?:" + pattern + r")\b", text, re.IGNORECASE):
        if skip_negated and NEGATION.search(text[max(0, m.start() - 40):m.start()]):
            continue
        if m.group(0).lower() not in hits:
            hits.append(m.group(0).lower())
    return hits


def analyze(email) -> list:
    # One line of text: subject + body, all whitespace (incl. line breaks) collapsed.
    text = re.sub(r"\s+", " ", f"{email.subject}. {email.body_text}")
    found = []
    for id_, name, weight, phrases, skip_negated, reason in CHECKS:
        hits = find("|".join(phrases), text, skip_negated)
        if hits:
            found.append(Indicator(id_, name, "content", weight, reason, hits))

    # Authority claims count only if the sender is NOT that authority's domain.
    sender = domain_of(email.from_email)
    claims = []
    for pattern, official in AUTHORITIES.items():
        if not (official and is_official(sender, official)):
            claims += find(pattern, f"{email.from_name}. {text}")
    if claims:
        found.append(Indicator("CNT_AUTHORITY_IMPERSONATION", "Authority impersonation", "content", 10,
                               "Claims to be a bank, government office, police or executive, but was not "
                               "sent from that authority's domain.", claims))
    return found
