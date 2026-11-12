"""
cia.py - Confidentiality / Integrity / Availability impact.   [Member 2]

Each indicator adds points (with a reason) to one or more CIA dimensions.
Points -> level: 0 None, 1-2 Low, 3-4 Medium, 5+ High.
"""
# indicator id -> {dimension: (points, reason)}
RULES = {
    "CNT_CREDENTIAL_REQUEST": {"C": (3, "Your password would be disclosed."), "I": (1, "The attacker could change your data.")},
    "CNT_PERSONAL_DATA": {"C": (3, "Aadhaar/PAN/card/OTP would be disclosed."), "I": (1, "An OTP lets the attacker approve transactions.")},
    "CNT_URGENCY": {"C": (1, "Pressure leads to hasty disclosure.")},
    "CNT_REWARD_BAIT": {"C": (1, "Bait is used to collect personal details.")},
    "CNT_PAYMENT_REQUEST": {"I": (2, "Fake payment/bank changes corrupt financial records."), "A": (1, "Lost money is no longer available.")},
    "CNT_AUTHORITY_IMPERSONATION": {"I": (2, "The claimed origin of the message is false.")},
    "URL_LOOKALIKE_DOMAIN": {"C": (2, "A fake login page captures what you type."), "I": (1, "The site pretends to be another.")},
    "URL_TEXT_MISMATCH": {"I": (2, "The message lies about where its link goes."), "C": (1, "The hidden target harvests data.")},
    "URL_HTTP_INSECURE": {"C": (2, "HTTP traffic can be read in transit."), "I": (1, "HTTP traffic can be modified in transit.")},
    "URL_IP_HOST": {"C": (1, "An unknown server may collect your data.")},
    "URL_PUNYCODE": {"I": (2, "A homograph domain forges a trusted name.")},
    "URL_SHORTENER": {"I": (1, "The real destination is hidden.")},
    "URL_AT_SYMBOL": {"I": (1, "The URL disguises its real host.")},
    "URL_SUSPICIOUS_TLD": {"C": (1, "Throw-away domains often collect data.")},
    "URL_EXCESSIVE_SUBDOMAINS": {"I": (1, "Subdomains disguise the real domain.")},
    "HDR_SPF_FAIL": {"I": (2, "The sending server was not authorised for the domain.")},
    "HDR_DKIM_FAIL": {"I": (3, "The digital signature failed: origin/content cannot be trusted.")},
    "HDR_DMARC_FAIL": {"I": (2, "The visible sender is not authenticated.")},
    "HDR_DISPLAY_NAME_MISMATCH": {"I": (1, "The displayed sender is not the real sender.")},
    "HDR_LOOKALIKE_SENDER": {"I": (2, "The sender domain forges a brand.")},
    "HDR_REPLY_TO_MISMATCH": {"C": (1, "Your reply goes to someone else.")},
    "HDR_RETURN_PATH_MISMATCH": {"I": (1, "Envelope sender differs from visible sender.")},
    "HDR_FREEMAIL_ORG": {"I": (1, "Organisational identity is claimed without proof.")},
    "ATT_DANGEROUS_EXT": {"C": (2, "Malware can steal data."), "I": (3, "Malware can modify the system."), "A": (3, "Ransomware can encrypt your files.")},
    "ATT_DOUBLE_EXT": {"I": (1, "The file pretends to be a document."), "A": (2, "The hidden program may be ransomware.")},
    "ATT_MACRO_OFFICE": {"C": (2, "Macro malware steals data."), "I": (2, "Macros can modify the system."), "A": (2, "Macros often deliver ransomware.")},
    "ATT_ARCHIVE": {"A": (1, "Archives can hide ransomware from scanners.")},
    "ATT_MAGIC_MISMATCH": {"I": (3, "The file is not what its name says."), "A": (2, "A disguised program can disrupt the system.")},
}
NAMES = {"C": "Confidentiality", "I": "Integrity", "A": "Availability"}


def compute_cia(indicators: list) -> dict:
    result = {name: {"points": 0, "reasons": []} for name in NAMES.values()}
    for ind in indicators:
        for dim, (points, reason) in RULES.get(ind.id, {}).items():
            result[NAMES[dim]]["points"] += points
            result[NAMES[dim]]["reasons"].append(f"{ind.name}: {reason}")
    for r in result.values():
        p = r["points"]
        r["level"] = "High" if p >= 5 else "Medium" if p >= 3 else "Low" if p >= 1 else "None"
    return result
