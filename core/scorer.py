"""
scorer.py - risk score, level and primary threat.   [Member 1]

Score:  points are summed per category, each category is capped (so one
        category cannot dominate), then the total is clipped to 0-100.
        If a malicious payload is attached the score is at least 40.
Level:  Low < 25 <= Medium < 50 <= High < 75 <= Critical
Threat: first matching rule in primary_threat() wins.
"""
CAPS = {"content": 45, "url": 40, "header": 35, "attachment": 45}
PHISHING_THRESHOLD = 25      # Medium or higher = phishing (used in evaluation)
PAYLOAD_FLOOR = 40

PAYLOAD = {"ATT_DANGEROUS_EXT", "ATT_DOUBLE_EXT", "ATT_MACRO_OFFICE", "ATT_MAGIC_MISMATCH"}
DECEPTIVE_LINKS = {"URL_LOOKALIKE_DOMAIN", "URL_TEXT_MISMATCH", "URL_IP_HOST", "URL_PUNYCODE", "URL_AT_SYMBOL"}
IMPERSONATION = {"CNT_AUTHORITY_IMPERSONATION", "HDR_REPLY_TO_MISMATCH", "HDR_FREEMAIL_ORG"}
MONEY = {"CNT_REWARD_BAIT", "CNT_PAYMENT_REQUEST", "CNT_PERSONAL_DATA"}


def level_for(score: int) -> str:
    return "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"


def primary_threat(ids: set, level: str) -> tuple:
    """Ordered rules -> (threat, reason)."""
    if level == "Low":
        return "Likely Safe", "The score is below the Medium threshold."
    if ids & PAYLOAD:
        return "Malicious Attachment", "An attachment can run code on your computer."
    if "CNT_CREDENTIAL_REQUEST" in ids or ids & DECEPTIVE_LINKS:
        return "Credential Phishing", "It asks you to log in, or its links lead to a disguised site."
    if ids & IMPERSONATION and "CNT_PAYMENT_REQUEST" in ids and "CNT_REWARD_BAIT" not in ids:
        return "Impersonation/BEC", "Someone posing as a boss/official asks for money."
    if ids & MONEY:
        return "Financial Fraud/Scam", "It is after your money or banking/identity details."
    return "Impersonation/BEC", "The sender's identity is faked."


def score_indicators(indicators: list) -> dict:
    per_category = {c: sum(i.weight for i in indicators if i.category == c) for c in CAPS}
    score = min(100, sum(min(points, CAPS[c]) for c, points in per_category.items()))
    ids = {i.id for i in indicators}
    if ids & PAYLOAD:
        score = max(score, PAYLOAD_FLOOR)
    level = level_for(score)
    threat, reason = primary_threat(ids, level)

    # Confidence: how many independent categories agree.
    active = [c for c, points in per_category.items() if points]
    confidence = "High" if len(active) >= 3 else "Medium" if len(active) == 2 else "Low"
    top = sorted(indicators, key=lambda i: -i.weight)[:3]
    explanation = (f"{len(indicators)} indicator(s) in {len(active)} categor{'y' if len(active) == 1 else 'ies'}. "
                   + ("Top: " + ", ".join(f"{i.name} ({i.weight} pts)" for i in top) if top else "Nothing suspicious found."))
    return {"score": score, "level": level, "threat": threat, "threat_reason": reason,
            "confidence": confidence, "explanation": explanation, "per_category": per_category}
