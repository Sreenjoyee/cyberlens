"""
analyzer.py - the whole pipeline in one function.

    EmailData -> indicators -> score + threat -> concept map -> CIA -> hashes
"""
from datetime import datetime

from core.cia import compute_cia
from core.indicators import run_all
from core.indicators.attachment import file_hashes
from core.integrity import sha256_bytes, sha256_text
from core.mapper import build_impact_map
from core.scorer import score_indicators


def analyze_email(email) -> dict:
    indicators = run_all(email)                                          # 1. detect
    score = score_indicators(indicators)                                 # 2. score
    return {
        "email": email,
        "indicators": indicators,
        "score": score,
        "impact": build_impact_map(indicators, score["threat"], email.subject),   # 3. explain
        "cia": compute_cia(indicators),                                  # 4. CIA impact
        "hashes": {                                                      # 5. integrity
            "body": sha256_text(email.body_text),
            "eml": sha256_bytes(email.raw) if email.raw else None,
            "attachments": file_hashes(email),
        },
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }
