"""
Indicator modules (Member 1). Each module has analyze(email) -> list[Indicator].
"""
from core.indicators import attachment, content, header, url
from core.indicators.common import Indicator


def run_all(email) -> list[Indicator]:
    """Run every detector and return all indicators that fired."""
    return content.analyze(email) + url.analyze(email) + header.analyze(email) + attachment.analyze(email)
