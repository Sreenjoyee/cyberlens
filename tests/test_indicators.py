"""Member 1: each indicator fires on a bad example and stays quiet on a good one."""
import pytest

from core.indicators import run_all
from core.indicators.common import levenshtein, lookalike, registered_domain
from core.parser import Attachment, parse_pasted
from core.scorer import level_for, score_indicators


def ids(**fields):
    return {i.id for i in run_all(parse_pasted(**fields))}


@pytest.mark.parametrize("indicator, bad, good", [
    # content
    ("CNT_URGENCY", {"body": "Your account will be suspended. Act now!"}, {"body": "See you at lunch."}),
    ("CNT_CREDENTIAL_REQUEST", {"body": "Click here to verify your account."},
     {"body": "We will never ask you to confirm your password."}),                       # negation
    ("CNT_PERSONAL_DATA", {"body": "Kindly share your Aadhaar number and OTP."},
     {"body": "Your OTP is 4821. Do not share this OTP with anyone."}),
    ("CNT_REWARD_BAIT", {"body": "You have won the lottery!"}, {"body": "Minutes attached."}),
    ("CNT_PAYMENT_REQUEST", {"body": "Please arrange a wire transfer today."}, {"body": "Thanks for the notes."}),
    ("CNT_GENERIC_GREETING", {"body": "Dear Customer, hello."}, {"subject": "Hello", "body": "Dear Ananya, hi."}),
    ("CNT_AUTHORITY_IMPERSONATION", {"body": "Income Tax Department notice", "from_email": "x@tax-help.com"},
     {"body": "Regards, State Bank of India", "from_email": "alerts@alerts.sbi.co.in"}),
    # url
    ("URL_HTTP_INSECURE", {"body": "http://example.org/a"}, {"body": "https://example.org/a"}),
    ("URL_IP_HOST", {"body": "https://192.168.1.20/login"}, {"body": "https://example.org"}),
    ("URL_SHORTENER", {"body": "https://bit.ly/abc"}, {"body": "https://example.org"}),
    ("URL_LOOKALIKE_DOMAIN", {"body": "https://paypa1.com/x"}, {"body": "https://www.paypal.com/x"}),
    ("URL_PUNYCODE", {"body": "https://xn--pple-43d.com/id"}, {"body": "https://apple.com/id"}),
    ("URL_EXCESSIVE_SUBDOMAINS", {"body": "https://a.b.c.evil.ru/x"}, {"body": "https://www.example.org"}),
    ("URL_SUSPICIOUS_TLD", {"body": "https://gift.xyz/claim"}, {"body": "https://gift.com/claim"}),
    ("URL_AT_SYMBOL", {"body": "https://bank.com@evil.example/x"}, {"body": "https://bank.com/x"}),
    ("URL_TEXT_MISMATCH", {"body": '<a href="http://evil.xyz">www.onlinesbi.sbi</a>'},
     {"body": '<a href="https://example.org/r.pdf">Report.pdf</a>'}),
    ("URL_LONG_OR_RANDOM", {"body": "https://example.org/aZ9kQ2mPz7LwR4tYb8NcVe1HuJ3oFgD5sKq6ZrT0yWi"},
     {"body": "https://example.org/blog/post"}),
    # header
    ("HDR_DISPLAY_NAME_MISMATCH", {"from_name": "PayPal Support", "from_email": "a@mail.xyz"},
     {"from_name": "PayPal", "from_email": "service@paypal.com"}),
    ("HDR_LOOKALIKE_SENDER", {"from_email": "a@netfiix.com"}, {"from_email": "a@netflix.com"}),
    ("HDR_REPLY_TO_MISMATCH", {"from_email": "ceo@acme.com", "reply_to": "ceo@acme-mail.net"},
     {"from_email": "a@acme.com", "reply_to": "b@mail.acme.com"}),
    ("HDR_RETURN_PATH_MISMATCH", {"from_email": "a@bank.com", "return_path": "x@bulk.net"},
     {"from_email": "a@bank.com", "return_path": "b@bank.com"}),
    ("HDR_SPF_FAIL", {"from_email": "a@x.com", "auth_results": "spf=softfail"}, {"auth_results": "spf=pass"}),
    ("HDR_DKIM_FAIL", {"from_email": "a@x.com", "auth_results": "dkim=fail"}, {"auth_results": "dkim=pass"}),
    ("HDR_DMARC_FAIL", {"from_email": "a@x.com", "auth_results": "dmarc=fail"}, {"auth_results": "dmarc=pass"}),
    ("HDR_FREEMAIL_ORG", {"from_name": "SBI Customer Care", "from_email": "sbi.care@gmail.com"},
     {"from_name": "Meera Iyer", "from_email": "meera@gmail.com"}),
    # attachment (names only)
    ("ATT_DANGEROUS_EXT", {"attachment_names": "setup.exe"}, {"attachment_names": "report.pdf"}),
    ("ATT_DOUBLE_EXT", {"attachment_names": "invoice.pdf.exe"}, {"attachment_names": "report.v2.pdf"}),
    ("ATT_MACRO_OFFICE", {"attachment_names": "budget.xlsm"}, {"attachment_names": "budget.xlsx"}),
    ("ATT_ARCHIVE", {"attachment_names": "files.zip"}, {"attachment_names": "photo.jpg"}),
])
def test_indicator(indicator, bad, good):
    assert indicator in ids(**bad)
    assert indicator not in ids(**good)


def test_magic_bytes_mismatch():
    email = parse_pasted()
    email.attachments = [Attachment("scan.pdf", b"MZ harmless test bytes")]   # a ".pdf" that is an .exe
    assert "ATT_MAGIC_MISMATCH" in {i.id for i in run_all(email)}
    email.attachments = [Attachment("scan.pdf", b"%PDF-1.7")]
    assert "ATT_MAGIC_MISMATCH" not in {i.id for i in run_all(email)}


def test_domain_helpers():
    assert registered_domain("alerts.sbi.co.in") == "sbi.co.in"
    assert levenshtein("netflix", "netfiix") == 1
    assert lookalike("accounts.google.com") is None
    assert lookalike("apply.university.ac.in") is None     # 'apply' is not 'apple'


@pytest.mark.parametrize("score, level", [(0, "Low"), (24, "Low"), (25, "Medium"), (50, "High"), (75, "Critical")])
def test_level_boundaries(score, level):
    assert level_for(score) == level


def test_scoring_rules():
    from core.indicators.common import Indicator
    url = [Indicator(f"URL_{n}", "x", "url", 20, "r") for n in range(5)]
    assert score_indicators(url)["score"] == 40                          # url category capped at 40
    macro = score_indicators([Indicator("ATT_MACRO_OFFICE", "m", "attachment", 15, "r")])
    assert macro["score"] == 40 and macro["threat"] == "Malicious Attachment"   # payload floor
    assert score_indicators([])["threat"] == "Likely Safe"
