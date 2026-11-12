"""Member 3: parser, full pipeline on the samples, database and report."""
from email.message import EmailMessage
from pathlib import Path

from core import db
from core.analyzer import analyze_email
from core.parser import parse_eml, parse_file, parse_pasted
from core.report import generate_html_report

SAMPLES = Path(__file__).parent.parent / "data" / "samples"


def test_parse_eml():
    m = EmailMessage()
    m["From"] = "PayPal <service@paypa1.com>"
    m["Reply-To"] = "help@other.net"
    m["Authentication-Results"] = "mx; spf=fail"
    m["Subject"] = "Verify"
    m.set_content("text https://plain.example.org")
    m.add_alternative('<a href="http://evil.xyz">paypal.com</a>', subtype="html")
    m.add_attachment(b"MZ test", maintype="application", subtype="pdf", filename="doc.pdf")
    e = parse_eml(bytes(m))
    assert (e.from_name, e.from_email, e.reply_to) == ("PayPal", "service@paypa1.com", "help@other.net")
    assert "spf=fail" in e.auth_results
    assert {l.url for l in e.links} == {"http://evil.xyz", "https://plain.example.org"}
    assert e.attachments[0].filename == "doc.pdf" and e.attachments[0].content.startswith(b"MZ")


def test_parse_pasted():
    e = parse_pasted(body="See https://x.org/page. Bye", attachment_names="a.pdf, b.exe")
    assert [l.url for l in e.links] == ["https://x.org/page"]
    assert [a.filename for a in e.attachments] == ["a.pdf", "b.exe"]


def test_samples_meet_goal():
    """Every phishing sample is Medium or higher, every legitimate sample is Low."""
    files = list(SAMPLES.iterdir())
    assert len(files) >= 20
    for path in files:
        level = analyze_email(parse_file(path))["score"]["level"]
        assert (level != "Low") == path.name.startswith("phish_"), f"{path.name}: {level}"


def test_database(tmp_path):
    path = tmp_path / "test.db"
    db.save_analysis(analyze_email(parse_pasted(subject="x'); DROP TABLE analyses;--")), path)   # SQL injection attempt
    assert db.load_history(path)["subject"][0].startswith("x');")
    db.clear_history(path)
    assert db.load_history(path).empty


def test_report_escapes_html():
    html = generate_html_report(analyze_email(parse_pasted(subject="<script>alert(1)</script>")))
    assert "<script>alert" not in html and "&lt;script&gt;" in html
