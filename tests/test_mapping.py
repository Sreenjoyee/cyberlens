"""Member 2: knowledge base, concept mapping, CIA and hashing."""
import re
from pathlib import Path

from core.cia import compute_cia
from core.indicators.common import Indicator
from core.integrity import sha256_text, tamper_demo, verify
from core.mapper import build_impact_map, load_kb

CRED = Indicator("CNT_CREDENTIAL_REQUEST", "Credential request", "content", 20, "r")
LOOK = Indicator("URL_LOOKALIKE_DOMAIN", "Lookalike domain", "url", 20, "r")


def test_every_detector_has_a_kb_entry():
    kb = load_kb()
    code = "".join(p.read_text(encoding="utf-8") for p in Path("core").rglob("*.py"))
    ids = set(re.findall(r'"((?:CNT|URL|HDR|ATT)_[A-Z_]+)"', code))
    ids |= {"HDR_SPF_FAIL", "HDR_DKIM_FAIL", "HDR_DMARC_FAIL"}       # built with an f-string in header.py
    assert ids <= set(kb["indicators"]), ids - set(kb["indicators"])


def test_kb_references_are_valid():
    kb = load_kb()
    for entry in kb["indicators"].values():
        assert set(entry["concepts"]) <= set(kb["concepts"])
        assert set(entry["mitre"]) <= set(kb["mitre"])
        assert set(entry["it_act"]) <= set(kb["it_act"])


def test_impact_map():
    m = build_impact_map([CRED, LOOK], "Credential Phishing", "Verify now")
    assert "authentication" in m["concepts"]
    assert {"66C", "66D"} <= {a["section"] for a in m["it_act"]}
    assert list(m["chain"]) == ["Message", "Threat", "Indicators", "Concepts", "Consequences"]
    assert all(0 <= s < len(m["sankey"]["labels"]) for s, t, v in m["sankey"]["links"])


def test_cia():
    assert compute_cia([])["Confidentiality"]["level"] == "None"
    assert compute_cia([CRED, LOOK])["Confidentiality"]["level"] == "High"       # 3 + 2 points


def test_hashing():
    assert sha256_text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"  # FIPS test vector
    assert verify("abc", sha256_text("abc")) and not verify("abd", sha256_text("abc"))
    d = tamper_demo("Pay Rs 500", 8)
    assert d["hash1"] != d["hash2"] and 64 < d["bits_changed"] < 192          # ~half the bits flip
