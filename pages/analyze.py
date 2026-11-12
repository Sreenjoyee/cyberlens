"""Analyze page: input an email, run the pipeline, show the explainable report.   [Member 3]"""
from pathlib import Path

import streamlit as st

from core import db
from core.analyzer import analyze_email
from core.integrity import tamper_demo, verify
from core.ml_baseline import get_model, predict
from core.parser import parse_eml, parse_file, parse_pasted
from core.report import generate_html_report
from ui import badge, gauge, sankey, show_table

SAMPLES = Path(__file__).parent.parent / "data" / "samples"

st.title("🔍 Analyze an email")

# ---------- 1. Input ----------
email = None
paste, upload, sample = st.tabs(["Paste fields", "Upload .eml", "Load a sample"])
with paste:
    with st.form("paste"):
        c1, c2 = st.columns(2)
        subject = c1.text_input("Subject")
        from_name = c1.text_input("From - display name")
        from_email = c2.text_input("From - email address")
        reply_to = c2.text_input("Reply-To (optional)")
        body = st.text_area("Body (plain text or HTML)", height=180)
        attachments = st.text_input("Attachment names, comma-separated (optional)")
        if st.form_submit_button("Analyze", type="primary"):
            email = parse_pasted(subject, from_name, from_email, reply_to, body, attachments)
with upload:
    file = st.file_uploader("Raw email file", type=["eml", "txt"])
    if file and st.button("Analyze file", type="primary"):
        email = parse_eml(file.getvalue())
with sample:
    choice = st.selectbox("Sample (phish_ = phishing, legit_ = legitimate)", sorted(p.name for p in SAMPLES.iterdir()))
    if st.button("Analyze sample", type="primary"):
        email = parse_file(SAMPLES / choice)

if email:                                   # new analysis: remember it across reruns and save it
    st.session_state.result = analyze_email(email)
    db.save_analysis(st.session_state.result)
if "result" not in st.session_state:
    st.stop()

r = st.session_state.result
email, score, impact = r["email"], r["score"], r["impact"]

# ---------- 2. Verdict ----------
st.divider()
left, right = st.columns([1, 2])
left.plotly_chart(gauge(score["score"], score["level"]))
with right:
    st.subheader(email.subject or "(no subject)")
    st.caption(f"From: {email.from_name} <{email.from_email}>")
    label = f"{score['level']} · {score['score']}/100"
    st.markdown(f"{badge(score['level'], label)} &nbsp; "
                f"**Primary threat:** {score['threat']} &nbsp; **Confidence:** {score['confidence']}",
                unsafe_allow_html=True)
    st.write(score["threat_reason"])
    st.caption(score["explanation"])

# ---------- 3. Details ----------
tabs = st.tabs(["Indicators", "Concept map", "CIA", "MITRE & IT Act", "Integrity", "Recommendations", "Rules vs ML"])

with tabs[0]:
    show_table([{"Category": i.category, "Indicator": i.name, "Weight": i.weight,
                 "Why it matters": i.reason, "Evidence": " | ".join(i.evidence)} for i in r["indicators"]])

with tabs[1]:
    st.plotly_chart(sankey(impact["sankey"]))
    st.markdown("**Attack chain**")
    for col, (stage, items) in zip(st.columns(5), impact["chain"].items()):
        col.markdown(f"**{stage}**\n\n" + "\n".join(f"- {x}" for x in items))
    for c in impact["concepts"].values():
        with st.expander(f"{c['name']} → {c['consequence']}"):
            st.write(c["description"])
            for indicator, explanation in c["entries"]:
                st.markdown(f"- **{indicator}:** {explanation}")
    st.markdown("**Vulnerabilities exploited**")
    show_table(impact["vulnerabilities"])

with tabs[2]:
    for col, (dim, v) in zip(st.columns(3), r["cia"].items()):
        col.markdown(f"#### {dim}\n{badge(v['level'])}", unsafe_allow_html=True)
        for reason in v["reasons"]:
            col.markdown(f"- {reason}")

with tabs[3]:
    st.markdown("**MITRE ATT&CK**")
    show_table([{"ID": m["id"], "Technique": m["name"], "Tactic": m["tactic"], "Triggered by": m["triggered_by"]}
                for m in impact["mitre"]])
    st.markdown("**Indian IT Act 2000**")
    for a in impact["it_act"]:
        st.markdown(f"**Section {a['section']}: {a['title']}**. {a['description']} *(from: {a['triggered_by']})*")

with tabs[4]:
    st.code(f"Body SHA-256: {r['hashes']['body']}\n.eml SHA-256: {r['hashes']['eml'] or '(pasted input)'}")
    if r["hashes"]["attachments"]:
        show_table(r["hashes"]["attachments"])
    expected = st.text_input("Verify: paste an expected SHA-256 of the body")
    if expected:
        st.success("Match: body unchanged") if verify(email.body_text, expected) else st.error("Mismatch: body differs")
    st.markdown("**Tamper demo (avalanche effect)**")
    text = st.text_input("Text", "Pay Rs 500 to account 1234")
    if text:
        d = tamper_demo(text, st.slider("Character to change", 0, len(text) - 1, min(9, len(text) - 1)))
        st.code(f"{text}\n{d['hash1']}\n\n{d['tampered']}\n{d['hash2']}")
        st.write(f"One input bit changed → **{d['bits_changed']} of 256** output bits changed.")

with tabs[5]:
    for i, rec in enumerate(impact["recommendations"], 1):
        st.markdown(f"{i}. {rec}")

with tabs[6]:
    ml = predict(get_model(), f"{email.subject}. {email.body_text}")
    c1, c2 = st.columns(2)
    c1.markdown(f"**Rule engine:** {score['level']} ({score['score']}/100), {score['threat']}, "
                f"with {len(r['indicators'])} named indicators and their evidence.")
    c2.markdown(f"**ML (TF-IDF + Logistic Regression):** {ml['label']} (probability {ml['probability']}), and nothing else.")
    st.info("The ML model only gives a label. The rules show *why*: each point of the score "
            "comes from visible evidence that is linked to a security concept.")

st.download_button("⬇️ Download HTML report", generate_html_report(r, ml), "cyberlens_report.html", "text/html")
