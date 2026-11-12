"""
CyberLens - Streamlit entry point.   [Member 3]

Run from the cyberlens folder:   streamlit run app.py
"""
import streamlit as st

st.set_page_config(page_title="CyberLens", page_icon="🔍", layout="wide")


def home():
    st.title("🔍 CyberLens")
    st.subheader("Explainable phishing & social-engineering analyzer")
    st.markdown("""
1. **Parse** an email (pasted fields or a `.eml` file).
2. **Detect** 30 indicators in its content, links, headers and attachments.
3. **Score** the risk from 0 to 100 and name the primary threat.
4. **Map** each indicator to security concepts, MITRE ATT&CK and the Indian IT Act.
5. **Explain** with an impact map, CIA impact, hashes, recommendations and a report.
""")
    st.info("Educational tool: verdicts can be wrong. Report cybercrime at cybercrime.gov.in or call 1930.")


st.navigation([
    st.Page(home, title="Home", icon="🏠", default=True),
    st.Page("pages/analyze.py", title="Analyze", icon="🔍"),
    st.Page("pages/batch_evaluation.py", title="Batch Evaluation", icon="📊"),
    st.Page("pages/history.py", title="History", icon="🕘"),
    st.Page("pages/concept_library.py", title="Concept Library", icon="📚"),
    st.Page("pages/about.py", title="About", icon="ℹ️"),
]).run()
