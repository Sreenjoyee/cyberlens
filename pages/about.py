"""About page.   [Member 3]"""
import streamlit as st

from ui import show_table

st.title("ℹ️ About CyberLens")
st.write("An explainable phishing analyzer built for *Computer and Cyber Security Fundamentals*. "
         "It explains which evidence was found and which security concepts it affects. Everything runs offline.")

show_table({
    "Member": ["Member 1", "Member 2", "Member 3"],
    "Role": ["Detection engine", "Concept mapping, knowledge base, CIA, integrity", "UI, storage, report, ML, evaluation"],
    "Files": ["core/parser.py, core/indicators/, core/scorer.py, core/analyzer.py",
              "core/knowledge_base.json, core/mapper.py, core/cia.py, core/integrity.py",
              "app.py, ui.py, pages/, core/db.py, core/report.py, core/ml_baseline.py, core/evaluation.py"],
})
st.warning("Educational tool: verdicts are heuristic and can be wrong. IT Act notes are not legal advice. "
           "Report cybercrime at cybercrime.gov.in or call 1930.")
