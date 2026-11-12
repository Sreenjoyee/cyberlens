"""Batch Evaluation page: rule engine vs ML on labelled data.   [Member 3]"""
import plotly.express as px
import streamlit as st

from core.evaluation import evaluate, load_samples
from core.ml_baseline import load_dataset
from ui import show_table

st.title("📊 Batch evaluation")
st.write("Rules predict *phishing* when the score is Medium or higher. "
         "The ML model is tested with 5-fold cross-validation (never on its own training rows).")

source = st.radio("Data", ["data/dataset.csv", "data/samples folder", "Upload CSV"], horizontal=True)
upload = st.file_uploader("CSV with text/body and label columns", type="csv") if source == "Upload CSV" else None

if st.button("Run evaluation", type="primary"):
    df = load_samples() if source == "data/samples folder" else load_dataset(upload or "data/dataset.csv")
    table, results = evaluate(df)

    show_table([{"Approach": name, **{k: round(m[k], 2) for k in ("accuracy", "precision", "recall", "f1")}}
                for name, m in results.items()])
    for col, (name, m) in zip(st.columns(2), results.items()):
        fig = px.imshow([[m["tn"], m["fp"]], [m["fn"], m["tp"]]], text_auto=True, title=name,
                        x=["Predicted legit", "Predicted phishing"], y=["Actual legit", "Actual phishing"])
        col.plotly_chart(fig)

    st.markdown("**Rule engine mistakes** (false positives / false negatives)")
    show_table(table[table["rule_pred"] != (table["actual"] == "phishing")])
