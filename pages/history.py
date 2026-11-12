"""History page: past analyses from SQLite.   [Member 3]"""
import plotly.express as px
import streamlit as st

from core import db
from ui import COLOURS, show_table

st.title("🕘 History")
df = db.load_history()
if df.empty:
    st.info("No analyses yet.")
    st.stop()

levels = st.multiselect("Risk level", ["Low", "Medium", "High", "Critical"], ["Low", "Medium", "High", "Critical"])
df = df[df["level"].isin(levels)]

fig = px.scatter(df, x="timestamp", y="score", color="level", color_discrete_map=COLOURS,
                 hover_data=["subject", "primary_threat"], title="Risk score over time")
st.plotly_chart(fig)
show_table(df[["timestamp", "subject", "sender", "score", "level", "primary_threat"]])

if st.button("Clear history"):
    db.clear_history()
    st.rerun()
