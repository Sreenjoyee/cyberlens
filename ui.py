"""
ui.py - small helpers shared by the Streamlit pages.   [Member 3]
"""
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

COLOURS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828", "None": "#9e9e9e"}

try:                        # st.dataframe needs pyarrow; some Windows PCs block its DLL
    import pyarrow  # noqa: F401
    ARROW_OK = True
except Exception:
    ARROW_OK = False


def show_table(data) -> None:
    """Interactive table if pyarrow works, otherwise a plain HTML table (text escaped)."""
    df = pd.DataFrame(data)
    if ARROW_OK:
        st.dataframe(df, hide_index=True)
    else:
        st.markdown(df.to_html(index=False, escape=True), unsafe_allow_html=True)


def badge(level: str, text: str = "") -> str:
    return (f"<span style='background:{COLOURS[level]};color:white;padding:3px 10px;border-radius:5px'>"
            f"{text or level}</span>")


def gauge(score: int, level: str) -> go.Figure:
    fig = go.Figure(go.Indicator(mode="gauge+number", value=score, title={"text": f"Risk: {level}"},
                                 gauge={"axis": {"range": [0, 100]}, "bar": {"color": COLOURS[level]}}))
    fig.update_layout(height=250, margin=dict(l=20, r=20, t=50, b=0))
    return fig


def sankey(data: dict) -> go.Figure:
    source, target, value = zip(*data["links"])
    fig = go.Figure(go.Sankey(node=dict(label=data["labels"], pad=12),
                              link=dict(source=source, target=target, value=value)))
    fig.update_layout(height=450, margin=dict(l=10, r=10, t=10, b=10))
    return fig
