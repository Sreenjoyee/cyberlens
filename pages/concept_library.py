"""Concept Library page: browse knowledge_base.json by concept.   [Member 2 content, Member 3 UI]"""
import streamlit as st

from core.mapper import load_kb
from ui import show_table

kb = load_kb()
st.title("📚 Concept library")

names = {c["name"]: cid for cid, c in kb["concepts"].items()}
cid = names[st.selectbox("Concept", list(names))]
concept = kb["concepts"][cid]
st.write(concept["description"])
st.markdown(f"**Consequence:** {concept['consequence']}  \n**Controls:** {'; '.join(concept['key_controls'])}")

st.markdown("**Indicators linked to this concept**")
show_table([{"Indicator": iid, "Explanation": e["concepts"][cid], "MITRE": ", ".join(e["mitre"]),
             "IT Act": ", ".join(e["it_act"])} for iid, e in kb["indicators"].items() if cid in e["concepts"]])

st.markdown("**IT Act 2000 sections**")
for sec, v in kb["it_act"].items():
    st.markdown(f"- **{sec}: {v['title']}**. {v['description']}")
