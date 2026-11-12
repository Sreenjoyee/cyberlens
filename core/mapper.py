"""
mapper.py - indicator -> cybersecurity concept mapping.   [Member 2]

All knowledge lives in knowledge_base.json. This module reads it and builds
the "Concept Impact Map":  Message -> Threat -> Indicators -> Concepts -> Consequences
"""
import json
from functools import lru_cache
from pathlib import Path


@lru_cache
def load_kb() -> dict:
    return json.loads((Path(__file__).parent / "knowledge_base.json").read_text(encoding="utf-8"))


def build_impact_map(indicators: list, threat: str, subject: str = "") -> dict:
    kb = load_kb()
    concepts, mitre, it_act, vulnerabilities = {}, {}, {}, []
    recommendations = list(kb["threats"][threat]["recommendations"])

    for ind in indicators:
        entry = kb["indicators"][ind.id]
        for cid, explanation in entry["concepts"].items():
            concepts.setdefault(cid, []).append((ind.name, explanation))
        for t in entry["mitre"]:
            mitre.setdefault(t, []).append(ind.name)
        for s in entry["it_act"]:
            it_act.setdefault(s, []).append(ind.name)
        vulnerabilities.append({"Indicator": ind.name, **entry["vulnerability"]})
        recommendations += [r for r in entry["recommendations"] if r not in recommendations]

    # Sankey diagram: nodes are labels, links are (source, target, value).
    labels, links = ["Message", threat], [(0, 1, sum(i.weight for i in indicators) or 1)]
    def node(label):
        if label not in labels:
            labels.append(label)
        return labels.index(label)
    for ind in indicators:
        i = node(ind.name)
        links.append((1, i, ind.weight))
        ids = kb["indicators"][ind.id]["concepts"]
        for cid in ids:                                   # weight is split between concepts
            c = node(kb["concepts"][cid]["name"])
            links.append((i, c, ind.weight / len(ids)))
            links.append((c, node(kb["concepts"][cid]["consequence"]), ind.weight / len(ids)))

    return {
        "concepts": {cid: {**kb["concepts"][cid], "entries": entries} for cid, entries in concepts.items()},
        "mitre": [{"id": t, **kb["mitre"][t], "triggered_by": ", ".join(src)} for t, src in mitre.items()],
        "it_act": [{"section": s, **kb["it_act"][s], "triggered_by": ", ".join(src)} for s, src in it_act.items()],
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations,
        "chain": {
            "Message": [subject or "(no subject)"], "Threat": [threat],
            "Indicators": [i.name for i in indicators] or ["none"],
            "Concepts": [kb["concepts"][c]["name"] for c in concepts] or ["none"],
            "Consequences": sorted({kb["concepts"][c]["consequence"] for c in concepts}) or ["none"],
        },
        "sankey": {"labels": labels, "links": links},
    }
