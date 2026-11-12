"""
report.py - standalone HTML report.   [Member 3]

Every email value goes through escape(): a subject like "<script>...</script>"
must be shown as text, never run in the reader's browser (XSS).
"""
from html import escape


def table(headers: list, rows: list) -> str:
    head = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def generate_html_report(result: dict, ml: dict | None = None) -> str:
    email, score, impact = result["email"], result["score"], result["impact"]
    sections = [
        ("Verdict", f"<p><b>{score['level']} risk - {score['score']}/100</b> · Primary threat: <b>{escape(score['threat'])}</b> "
                    f"· Confidence: {score['confidence']}</p><p>{escape(score['threat_reason'])} {escape(score['explanation'])}</p>"),
        ("Message", table(["Subject", "From", "Reply-To", "Links", "Attachments"],
                          [[email.subject, f"{email.from_name} <{email.from_email}>", email.reply_to or "-",
                            len(email.links), len(email.attachments)]])),
        ("Indicators", table(["Indicator", "Category", "Weight", "Why", "Evidence"],
                             [[i.name, i.category, i.weight, i.reason, "; ".join(i.evidence)] for i in result["indicators"]])),
        ("Attack chain", " &rarr; ".join(f"<b>{stage}:</b> {escape(', '.join(items))}" for stage, items in impact["chain"].items())),
        ("CIA impact", table(["Dimension", "Level", "Reasons"],
                             [[d, v["level"], " | ".join(v["reasons"]) or "-"] for d, v in result["cia"].items()])),
        ("Concepts", table(["Concept", "Indicator", "Explanation"],
                           [[c["name"], ind, expl] for c in impact["concepts"].values() for ind, expl in c["entries"]])),
        ("MITRE ATT&CK", table(["ID", "Technique", "Tactic", "Triggered by"],
                               [[m["id"], m["name"], m["tactic"], m["triggered_by"]] for m in impact["mitre"]])),
        ("IT Act 2000", table(["Section", "Title", "Summary", "Triggered by"],
                              [[a["section"], a["title"], a["description"], a["triggered_by"]] for a in impact["it_act"]])),
        ("Integrity (SHA-256)", table(["Item", "SHA-256"], [["Body", result["hashes"]["body"]], [".eml file", result["hashes"]["eml"] or "-"]]
                                      + [[a["filename"], a["sha256"]] for a in result["hashes"]["attachments"]])),
        ("Recommendations", "<ol>" + "".join(f"<li>{escape(r)}</li>" for r in impact["recommendations"]) + "</ol>"),
    ]
    if ml:
        sections.append(("ML baseline", f"<p>{ml['label']} (probability {ml['probability']}) - a label without reasons.</p>"))
    body = "".join(f"<h2>{escape(title)}</h2>{html}" for title, html in sections)
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>CyberLens report</title>
<style>body{{font-family:Arial,sans-serif;max-width:1000px;margin:auto;padding:20px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:5px;text-align:left;vertical-align:top}}
th{{background:#eee}}</style></head><body><h1>CyberLens Analysis Report</h1><p>{result['timestamp']}</p>{body}
<p><i>Educational tool - verdicts can be wrong. IT Act notes are not legal advice. Report cybercrime at
cybercrime.gov.in or call 1930.</i></p></body></html>"""
