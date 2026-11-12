"""
evaluation.py - accuracy / precision / recall / F1 for rules and ML.   [Member 3]

Run from the cyberlens folder:   python -m core.evaluation
"""
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from core.analyzer import analyze_email
from core.ml_baseline import cross_validated, load_dataset
from core.parser import parse_file, parse_pasted
from core.scorer import PHISHING_THRESHOLD

SAMPLES = Path(__file__).parent.parent / "data" / "samples"


def load_samples() -> pd.DataFrame:
    """Sample files: label comes from the name prefix (phish_ / legit_)."""
    rows = []
    for path in sorted(SAMPLES.glob("*_*.*")):
        email = parse_file(path)
        rows.append({"id": path.name, "email": email, "text": f"{email.subject}. {email.body_text}",
                     "y": int(path.name.startswith("phish_"))})
    return pd.DataFrame(rows)


def row_to_email(row):
    """CSV row -> EmailData; columns that do not exist simply stay empty."""
    get = lambda col: str(row[col]) if col in row and pd.notna(row[col]) else ""
    return parse_pasted(get("subject"), get("from_name"), get("from_email"), get("reply_to"),
                        get("body") or row["text"], get("attachments"))


def metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y_true, y_pred), "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0), "f1": f1_score(y_true, y_pred, zero_division=0),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def evaluate(df: pd.DataFrame) -> tuple:
    """Returns (per-email results table, {"Rules": metrics, "ML": metrics})."""
    rows = []
    for i, row in df.iterrows():
        res = analyze_email(row["email"] if "email" in row else row_to_email(row))
        rows.append({"id": row.get("id", i), "subject": res["email"].subject[:60],
                     "actual": "phishing" if row["y"] else "legit", "score": res["score"]["score"],
                     "level": res["score"]["level"], "rule_pred": int(res["score"]["score"] >= PHISHING_THRESHOLD),
                     "indicators": ", ".join(ind.id for ind in res["indicators"])})
    table = pd.DataFrame(rows)
    table["ml_pred"] = cross_validated(df)
    return table, {"Rules": metrics(df["y"], table["rule_pred"]), "ML": metrics(df["y"], table["ml_pred"])}


if __name__ == "__main__":
    for name, df in [("Samples", load_samples()), ("dataset.csv", load_dataset())]:
        table, results = evaluate(df)
        print(f"\n=== {name} ({len(df)} emails) ===")
        for approach, m in results.items():
            print(f"{approach:>5}: accuracy={m['accuracy']:.2f} precision={m['precision']:.2f} "
                  f"recall={m['recall']:.2f} f1={m['f1']:.2f}  (FP={m['fp']} FN={m['fn']})")
        for _, r in table[table["rule_pred"] != (table["actual"] == "phishing")].iterrows():
            print(f"  rule error: {r['id']} ({r['actual']}, score {r['score']}) [{r['indicators']}]")
