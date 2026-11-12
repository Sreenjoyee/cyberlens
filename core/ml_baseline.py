"""
ml_baseline.py - TF-IDF + Logistic Regression, for COMPARISON only.   [Member 3]

The model gives a label and a probability but no reasons. Showing it next
to the rule engine demonstrates why explainability matters.

load_dataset() accepts any CSV with a text column (text / body / Email Text)
and a label column (label / Email Type) so a public dataset can be dropped in.
"""
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
from sklearn.pipeline import make_pipeline

DATA = Path(__file__).parent.parent / "data"
MODEL_PATH = DATA / "models" / "ml_baseline.joblib"
PHISHING_LABELS = {"1", "phishing", "spam", "phishing email"}


def load_dataset(path=DATA / "dataset.csv") -> pd.DataFrame:
    """Return the CSV with two extra columns: text (subject + body) and y (1 = phishing)."""
    df = pd.read_csv(path)
    cols = {c.lower(): c for c in df.columns}
    text_col = next(cols[c] for c in ("body", "text", "email text", "message") if c in cols)
    label_col = next(cols[c] for c in ("label", "email type", "class") if c in cols)
    subject = df[cols["subject"]].fillna("") + ". " if "subject" in cols else ""
    df["text"] = subject + df[text_col].fillna("").astype(str)
    df["y"] = df[label_col].astype(str).str.strip().str.lower().isin(PHISHING_LABELS).astype(int)
    return df


def new_model():
    # Words and word pairs weighted by TF-IDF, then a linear classifier.
    return make_pipeline(TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True),
                         LogisticRegression(max_iter=1000, class_weight="balanced"))


def get_model():
    """Load the saved model, or train and save one. (Only load model files you trained yourself:
    joblib/pickle files can run code when loaded.)"""
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    df = load_dataset()
    model = new_model().fit(df["text"], df["y"])
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model


def predict(model, text: str) -> dict:
    p = float(model.predict_proba([text])[0][1])
    return {"label": "Phishing" if p >= 0.5 else "Legitimate", "probability": round(p, 2)}


def cross_validated(df: pd.DataFrame):
    """5-fold CV: every row is predicted by a model that never saw it during training."""
    return cross_val_predict(new_model(), df["text"], df["y"], cv=5)
