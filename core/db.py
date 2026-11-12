"""
db.py - SQLite history of analyses.   [Member 3]

Queries use '?' placeholders (parameterised queries): the subject and sender
are attacker-controlled text, so gluing them into SQL would allow SQL injection.
"""
import json
import sqlite3
from pathlib import Path

import pandas as pd

DB_PATH = Path(__file__).parent.parent / "data" / "cyberlens.db"


def _connect(path):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, subject TEXT, sender TEXT,
        score INTEGER, level TEXT, primary_threat TEXT, indicators_json TEXT)""")
    return conn


def save_analysis(result: dict, path=DB_PATH) -> None:
    conn = _connect(path)
    with conn:                                              # commits the transaction
        conn.execute("INSERT INTO analyses (timestamp, subject, sender, score, level, primary_threat, indicators_json) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (result["timestamp"], result["email"].subject, result["email"].from_email,
                      result["score"]["score"], result["score"]["level"], result["score"]["threat"],
                      json.dumps([i.to_dict() for i in result["indicators"]])))
    conn.close()


def load_history(path=DB_PATH) -> pd.DataFrame:
    conn = _connect(path)
    df = pd.read_sql_query("SELECT * FROM analyses ORDER BY timestamp DESC", conn)
    conn.close()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def clear_history(path=DB_PATH) -> None:
    conn = _connect(path)
    with conn:
        conn.execute("DELETE FROM analyses")
    conn.close()
