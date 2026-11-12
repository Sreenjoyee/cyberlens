# 🔍 CyberLens: Explainable Phishing Analyzer

A PBL project for **Computer and Cyber Security Fundamentals**. Give CyberLens a suspicious email
(pasted fields or a `.eml` file) and it:

* finds **30 threat indicators** in the content, links, headers and attachments
* scores the risk from **0 to 100** (Low / Medium / High / Critical) and names the **primary threat**
* maps each indicator to **security concepts**, **MITRE ATT&CK** and the **Indian IT Act 2000**
* shows a **Concept Impact Map**, CIA impact, SHA-256 hashes and recommendations, plus an HTML report

It runs fully offline.

## Setup in VS Code (Windows)

**You need:** [Python 3.10+](https://www.python.org/downloads/) (tick *"Add python.exe to PATH"* during
install), [VS Code](https://code.visualstudio.com/), and the **Python** extension by Microsoft.

**1. Open the project:** *File → Open Folder…* and choose the folder that contains `cyberlens`.

**2. Open a terminal:** *Terminal → New Terminal* (or press Ctrl+`). It opens in PowerShell.

**3. Create the virtual environment and install the packages** (first time only):
```powershell
cd cyberlens
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

**4. Select the interpreter:** press Ctrl+Shift+P → **Python: Select Interpreter** → pick
`.\cyberlens\.venv\Scripts\python.exe`. This clears the "Import could not be resolved" warnings.

**5. Run it** (from the `cyberlens` folder):
```powershell
.venv\Scripts\python -m pytest                    # run the tests
.venv\Scripts\python -m core.evaluation           # rules vs ML metrics
.venv\Scripts\python -m streamlit run app.py      # opens http://localhost:8501
```
Press **Ctrl+C** in the terminal to stop the app.

**Troubleshooting**
- **"python is not recognized":** reinstall Python with *"Add python.exe to PATH"* ticked, then restart VS Code.
- **"running scripts is disabled"** (when the venv auto-activates): run
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then open a new terminal.
- **"DLL load failed … Application Control policy" for pyarrow:** Windows is blocking pyarrow, which
  Streamlit uses for interactive tables. CyberLens detects this and shows plain HTML tables instead,
  so the app still works.

## Structure

```
cyberlens/
  app.py, ui.py, pages/        Streamlit UI                                  [Member 3]
  core/
    parser.py                  pasted input / .eml -> EmailData              [Member 1]
    indicators/                content, url, header, attachment checks       [Member 1]
    scorer.py, analyzer.py     score, threat rules, the pipeline             [Member 1]
    knowledge_base.json        concepts, MITRE, IT Act, advice               [Member 2]
    mapper.py, cia.py          concept impact map, CIA impact                [Member 2]
    integrity.py               SHA-256, verify, tamper demo                  [Member 2]
    ml_baseline.py             TF-IDF + Logistic Regression                  [Member 3]
    evaluation.py, db.py       metrics, SQLite history                       [Member 3]
    report.py                  HTML report                                   [Member 3]
  data/samples/                14 phishing + 13 legitimate emails
  data/dataset.csv             40 labelled rows for evaluation
  tests/                       one test file per member
  docs/                        architecture.md, contributions.md
```

## Results

| Data | Approach | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|
| samples (27) | Rules | 1.00 | 1.00 | 1.00 | 1.00 |
| samples (27) | ML (5-fold CV) | 0.74 | 0.68 | 0.93 | 0.79 |
| dataset.csv (40) | Rules | 0.93 | 1.00 | 0.85 | 0.92 |
| dataset.csv (40) | ML (5-fold CV) | 0.75 | 0.71 | 0.85 | 0.77 |

The weights were tuned on these files. For an independent test, replace `data/dataset.csv` with a
public dataset. It needs a text column (`body`, `text` or `Email Text`) and a label column
(`label` or `Email Type`). Then delete `data/models/ml_baseline.joblib` so the model retrains.

## Disclaimer

This is an educational tool, and its verdicts can be wrong. The sample attachments are harmless
placeholder bytes. The IT Act notes are not legal advice. Report cybercrime at
**cybercrime.gov.in** or call **1930**.
