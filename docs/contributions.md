# Contributions

> Replace "Member 1/2/3" with your names (also in `pages/about.py`).

## Member 1: Detection engine
- `core/parser.py`: email parsing
- `core/indicators/` (`common.py`, `content.py`, `url.py`, `header.py`, `attachment.py`): 30 indicators
- `core/scorer.py`, `core/analyzer.py`: scoring, threat rules, pipeline
- `data/samples/`: 14 phishing + 13 legitimate samples
- `tests/test_indicators.py`

Viva topics: MIME, SPF/DKIM/DMARC, typosquatting and punycode, the URL `@` trick, magic bytes,
regex word boundaries, and category caps.

## Member 2: Concept mapping, knowledge base, CIA, integrity
- `core/knowledge_base.json`: concepts, MITRE, IT Act, recommendations
- `core/mapper.py`: Concept Impact Map, attack chain, Sankey data
- `core/cia.py`: CIA impact
- `core/integrity.py`: SHA-256, verification, avalanche demo
- `tests/test_mapping.py`

Viva topics: the CIA triad, threat vs vulnerability, authentication vs access control,
MITRE ATT&CK, IT Act sections 43, 66, 66C and 66D, and hash properties.

## Member 3: UI, storage, reporting, ML baseline, evaluation
- `app.py`, `ui.py`, `pages/`: Streamlit interface
- `core/db.py`: SQLite history
- `core/report.py`: HTML report
- `core/ml_baseline.py`, `core/evaluation.py`, `data/dataset.csv`: ML comparison and metrics
- `tests/test_pipeline.py`

Viva topics: TF-IDF and logistic regression, cross-validation, precision vs recall, SQL
injection and XSS, and why ML alone is not explainable.
