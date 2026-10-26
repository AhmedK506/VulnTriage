# VulnTriage

AI-assisted vulnerability triage for penetration testers. Feed it scanner output (OWASP ZAP, Nuclei, Nessus) and it cuts the noise down to the findings that actually matter — then writes the report.

## What it does

Runs every finding through a full triage pipeline:

**parse → normalise → deduplicate → CWE map → NVD enrich → ML prioritise → confidence score → (optional) live PoC → PDF report**

- **Multi-scanner ingestion** — parsers for ZAP (XML), Nuclei (JSON/JSONL) and Nessus (`.nessus`), normalised into one schema and de-duplicated across tools.
- **CWE mapping & NVD enrichment** — maps findings to CWEs, pulls CVE/CVSS data from the NVD API, with an offline CWE→CVSS profile fallback.
- **ML severity prioritisation** — Random Forest trained on ~108k real NVD records (99.7% accuracy, 0.994 macro-F1 on a held-out set).
- **Confidence engine** — scores each finding 0–100 on *how likely it is a true positive* (not how severe it is), using scanner agreement, ML/scanner severity consistency, CVE and exploit availability, and PoC results. Classifies as Confirmed / Needs Manual Verification / Not Confirmed.
- **Safe PoC validation** — non-destructive checks (reflected XSS, error/boolean SQLi, security headers, CORS, version disclosure), restricted to an authorised scope.
- **Exploit lookup** — flags findings with known public exploits.
- **Auto Scan** — drives ZAP + Nuclei against an authorised target and triages the results end to end.
- **AI summary (optional)** — Google Gemini generates an executive summary and plain-language remediation. Scanner text is treated as data, never instructions. Off unless an API key is set.
- **Reports** — PDF/DOCX reports with escaped scanner content.

## Three ways to run it

| Interface | For | Database |
|---|---|---|
| **Web app** (Flask + React) | Teams, dashboards | PostgreSQL |
| **CLI** | Pentesters in the terminal | SQLite (zero setup) |
| **Desktop app** (pywebview) | Kali / Debian, launches from the app menu | SQLite |

## Quick start

### Docker (full stack)

```bash
docker compose up --build
# open http://localhost:5000  — default login admin / admin (change it)
```

### CLI

```bash
cd backend
pip install -r requirements.txt
python cli.py scan ../samples/zap-sample.xml -s zap -o report.pdf
python cli.py scan results.json -s nuclei --poc --scope target.example --exploits
python cli.py autoscan https://target.example --authorise
```

### Desktop app (Kali)

```bash
./install-kali-app.sh
# then launch "VulnTriage" from the applications menu, or ./bin/vulntriage-app
```

### Dev setup

```bash
# backend
cd backend && cp .env.example .env && pip install -r requirements.txt && python run.py
# frontend
cd frontend && npm install && npm run dev
```

## Configuration

Copy `backend/.env.example` to `backend/.env`. Optional keys:

- `NVD_API_KEY` — higher NVD rate limits
- `GEMINI_API_KEY` — enables AI summaries

## ML model

The trained model (`ml_data/models/`) and raw NVD feeds (`ml_data/nvd/`) aren't committed because of size. To train locally, put NVD feeds in `ml_data/nvd/` and run:

```bash
python backend/app/ml/model_trainer.py
```

`ml_data/cwe_cvss_profiles.json` is committed so CWE→CVSS enrichment works without the raw feeds.

## Tests

```bash
cd backend && pytest
```

## Tech stack

Python · Flask · SQLAlchemy · scikit-learn · PostgreSQL/SQLite · React · Vite · Tailwind · Recharts · ReportLab · Docker

## Responsible use

Only scan and run PoC checks against systems you own or are explicitly authorised to test.
