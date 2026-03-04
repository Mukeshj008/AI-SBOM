# AI-SBOM

AI-SBOM is a polyglot source-code scanner that generates an AI-focused Software Bill of Materials (SBOM) from codebases.

It detects:
- AI SDK usage
- LLM model references
- Local model artifacts
- Vector database usage
- AI endpoint usage
- Risk patterns (for example hardcoded keys or unsafe loaders)

It also supports optional LLM-powered enrichment (Ollama, OpenAI, Gemini) for higher-accuracy semantic detection.
It can also persist findings in a local SQLite database and expose a local UI for browsing projects/scans.

## What Is New (Current)

- Scanner output now shows active UI URL when UI is running.
- Enterprise-style UI theme with improved tables, cards, filters, and readability.
- Color-coded categories across UI, HTML report, and Excel exports.
- Clickable instance counts with an instance-detail drill-down page.
- Secure login/session controls:
  - mandatory admin reset flow before dashboard (for default admin credentials)
  - unique session per login
  - session timeout after 15 minutes of inactivity
  - session destroyed on logout
  - clear-cache option in UI.

## Project Architecture

The project is intentionally simple and centered around one executable:

- `ai-sbom.py`
  - **Scanner engine (`AICodeScanner`)**
    - File discovery and filtering
    - Language-specific dependency scanning (Python, JS/TS, Java, Go, Rust, .NET, Ruby, PHP, Dart)
    - Source pattern and endpoint scanning
    - Optional Ollama runtime + semantic enrichment (Ollama/OpenAI/Gemini)
  - **Normalization and aggregation**
    - Deduplication
    - Alias canonicalization (for example package aliases to one logical component)
    - Instance-based aggregation with source references
  - **Report writers**
    - JSON (`ai_sbom.json`)
    - HTML (`ai_sbom.html`) with dashboard + pie chart
    - Excel-compatible `.xls` (`ai_sbom.xls`)
  - **Local DB persistence**
    - SQLite database (`ai_sbom.db`) with projects, scans, and findings
  - **UI server**
    - `ai-sbom-ui.py` for browsing local DB data in browser
  - **CLI layer**
    - Argument parsing and report generation workflow

## Detection Pipeline

1. Scan dependency manifests and lockfiles
2. Scan code and text patterns across common languages
3. Optionally enrich findings via LLM providers (`--ollama`, `--openai`, `--gemini`)
4. Deduplicate and aggregate into instance-based components
5. Generate output reports
6. Optionally persist to local SQLite (`--db`) and browse via UI

## Installation

No Python third-party package is required for default scanning.

See `REQUIREMENTS.md` for full runtime requirements.

## Usage

Basic scan (JSON):

```bash
python3 ai-sbom.py <project_path>
```

Generate all reports:

```bash
python3 ai-sbom.py <project_path> --html --excel
```

Enable Ollama enrichment:

```bash
python3 ai-sbom.py <project_path> --ollama --ollama-model "llama3.2:latest" --html --excel
```

Enable OpenAI enrichment:

```bash
python3 ai-sbom.py <project_path> --openai --openai-model "gpt-4o-mini" --html --excel
```

Enable Gemini enrichment:

```bash
python3 ai-sbom.py <project_path> --gemini --gemini-model "gemini-1.5-flash" --html --excel
```

Enable all providers together:

```bash
python3 ai-sbom.py <project_path> --ollama --openai --gemini --html --excel
```

Store scan in local DB:

```bash
python3 ai-sbom.py <project_path> --db --html --excel
```

Note:
- If `ai_sbom_active_db.txt` exists, scanner writes to that DB automatically.
- If link file does not exist, `--db` writes to `ai_sbom.db`.

Create a fresh DB and auto-link UI:

```bash
python3 run-ui.py --new-db
```

Attach an existing DB and auto-link UI:

```bash
python3 run-ui.py --attach-db /absolute/path/to/my.db
```

Auto-link behavior:
- If `ai_sbom_active_db.txt` is present, UI and scanner use that DB automatically.
- If path in `ai_sbom_active_db.txt` is invalid, command stops with a clear error.
- Error message suggests:
  - check DB path in `ai_sbom_active_db.txt`, or
  - create a new DB with `python3 run-ui.py --new-db --port 9007`

Start local UI (recommended):

```bash
python3 run-ui.py
```

UI login:
- Default admin credentials: `admin` / `admin`
- Admin can create additional users from the `Users` tab
- Admin can reset credentials for any user
- Admin can delete users (with safeguards)
- On first login with default admin credentials, password reset is mandatory before dashboard access

Session behavior:
- Unique session ID per login
- Session expires after 15 minutes of inactivity
- Logout destroys session immediately

From UI you can:
- trigger new scans (`Run Scan` tab)
- browse scan IDs and scan UIDs
- export scan/component data to Excel
- view component versions in scan findings
- click total instance counts to view detailed instance records
- delete project/scan/component (admin)
- clean full DB in one click (admin)
- clear browser-side cache/session artifacts (`Clear Cache`)

## Output Files

- `ai_sbom.json`: machine-readable findings
- `ai_sbom.html`: professional dashboard report
- `ai_sbom.xls`: Excel-compatible workbook

## License

This project is licensed under the MIT License. See `LICENSE`.
