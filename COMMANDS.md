# Commands

## Basic

```bash
python3 ai-sbom.py <project_path>
```

Generates:
- `<project_path>/ai_sbom.json`

## Generate HTML + Excel

```bash
python3 ai-sbom.py <project_path> --html --excel
```

Generates:
- `<project_path>/ai_sbom.json`
- `<project_path>/ai_sbom.html`
- `<project_path>/ai_sbom.xls`

## Disable JSON

```bash
python3 ai-sbom.py <project_path> --no-json --html --excel
```

## Enable Ollama Enrichment (default model)

```bash
python3 ai-sbom.py <project_path> --ollama --html --excel
```

## Enable Ollama Enrichment (custom model)

```bash
python3 ai-sbom.py <project_path> --ollama --ollama-model "llama3.2:latest" --html --excel
```

## Enable OpenAI Enrichment

```bash
python3 ai-sbom.py <project_path> --openai --openai-model "gpt-4o-mini" --html --excel
```

## Enable Gemini Enrichment

```bash
python3 ai-sbom.py <project_path> --gemini --gemini-model "gemini-1.5-flash" --html --excel
```

## Enable All Enrichment Providers

```bash
python3 ai-sbom.py <project_path> --ollama --openai --gemini --html --excel
```

## Store Scan in Local SQLite DB

```bash
python3 ai-sbom.py <project_path> --db --html --excel
```

How DB selection works:
- If `ai_sbom_active_db.txt` exists, scanner writes to that DB automatically.
- If link file is missing, scanner uses `ai_sbom.db` when `--db` is used.

## Create New DB and Auto-Link UI

```bash
python3 run-ui.py --new-db
```

This creates `ai_sbom_*.db` in current directory and updates `ai_sbom_active_db.txt`.

## Attach Existing DB and Auto-Link UI

```bash
python3 run-ui.py --attach-db /absolute/path/to/my.db
```

## Auto-link Rules

- If `ai_sbom_active_db.txt` exists, scanner and UI use that DB automatically.
- If path in that file is wrong, command stops and tells you to:
  - check path in `ai_sbom_active_db.txt`, or
  - create a new DB:

```bash
python3 run-ui.py --new-db
```

## Start Local UI (Browser)

```bash
python3 run-ui.py
```

When started successfully, it prints:
- UI URL
- active DB path
- log file path

## Start UI via helper script (custom port)

```bash
python3 run-ui.py --port 8793
```

Default UI login:

```text
username: admin
password: admin
```

Important login behavior:
- If using default admin credentials (`admin/admin`), password reset is required before dashboard access.
- Session expires after 15 minutes of inactivity.

## Clear Browser Cache / Session Artifacts

Open in browser:

```text
http://127.0.0.1:9007/cache/clear
```

This clears browser storage/cache and expires server session cookie.

## Scan Current Directory

```bash
python3 ai-sbom.py . --html --excel
```

If UI is active, scanner output also prints:
- `UI (active): http://127.0.0.1:<port>`

## Quick Validation

```bash
python3 ai-sbom.py . --ollama --ollama-model "llama3.2:latest"
```
