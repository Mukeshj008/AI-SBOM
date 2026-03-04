# Requirements

## Default Scan Mode

- Python 3.9+ (recommended)
- No external Python packages required (standard library only)

## Optional Ollama Enrichment Mode

If you use `--ollama`, you also need:

- Ollama installed and available on PATH
- At least one local model pulled (for example `llama3.2:latest`)
- Ollama service running

Check setup:

```bash
ollama --version
ollama list
```

## Optional OpenAI Enrichment Mode

If you use `--openai`, you also need:

- `OPENAI_API_KEY` set in environment
- Network access to `api.openai.com`

Example:

```bash
export OPENAI_API_KEY="your_key"
python3 ai-sbom.py . --openai
```

## Optional Gemini Enrichment Mode

If you use `--gemini`, you also need:

- `GEMINI_API_KEY` or `GOOGLE_API_KEY` set in environment
- Network access to `generativelanguage.googleapis.com`

Example:

```bash
export GEMINI_API_KEY="your_key"
python3 ai-sbom.py . --gemini
```

## Permissions

- Read access to the target project path
- Write access to output report files in the target project path
- Write access to SQLite DB path if using `--db`

## Local UI Mode

For browser UI (`ai-sbom-ui.py`):

- Python 3.9+
- Optional existing SQLite DB (UI can create one if missing)
- Recommended launcher: `run-ui.py`

DB behavior in simple terms:
- `run-ui.py --new-db` creates and links a fresh DB
- `run-ui.py --attach-db /path/to/file.db` links an existing DB
- `ai-sbom.py` writes to linked DB automatically when `ai_sbom_active_db.txt` is present
