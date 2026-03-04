import argparse
import hashlib
import html
import json
import re
import secrets
import sqlite3
import subprocess
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

SESSIONS = {}
SESSION_COOKIE = "ai_sbom_session"
SESSION_IDLE_TIMEOUT_SECONDS = 15 * 60
CATEGORY_OPTIONS = ["ai_sdks", "llm_models", "local_models", "vector_dbs", "ai_endpoints", "risks"]
CATEGORY_COLOR_CLASSES = {
    "ai_sdks": "cat-ai-sdks",
    "llm_models": "cat-llm-models",
    "local_models": "cat-local-models",
    "vector_dbs": "cat-vector-dbs",
    "ai_endpoints": "cat-ai-endpoints",
    "risks": "cat-risks",
}


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def validate_password_complexity(password):
    if len(password or "") < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-zA-Z]", password):
        return False, "Password must include at least one alphabetic character."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[^a-zA-Z0-9]", password):
        return False, "Password must include at least one special character."
    return True, ""


def category_css_class(category):
    return CATEGORY_COLOR_CLASSES.get(str(category or "").strip(), "cat-default")


def open_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    conn = open_db(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                must_reset_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        user_cols = {row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()}
        if "must_reset_password" not in user_cols:
            cur.execute("ALTER TABLE users ADD COLUMN must_reset_password INTEGER NOT NULL DEFAULT 0")
        scan_table_exists = cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()
        if scan_table_exists:
            cols = {row[1] for row in cur.execute("PRAGMA table_info(scans)").fetchall()}
            if "scan_uid" not in cols:
                cur.execute("ALTER TABLE scans ADD COLUMN scan_uid TEXT")
        cur.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, role, must_reset_password, created_at) VALUES(?, ?, ?, ?, ?)",
            ("admin", hash_password("admin"), "admin", 1, datetime.now().isoformat(timespec="seconds")),
        )
        cur.execute(
            """
            UPDATE users
            SET must_reset_password = 1
            WHERE username = 'admin' AND password_hash = ?
            """,
            (hash_password("admin"),),
        )
        conn.commit()
    finally:
        conn.close()


def recalc_scan_totals(conn, scan_ids=None):
    if scan_ids is None:
        rows = conn.execute("SELECT id FROM scans").fetchall()
        scan_ids = [row["id"] for row in rows]
    for scan_id in scan_ids:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total_components, COALESCE(SUM(instances), 0) AS total_instances
            FROM findings
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()
        conn.execute(
            "UPDATE scans SET total_components = ?, total_instances = ? WHERE id = ?",
            (int(row["total_components"] or 0), int(row["total_instances"] or 0), scan_id),
        )


def page_template(title, body, user=None, hide_nav=False):
    user_html = ""
    if user and not hide_nav:
        user_html = (
            "<div class='card nav'>"
            "<a href='/'>Projects</a>"
            "<a href='/components'>All Components</a>"
            "<a href='/scan/new'>Run Scan</a>"
            "<a href='/cache/clear'>Clear Cache</a>"
            + ("<a href='/users'>Users</a>" if user.get("role") == "admin" else "")
            + f"<span class='muted' style='margin-left:12px;'>Signed in as {html.escape(user['username'])}</span>"
            + "<a style='margin-left:12px;' href='/logout'>Logout</a>"
            + (
                "<form method='post' action='/db/clear' style='display:inline;margin-left:12px;' "
                "onsubmit=\"return confirm('This will delete all projects, scans, findings and reset users to default admin. Continue?');\">"
                "<button class='btn danger' type='submit'>Clean DB</button>"
                "</form>"
                if user.get("role") == "admin"
                else ""
            )
            + "</div>"
        )
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0" />
  <meta http-equiv="Pragma" content="no-cache" />
  <meta http-equiv="Expires" content="0" />
  <title>{html.escape(title)}</title>
  <style>
    :root {{ --bg:#f3f6fb; --text:#0f172a; --muted:#64748b; --line:#dbe4f0; --card:#ffffff; --brand:#1d4ed8; --brand-dark:#1e3a8a; }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: Inter, Segoe UI, Arial, sans-serif; margin: 0; background: linear-gradient(180deg, #eef2ff 0%, var(--bg) 28%, #f8fafc 100%); color: var(--text); }}
    .wrap {{ max-width: 1280px; margin: 0 auto; padding: 22px; }}
    .hero {{ background: linear-gradient(120deg, #0f172a, #1e3a8a 44%, #2563eb 100%); color: #fff; border: 1px solid rgba(255,255,255,.16); border-radius: 16px; padding: 18px 22px; box-shadow: 0 16px 36px rgba(15,23,42,.28); }}
    .hero h1 {{ margin: 0; font-size: 24px; letter-spacing: .2px; }}
    .hero p {{ margin: 7px 0 0; color: #dbeafe; font-size: 13px; }}
    .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; margin-top: 14px; padding: 14px; box-shadow: 0 4px 14px rgba(15,23,42,.05); }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; overflow: hidden; border-radius: 10px; }}
    th, td {{ text-align: left; padding: 11px; border-bottom: 1px solid #e8edf5; vertical-align: top; }}
    th {{ position: sticky; top: 0; z-index: 1; background: #f8fbff; color: #334155; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }}
    tbody tr:nth-child(even) td {{ background: #fbfdff; }}
    tbody tr:hover td {{ background: #f4f8ff; }}
    a {{ color: var(--brand); text-decoration: none; }}
    a:hover {{ color: var(--brand-dark); text-decoration: underline; text-underline-offset: 2px; }}
    .pill {{ display: inline-block; background: #eff6ff; color: #1d4ed8; border: 1px solid #dbeafe; border-radius: 999px; padding: 2px 8px; font-size: 12px; margin: 2px 4px 2px 0; }}
    .muted {{ color: var(--muted); }}
    .nav {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
    .nav a {{ margin-right: 0; border: 1px solid #dbe4f0; border-radius: 8px; padding: 6px 10px; background: #f8fbff; font-size: 13px; }}
    .btn {{ display: inline-block; background: linear-gradient(135deg, #1d4ed8, #1e40af); color: #fff; border-radius: 9px; padding: 7px 11px; font-size: 13px; margin-right: 8px; border: 1px solid rgba(255,255,255,.16); cursor: pointer; box-shadow: 0 6px 14px rgba(29,78,216,.25); }}
    .btn:hover {{ filter: brightness(1.04); }}
    .btn.alt {{ background: linear-gradient(135deg, #334155, #1f2937); box-shadow: 0 6px 14px rgba(51,65,85,.18); }}
    .btn.danger {{ background: #b91c1c; }}
    .chart-card {{ background: white; border: 1px solid var(--line); border-radius: 14px; margin-top: 14px; padding: 14px; box-shadow: 0 4px 14px rgba(15,23,42,.05); }}
    .chart-wrap {{ display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }}
    .pie {{ width: 180px; height: 180px; border-radius: 50%; position: relative; box-shadow: inset 0 0 0 1px rgba(15,23,42,.08); }}
    .pie::after {{ content: ""; position: absolute; inset: 38px; border-radius: 50%; background: white; box-shadow: inset 0 0 0 1px #e2e8f0; }}
    .pie-center {{ position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-weight: 700; color: #334155; z-index: 1; }}
    .legend {{ display: grid; gap: 6px; min-width: 260px; }}
    .legend-row {{ display: grid; grid-template-columns: 12px 1fr auto; gap: 8px; align-items: center; border: 1px solid #e2e8f0; background: #f8fafc; border-radius: 8px; padding: 4px 8px; font-size: 12px; }}
    .swatch {{ width: 10px; height: 10px; border-radius: 2px; }}
    .legend-value {{ font-weight: 700; color: #0f172a; }}
    input, select {{ padding: 9px; border: 1px solid #cbd5e1; border-radius: 10px; min-width: 260px; background: #fff; }}
    input:focus, select:focus {{ outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,.15); }}
    label {{ font-size: 13px; color: #334155; display:block; margin-top:10px; }}
    .toolbar {{ display:flex; gap:10px; flex-wrap:wrap; align-items:end; margin-top: 8px; }}
    .toolbar .field {{ display:flex; flex-direction:column; gap:4px; }}
    .toolbar input, .toolbar select {{ min-width: 220px; }}
    .toolbar-actions {{ display:flex; gap:8px; }}
    .chips {{ margin-top: 10px; display:flex; gap:6px; flex-wrap:wrap; }}
    .chip {{ display:inline-block; background:#f1f5f9; color:#0f172a; border:1px solid #cbd5e1; border-radius:999px; padding:4px 10px; font-size:12px; }}
    .chip.active {{ background:#dbeafe; color:#1e40af; border-color:#93c5fd; }}
    .stats {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }}
    .stat {{ background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:6px 10px; font-size:12px; }}
    .cat-badge {{ display:inline-block; border-radius:999px; padding:3px 9px; font-size:12px; font-weight:600; border:1px solid transparent; }}
    .cat-default {{ background:#f1f5f9; color:#0f172a; border-color:#cbd5e1; }}
    .cat-ai-sdks {{ background:#eef2ff; color:#3730a3; border-color:#c7d2fe; }}
    .cat-llm-models {{ background:#ecfeff; color:#0e7490; border-color:#a5f3fc; }}
    .cat-local-models {{ background:#ecfdf5; color:#047857; border-color:#a7f3d0; }}
    .cat-vector-dbs {{ background:#fffbeb; color:#b45309; border-color:#fcd34d; }}
    .cat-ai-endpoints {{ background:#fef2f2; color:#b91c1c; border-color:#fecaca; }}
    .cat-risks {{ background:#fdf4ff; color:#a21caf; border-color:#f5d0fe; }}
    .prompt-screen {{ min-height: 70vh; display:flex; align-items:center; justify-content:center; }}
    .prompt-card {{ width: min(560px, 96%); border: 1px solid #bfdbfe; box-shadow: 0 18px 40px rgba(30,64,175,.18); border-radius: 14px; background: #ffffff; padding: 18px; }}
    .prompt-title {{ margin:0; font-size: 20px; color:#1e3a8a; }}
    .prompt-subtitle {{ margin:8px 0 0; color:#475569; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>AI SBOM Local Database</h1>
      <p>Enterprise dashboard for AI component governance, findings review, and audit-ready exports</p>
    </div>
    {user_html}
    {body}
  </div>
</body>
</html>"""


def password_prompt_template(body):
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0" />
  <meta http-equiv="Pragma" content="no-cache" />
  <meta http-equiv="Expires" content="0" />
  <title>Password Reset Required</title>
  <style>
    body {{ margin:0; min-height:100vh; font-family: Inter, Segoe UI, Arial, sans-serif; background: radial-gradient(circle at top, #dbeafe, #eff6ff 42%, #f8fafc 100%); display:flex; align-items:center; justify-content:center; color:#0f172a; }}
    .prompt-card {{ width:min(560px, 94%); background:#fff; border:1px solid #bfdbfe; border-radius:16px; box-shadow:0 18px 50px rgba(30,64,175,.20); padding:20px; }}
    .prompt-title {{ margin:0; font-size:22px; color:#1e3a8a; }}
    .prompt-subtitle {{ margin:8px 0 0; color:#475569; font-size:13px; }}
    .muted {{ color:#64748b; font-size:13px; }}
    label {{ font-size:13px; color:#334155; display:block; margin-top:10px; }}
    input {{ width:100%; box-sizing:border-box; padding:10px; border:1px solid #cbd5e1; border-radius:10px; }}
    .btn {{ display:inline-block; background:#1d4ed8; color:#fff; border-radius:10px; padding:8px 12px; font-size:14px; border:none; cursor:pointer; }}
  </style>
</head>
<body>
  {body}
</body>
</html>"""


def build_excel_xml(rows, title):
    def esc(value):
        return (
            str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    def normalize_excel_value(value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            return " | ".join(str(v) for v in value)
        if isinstance(value, dict):
            return " | ".join(f"{k}:{v}" for k, v in value.items())
        return str(value)

    def ordered_columns(data_rows):
        preferred = [
            "category",
            "entity",
            "instances",
            "total_instances",
            "projects_count",
            "scans_count",
            "versions",
            "detection_methods",
            "source_files",
            "project_name",
            "project_path",
            "scan_uid",
            "scanned_at",
        ]
        seen = set()
        cols = []
        for key in preferred:
            if any(key in row for row in data_rows):
                cols.append(key)
                seen.add(key)
        for row in data_rows:
            for key in row.keys():
                if key not in seen:
                    cols.append(key)
                    seen.add(key)
        return cols

    def col_width(col):
        width_map = {
            "category": 90,
            "entity": 180,
            "instances": 70,
            "total_instances": 90,
            "projects_count": 90,
            "scans_count": 80,
            "versions": 120,
            "detection_methods": 150,
            "source_files": 420,
            "project_name": 130,
            "project_path": 320,
            "scan_uid": 180,
            "scanned_at": 130,
        }
        return width_map.get(col, 140)

    if not rows:
        rows = [{"message": "No data"}]
    columns = ordered_columns(rows)
    excel_styles = {
        "default": ("#FFFFFF", "#0F172A"),
        "header": ("#1D4ED8", "#FFFFFF"),
        "cat-ai-sdks": ("#EEF2FF", "#3730A3"),
        "cat-llm-models": ("#ECFEFF", "#0E7490"),
        "cat-local-models": ("#ECFDF5", "#047857"),
        "cat-vector-dbs": ("#FFFBEB", "#B45309"),
        "cat-ai-endpoints": ("#FEF2F2", "#B91C1C"),
        "cat-risks": ("#FDF4FF", "#A21CAF"),
        "cat-default": ("#F8FAFC", "#0F172A"),
    }
    parts = [
        "<?xml version=\"1.0\"?>",
        "<?mso-application progid=\"Excel.Sheet\"?>",
        "<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\" xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\">",
        "<Styles>",
    ]
    for style_id, (bg, fg) in excel_styles.items():
        parts.append(
            f"<Style ss:ID=\"{esc(style_id)}\">"
            f"<Font ss:Color=\"{esc(fg)}\" ss:FontName=\"Calibri\" ss:Size=\"11\"/>"
            f"<Interior ss:Color=\"{esc(bg)}\" ss:Pattern=\"Solid\"/>"
            "<Alignment ss:Vertical=\"Top\" ss:WrapText=\"1\"/>"
            "<Borders>"
            "<Border ss:Position=\"Bottom\" ss:LineStyle=\"Continuous\" ss:Weight=\"1\" ss:Color=\"#D1D9E6\"/>"
            "<Border ss:Position=\"Top\" ss:LineStyle=\"Continuous\" ss:Weight=\"1\" ss:Color=\"#D1D9E6\"/>"
            "<Border ss:Position=\"Left\" ss:LineStyle=\"Continuous\" ss:Weight=\"1\" ss:Color=\"#D1D9E6\"/>"
            "<Border ss:Position=\"Right\" ss:LineStyle=\"Continuous\" ss:Weight=\"1\" ss:Color=\"#D1D9E6\"/>"
            "</Borders>"
            "</Style>"
        )
    parts.extend([
        "</Styles>",
        f"<Worksheet ss:Name=\"{esc(title[:31])}\"><Table>",
    ])
    for col in columns:
        parts.append(f"<Column ss:Width=\"{col_width(col)}\"/>")
    header = "".join(
        f"<Cell ss:StyleID=\"header\"><Data ss:Type=\"String\">{esc(col)}</Data></Cell>" for col in columns
    )
    parts.append(f"<Row>{header}</Row>")
    for row in rows:
        cat = row.get("category", "")
        style_id = category_css_class(cat)
        if style_id not in excel_styles:
            style_id = "cat-default"
        value_cells = []
        for col in columns:
            raw = row.get(col, "")
            text = normalize_excel_value(raw)
            if col in {"instances", "total_instances", "projects_count", "scans_count"}:
                try:
                    number_value = int(raw)
                    value_cells.append(
                        f"<Cell ss:StyleID=\"{esc(style_id)}\"><Data ss:Type=\"Number\">{number_value}</Data></Cell>"
                    )
                    continue
                except Exception:
                    pass
            value_cells.append(
                f"<Cell ss:StyleID=\"{esc(style_id)}\"><Data ss:Type=\"String\">{esc(text)}</Data></Cell>"
            )
        values = "".join(value_cells)
        parts.append(f"<Row>{values}</Row>")
    parts.append("</Table></Worksheet></Workbook>")
    return "".join(parts).encode("utf-8")


def build_pie_chart_html(title, items, empty_text="No data for chart"):
    palette = ["#4f46e5", "#06b6d4", "#10b981", "#f59e0b", "#ef4444", "#d946ef", "#0ea5e9", "#84cc16", "#f97316"]
    filtered = [(str(label), int(value)) for label, value in items if int(value) > 0]
    total = sum(value for _, value in filtered)
    if total <= 0:
        return f"<div class='chart-card'><h3>{html.escape(title)}</h3><p class='muted'>{html.escape(empty_text)}</p></div>"
    filtered.sort(key=lambda x: x[1], reverse=True)
    top = filtered[:10]
    if len(filtered) > 10:
        others = sum(v for _, v in filtered[10:])
        if others > 0:
            top.append(("Others", others))
    start = 0.0
    segments = []
    legend_rows = []
    chart_total = sum(v for _, v in top)
    for idx, (label, value) in enumerate(top):
        span = (value / chart_total) * 360.0
        end = start + span
        color = palette[idx % len(palette)]
        segments.append(f"{color} {start:.2f}deg {end:.2f}deg")
        legend_rows.append(
            "<div class='legend-row'>"
            f"<span class='swatch' style='background:{color}'></span>"
            f"<span>{html.escape(label)}</span>"
            f"<span class='legend-value'>{value}</span>"
            "</div>"
        )
        start = end
    pie_bg = f"conic-gradient({', '.join(segments)})"
    return (
        "<div class='chart-card'>"
        f"<h3>{html.escape(title)}</h3>"
        "<div class='chart-wrap'>"
        f"<div class='pie' style='background:{pie_bg}'><div class='pie-center'>{chart_total}</div></div>"
        f"<div class='legend'>{''.join(legend_rows)}</div></div></div>"
    )


def render_filter_toolbar(base_path, category="", q="", extra_query=None):
    extra_query = extra_query or {}
    hidden_fields = "".join(
        f"<input type='hidden' name='{html.escape(str(k))}' value='{html.escape(str(v))}' />"
        for k, v in extra_query.items()
    )
    option_rows = ["<option value=''>all categories</option>"]
    for option in CATEGORY_OPTIONS:
        selected = " selected" if option == category else ""
        option_rows.append(f"<option value='{option}'{selected}>{option}</option>")
    base_params = dict(extra_query)
    all_params = dict(base_params)
    all_params["q"] = q
    chips = [f"<a class='chip cat-default{' active' if not category else ''}' href='{base_path}?{urlencode(all_params)}'>all</a>"]
    for option in CATEGORY_OPTIONS:
        chip_params = dict(base_params)
        chip_params["category"] = option
        chip_params["q"] = q
        chips.append(
            f"<a class='chip {category_css_class(option)}{' active' if category == option else ''}' "
            f"href='{base_path}?{urlencode(chip_params)}'>{option}</a>"
        )
    reset_href = base_path if not base_params else f"{base_path}?{urlencode(base_params)}"
    return (
        "<div class='card'>"
        "<form method='get' class='toolbar'>"
        f"{hidden_fields}"
        "<div class='field'><label>Category</label>"
        f"<select name='category'>{''.join(option_rows)}</select></div>"
        "<div class='field'><label>Search entity/source file</label>"
        f"<input name='q' value='{html.escape(q)}' placeholder='e.g. openai, pinecone, /src/' /></div>"
        "<div class='toolbar-actions'>"
        "<button class='btn' type='submit'>Apply Filter</button>"
        f"<a class='btn alt' href='{reset_href}'>Reset</a>"
        "</div>"
        "</form>"
        f"<div class='chips'>{''.join(chips)}</div>"
        "</div>"
    )


class Handler(BaseHTTPRequestHandler):
    db_path = "ai_sbom.db"
    db_link_file = "ai_sbom_active_db.txt"

    def _apply_no_cache_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")

    def _send_html(self, text, status=200):
        encoded = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._apply_no_cache_headers()
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_binary(self, payload, content_type, filename, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self._apply_no_cache_headers()
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _get_db_path(self):
        link_path = Path(self.db_link_file)
        if not link_path.is_absolute():
            link_path = Path.cwd() / link_path
        if link_path.exists():
            try:
                active = Path(link_path.read_text(encoding="utf-8").strip())
                if active.exists():
                    return str(active)
            except Exception:
                pass
        return self.db_path

    def _open_db(self):
        effective_db = self._get_db_path()
        init_db(effective_db)
        return open_db(effective_db)

    def _set_active_db_path(self, db_path):
        link_path = Path(self.db_link_file)
        if not link_path.is_absolute():
            link_path = Path.cwd() / link_path
        with open(link_path, "w", encoding="utf-8") as handle:
            handle.write(str(Path(db_path).resolve()))

    def _redirect(self, location, set_cookie=None):
        self.send_response(302)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self._apply_no_cache_headers()
        self.send_header("Location", location)
        self.end_headers()

    def _read_post_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        return parse_qs(raw)

    def _extract_session_token(self):
        cookie_header = self.headers.get("Cookie", "")
        for chunk in cookie_header.split(";"):
            chunk = chunk.strip()
            if chunk.startswith(f"{SESSION_COOKIE}="):
                return chunk.split("=", 1)[1]
        return None

    def _current_user(self):
        token = self._extract_session_token()
        if not token:
            return None
        session = SESSIONS.get(token)
        if not session:
            return None
        now = time.time()
        last_activity = float(session.get("last_activity", now))
        if now - last_activity > SESSION_IDLE_TIMEOUT_SECONDS:
            del SESSIONS[token]
            return None
        session["last_activity"] = now
        return session

    def _load_user_flags(self, username):
        conn = self._open_db()
        try:
            row = conn.execute(
                "SELECT must_reset_password, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not row:
                return None
            return {
                "must_reset_password": int(row["must_reset_password"] or 0) == 1,
                "role": row["role"],
            }
        finally:
            conn.close()

    def _require_auth(self, admin=False):
        user = self._current_user()
        if not user:
            self._redirect("/login", set_cookie=f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            return None
        # Re-check password reset enforcement on every authenticated request.
        # This covers stale sessions created before reset policy was added.
        flags = self._load_user_flags(user.get("username"))
        if not flags:
            self._redirect("/login", set_cookie=f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            return None
        user["must_reset_password"] = flags["must_reset_password"]
        user["role"] = flags["role"]
        if admin and user.get("role") != "admin":
            self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/login":
            ok = query.get("ok", [""])[0]
            return self.render_login(ok=ok)
        if path == "/logout":
            return self.logout()
        if path == "/cache/clear":
            return self.clear_browser_cache()
        if path == "/password/reset":
            user = self._current_user()
            if not user:
                self._redirect("/login")
                return
            error = query.get("error", [""])[0]
            ok = query.get("ok", [""])[0]
            return self.render_password_reset(user, error=error, ok=ok)

        user = self._require_auth()
        if not user:
            return
        if user.get("must_reset_password"):
            self._redirect("/password/reset")
            return

        if path == "/":
            return self.render_projects(user)
        if path == "/project":
            return self.render_project_scans(user, query)
        if path == "/scan":
            return self.render_scan_findings(user, query)
        if path == "/components":
            return self.render_all_components(user, query)
        if path == "/instances":
            return self.render_component_instances(user, query)
        if path == "/export":
            return self.export_excel(query)
        if path == "/users":
            return self.render_users(user)
        if path == "/scan/new":
            return self.render_scan_new(user)
        self._send_html(page_template("Not found", "<div class='card'>Not found</div>", user=user), status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/login":
            return self.handle_login()
        if path == "/password/reset":
            user = self._current_user()
            if not user:
                self._redirect("/login")
                return
            return self.handle_password_reset(user)

        user = self._require_auth()
        if not user:
            return
        if user.get("must_reset_password"):
            self._redirect("/password/reset")
            return
        if path == "/users/add":
            return self.handle_add_user(user)
        if path == "/users/reset":
            return self.handle_reset_user_password(user)
        if path == "/users/delete":
            return self.handle_delete_user(user)
        if path == "/scan/run":
            return self.handle_run_scan(user)
        if path == "/db/clear":
            return self.handle_clear_db(user)
        if path == "/delete/project":
            return self.handle_delete_project(user)
        if path == "/delete/scan":
            return self.handle_delete_scan(user)
        if path == "/delete/component":
            return self.handle_delete_component(user)
        self._send_html(page_template("Not found", "<div class='card'>Not found</div>", user=user), status=404)

    def render_login(self, error="", ok=""):
        err = f"<p style='color:#b91c1c'>{html.escape(error)}</p>" if error else ""
        ok_html = f"<p style='color:#166534'>{html.escape(ok)}</p>" if ok else ""
        body = (
            "<div class='card'><h3>Login</h3>"
            f"{err}{ok_html}"
            "<form method='post' action='/login'>"
            "<label>Username</label><input name='username' required />"
            "<label>Password</label><input type='password' name='password' required />"
            "<br/><br/><button class='btn' type='submit'>Sign In</button>"
            "</form>"
            "<p class='muted'>Default admin credentials: admin / admin</p>"
            "</div>"
        )
        self._send_html(page_template("Login", body))

    def handle_login(self):
        form = self._read_post_form()
        username = (form.get("username", [""])[0]).strip()
        password = form.get("password", [""])[0]
        conn = self._open_db()
        try:
            user = conn.execute(
                "SELECT id, username, role, password_hash, must_reset_password FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            # If default admin credentials are used, enforce mandatory reset in DB before session.
            if user and user["username"] == "admin" and password == "admin":
                conn.execute("UPDATE users SET must_reset_password = 1 WHERE id = ?", (user["id"],))
                conn.commit()
                user = conn.execute(
                    "SELECT id, username, role, password_hash, must_reset_password FROM users WHERE id = ?",
                    (user["id"],),
                ).fetchone()
        finally:
            conn.close()
        if not user or user["password_hash"] != hash_password(password):
            return self.render_login("Invalid username or password.")
        token = secrets.token_urlsafe(24)
        must_reset = int(user["must_reset_password"] or 0) == 1
        SESSIONS[token] = {
            "session_id": token,
            "username": user["username"],
            "role": user["role"],
            "must_reset_password": must_reset,
            "last_activity": time.time(),
        }
        redirect_to = "/password/reset" if must_reset else "/"
        self._redirect(redirect_to, set_cookie=f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax")

    def render_password_reset(self, user, error="", ok=""):
        err_html = f"<p style='color:#b91c1c'>{html.escape(error)}</p>" if error else ""
        ok_html = f"<p style='color:#166534'>{html.escape(ok)}</p>" if ok else ""
        body = (
            "<div class='prompt-card'>"
            "<h3 class='prompt-title'>Password Reset Required</h3>"
            "<p class='prompt-subtitle'>Before accessing dashboard options, reset your credentials now.</p>"
            "<p class='muted'>Password policy: minimum 8 chars, at least one uppercase letter, one number, and one special character.</p>"
            f"{err_html}{ok_html}"
            "<form method='post' action='/password/reset'>"
            "<label>New Password</label><input type='password' name='new_password' required autofocus />"
            "<label>Confirm New Password</label><input type='password' name='confirm_password' required />"
            "<br/><br/><button class='btn' type='submit'>Reset and Continue</button>"
            "</form>"
            "</div>"
        )
        self._send_html(password_prompt_template(body))

    def handle_password_reset(self, user):
        form = self._read_post_form()
        new_password = form.get("new_password", [""])[0]
        confirm_password = form.get("confirm_password", [""])[0]
        if new_password != confirm_password:
            return self._redirect("/password/reset?error=Passwords+do+not+match")
        ok, message = validate_password_complexity(new_password)
        if not ok:
            return self._redirect(f"/password/reset?error={urlencode({'m': message})[2:]}")
        conn = self._open_db()
        try:
            conn.execute(
                "UPDATE users SET password_hash = ?, must_reset_password = 0 WHERE username = ?",
                (hash_password(new_password), user["username"]),
            )
            conn.commit()
        finally:
            conn.close()
        user["must_reset_password"] = False
        self._redirect("/?ok=password-updated")

    def clear_browser_cache(self):
        token = self._extract_session_token()
        if token and token in SESSIONS:
            del SESSIONS[token]
        body = (
            "<div class='card'><h3>Clearing Browser Cache</h3>"
            "<p class='muted'>Clearing local cache and redirecting to login.</p>"
            "<script>"
            "try { localStorage.clear(); } catch(e) {}"
            "try { sessionStorage.clear(); } catch(e) {}"
            "if ('caches' in window) {"
            "  caches.keys().then(function(keys){ return Promise.all(keys.map(function(k){ return caches.delete(k); })); }).finally(function(){ window.location='/login?ok=cache-cleared'; });"
            "} else { window.location='/login?ok=cache-cleared'; }"
            "</script>"
            "</div>"
        )
        self.send_response(200)
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._apply_no_cache_headers()
        encoded = page_template("Clear Cache", body).encode("utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def logout(self):
        token = self._extract_session_token()
        if token and token in SESSIONS:
            del SESSIONS[token]
        self._redirect("/login", set_cookie=f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")

    def render_projects(self, user):
        conn = self._open_db()
        try:
            rows = conn.execute(
                """
                SELECT p.id, p.name, p.path,
                       (SELECT MAX(scanned_at) FROM scans s WHERE s.project_id = p.id) AS last_scan,
                       (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) AS total_scans,
                       (SELECT s2.total_instances FROM scans s2 WHERE s2.project_id = p.id ORDER BY s2.scanned_at DESC LIMIT 1) AS latest_instances
                FROM projects p
                ORDER BY last_scan DESC
                """
            ).fetchall()
        finally:
            conn.close()
        rows_html = []
        for row in rows:
            delete_btn = ""
            if user.get("role") == "admin":
                delete_btn = (
                    "<form method='post' action='/delete/project' "
                    "onsubmit=\"return confirm('Delete this project and all its scans/findings?');\" style='display:inline'>"
                    f"<input type='hidden' name='project_id' value='{row['id']}' />"
                    "<button class='btn danger' type='submit'>Delete</button>"
                    "</form>"
                )
            rows_html.append(
                "<tr>"
                f"<td><a href='/project?id={row['id']}'>{html.escape(row['name'])}</a></td>"
                f"<td class='muted'>{html.escape(row['path'])}</td>"
                f"<td>{html.escape(str(row['last_scan'] or '-'))}</td>"
                f"<td>{row['total_scans']}</td>"
                f"<td>{row['latest_instances'] if row['latest_instances'] is not None else '-'}</td>"
                f"<td>{delete_btn}</td>"
                "</tr>"
            )
        chart_items = [(row["name"], row["latest_instances"] or 0) for row in rows]
        body = (
            build_pie_chart_html("Project-wise Findings (latest scan instances)", chart_items)
            + "<div class='card'><h3>Projects</h3>"
            + "<table><thead><tr><th>Name</th><th>Path</th><th>Last Scan</th><th>Scans</th><th>Latest Instances</th><th>Actions</th></tr></thead>"
            + f"<tbody>{''.join(rows_html) or '<tr><td colspan=6>No projects found.</td></tr>'}</tbody></table></div>"
        )
        self._send_html(page_template("Projects", body, user=user))

    def render_project_scans(self, user, query):
        project_id = query.get("id", [""])[0]
        if not project_id:
            return self._send_html(page_template("Missing project", "<div class='card'>Missing project id.</div>", user=user), 400)
        conn = self._open_db()
        try:
            project = conn.execute("SELECT id, name, path FROM projects WHERE id = ?", (project_id,)).fetchone()
            scans = conn.execute(
                "SELECT id, scan_uid, scanned_at, total_components, total_instances FROM scans WHERE project_id = ? ORDER BY scanned_at DESC",
                (project_id,),
            ).fetchall()
        finally:
            conn.close()
        if not project:
            return self._send_html(page_template("Not found", "<div class='card'>Project not found.</div>", user=user), 404)
        rows = []
        for scan in scans:
            uid = scan["scan_uid"] or f"SCAN-{scan['id']}"
            delete_btn = ""
            if user.get("role") == "admin":
                delete_btn = (
                    "<form method='post' action='/delete/scan' "
                    "onsubmit=\"return confirm('Delete this scan and its findings?');\" style='display:inline'>"
                    f"<input type='hidden' name='scan_id' value='{scan['id']}' />"
                    "<button class='btn danger' type='submit'>Delete</button>"
                    "</form>"
                )
            rows.append(
                "<tr>"
                f"<td><a href='/scan?id={scan['id']}'>{html.escape(uid)}</a></td>"
                f"<td>{scan['id']}</td>"
                f"<td>{html.escape(scan['scanned_at'])}</td>"
                f"<td>{scan['total_components']}</td>"
                f"<td><a href='/scan?id={scan['id']}'>{scan['total_instances']}</a></td>"
                f"<td>{delete_btn}</td>"
                "</tr>"
            )
        body = (
            "<div class='card'>"
            f"<h3>{html.escape(project['name'])}</h3>"
            f"<p class='muted'>{html.escape(project['path'])}</p>"
            "<table><thead><tr><th>Scan UID</th><th>Scan ID</th><th>Scanned At</th><th>Components</th><th>Instances</th><th>Actions</th></tr></thead>"
            + f"<tbody>{''.join(rows) or '<tr><td colspan=6>No scans found.</td></tr>'}</tbody></table></div>"
        )
        self._send_html(page_template("Project Scans", body, user=user))

    def render_scan_findings(self, user, query):
        scan_id = query.get("id", [""])[0]
        category = query.get("category", [""])[0]
        q = query.get("q", [""])[0].strip().lower()
        if not scan_id:
            return self._send_html(page_template("Missing scan", "<div class='card'>Missing scan id.</div>", user=user), 400)
        conn = self._open_db()
        try:
            scan = conn.execute(
                """
                SELECT s.id, s.scan_uid, s.scanned_at, p.name AS project_name, p.path AS project_path
                FROM scans s JOIN projects p ON p.id = s.project_id
                WHERE s.id = ?
                """,
                (scan_id,),
            ).fetchone()
            if category:
                findings = conn.execute(
                    "SELECT category, entity, instances, source_files_json, meta_json FROM findings WHERE scan_id = ? AND category = ? ORDER BY category, entity",
                    (scan_id, category),
                ).fetchall()
            else:
                findings = conn.execute(
                    "SELECT category, entity, instances, source_files_json, meta_json FROM findings WHERE scan_id = ? ORDER BY category, entity",
                    (scan_id,),
                ).fetchall()
        finally:
            conn.close()
        if not scan:
            return self._send_html(page_template("Not found", "<div class='card'>Scan not found.</div>", user=user), 404)

        uid = scan["scan_uid"] or f"SCAN-{scan['id']}"
        finding_cards = []
        total_instances = 0
        category_totals = {}
        filtered_findings = []
        for f in findings:
            source_files = json.loads(f["source_files_json"]) if f["source_files_json"] else []
            entity_match = q in str(f["entity"]).lower() if q else True
            path_match = any(q in str(path).lower() for path in source_files) if q else True
            if entity_match or path_match:
                filtered_findings.append(f)
                total_instances += int(f["instances"] or 0)
                cat = str(f["category"])
                category_totals[cat] = category_totals.get(cat, 0) + int(f["instances"] or 0)
        finding_cards.append(f"<span class='stat'><strong>Components:</strong> {len(filtered_findings)}</span>")
        finding_cards.append(f"<span class='stat'><strong>Instances:</strong> {total_instances}</span>")
        for cat in CATEGORY_OPTIONS:
            if category_totals.get(cat, 0) > 0:
                finding_cards.append(f"<span class='stat'><strong>{html.escape(cat)}:</strong> {category_totals[cat]}</span>")
        header = (
            "<div class='card'>"
            f"<strong>Project:</strong> {html.escape(scan['project_name'])} <span class='muted'>({html.escape(scan['project_path'])})</span><br/>"
            f"<strong>Scan:</strong> {html.escape(uid)} (ID: {scan['id']}) <span class='muted'>at {html.escape(scan['scanned_at'])}</span><br/>"
            f"<span class='muted'>Search:</span> {html.escape(q or 'none')}<br/><br/>"
            f"<a class='btn' href='/export?type=scan&id={scan_id}'>Export This Scan (Excel)</a>"
            f"<div class='stats'>{''.join(finding_cards)}</div>"
            "</div>"
        )

        rows = []
        for f in filtered_findings:
            source_files = json.loads(f["source_files_json"]) if f["source_files_json"] else []
            meta = json.loads(f["meta_json"]) if f["meta_json"] else {}
            versions = meta.get("versions", [])
            cat_class = category_css_class(f["category"])
            versions_html = "".join(f"<span class='pill'>{html.escape(str(v))}</span>" for v in versions) or "<span class='muted'>-</span>"
            files_html = "".join(f"<span class='pill'>{html.escape(str(path))}</span>" for path in source_files[:6])
            if len(source_files) > 6:
                files_html += f"<span class='pill'>+{len(source_files)-6} more</span>"
            rows.append(
                "<tr>"
                f"<td><span class='cat-badge {cat_class}'>{html.escape(f['category'])}</span></td>"
                f"<td>{html.escape(f['entity'])}</td>"
                f"<td>{f['instances']}</td>"
                f"<td>{versions_html}</td>"
                f"<td>{files_html or '<span class=\"muted\">-</span>'}</td>"
                "</tr>"
            )
        body = (
            header
            + render_filter_toolbar("/scan", category=category, q=q, extra_query={"id": scan_id})
            + "<div class='card'>"
            + "<table><thead><tr><th>Category</th><th>Entity</th><th>Instances</th><th>Versions</th><th>Source Files</th></tr></thead>"
            + f"<tbody>{''.join(rows) or '<tr><td colspan=5>No findings.</td></tr>'}</tbody></table></div>"
        )
        self._send_html(page_template("Scan Findings", body, user=user))

    def render_all_components(self, user, query):
        category = query.get("category", [""])[0]
        q = query.get("q", [""])[0].strip().lower()
        conn = self._open_db()
        try:
            if category:
                rows = conn.execute(
                    """
                    SELECT f.category, f.entity, SUM(f.instances) AS total_instances,
                           COUNT(DISTINCT s.project_id) AS projects_count, COUNT(DISTINCT f.scan_id) AS scans_count
                    FROM findings f JOIN scans s ON s.id = f.scan_id
                    WHERE f.category = ?
                    GROUP BY f.category, f.entity
                    ORDER BY total_instances DESC, f.entity
                    """,
                    (category,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT f.category, f.entity, SUM(f.instances) AS total_instances,
                           COUNT(DISTINCT s.project_id) AS projects_count, COUNT(DISTINCT f.scan_id) AS scans_count
                    FROM findings f JOIN scans s ON s.id = f.scan_id
                    GROUP BY f.category, f.entity
                    ORDER BY total_instances DESC, f.entity
                    """
                ).fetchall()
            detail_rows = conn.execute(
                """
                SELECT f.category, f.entity, p.name AS project_name, f.source_files_json
                FROM findings f
                JOIN scans s ON s.id = f.scan_id
                JOIN projects p ON p.id = s.project_id
                ORDER BY f.category, f.entity
                """
            ).fetchall()
        finally:
            conn.close()
        details_by_key = {}
        for d in detail_rows:
            key = (str(d["category"]), str(d["entity"]))
            bucket = details_by_key.setdefault(key, {"projects": set(), "files": set()})
            if d["project_name"]:
                bucket["projects"].add(str(d["project_name"]))
            source_files = json.loads(d["source_files_json"]) if d["source_files_json"] else []
            for path in source_files:
                bucket["files"].add(str(path))
        if q:
            rows = [r for r in rows if q in str(r["entity"]).lower()]
        filters = (
            render_filter_toolbar("/components", category=category, q=q)
            + f"<div class='card'><a class='btn' href='/export?type=components&category={html.escape(category)}'>Export Components (Excel)</a></div>"
        )
        category_totals = {}
        total_instances = 0
        for r in rows:
            total_instances += int(r["total_instances"] or 0)
            cat = str(r["category"])
            category_totals[cat] = category_totals.get(cat, 0) + int(r["total_instances"] or 0)
        stats = [f"<span class='stat'><strong>Components:</strong> {len(rows)}</span>", f"<span class='stat'><strong>Instances:</strong> {total_instances}</span>"]
        for cat in CATEGORY_OPTIONS:
            if category_totals.get(cat, 0) > 0:
                stats.append(f"<span class='stat'><strong>{html.escape(cat)}:</strong> {category_totals[cat]}</span>")
        chart_items = [(r["entity"], r["total_instances"]) for r in rows]
        rows_html = []
        for r in rows:
            delete_btn = ""
            cat_class = category_css_class(r["category"])
            detail = details_by_key.get((str(r["category"]), str(r["entity"])), {"projects": set(), "files": set()})
            project_list = sorted(detail["projects"])
            source_file_list = sorted(detail["files"])
            projects_html = "".join(f"<span class='pill'>{html.escape(name)}</span>" for name in project_list[:4])
            if len(project_list) > 4:
                projects_html += f"<span class='pill'>+{len(project_list)-4} more</span>"
            files_html = "".join(f"<span class='pill'>{html.escape(path)}</span>" for path in source_file_list[:6])
            if len(source_file_list) > 6:
                files_html += f"<span class='pill'>+{len(source_file_list)-6} more</span>"
            if user.get("role") == "admin":
                delete_btn = (
                    "<form method='post' action='/delete/component' "
                    "onsubmit=\"return confirm('Delete this component across all scans?');\" style='display:inline'>"
                    f"<input type='hidden' name='category' value='{html.escape(r['category'])}' />"
                    f"<input type='hidden' name='entity' value='{html.escape(r['entity'])}' />"
                    "<button class='btn danger' type='submit'>Delete</button>"
                    "</form>"
                )
            rows_html.append(
                "<tr>"
                f"<td><span class='cat-badge {cat_class}'>{html.escape(r['category'])}</span></td>"
                f"<td>{html.escape(r['entity'])}</td>"
                f"<td><a href='/instances?{urlencode({'category': r['category'], 'entity': r['entity']})}'>{r['total_instances']}</a></td>"
                f"<td>{r['projects_count']}</td>"
                f"<td>{r['scans_count']}</td>"
                f"<td>{projects_html or '<span class=\"muted\">-</span>'}</td>"
                f"<td>{files_html or '<span class=\"muted\">-</span>'}</td>"
                f"<td>{delete_btn}</td>"
                "</tr>"
            )
        body = (
            filters
            + f"<div class='card'><div class='stats'>{''.join(stats)}</div></div>"
            + build_pie_chart_html("Component-wise Findings (total instances)", chart_items)
            + "<div class='card'><h3>All Components</h3>"
            + "<table><thead><tr><th>Category</th><th>Entity</th><th>Total Instances</th><th>Projects</th><th>Scans</th><th>Project Names</th><th>Source Files</th><th>Actions</th></tr></thead>"
            + f"<tbody>{''.join(rows_html) or '<tr><td colspan=8>No components found.</td></tr>'}</tbody></table></div>"
        )
        self._send_html(page_template("All Components", body, user=user))

    def render_component_instances(self, user, query):
        category = query.get("category", [""])[0]
        entity = query.get("entity", [""])[0]
        if not category or not entity:
            return self._send_html(page_template("Missing params", "<div class='card'>Missing category or entity.</div>", user=user), 400)
        conn = self._open_db()
        try:
            rows = conn.execute(
                """
                SELECT f.instances, f.source_files_json,
                       s.id AS scan_id, s.scan_uid, s.scanned_at,
                       p.name AS project_name, p.path AS project_path
                FROM findings f
                JOIN scans s ON s.id = f.scan_id
                JOIN projects p ON p.id = s.project_id
                WHERE f.category = ? AND f.entity = ?
                ORDER BY s.scanned_at DESC
                """,
                (category, entity),
            ).fetchall()
        finally:
            conn.close()
        cat_class = category_css_class(category)
        total_instances = sum(int(r["instances"] or 0) for r in rows)
        table_rows = []
        for row in rows:
            source_files = json.loads(row["source_files_json"]) if row["source_files_json"] else []
            files_html = "".join(f"<span class='pill'>{html.escape(str(path))}</span>" for path in source_files[:8])
            if len(source_files) > 8:
                files_html += f"<span class='pill'>+{len(source_files)-8} more</span>"
            scan_uid = row["scan_uid"] or f"SCAN-{row['scan_id']}"
            table_rows.append(
                "<tr>"
                f"<td><a href='/scan?id={row['scan_id']}'>{html.escape(scan_uid)}</a></td>"
                f"<td>{html.escape(row['project_name'])}</td>"
                f"<td class='muted'>{html.escape(row['project_path'])}</td>"
                f"<td>{html.escape(row['scanned_at'])}</td>"
                f"<td>{int(row['instances'] or 0)}</td>"
                f"<td>{files_html or '<span class=\"muted\">-</span>'}</td>"
                "</tr>"
            )
        body = (
            "<div class='card'>"
            f"<h3>Instance Details</h3>"
            f"<p><span class='cat-badge {cat_class}'>{html.escape(category)}</span> "
            f"<strong>{html.escape(entity)}</strong></p>"
            f"<div class='stats'><span class='stat'><strong>Total Instances:</strong> {total_instances}</span>"
            f"<span class='stat'><strong>Scans:</strong> {len(rows)}</span></div>"
            "</div>"
            "<div class='card'>"
            "<table><thead><tr><th>Scan</th><th>Project</th><th>Project Path</th><th>Scanned At</th><th>Instances</th><th>Source Files</th></tr></thead>"
            f"<tbody>{''.join(table_rows) or '<tr><td colspan=6>No instances found.</td></tr>'}</tbody></table>"
            "</div>"
        )
        self._send_html(page_template("Instance Details", body, user=user))

    def render_users(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        error = query.get("error", [""])[0]
        ok = query.get("ok", [""])[0]
        msg_html = ""
        if error:
            msg_html += f"<p style='color:#b91c1c'>{html.escape(error)}</p>"
        if ok:
            msg_html += f"<p style='color:#166534'>{html.escape(ok)}</p>"
        conn = self._open_db()
        try:
            users = conn.execute(
                "SELECT id, username, role, must_reset_password, created_at FROM users ORDER BY created_at DESC"
            ).fetchall()
        finally:
            conn.close()
        rows = []
        for u in users:
            reset_form = (
                "<form method='post' action='/users/reset' style='display:inline'>"
                f"<input type='hidden' name='user_id' value='{u['id']}' />"
                "<input type='password' name='new_password' placeholder='New password' required style='min-width:180px;' />"
                "<button class='btn alt' type='submit'>Reset Credential</button>"
                "</form>"
            )
            delete_form = ""
            if u["username"] != user["username"]:
                delete_form = (
                    "<form method='post' action='/users/delete' style='display:inline;margin-left:6px;' "
                    "onsubmit=\"return confirm('Delete this user?');\">"
                    f"<input type='hidden' name='user_id' value='{u['id']}' />"
                    "<button class='btn danger' type='submit'>Delete</button>"
                    "</form>"
                )
            rows.append(
                "<tr>"
                f"<td>{html.escape(u['username'])}</td>"
                f"<td>{html.escape(u['role'])}</td>"
                f"<td>{'yes' if int(u['must_reset_password'] or 0) == 1 else 'no'}</td>"
                f"<td>{html.escape(u['created_at'])}</td>"
                f"<td>{reset_form}{delete_form}</td>"
                "</tr>"
            )
        body = (
            "<div class='card'><h3>User Management</h3>"
            f"{msg_html}"
            "<p class='muted'>User management and delete actions are admin-only.</p>"
            "<form method='post' action='/users/add'>"
            "<label>Username</label><input name='username' required />"
            "<label>Password</label><input type='password' name='password' required />"
            "<label>Role</label><select name='role'><option value='viewer'>viewer</option><option value='admin'>admin</option></select>"
            "<br/><br/><button class='btn' type='submit'>Add User</button>"
            "</form></div>"
            "<div class='card'><table><thead><tr><th>Username</th><th>Role</th><th>Must Reset Password</th><th>Created At</th><th>Actions</th></tr></thead>"
            f"<tbody>{''.join(rows) or '<tr><td colspan=5>No users</td></tr>'}</tbody></table></div>"
        )
        self._send_html(page_template("Users", body, user=user))

    def handle_add_user(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        form = self._read_post_form()
        username = form.get("username", [""])[0].strip()
        password = form.get("password", [""])[0]
        role = form.get("role", ["viewer"])[0]
        if not username or not password:
            return self._redirect("/users?error=Username+and+password+are+required")
        ok, message = validate_password_complexity(password)
        if not ok:
            return self._redirect(f"/users?error={urlencode({'m': message})[2:]}")
        conn = self._open_db()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO users(username, password_hash, role, must_reset_password, created_at) VALUES(?, ?, ?, ?, ?)",
                (username, hash_password(password), role if role in {"admin", "viewer"} else "viewer", 0, datetime.now().isoformat(timespec="seconds")),
            )
            conn.commit()
            if conn.total_changes == 0:
                return self._redirect("/users?error=Username+already+exists")
        finally:
            conn.close()
        self._redirect("/users?ok=User+added+successfully")

    def handle_reset_user_password(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        form = self._read_post_form()
        user_id = form.get("user_id", [""])[0]
        new_password = form.get("new_password", [""])[0]
        if not user_id or not new_password:
            return self._redirect("/users?error=User+and+new+password+are+required")
        ok, message = validate_password_complexity(new_password)
        if not ok:
            return self._redirect(f"/users?error={urlencode({'m': message})[2:]}")
        conn = self._open_db()
        try:
            target = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
            if not target:
                return self._redirect("/users?error=User+not+found")
            conn.execute(
                "UPDATE users SET password_hash = ?, must_reset_password = 0 WHERE id = ?",
                (hash_password(new_password), user_id),
            )
            conn.commit()
        finally:
            conn.close()
        self._redirect("/users?ok=Credential+reset+successfully")

    def handle_delete_user(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        form = self._read_post_form()
        user_id = form.get("user_id", [""])[0]
        if not user_id:
            return self._redirect("/users?error=Missing+user")
        conn = self._open_db()
        try:
            target = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
            if not target:
                return self._redirect("/users?error=User+not+found")
            if target["username"] == user["username"]:
                return self._redirect("/users?error=You+cannot+delete+the+logged-in+admin")
            if target["role"] == "admin":
                admin_count = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]
                if int(admin_count or 0) <= 1:
                    return self._redirect("/users?error=At+least+one+admin+must+remain")
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()
        self._redirect("/users?ok=User+deleted+successfully")

    def render_scan_new(self, user):
        active_db = html.escape(self._get_db_path())
        body = (
            "<div class='card'><h3>Run New Scan</h3>"
            f"<p class='muted'>Active DB: {active_db}</p>"
            "<form method='post' action='/scan/run'>"
            "<label>Project Path</label><input name='project_path' value='.' required />"
            "<label>DB Path</label><input name='db_path' value='ai_sbom.db' required />"
            "<label><input type='checkbox' name='new_db' /> Create New DB and auto-link UI</label>"
            "<label><input type='checkbox' name='html' checked /> Generate HTML</label>"
            "<label><input type='checkbox' name='excel' checked /> Generate Excel</label>"
            "<label><input type='checkbox' name='ollama' /> Use Ollama</label>"
            "<label><input type='checkbox' name='openai' /> Use OpenAI</label>"
            "<label><input type='checkbox' name='gemini' /> Use Gemini</label>"
            "<br/><br/><button class='btn' type='submit'>Start Scan</button>"
            "</form></div>"
        )
        self._send_html(page_template("Run Scan", body, user=user))

    def handle_run_scan(self, user):
        form = self._read_post_form()
        project_path = form.get("project_path", ["."])[0]
        db_path = form.get("db_path", [self.db_path])[0]
        if "new_db" in form:
            db_path = f"ai_sbom_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.db"
        if db_path:
            self._set_active_db_path(db_path)
        script_path = Path(__file__).resolve().with_name("ai-sbom.py")
        cmd = ["python3", str(script_path), project_path, "--db"]
        if "html" in form:
            cmd.append("--html")
        if "excel" in form:
            cmd.append("--excel")
        if "ollama" in form:
            cmd.append("--ollama")
        if "openai" in form:
            cmd.append("--openai")
        if "gemini" in form:
            cmd.append("--gemini")
        try:
            result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=180)
        except Exception:
            return self._send_html(page_template("Scan Error", "<div class='card'>Failed to run scan.</div>", user=user), 500)
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        match = None
        import re
        match = re.search(r"scan_id=(\d+)", output)
        if match:
            return self._redirect(f"/scan?id={match.group(1)}")
        return self._send_html(page_template("Scan Output", f"<div class='card'><pre>{html.escape(output)}</pre></div>", user=user))

    def handle_clear_db(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        conn = self._open_db()
        try:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM projects")
            conn.execute("DELETE FROM users")
            conn.execute("DELETE FROM sqlite_sequence")
            conn.execute(
                "INSERT INTO users(username, password_hash, role, must_reset_password, created_at) VALUES(?, ?, ?, ?, ?)",
                ("admin", hash_password("admin"), "admin", 1, datetime.now().isoformat(timespec="seconds")),
            )
            conn.commit()
        finally:
            conn.close()

        # Force logout all sessions after DB reset.
        SESSIONS.clear()
        self._redirect("/login", set_cookie=f"{SESSION_COOKIE}=; Path=/; Max-Age=0")

    def handle_delete_project(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        form = self._read_post_form()
        project_id = form.get("project_id", [""])[0]
        if not project_id:
            return self._redirect("/")
        conn = self._open_db()
        try:
            scan_ids = [row["id"] for row in conn.execute("SELECT id FROM scans WHERE project_id = ?", (project_id,)).fetchall()]
            if scan_ids:
                placeholders = ",".join("?" for _ in scan_ids)
                conn.execute(f"DELETE FROM findings WHERE scan_id IN ({placeholders})", scan_ids)
                conn.execute(f"DELETE FROM scans WHERE id IN ({placeholders})", scan_ids)
            conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            conn.commit()
        finally:
            conn.close()
        self._redirect("/")

    def handle_delete_scan(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        form = self._read_post_form()
        scan_id = form.get("scan_id", [""])[0]
        if not scan_id:
            return self._redirect("/")
        conn = self._open_db()
        try:
            project_row = conn.execute("SELECT project_id FROM scans WHERE id = ?", (scan_id,)).fetchone()
            project_id = project_row["project_id"] if project_row else None
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
        finally:
            conn.close()
        if project_id:
            self._redirect(f"/project?id={project_id}")
        else:
            self._redirect("/")

    def handle_delete_component(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        form = self._read_post_form()
        category = form.get("category", [""])[0]
        entity = form.get("entity", [""])[0]
        if not category or not entity:
            return self._redirect("/components")
        conn = self._open_db()
        try:
            touched_scan_rows = conn.execute(
                "SELECT DISTINCT scan_id FROM findings WHERE category = ? AND entity = ?",
                (category, entity),
            ).fetchall()
            touched_scan_ids = [row["scan_id"] for row in touched_scan_rows]
            conn.execute("DELETE FROM findings WHERE category = ? AND entity = ?", (category, entity))
            if touched_scan_ids:
                recalc_scan_totals(conn, touched_scan_ids)
            conn.commit()
        finally:
            conn.close()
        self._redirect(f"/components?category={category}")

    def export_excel(self, query):
        export_type = query.get("type", [""])[0]
        conn = self._open_db()
        try:
            if export_type == "scan":
                scan_id = query.get("id", [""])[0]
                rows = conn.execute(
                    """
                    SELECT f.category, f.entity, f.instances, f.source_files_json, f.meta_json,
                           s.scan_uid, s.scanned_at, p.name AS project_name, p.path AS project_path
                    FROM findings f
                    JOIN scans s ON s.id = f.scan_id
                    JOIN projects p ON p.id = s.project_id
                    WHERE f.scan_id = ?
                    ORDER BY f.category, f.entity
                    """,
                    (scan_id,),
                ).fetchall()
                export_rows = []
                for row in rows:
                    source_files = json.loads(row["source_files_json"]) if row["source_files_json"] else []
                    meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
                    versions = meta.get("versions", [])
                    detection_methods = meta.get("detection_methods", [])
                    export_rows.append(
                        {
                            "category": row["category"],
                            "entity": row["entity"],
                            "instances": row["instances"],
                            "versions": " | ".join(str(v) for v in versions),
                            "detection_methods": " | ".join(str(v) for v in detection_methods),
                            "source_files": " | ".join(source_files),
                            "project_name": row["project_name"],
                            "project_path": row["project_path"],
                            "scan_uid": row["scan_uid"] or "",
                            "scanned_at": row["scanned_at"],
                        }
                    )
                payload = build_excel_xml(export_rows, f"scan_{scan_id}")
                return self._send_binary(payload, "application/vnd.ms-excel", f"scan_{scan_id}.xls")
            if export_type == "components":
                category = query.get("category", [""])[0]
                if category:
                    rows = conn.execute(
                        """
                        SELECT f.category, f.entity, SUM(f.instances) AS total_instances,
                               COUNT(DISTINCT s.project_id) AS projects_count, COUNT(DISTINCT f.scan_id) AS scans_count
                        FROM findings f JOIN scans s ON s.id = f.scan_id
                        WHERE f.category = ?
                        GROUP BY f.category, f.entity
                        ORDER BY total_instances DESC, f.entity
                        """,
                        (category,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT f.category, f.entity, SUM(f.instances) AS total_instances,
                               COUNT(DISTINCT s.project_id) AS projects_count, COUNT(DISTINCT f.scan_id) AS scans_count
                        FROM findings f JOIN scans s ON s.id = f.scan_id
                        GROUP BY f.category, f.entity
                        ORDER BY total_instances DESC, f.entity
                        """
                    ).fetchall()
                payload = build_excel_xml([dict(r) for r in rows], "all_components")
                return self._send_binary(payload, "application/vnd.ms-excel", "all_components.xls")
        finally:
            conn.close()
        self._send_html(page_template("Invalid export", "<div class='card'>Invalid export request.</div>", user=self._current_user()), 400)


def main():
    parser = argparse.ArgumentParser(description="Run local UI for AI SBOM SQLite database.")
    parser.add_argument("--db-path", default="ai_sbom.db", help="Path to sqlite DB")
    parser.add_argument("--db-link-file", default="ai_sbom_active_db.txt", help="Path to active DB link file")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=9007, help="Port to bind (default: 9007)")
    args = parser.parse_args()
    init_db(args.db_path)
    Handler.db_path = args.db_path
    Handler.db_link_file = args.db_link_file
    server = HTTPServer((args.host, args.port), Handler)
    print(f"AI SBOM UI running at http://{args.host}:{args.port}")
    print(f"Using database: {args.db_path}")
    server.serve_forever()


if __name__ == "__main__":
    main()
