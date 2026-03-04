import argparse
import hashlib
import html
import json
import secrets
import sqlite3
import subprocess
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

SESSIONS = {}
SESSION_COOKIE = "ai_sbom_session"
CATEGORY_OPTIONS = ["ai_sdks", "llm_models", "local_models", "vector_dbs", "ai_endpoints", "risks"]


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


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
                created_at TEXT NOT NULL
            )
            """
        )
        scan_table_exists = cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()
        if scan_table_exists:
            cols = {row[1] for row in cur.execute("PRAGMA table_info(scans)").fetchall()}
            if "scan_uid" not in cols:
                cur.execute("ALTER TABLE scans ADD COLUMN scan_uid TEXT")
        cur.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, role, created_at) VALUES(?, ?, ?, ?)",
            ("admin", hash_password("admin"), "admin", datetime.now().isoformat(timespec="seconds")),
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


def page_template(title, body, user=None):
    user_html = ""
    if user:
        user_html = (
            "<div class='card nav'>"
            "<a href='/'>Projects</a>"
            "<a href='/components'>All Components</a>"
            "<a href='/scan/new'>Run Scan</a>"
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
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Inter, Segoe UI, Arial, sans-serif; margin: 0; background: #f5f7fb; color: #0f172a; }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
    .hero {{ background: linear-gradient(135deg, #1e3a8a, #2563eb); color: white; border-radius: 12px; padding: 16px 20px; }}
    .hero h1 {{ margin: 0; font-size: 22px; }}
    .hero p {{ margin: 6px 0 0; color: #dbeafe; }}
    .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 12px; margin-top: 14px; padding: 14px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #eef2f7; vertical-align: top; }}
    th {{ background: #f8fafc; color: #334155; }}
    a {{ color: #2563eb; text-decoration: none; }}
    .pill {{ display: inline-block; background: #eff6ff; color: #1d4ed8; border: 1px solid #dbeafe; border-radius: 999px; padding: 2px 8px; font-size: 12px; margin: 2px 4px 2px 0; }}
    .muted {{ color: #64748b; }}
    .nav a {{ margin-right: 12px; }}
    .btn {{ display: inline-block; background: #1d4ed8; color: #fff; border-radius: 8px; padding: 6px 10px; font-size: 13px; margin-right: 8px; border: none; cursor: pointer; }}
    .btn.alt {{ background: #334155; }}
    .btn.danger {{ background: #b91c1c; }}
    .chart-card {{ background: white; border: 1px solid #e2e8f0; border-radius: 12px; margin-top: 14px; padding: 14px; }}
    .chart-wrap {{ display: flex; gap: 14px; align-items: center; flex-wrap: wrap; }}
    .pie {{ width: 180px; height: 180px; border-radius: 50%; position: relative; box-shadow: inset 0 0 0 1px rgba(15,23,42,.08); }}
    .pie::after {{ content: ""; position: absolute; inset: 38px; border-radius: 50%; background: white; box-shadow: inset 0 0 0 1px #e2e8f0; }}
    .pie-center {{ position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-weight: 700; color: #334155; z-index: 1; }}
    .legend {{ display: grid; gap: 6px; min-width: 260px; }}
    .legend-row {{ display: grid; grid-template-columns: 12px 1fr auto; gap: 8px; align-items: center; border: 1px solid #e2e8f0; background: #f8fafc; border-radius: 8px; padding: 4px 8px; font-size: 12px; }}
    .swatch {{ width: 10px; height: 10px; border-radius: 2px; }}
    .legend-value {{ font-weight: 700; color: #0f172a; }}
    input, select {{ padding: 8px; border: 1px solid #cbd5e1; border-radius: 8px; min-width: 260px; }}
    label {{ font-size: 13px; color: #334155; display:block; margin-top:10px; }}
    .toolbar {{ display:flex; gap:10px; flex-wrap:wrap; align-items:end; margin-top: 8px; }}
    .toolbar .field {{ display:flex; flex-direction:column; gap:4px; }}
    .toolbar input, .toolbar select {{ min-width: 220px; }}
    .toolbar-actions {{ display:flex; gap:8px; }}
    .chips {{ margin-top: 10px; display:flex; gap:6px; flex-wrap:wrap; }}
    .chip {{ display:inline-block; background:#f1f5f9; color:#0f172a; border:1px solid #cbd5e1; border-radius:999px; padding:4px 10px; font-size:12px; }}
    .chip.active {{ background:#dbeafe; color:#1e40af; border-color:#93c5fd; }}
    .stats {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }}
    .stat {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:6px 10px; font-size:12px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>AI SBOM Local Database</h1>
      <p>Browse projects, scans, and findings</p>
    </div>
    {user_html}
    {body}
  </div>
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

    if not rows:
        rows = [{"message": "No data"}]
    columns = sorted({key for row in rows for key in row.keys()})
    parts = [
        "<?xml version=\"1.0\"?>",
        "<?mso-application progid=\"Excel.Sheet\"?>",
        "<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\" xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\">",
        f"<Worksheet ss:Name=\"{esc(title[:31])}\"><Table>",
    ]
    header = "".join(f"<Cell><Data ss:Type=\"String\">{esc(col)}</Data></Cell>" for col in columns)
    parts.append(f"<Row>{header}</Row>")
    for row in rows:
        values = "".join(f"<Cell><Data ss:Type=\"String\">{esc(row.get(col, ''))}</Data></Cell>" for col in columns)
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
    chips = [f"<a class='chip{' active' if not category else ''}' href='{base_path}?{urlencode(all_params)}'>all</a>"]
    for option in CATEGORY_OPTIONS:
        chip_params = dict(base_params)
        chip_params["category"] = option
        chip_params["q"] = q
        chips.append(f"<a class='chip{' active' if category == option else ''}' href='{base_path}?{urlencode(chip_params)}'>{option}</a>")
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

    def _send_html(self, text, status=200):
        encoded = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_binary(self, payload, content_type, filename, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
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
        self.send_header("Location", location)
        self.end_headers()

    def _read_post_form(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        return parse_qs(raw)

    def _current_user(self):
        cookie_header = self.headers.get("Cookie", "")
        token = None
        for chunk in cookie_header.split(";"):
            chunk = chunk.strip()
            if chunk.startswith(f"{SESSION_COOKIE}="):
                token = chunk.split("=", 1)[1]
                break
        if not token:
            return None
        return SESSIONS.get(token)

    def _require_auth(self, admin=False):
        user = self._current_user()
        if not user:
            self._redirect("/login")
            return None
        if admin and user.get("role") != "admin":
            self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/login":
            return self.render_login()
        if path == "/logout":
            return self.logout()

        user = self._require_auth()
        if not user:
            return

        if path == "/":
            return self.render_projects(user)
        if path == "/project":
            return self.render_project_scans(user, query)
        if path == "/scan":
            return self.render_scan_findings(user, query)
        if path == "/components":
            return self.render_all_components(user, query)
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

        user = self._require_auth()
        if not user:
            return
        if path == "/users/add":
            return self.handle_add_user(user)
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

    def render_login(self, error=""):
        err = f"<p style='color:#b91c1c'>{html.escape(error)}</p>" if error else ""
        body = (
            "<div class='card'><h3>Login</h3>"
            f"{err}"
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
                "SELECT username, role, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            conn.close()
        if not user or user["password_hash"] != hash_password(password):
            return self.render_login("Invalid username or password.")
        token = secrets.token_urlsafe(24)
        SESSIONS[token] = {"username": user["username"], "role": user["role"]}
        self._redirect("/", set_cookie=f"{SESSION_COOKIE}={token}; Path=/; HttpOnly")

    def logout(self):
        user = self._current_user()
        if user:
            for token, session_user in list(SESSIONS.items()):
                if session_user == user:
                    del SESSIONS[token]
        self._redirect("/login", set_cookie=f"{SESSION_COOKIE}=; Path=/; Max-Age=0")

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
                f"<td>{scan['total_instances']}</td>"
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
            versions_html = "".join(f"<span class='pill'>{html.escape(str(v))}</span>" for v in versions) or "<span class='muted'>-</span>"
            files_html = "".join(f"<span class='pill'>{html.escape(str(path))}</span>" for path in source_files[:6])
            if len(source_files) > 6:
                files_html += f"<span class='pill'>+{len(source_files)-6} more</span>"
            rows.append(
                "<tr>"
                f"<td>{html.escape(f['category'])}</td>"
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
        finally:
            conn.close()
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
                f"<td>{html.escape(r['category'])}</td>"
                f"<td>{html.escape(r['entity'])}</td>"
                f"<td>{r['total_instances']}</td>"
                f"<td>{r['projects_count']}</td>"
                f"<td>{r['scans_count']}</td>"
                f"<td>{delete_btn}</td>"
                "</tr>"
            )
        body = (
            filters
            + f"<div class='card'><div class='stats'>{''.join(stats)}</div></div>"
            + build_pie_chart_html("Component-wise Findings (total instances)", chart_items)
            + "<div class='card'><h3>All Components</h3>"
            + "<table><thead><tr><th>Category</th><th>Entity</th><th>Total Instances</th><th>Projects</th><th>Scans</th><th>Actions</th></tr></thead>"
            + f"<tbody>{''.join(rows_html) or '<tr><td colspan=6>No components found.</td></tr>'}</tbody></table></div>"
        )
        self._send_html(page_template("All Components", body, user=user))

    def render_users(self, user):
        if user.get("role") != "admin":
            return self._send_html(page_template("Forbidden", "<div class='card'>Admin access required.</div>", user=user), 403)
        conn = self._open_db()
        try:
            users = conn.execute("SELECT username, role, created_at FROM users ORDER BY created_at DESC").fetchall()
        finally:
            conn.close()
        rows = "".join(
            f"<tr><td>{html.escape(u['username'])}</td><td>{html.escape(u['role'])}</td><td>{html.escape(u['created_at'])}</td></tr>"
            for u in users
        )
        body = (
            "<div class='card'><h3>User Management</h3>"
            "<form method='post' action='/users/add'>"
            "<label>Username</label><input name='username' required />"
            "<label>Password</label><input type='password' name='password' required />"
            "<label>Role</label><select name='role'><option value='viewer'>viewer</option><option value='admin'>admin</option></select>"
            "<br/><br/><button class='btn' type='submit'>Add User</button>"
            "</form></div>"
            "<div class='card'><table><thead><tr><th>Username</th><th>Role</th><th>Created At</th></tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=3>No users</td></tr>'}</tbody></table></div>"
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
            return self._redirect("/users")
        conn = self._open_db()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO users(username, password_hash, role, created_at) VALUES(?, ?, ?, ?)",
                (username, hash_password(password), role if role in {"admin", "viewer"} else "viewer", datetime.now().isoformat(timespec="seconds")),
            )
            conn.commit()
        finally:
            conn.close()
        self._redirect("/users")

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
                "INSERT INTO users(username, password_hash, role, created_at) VALUES(?, ?, ?, ?)",
                ("admin", hash_password("admin"), "admin", datetime.now().isoformat(timespec="seconds")),
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
                    export_rows.append(
                        {
                            "scan_uid": row["scan_uid"] or "",
                            "project_name": row["project_name"],
                            "project_path": row["project_path"],
                            "scanned_at": row["scanned_at"],
                            "category": row["category"],
                            "entity": row["entity"],
                            "instances": row["instances"],
                            "versions": "; ".join(str(v) for v in versions),
                            "source_files": "; ".join(source_files),
                            "meta": json.dumps(meta),
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
