import csv
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, abort, flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_NAME = "ForensicBuddy"
BASE_DIR = Path(__file__).resolve().parent
INSTANCE_PATH = Path(os.getenv("INSTANCE_PATH", BASE_DIR / "instance"))
EVIDENCE_PATH = Path(os.getenv("EVIDENCE_PATH", INSTANCE_PATH / "evidence"))
DB_PATH = INSTANCE_PATH / "forensicbuddy.db"
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "512"))

INSTANCE_PATH.mkdir(parents=True, exist_ok=True)
EVIDENCE_PATH.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

FERNET_KEY = os.getenv("EVIDENCE_FERNET_KEY", "").strip()
cipher = Fernet(FERNET_KEY.encode()) if FERNET_KEY else None

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','investigator','reviewer')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    classification TEXT NOT NULL DEFAULT 'Sensitive',
    status TEXT NOT NULL DEFAULT 'Open',
    lead_investigator TEXT,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    evidence_number TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    media_type TEXT,
    source_tool TEXT,
    source_system TEXT,
    collector TEXT,
    collection_time TEXT,
    notes TEXT,
    sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 0,
    parser TEXT,
    parsed_records INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(case_id, evidence_number),
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail TEXT,
    event_time TEXT NOT NULL,
    FOREIGN KEY(evidence_id) REFERENCES evidence(id)
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    evidence_id INTEGER,
    event_time TEXT,
    event_type TEXT,
    source TEXT,
    summary TEXT NOT NULL,
    raw_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(evidence_id) REFERENCES evidence(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'Informational',
    confidence TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'Open',
    description TEXT NOT NULL,
    impact TEXT,
    recommendation TEXT,
    evidence_refs TEXT,
    created_by INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    object_type TEXT,
    object_id TEXT,
    detail TEXT,
    previous_hash TEXT,
    record_hash TEXT NOT NULL
);
"""

CSS = """
:root { color-scheme: light; --bg:#f3f5f7; --panel:#fff; --ink:#17202a; --muted:#667085; --line:#d7dde5; --dark:#111827; }
* { box-sizing:border-box; }
body { margin:0; font-family:Arial,Helvetica,sans-serif; background:var(--bg); color:var(--ink); }
header { background:var(--dark); color:#fff; padding:14px 24px; display:flex; justify-content:space-between; align-items:center; }
header a { color:#fff; text-decoration:none; margin-left:16px; }
main { max-width:1280px; margin:24px auto; padding:0 20px 40px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; margin-bottom:18px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; }
label { display:block; font-size:13px; font-weight:700; margin-bottom:5px; }
input, textarea, select { width:100%; padding:9px 10px; border:1px solid #b8c0cc; border-radius:5px; background:#fff; }
textarea { min-height:110px; resize:vertical; }
button,.btn { display:inline-block; background:#1f2937; color:#fff; border:none; border-radius:5px; padding:9px 13px; text-decoration:none; cursor:pointer; }
.btn.secondary { background:#475467; }
.btn.danger { background:#7f1d1d; }
table { width:100%; border-collapse:collapse; background:#fff; }
th,td { border-bottom:1px solid var(--line); padding:10px; text-align:left; vertical-align:top; }
th { background:#eef1f5; }
.small { font-size:12px; color:var(--muted); }
.flash { padding:10px 12px; background:#fff4cc; border:1px solid #e4c75f; margin-bottom:12px; border-radius:5px; }
.badge { display:inline-block; padding:2px 7px; border-radius:12px; background:#e7ecf2; font-size:12px; }
pre { white-space:pre-wrap; word-break:break-word; }
h1,h2,h3 { margin-top:0; }
.actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
"""

BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{ title }} - ForensicBuddy</title>
  <style>{{ css }}</style>
</head>
<body>
<header>
  <div><strong>ForensicBuddy</strong></div>
  {% if session.get('user_id') %}
  <nav>
    <a href="{{ url_for('dashboard') }}">Cases</a>
    <a href="{{ url_for('audit') }}">Audit</a>
    {% if session.get('role') == 'admin' %}<a href="{{ url_for('users') }}">Users</a>{% endif %}
    <a href="{{ url_for('logout') }}">Sign out</a>
  </nav>
  {% endif %}
</header>
<main>
  {% for message in get_flashed_messages() %}<div class="flash">{{ message }}</div>{% endfor %}
  {{ body|safe }}
</main>
</body>
</html>
"""

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)
        count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if count == 0:
            password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMeImmediately!")
            conn.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                ("admin", generate_password_hash(password), "admin", now()),
            )

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token

app.jinja_env.globals["csrf_token"] = csrf_token

def validate_csrf():
    if request.method == "POST":
        supplied = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(supplied, expected):
            abort(400, "Invalid CSRF token")

@app.before_request
def security_gate():
    if request.method == "POST":
        validate_csrf()

@app.after_request
def secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response

def page(title, body_template, **ctx):
    body = render_template_string(body_template, **ctx)
    return render_template_string(BASE_TEMPLATE, title=title, body=body, css=CSS)

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

def audit_event(action, object_type=None, object_id=None, detail=None):
    with db() as conn:
        prev = conn.execute("SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = prev["record_hash"] if prev else ""
        payload = {
            "event_time": now(),
            "user_id": session.get("user_id"),
            "username": session.get("username"),
            "action": action,
            "object_type": object_type,
            "object_id": str(object_id) if object_id is not None else None,
            "detail": detail or "",
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        record_hash = hashlib.sha256(canonical.encode()).hexdigest()
        conn.execute(
            """INSERT INTO audit_log(event_time,user_id,username,action,object_type,object_id,detail,previous_hash,record_hash)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                payload["event_time"], payload["user_id"], payload["username"], action,
                object_type, payload["object_id"], payload["detail"], previous_hash, record_hash
            ),
        )

def get_case(case_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        abort(404)
    return row

def normalize_time(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        # Zeek epoch timestamps
        if re.fullmatch(r"\d{10}(\.\d+)?", text):
            return datetime.fromtimestamp(float(text), tz=timezone.utc).isoformat()
        # ISO-like timestamps
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(value)

def best_timestamp(record):
    candidates = [
        "ts", "timestamp", "time", "datetime", "date_time", "event_time", "@timestamp",
        "TimeGenerated", "Timestamp", "CreationTime", "LastModified", "StartTime",
    ]
    for key in candidates:
        if key in record and record[key] not in (None, ""):
            return normalize_time(record[key])
    return None

def summary_for(record):
    preferred = [
        "summary", "message", "Message", "query", "url", "uri", "host", "hostname",
        "process_name", "ProcessName", "event_type", "EventType", "action", "ActionType",
        "name", "Name",
    ]
    parts = []
    for key in preferred:
        if key in record and record[key] not in (None, ""):
            parts.append(f"{key}={record[key]}")
        if len(parts) >= 3:
            break
    if not parts:
        for key, value in list(record.items())[:4]:
            if value not in (None, ""):
                parts.append(f"{key}={value}")
    return " | ".join(parts)[:1000] or "Parsed event"

def parse_json_lines(text):
    records = []
    parser = "JSON"
    stripped = text.strip()
    try:
        obj = json.loads(stripped)
        if isinstance(obj, list):
            records = [x for x in obj if isinstance(x, dict)]
        elif isinstance(obj, dict):
            records = [obj]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError:
                continue
        parser = "JSONL/NDJSON"
    return parser, records

def parse_csv_text(text):
    stream = io.StringIO(text)
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(stream, dialect=dialect)
    return [dict(r) for r in reader]

def parse_zeek_tsv(text):
    lines = text.splitlines()
    fields = None
    rows = []
    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#") or not line.strip():
            continue
        elif fields:
            vals = line.split("\t")
            rows.append({fields[i]: vals[i] if i < len(vals) else "" for i in range(len(fields))})
    return rows

def parse_squid(text):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        rows.append({
            "timestamp": parts[0],
            "elapsed_ms": parts[1] if len(parts) > 1 else "",
            "client_ip": parts[2] if len(parts) > 2 else "",
            "result_code": parts[3] if len(parts) > 3 else "",
            "bytes": parts[4] if len(parts) > 4 else "",
            "method": parts[5] if len(parts) > 5 else "",
            "url": parts[6] if len(parts) > 6 else "",
            "user": parts[7] if len(parts) > 7 else "",
            "hierarchy": parts[8] if len(parts) > 8 else "",
            "content_type": parts[9] if len(parts) > 9 else "",
        })
    return rows

def parse_nmap_xml(data):
    rows = []
    root = ET.fromstring(data)
    for host in root.findall("host"):
        addrs = [a.attrib.get("addr") for a in host.findall("address") if a.attrib.get("addr")]
        state_node = host.find("status")
        host_state = state_node.attrib.get("state") if state_node is not None else ""
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            rows.append({
                "host": ",".join(addrs),
                "host_state": host_state,
                "protocol": port.attrib.get("protocol"),
                "port": port.attrib.get("portid"),
                "port_state": state.attrib.get("state") if state is not None else "",
                "service": service.attrib.get("name") if service is not None else "",
                "product": service.attrib.get("product") if service is not None else "",
                "version": service.attrib.get("version") if service is not None else "",
            })
    return rows

def parse_evidence(filename, data):
    lower = filename.lower()
    text = None
    if lower.endswith(".xml"):
        try:
            return "Nmap XML", parse_nmap_xml(data)
        except Exception:
            return None, []
    try:
        text = data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16", errors="strict")
        except UnicodeDecodeError:
            return None, []
    if text.startswith("#separator") or "#fields\t" in text:
        rows = parse_zeek_tsv(text)
        return ("Zeek TSV", rows) if rows else (None, [])
    if lower.endswith((".json", ".jsonl", ".ndjson")) or text.lstrip().startswith(("{", "[")):
        parser, rows = parse_json_lines(text)
        if rows:
            if any("uid" in r and "ts" in r for r in rows[:20]):
                parser = "Zeek JSON"
            return parser, rows
    if "squid" in lower or "access.log" in lower:
        rows = parse_squid(text)
        if rows:
            return "Squid access.log", rows
    if lower.endswith((".csv", ".tsv")):
        rows = parse_csv_text(text)
        return ("CSV/TSV", rows) if rows else (None, [])
    # Generic text parser: preserve lines as searchable timeline records.
    rows = [{"line": line} for line in text.splitlines() if line.strip()]
    return ("Generic text", rows[:100000]) if rows else (None, [])

def store_evidence(data):
    stored = f"{uuid.uuid4().hex}.bin"
    path = EVIDENCE_PATH / stored
    payload = cipher.encrypt(data) if cipher else data
    path.write_bytes(payload)
    return stored, 1 if cipher else 0

def read_evidence(stored_filename, encrypted):
    payload = (EVIDENCE_PATH / stored_filename).read_bytes()
    if encrypted:
        if not cipher:
            raise RuntimeError("Evidence encryption key is not configured")
        return cipher.decrypt(payload)
    return payload

def import_events(case_id, evidence_id, parser, records):
    inserted = 0
    with db() as conn:
        for record in records[:100000]:
            if not isinstance(record, dict):
                record = {"value": str(record)}
            summary = summary_for(record)
            event_type = record.get("event_type") or record.get("EventType") or record.get("_path") or parser
            source = record.get("source") or record.get("host") or record.get("hostname") or record.get("Computer") or ""
            conn.execute(
                """INSERT INTO timeline_events(case_id,evidence_id,event_time,event_type,source,summary,raw_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (case_id, evidence_id, best_timestamp(record), str(event_type)[:200], str(source)[:300],
                 summary, json.dumps(record, ensure_ascii=False)[:20000], now()),
            )
            inserted += 1
    return inserted

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            audit_event("LOGIN_FAILED", "user", username, "Invalid credentials")
            flash("Invalid credentials.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["_csrf"] = secrets.token_urlsafe(32)
            audit_event("LOGIN_SUCCESS", "user", user["id"])
            return redirect(request.args.get("next") or url_for("dashboard"))
    return page("Sign in", """
    <div class="card" style="max-width:420px;margin:50px auto">
      <h1>Sign in</h1>
      <form method="post">
        <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
        <label>Username</label><input name="username" autocomplete="username" required>
        <label style="margin-top:12px">Password</label><input type="password" name="password" autocomplete="current-password" required>
        <div style="margin-top:14px"><button>Sign in</button></div>
      </form>
    </div>
    """)

@app.route("/logout")
@login_required
def logout():
    audit_event("LOGOUT", "user", session.get("user_id"))
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    with db() as conn:
        cases = conn.execute(
            """SELECT c.*, u.username creator,
               (SELECT COUNT(*) FROM evidence e WHERE e.case_id=c.id) evidence_count,
               (SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) finding_count
               FROM cases c JOIN users u ON u.id=c.created_by ORDER BY c.updated_at DESC"""
        ).fetchall()
    return page("Cases", """
    <div class="actions" style="justify-content:space-between">
      <h1>Investigation Cases</h1>
      {% if session.get('role') in ['admin','investigator'] %}<a class="btn" href="{{ url_for('new_case') }}">New case</a>{% endif %}
    </div>
    <div class="card">
    <table><thead><tr><th>Case</th><th>Title</th><th>Status</th><th>Classification</th><th>Evidence</th><th>Findings</th><th>Updated</th></tr></thead>
    <tbody>
    {% for c in cases %}
      <tr>
        <td><a href="{{ url_for('case_detail', case_id=c.id) }}">{{ c.case_number }}</a></td>
        <td>{{ c.title }}</td><td>{{ c.status }}</td><td>{{ c.classification }}</td>
        <td>{{ c.evidence_count }}</td><td>{{ c.finding_count }}</td><td class="small">{{ c.updated_at }}</td>
      </tr>
    {% else %}<tr><td colspan="7">No cases yet.</td></tr>{% endfor %}
    </tbody></table></div>
    """, cases=cases)

@app.route("/cases/new", methods=["GET", "POST"])
@roles_required("admin", "investigator")
def new_case():
    if request.method == "POST":
        case_number = request.form["case_number"].strip()
        title = request.form["title"].strip()
        if not case_number or not title:
            flash("Case number and title are required.")
        else:
            try:
                with db() as conn:
                    cur = conn.execute(
                        """INSERT INTO cases(case_number,title,description,classification,status,lead_investigator,created_by,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (case_number, title, request.form.get("description",""), request.form.get("classification","Sensitive"),
                         "Open", request.form.get("lead_investigator",""), session["user_id"], now(), now()),
                    )
                    case_id = cur.lastrowid
                audit_event("CASE_CREATED", "case", case_id, case_number)
                return redirect(url_for("case_detail", case_id=case_id))
            except sqlite3.IntegrityError:
                flash("That case number already exists.")
    return page("New case", """
    <h1>New case</h1><div class="card">
    <form method="post">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <div class="grid">
        <div><label>Case number</label><input name="case_number" placeholder="IR-2026-001" required></div>
        <div><label>Title</label><input name="title" required></div>
        <div><label>Classification</label><select name="classification"><option>Sensitive</option><option>ePHI</option><option>Confidential</option><option>Public</option></select></div>
        <div><label>Lead investigator</label><input name="lead_investigator" value="{{ session.get('username') }}"></div>
      </div>
      <label style="margin-top:12px">Description / scope</label><textarea name="description"></textarea>
      <div style="margin-top:12px"><button>Create case</button></div>
    </form></div>
    """)

@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id):
    case = get_case(case_id)
    with db() as conn:
        evidence = conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        findings = conn.execute("SELECT * FROM findings WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
        timeline = conn.execute(
            "SELECT * FROM timeline_events WHERE case_id=? ORDER BY CASE WHEN event_time IS NULL THEN 1 ELSE 0 END,event_time,id LIMIT 250",
            (case_id,),
        ).fetchall()
    return page(case["case_number"], """
    <div class="actions" style="justify-content:space-between">
      <div><h1>{{ case.case_number }} - {{ case.title }}</h1><div class="small">{{ case.classification }} | {{ case.status }} | Lead: {{ case.lead_investigator or 'Unassigned' }}</div></div>
      <div class="actions"><a class="btn secondary" href="{{ url_for('report', case_id=case.id) }}">Report</a>{% if session.get('role') in ['admin','investigator'] %}<a class="btn" href="{{ url_for('upload_evidence', case_id=case.id) }}">Add evidence</a><a class="btn" href="{{ url_for('new_finding', case_id=case.id) }}">Add finding</a>{% endif %}</div>
    </div>
    <div class="card"><h3>Scope / description</h3><p>{{ case.description or 'No description entered.' }}</p></div>

    <h2>Evidence</h2><div class="card"><table><thead><tr><th>ID</th><th>File</th><th>Source</th><th>SHA-256</th><th>Parser</th><th>Records</th><th></th></tr></thead><tbody>
    {% for e in evidence %}<tr>
      <td>{{ e.evidence_number }}</td><td>{{ e.original_filename }}<div class="small">{{ e.byte_size }} bytes{% if e.encrypted %} | encrypted{% endif %}</div></td>
      <td>{{ e.source_tool or '' }}<div class="small">{{ e.source_system or '' }}</div></td><td class="small">{{ e.sha256 }}</td>
      <td>{{ e.parser or 'Preserved only' }}</td><td>{{ e.parsed_records }}</td>
      <td><a href="{{ url_for('evidence_detail', evidence_id=e.id) }}">Details</a></td>
    </tr>{% else %}<tr><td colspan="7">No evidence.</td></tr>{% endfor %}
    </tbody></table></div>

    <h2>Findings</h2><div class="card"><table><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Status</th></tr></thead><tbody>
    {% for f in findings %}<tr><td>{{ f.severity }}</td><td><strong>{{ f.title }}</strong><div class="small">{{ f.description[:220] }}</div></td><td>{{ f.confidence }}</td><td>{{ f.status }}</td></tr>
    {% else %}<tr><td colspan="4">No findings.</td></tr>{% endfor %}</tbody></table></div>

    <h2>Timeline (first 250)</h2><div class="card"><table><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Summary</th></tr></thead><tbody>
    {% for t in timeline %}<tr><td class="small">{{ t.event_time or 'Unknown' }}</td><td>{{ t.event_type }}</td><td>{{ t.source }}</td><td>{{ t.summary }}</td></tr>
    {% else %}<tr><td colspan="4">No parsed timeline events.</td></tr>{% endfor %}</tbody></table></div>
    """, case=case, evidence=evidence, findings=findings, timeline=timeline)

@app.route("/cases/<int:case_id>/evidence/new", methods=["GET", "POST"])
@roles_required("admin", "investigator")
def upload_evidence(case_id):
    case = get_case(case_id)
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Choose a file.")
        else:
            data = uploaded.read()
            sha256 = hashlib.sha256(data).hexdigest()
            evidence_number = request.form.get("evidence_number","").strip()
            if not evidence_number:
                with db() as conn:
                    n = conn.execute("SELECT COUNT(*) c FROM evidence WHERE case_id=?", (case_id,)).fetchone()["c"] + 1
                evidence_number = f"E-{n:04d}"
            stored, encrypted = store_evidence(data)
            parser, records = parse_evidence(uploaded.filename, data)
            try:
                with db() as conn:
                    cur = conn.execute(
                        """INSERT INTO evidence(case_id,evidence_number,original_filename,stored_filename,media_type,source_tool,source_system,collector,collection_time,notes,sha256,byte_size,encrypted,parser,created_by,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (case_id, evidence_number, uploaded.filename, stored, uploaded.mimetype,
                         request.form.get("source_tool",""), request.form.get("source_system",""),
                         request.form.get("collector","") or session.get("username"), request.form.get("collection_time",""),
                         request.form.get("notes",""), sha256, len(data), encrypted, parser, session["user_id"], now()),
                    )
                    evidence_id = cur.lastrowid
                    conn.execute(
                        "INSERT INTO custody_events(evidence_id,action,actor,detail,event_time) VALUES(?,?,?,?,?)",
                        (evidence_id, "ACQUIRED", session.get("username"), f"Uploaded and SHA-256 hashed: {sha256}", now()),
                    )
                parsed_records = import_events(case_id, evidence_id, parser, records) if parser and records else 0
                with db() as conn:
                    conn.execute("UPDATE evidence SET parsed_records=? WHERE id=?", (parsed_records, evidence_id))
                    conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (now(), case_id))
                audit_event("EVIDENCE_ADDED", "evidence", evidence_id, f"{evidence_number} {uploaded.filename} sha256={sha256}")
                flash(f"Evidence added. SHA-256: {sha256}. Parsed {parsed_records} record(s).")
                return redirect(url_for("evidence_detail", evidence_id=evidence_id))
            except sqlite3.IntegrityError:
                (EVIDENCE_PATH / stored).unlink(missing_ok=True)
                flash("Evidence number already exists in this case.")
    return page("Add evidence", """
    <h1>Add evidence to {{ case.case_number }}</h1><div class="card">
    <form method="post" enctype="multipart/form-data">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <div class="grid">
        <div><label>Evidence number</label><input name="evidence_number" placeholder="Auto-generated if blank"></div>
        <div><label>File</label><input type="file" name="file" required></div>
        <div><label>Source tool</label><input name="source_tool" placeholder="Zeek, KAPE, tshark, XSIAM..."></div>
        <div><label>Source system / device</label><input name="source_system"></div>
        <div><label>Collector</label><input name="collector" value="{{ session.get('username') }}"></div>
        <div><label>Collection time (UTC preferred)</label><input name="collection_time" placeholder="2026-10-01T18:00:00Z"></div>
      </div>
      <label style="margin-top:12px">Notes / acquisition method</label><textarea name="notes"></textarea>
      <div style="margin-top:12px"><button>Ingest evidence</button></div>
    </form></div>
    <div class="card small"><strong>Safety:</strong> uploaded files are treated as evidence, not executed. Structured text is parsed; unsupported/binary formats are preserved without execution.</div>
    """, case=case)

@app.route("/evidence/<int:evidence_id>")
@login_required
def evidence_detail(evidence_id):
    with db() as conn:
        e = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not e:
            abort(404)
        custody = conn.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id", (evidence_id,)).fetchall()
    return page(e["evidence_number"], """
    <div class="actions"><a class="btn secondary" href="{{ url_for('case_detail', case_id=e.case_id) }}">Back to case</a>
    {% if session.get('role') in ['admin','investigator'] %}<form method="post" action="{{ url_for('verify_evidence', evidence_id=e.id) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button>Verify hash</button></form>{% endif %}</div>
    <div class="card"><h1>{{ e.evidence_number }} - {{ e.original_filename }}</h1>
    <div class="grid">
      <div><strong>SHA-256</strong><div class="small">{{ e.sha256 }}</div></div>
      <div><strong>Bytes</strong><div>{{ e.byte_size }}</div></div>
      <div><strong>Parser</strong><div>{{ e.parser or 'Preserved only' }}</div></div>
      <div><strong>Parsed records</strong><div>{{ e.parsed_records }}</div></div>
      <div><strong>Source tool</strong><div>{{ e.source_tool or '' }}</div></div>
      <div><strong>Source system</strong><div>{{ e.source_system or '' }}</div></div>
    </div>
    <h3 style="margin-top:18px">Notes</h3><p>{{ e.notes or '' }}</p></div>
    <h2>Chain of custody</h2><div class="card"><table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Detail</th></tr></thead><tbody>
    {% for c in custody %}<tr><td class="small">{{ c.event_time }}</td><td>{{ c.action }}</td><td>{{ c.actor }}</td><td>{{ c.detail }}</td></tr>{% endfor %}
    </tbody></table></div>
    """, e=e, custody=custody)

@app.post("/evidence/<int:evidence_id>/verify")
@roles_required("admin", "investigator")
def verify_evidence(evidence_id):
    with db() as conn:
        e = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not e:
        abort(404)
    try:
        data = read_evidence(e["stored_filename"], e["encrypted"])
        actual = hashlib.sha256(data).hexdigest()
        ok = secrets.compare_digest(actual, e["sha256"])
        detail = f"Expected {e['sha256']}; actual {actual}; result={'MATCH' if ok else 'MISMATCH'}"
        with db() as conn:
            conn.execute(
                "INSERT INTO custody_events(evidence_id,action,actor,detail,event_time) VALUES(?,?,?,?,?)",
                (evidence_id, "INTEGRITY_VERIFY", session.get("username"), detail, now()),
            )
        audit_event("EVIDENCE_VERIFIED", "evidence", evidence_id, detail)
        flash("Integrity verification passed." if ok else "WARNING: integrity verification FAILED.")
    except (RuntimeError, InvalidToken, OSError) as exc:
        flash(f"Verification failed: {exc}")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))

@app.route("/cases/<int:case_id>/findings/new", methods=["GET", "POST"])
@roles_required("admin", "investigator")
def new_finding(case_id):
    case = get_case(case_id)
    if request.method == "POST":
        with db() as conn:
            cur = conn.execute(
                """INSERT INTO findings(case_id,title,severity,confidence,status,description,impact,recommendation,evidence_refs,created_by,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (case_id, request.form["title"].strip(), request.form.get("severity","Informational"),
                 request.form.get("confidence","Medium"), "Open", request.form["description"].strip(),
                 request.form.get("impact",""), request.form.get("recommendation",""),
                 request.form.get("evidence_refs",""), session["user_id"], now(), now()),
            )
            finding_id = cur.lastrowid
            conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (now(), case_id))
        audit_event("FINDING_CREATED", "finding", finding_id, request.form["title"].strip())
        return redirect(url_for("case_detail", case_id=case_id))
    return page("New finding", """
    <h1>New finding - {{ case.case_number }}</h1><div class="card"><form method="post">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <label>Title</label><input name="title" required>
      <div class="grid" style="margin-top:12px">
        <div><label>Severity</label><select name="severity"><option>Informational</option><option>Low</option><option>Moderate</option><option>High</option><option>Critical</option></select></div>
        <div><label>Confidence</label><select name="confidence"><option>Low</option><option selected>Medium</option><option>High</option></select></div>
        <div><label>Evidence references</label><input name="evidence_refs" placeholder="E-0001, E-0004"></div>
      </div>
      <label style="margin-top:12px">Description / analysis</label><textarea name="description" required></textarea>
      <label>Impact</label><textarea name="impact"></textarea>
      <label>Recommendation</label><textarea name="recommendation"></textarea>
      <button>Save finding</button>
    </form></div>
    """, case=case)

def build_report_markdown(case_id):
    case = get_case(case_id)
    with db() as conn:
        evidence = conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        findings = conn.execute("SELECT * FROM findings WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
        timeline = conn.execute(
            "SELECT * FROM timeline_events WHERE case_id=? ORDER BY CASE WHEN event_time IS NULL THEN 1 ELSE 0 END,event_time,id LIMIT 1000",
            (case_id,),
        ).fetchall()
    lines = [
        f"# Investigation Report - {case['case_number']}",
        "",
        f"**Title:** {case['title']}",
        f"**Classification:** {case['classification']}",
        f"**Status:** {case['status']}",
        f"**Lead Investigator:** {case['lead_investigator'] or 'Unassigned'}",
        f"**Generated:** {now()}",
        "",
        "## Scope and Background",
        "",
        case["description"] or "No scope narrative entered.",
        "",
        "## Evidence",
        "",
    ]
    for e in evidence:
        lines += [
            f"### {e['evidence_number']} - {e['original_filename']}",
            f"- SHA-256: `{e['sha256']}`",
            f"- Size: {e['byte_size']} bytes",
            f"- Source tool: {e['source_tool'] or 'Not specified'}",
            f"- Source system: {e['source_system'] or 'Not specified'}",
            f"- Collector: {e['collector'] or 'Not specified'}",
            f"- Collection time: {e['collection_time'] or 'Not specified'}",
            f"- Parser: {e['parser'] or 'Preserved only'}",
            f"- Parsed records: {e['parsed_records']}",
            f"- Notes: {e['notes'] or ''}",
            "",
        ]
    lines += ["## Findings", ""]
    for f in findings:
        lines += [
            f"### {f['title']}",
            f"- Severity: {f['severity']}",
            f"- Confidence: {f['confidence']}",
            f"- Evidence: {f['evidence_refs'] or 'Not specified'}",
            "",
            f["description"],
            "",
            f"**Impact:** {f['impact'] or 'Not specified'}",
            "",
            f"**Recommendation:** {f['recommendation'] or 'Not specified'}",
            "",
        ]
    lines += ["## Timeline", "", "| Time | Type | Source | Summary |", "|---|---|---|---|"]
    for t in timeline:
        vals = [t["event_time"] or "Unknown", t["event_type"] or "", t["source"] or "", (t["summary"] or "").replace("|","\\|")]
        lines.append("| " + " | ".join(vals) + " |")
    lines += [
        "",
        "## Methodology and Integrity",
        "",
        "Evidence records include SHA-256 hashes calculated over original uploaded bytes. Original evidence is preserved separately from normalized parsed events. Integrity verification events and chain-of-custody activity are recorded by the application.",
        "",
        "## Limitations",
        "",
        "This report reflects the evidence and analyst findings recorded in ForensicBuddy. Absence of a parsed event does not prove absence of activity; unsupported or binary evidence may require analysis in specialist forensic tooling.",
    ]
    return "\n".join(lines)

@app.route("/cases/<int:case_id>/report")
@login_required
def report(case_id):
    case = get_case(case_id)
    md = build_report_markdown(case_id)
    audit_event("REPORT_VIEWED", "case", case_id)
    return page("Report", """
    <div class="actions" style="justify-content:space-between"><h1>Report - {{ case.case_number }}</h1>
    <a class="btn" href="{{ url_for('report_download', case_id=case.id) }}">Download Markdown</a></div>
    <div class="card"><pre>{{ md }}</pre></div>
    """, case=case, md=md)

@app.route("/cases/<int:case_id>/report.md")
@login_required
def report_download(case_id):
    case = get_case(case_id)
    md = build_report_markdown(case_id)
    audit_event("REPORT_EXPORTED", "case", case_id, "Markdown")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", case["case_number"])
    return Response(md, mimetype="text/markdown", headers={"Content-Disposition": f'attachment; filename="{safe}_report.md"'})

@app.route("/audit")
@login_required
def audit():
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
    return page("Audit log", """
    <h1>Application audit log</h1><div class="card small">Records are hash-chained: each audit record includes the previous record hash in the material used to calculate its own SHA-256 hash.</div>
    <div class="card"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Object</th><th>Detail</th><th>Record hash</th></tr></thead><tbody>
    {% for r in rows %}<tr><td class="small">{{ r.event_time }}</td><td>{{ r.username or 'anonymous' }}</td><td>{{ r.action }}</td><td>{{ r.object_type or '' }} {{ r.object_id or '' }}</td><td>{{ r.detail }}</td><td class="small">{{ r.record_hash }}</td></tr>{% endfor %}
    </tbody></table></div>
    """, rows=rows)

@app.route("/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    if request.method == "POST":
        username = request.form["username"].strip()
        role = request.form.get("role","investigator")
        password = request.form["password"]
        if role not in {"admin","investigator","reviewer"} or len(password) < 12:
            flash("Password must be at least 12 characters and role must be valid.")
        else:
            try:
                with db() as conn:
                    cur = conn.execute(
                        "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                        (username, generate_password_hash(password), role, now()),
                    )
                audit_event("USER_CREATED", "user", cur.lastrowid, f"{username} role={role}")
                flash("User created.")
            except sqlite3.IntegrityError:
                flash("Username already exists.")
    with db() as conn:
        rows = conn.execute("SELECT id,username,role,active,created_at FROM users ORDER BY username").fetchall()
    return page("Users", """
    <h1>Users</h1><div class="card"><form method="post">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <div class="grid"><div><label>Username</label><input name="username" required></div>
      <div><label>Role</label><select name="role"><option>investigator</option><option>reviewer</option><option>admin</option></select></div>
      <div><label>Temporary password</label><input type="password" name="password" minlength="12" required></div></div>
      <div style="margin-top:12px"><button>Create user</button></div>
    </form></div>
    <div class="card"><table><thead><tr><th>User</th><th>Role</th><th>Active</th><th>Created</th></tr></thead><tbody>
    {% for u in rows %}<tr><td>{{ u.username }}</td><td>{{ u.role }}</td><td>{{ 'Yes' if u.active else 'No' }}</td><td class="small">{{ u.created_at }}</td></tr>{% endfor %}
    </tbody></table></div>
    """, rows=rows)

@app.errorhandler(413)
def too_large(_):
    return page("Upload too large", f"<div class='card'><h1>Upload too large</h1><p>Maximum upload size is {MAX_UPLOAD_MB} MB.</p></div>"), 413

init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
