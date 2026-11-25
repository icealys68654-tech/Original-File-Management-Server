from pathlib import Path
from datetime import datetime, timezone
from ipaddress import ip_network
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string, flash, abort, session, g
from werkzeug.utils import secure_filename
import os, shutil, subprocess, json, hashlib, sqlite3, secrets, hmac, sys, getpass, re
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
from key_management import normalize_public_key, encrypt_for_recipients, validate_cfs_v2_envelopes

ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage"
STORAGE.mkdir(exist_ok=True)
KEYS = ROOT / "keys"
KEYS.mkdir(exist_ok=True)
PUBLIC_KEY_PATH = KEYS / "recipient_public.pem"
ENCRYPTED_MAGIC = b"CFS-HYBRID-ENCRYPTED-V1\n"
MAX_MB = int(os.environ.get("MAX_UPLOAD_MB", "250"))
APP_VERSION = "1.3.0"
DB_PATH = ROOT / "cloud_file_server.sqlite3"
AUDIT_PATH = ROOT / "audit.jsonl"
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=__import__("datetime").timedelta(hours=8),
)


def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with db_connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','user')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS user_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            fingerprint TEXT NOT NULL,
            public_key_pem BLOB NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active','retired','revoked')),
            created_at TEXT NOT NULL,
            revoked_at TEXT,
            UNIQUE(user_id, fingerprint)
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_user_keys_active ON user_keys(user_id,status)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_key_per_user ON user_keys(user_id) WHERE status='active'")
        db.execute("""CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            storage_name TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            encrypted INTEGER NOT NULL DEFAULT 0 CHECK(encrypted IN (0,1)),
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            deleted_at TEXT
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id,deleted_at)")
        db.execute("""CREATE TABLE IF NOT EXISTS file_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES files(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            role TEXT NOT NULL CHECK(role IN ('viewer','download')),
            status TEXT NOT NULL CHECK(status IN ('active','revoked')),
            granted_by INTEGER NOT NULL REFERENCES users(id),
            granted_at TEXT NOT NULL,
            revoked_at TEXT,
            envelope_fingerprint TEXT,
            envelope_public_key_pem BLOB,
            UNIQUE(file_id,user_id)
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_file_permissions_user ON file_permissions(user_id,status)")


def audit_event(actor_id, action, outcome="success", file_id=None, target_user_id=None, details=None):
    """Append one redacted JSONL event; never log credentials, tokens, keys or file bytes."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_user_id": actor_id,
        "action": action,
        "outcome": outcome,
        "file_id": file_id,
        "target_user_id": target_user_id,
        "details": details or {},
    }
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(AUDIT_PATH), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def current_active_key(db, user_id):
    return db.execute("SELECT fingerprint,public_key_pem FROM user_keys WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()


def file_access_row(db, file_id, user_id):
    return db.execute("""SELECT f.*, p.role AS permission_role, p.status AS permission_status
        FROM files f LEFT JOIN file_permissions p ON p.file_id=f.id AND p.user_id=?
        WHERE f.id=? AND f.deleted_at IS NULL""", (user_id, file_id)).fetchone()


def can_read_file(row, user_id, role):
    """Metadata visibility: viewer and download permissions both qualify."""
    return bool(row and (role == "admin" or row["owner_id"] == user_id or
        (row["permission_status"] == "active" and row["permission_role"] in ("viewer", "download"))))


def can_download_file(row, user_id, role):
    if not row:
        return False
    if role == "admin":
        return True
    if row["owner_id"] == user_id:
        # An encrypted owner must retain an active envelope-backed permission too.
        return (not row["encrypted"] or
                (row["permission_status"] == "active" and row["permission_role"] == "download"))
    return row["permission_status"] == "active" and row["permission_role"] == "download"


def validate_file_envelopes(file_row):
    """Check every recorded envelope against its immutable key snapshot, including revoked ACLs.

    Keeping revoked envelope snapshots allows the strict CFS v2 validator to verify the
    complete original envelope set. Application ACLs still block revoked recipients.
    """
    if not file_row["encrypted"]:
        return
    path = STORAGE / file_row["storage_name"]
    with db_connect() as db:
        rows = db.execute("SELECT user_id,envelope_fingerprint,envelope_public_key_pem FROM file_permissions WHERE file_id=? AND envelope_fingerprint IS NOT NULL", (file_row["id"],)).fetchall()
    expected = {str(r["user_id"]): (r["envelope_fingerprint"], bytes(r["envelope_public_key_pem"])) for r in rows}
    if not expected:
        raise ValueError("Encrypted file has no recorded recipient envelopes.")
    validate_cfs_v2_envelopes(path.read_bytes(), expected)


def record_file(db, storage_name, original_name, owner_id, encrypted, data):
    now = datetime.now(timezone.utc).isoformat()
    digest = hashlib.sha256(data).hexdigest()
    cur = db.execute("INSERT INTO files(storage_name,original_name,owner_id,encrypted,size_bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?)",
        (storage_name, original_name, owner_id, int(encrypted), len(data), digest, now))
    return cur.lastrowid

def create_user(username, password, role="user"):
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        raise ValueError("Username must be 3–64 characters: letters, numbers, dot, underscore or hyphen.")
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    if role not in ("admin", "user"):
        raise ValueError("Role must be admin or user.")
    with db_connect() as db:
        db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                   (username, generate_password_hash(password), role,
                    datetime.now(timezone.utc).isoformat()))


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


init_db()

LOGIN_PAGE = """<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Sign in · Cloud File Server</title><style>body{font:16px system-ui;background:#f4f6fa;margin:0;display:grid;place-items:center;min-height:100vh;color:#172033}.box{background:white;padding:30px;border:1px solid #e4e9f1;border-radius:14px;width:min(390px,calc(100% - 48px))}input,button{font:inherit;padding:11px;border:1px solid #cbd4e1;border-radius:8px;width:100%;box-sizing:border-box;margin:7px 0}button{background:#2357c6;color:white;border:0;cursor:pointer}.muted{color:#69758a;font-size:13px}</style><div class='box'><h1>Cloud File Server</h1><p class='muted'>Sign in to continue</p>{% with messages=get_flashed_messages() %}{% for m in messages %}<p>{{m}}</p>{% endfor %}{% endwith %}<form method='post'><input type='hidden' name='csrf_token' value='{{csrf_token}}'><label>Username<input name='username' autocomplete='username' required autofocus></label><label>Password<input type='password' name='password' autocomplete='current-password' required></label><button>Sign in</button></form></div></html>"""

@app.before_request
def csrf_and_identity_guard():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        submitted = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
        if not hmac.compare_digest(submitted, session.get("csrf_token", "")):
            abort(400, "CSRF token missing or invalid.")
    public_endpoints = {"login", "login_post", "static"}
    if request.endpoint not in public_endpoints and not session.get("user_id"):
        return redirect(url_for("login", next=request.path))
    # Legacy administrative endpoints remain admin-only through their decorators.
    # v1.3.0 file APIs apply ownership and per-file ACL checks individually.


@app.get("/login")
def login():
    return render_template_string(LOGIN_PAGE, csrf_token=session["csrf_token"])


@app.post("/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    with db_connect() as db:
        user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        audit_event(user["id"] if user else None, "auth.login", outcome="denied", details={"username": username[:64]})
        flash("Invalid username or password.")
        return redirect(url_for("login"))
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    audit_event(user["id"], "auth.login")
    destination = request.args.get("next", "")
    if not destination.startswith("/") or destination.startswith("//"):
        destination = url_for("index")
    return redirect(destination)


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for("login"))


@app.post("/admin/users")
@admin_required
def admin_create_user():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    try:
        create_user(username, password, role)
        flash(f"Created {role} account: {username.strip()}")
    except sqlite3.IntegrityError:
        flash("That username already exists.")
    except ValueError as exc:
        flash(str(exc))
    return redirect(url_for("index"))


STATS = {
    "count": 7,
    "checksum": 5,
    "mean": 5.285714285714286,
    "variance": 8.198624489795918,
    "standard_deviation": 2.8633240280827312,
}

PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud File Server</title>
<style>
:root{font-family:Inter,system-ui,Arial;color:#172033;background:#f4f6fa}*{box-sizing:border-box}
body{margin:0}.top{background:#111c33;color:white;padding:22px max(24px,calc((100% - 1120px)/2))}
.top small{color:#b8c5dd}.wrap{max-width:1120px;margin:26px auto;padding:0 20px}
h1{margin:0 0 4px;font-size:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:18px 0}
.card{background:white;border:1px solid #e4e9f1;border-radius:14px;padding:18px;box-shadow:0 3px 12px #14213d08}
.metric{font-size:25px;font-weight:700;margin-top:6px}.muted{color:#69758a;font-size:13px}
.panel{background:white;border:1px solid #e4e9f1;border-radius:14px;padding:20px;margin:16px 0}
input,button{font:inherit;padding:10px 12px;border:1px solid #cbd4e1;border-radius:8px}
button,.btn{background:#2357c6;color:white;border:0;cursor:pointer;text-decoration:none;padding:10px 14px;border-radius:8px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px 8px;border-bottom:1px solid #edf0f5}
th{font-size:12px;color:#69758a;text-transform:uppercase}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.danger{background:#b42318}.notice{padding:10px 12px;background:#edf5ff;border-radius:8px;margin:10px 0}
code{background:#f0f3f8;padding:2px 5px;border-radius:4px}
@media(max-width:600px){table{font-size:13px}.hide-mobile{display:none}}
</style></head><body>
<header class="top"><h1>Cloud File Server</h1><small>v{{version}} · Signed in as {{username}} ({{role}}) · <a style="color:#fff" href="/admin/audit">Audit log</a></small><form method="post" action="/logout" style="margin-top:10px">{{ csrf_field|safe }}<button>Sign out</button></form></header>
<main class="wrap">
{% with messages = get_flashed_messages() %}{% for m in messages %}<div class="notice">{{m}}</div>{% endfor %}{% endwith %}
<div class="grid">
<div class="card"><div class="muted">Dataset count</div><div class="metric">{{stats.count}}</div></div>
<div class="card"><div class="muted">Mean</div><div class="metric">{{"%.4f"|format(stats.mean)}}</div></div>
<div class="card"><div class="muted">Variance</div><div class="metric">{{"%.4f"|format(stats.variance)}}</div></div>
<div class="card"><div class="muted">Std. deviation</div><div class="metric">{{"%.4f"|format(stats.standard_deviation)}}</div></div>
</div>
<section class="panel"><h2>Per-user encryption keys</h2><p class="muted">Each account registers its own RSA-3072+ public key. Users generate and retain their encrypted private keys locally. Verify fingerprints with each user over a separate trusted channel.</p><table><thead><tr><th>User</th><th>Key fingerprint</th><th>Status</th><th>Registered</th><th>Action</th></tr></thead><tbody>{% for k in registered_keys %}<tr><td>{{k.username}}</td><td><code>{{k.fingerprint}}</code></td><td>{{k.status}}</td><td>{{k.created_at}}</td><td>{% if k.status in ['active','retired'] %}<form method="post" action="/admin/keys/{{k.id}}/revoke">{{csrf_field|safe}}<button class="danger">Revoke</button></form>{% endif %}</td></tr>{% endfor %}</tbody></table><p class="muted">To register or rotate your own key, use the user key-registration form below.</p><form class="actions" method="post" action="/keys/me" enctype="multipart/form-data">{{csrf_field|safe}}<input type="file" name="public_key" accept=".pem,.pub" required><button>Register / rotate my public key</button></form></section><section class="panel"><h2>Upload files</h2><p class="muted">Files are stored in this project's local <code>storage/</code> directory. Maximum upload: {{max_mb}} MB.</p>
<form class="actions" method="post" action="/upload" enctype="multipart/form-data">{{ csrf_field|safe }}<input type="file" name="file" required><button>Upload</button></form><p class="muted">Standard upload stores the file as-is.</p></section><section class="panel"><h2>Multi-recipient encrypted upload</h2><p class="muted">One AES-256-GCM file key is wrapped independently to each selected user's active RSA key. Recipients receive server download permission only when their matching RSA envelope is present.</p><form method="post" action="/upload-encrypted" enctype="multipart/form-data">{{ csrf_field|safe }}<input type="file" name="file" required><p><label>Recipients (Ctrl-click to select multiple)</label><br><select name="recipient_ids" multiple required size="5">{% for r in eligible_recipients %}<option value="{{r.id}}">{{r.username}} — {{r.fingerprint[:16]}}…</option>{% endfor %}</select></p><button>Encrypt and upload</button></form></section><section class="panel"><h2>Stored files</h2>
{% if files %}<table><thead><tr><th>Name</th><th>Size</th><th class="hide-mobile">Modified (UTC)</th><th>Actions</th></tr></thead><tbody>
{% for f in files %}<tr><td>{{f.name}}</td><td>{{f.size}}</td><td class="hide-mobile">{{f.modified}}</td><td><div class="actions"><a class="btn" href="{{url_for('download', filename=f.name)}}">Download</a>
<form method="post" action="{{url_for('delete_file', filename=f.name)}}" onsubmit="return confirm('Delete this file?')">{{ csrf_field|safe }}<button class="danger">Delete</button></form></div></td></tr>{% endfor %}
</tbody></table>{% else %}<p class="muted">No files uploaded yet.</p>{% endif %}</section>
<section class="panel"><h2>Account provisioning</h2><p class="muted">Administrators can create accounts. Passwords must be at least 12 characters.</p><form class="actions" method="post" action="/admin/users">{{ csrf_field|safe }}<input name="username" placeholder="Username" minlength="3" maxlength="64" required><input name="password" type="password" placeholder="Temporary password (12+ chars)" minlength="12" required><select name="role"><option value="user">User</option><option value="admin">Administrator</option></select><button>Create account</button></form><h3>Existing accounts</h3><ul>{% for u in users %}<li>{{u.username}} — {{u.role}}{% if not u.active %} (disabled){% endif %}</li>{% endfor %}</ul></section><section class="panel"><h2>Infrastructure inventory</h2><p class="muted">Add known cloud hosts, endpoints, or private network ranges to keep a simple inventory. This does not automatically connect to cloud accounts.</p>
<form class="actions" method="post" action="/hosts">{{ csrf_field|safe }}<input name="host" placeholder="hostname or IP address" required><input name="notes" placeholder="Notes (optional)"><button>Add host</button></form>
{% if hosts %}<table><thead><tr><th>Host</th><th>Notes</th><th>Added</th></tr></thead><tbody>{% for h in hosts %}<tr><td>{{h.host}}</td><td>{{h.notes}}</td><td>{{h.added}}</td></tr>{% endfor %}</tbody></table>{% else %}<p class="muted">No hosts recorded.</p>{% endif %}</section>
<section class="panel"><h2>Nmap discovery (optional)</h2><p class="muted">Nmap must be installed. Only scan networks you own or are explicitly authorized to assess. This app restricts scans to private IPv4 ranges.</p>
<form class="actions" method="post" action="/scan">{{ csrf_field|safe }}<input name="network" placeholder="e.g. 192.168.1.0/24" required><button>Run host discovery</button></form>
{% if scan_result %}<h3>Latest scan output</h3><pre style="white-space:pre-wrap;overflow-wrap:anywhere">{{scan_result}}</pre>{% endif %}</section>
<p class="muted">Security note: development server is intended for localhost use only. Do not expose it to the internet without authentication, HTTPS, access controls, and production deployment hardening.</p>
</main></body></html>
"""


def encrypt_payload(plaintext: bytes, filename: str, public_key_pem: bytes) -> bytes:
    """Encrypt bytes using a fresh AES-256-GCM key wrapped by recipient RSA-OAEP."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
        raise ValueError("Recipient key must be an RSA public key of at least 3072 bits.")
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    envelope = {
        "version": 1,
        "algorithm": "AES-256-GCM + RSA-OAEP-SHA256",
        "filename": filename,
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return ENCRYPTED_MAGIC + json.dumps(envelope, separators=(",", ":")).encode("utf-8")

def public_key_fingerprint(pem: bytes) -> str:
    key = serialization.load_pem_public_key(pem)
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()

def load_hosts():
    p = ROOT / "hosts.json"
    if not p.exists(): return []
    try: return json.loads(p.read_text())
    except Exception: return []

@app.get("/")
@login_required
def index():
    if session.get("role") != "admin":
        with db_connect() as db:
            my_key = db.execute("SELECT fingerprint,status,created_at FROM user_keys WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1", (session["user_id"],)).fetchone()
            rows = db.execute("""SELECT f.id,f.original_name,f.size_bytes,f.created_at,f.owner_id,
                CASE WHEN f.owner_id=? THEN 'owner' ELSE p.role END AS access_role
                FROM files f LEFT JOIN file_permissions p ON p.file_id=f.id AND p.user_id=? AND p.status='active'
                WHERE f.deleted_at IS NULL AND (f.owner_id=? OR p.status='active') ORDER BY f.created_at DESC""",
                (session["user_id"],session["user_id"],session["user_id"])).fetchall()
        return render_template_string("""<!doctype html><meta charset='utf-8'><title>Cloud File Server</title><h1>Welcome, {{username}}</h1>
        <p>v{{version}} · Your files and files shared with you</p>
        <h2>Your encryption key</h2>{% if my_key %}<p>Active SHA-256 fingerprint: <code>{{my_key.fingerprint}}</code></p>{% else %}<p>No active key registered.</p>{% endif %}
        <form method='post' action='/keys/me' enctype='multipart/form-data'><input type='hidden' name='csrf_token' value='{{csrf_token}}'><input type='file' name='public_key' accept='.pem,.pub' required><button>Register / rotate public key</button></form>
        <h2>Upload a file</h2><form method='post' action='/api/files' enctype='multipart/form-data'><input type='hidden' name='csrf_token' value='{{csrf_token}}'><input type='file' name='file' required><button>Upload private file</button></form>
        <h2>Your accessible files</h2><ul>{% for f in files %}<li>{{f.original_name}} — {{f.access_role}} — {{f.size_bytes}} bytes {% if f.access_role != 'viewer' %}<a href='/api/files/{{f.id}}/download'>Download</a>{% endif %}{% if f.owner_id == uid %}<a href='/api/files/{{f.id}}/permissions'>Manage permissions</a>{% endif %}</li>{% else %}<li>No files yet.</li>{% endfor %}</ul>
        <form method='post' action='/logout'><input type='hidden' name='csrf_token' value='{{csrf_token}}'><button>Sign out</button></form>""", username=session["username"], csrf_token=session["csrf_token"], my_key=my_key, files=rows, uid=session["user_id"], version=APP_VERSION)
    files=[]
    for p in sorted(STORAGE.iterdir(), key=lambda x:x.name.lower()):
        if p.is_file():
            st=p.stat()
            files.append({"name":p.name,"size":f"{st.st_size:,} bytes","modified":datetime.fromtimestamp(st.st_mtime,timezone.utc).strftime("%Y-%m-%d %H:%M")})
    scan_file=ROOT/"last_scan.txt"
    scan=scan_file.read_text() if scan_file.exists() else ""
    fingerprint = public_key_fingerprint(PUBLIC_KEY_PATH.read_bytes()) if PUBLIC_KEY_PATH.exists() else None
    with db_connect() as db:
        users = db.execute("SELECT username,role,active FROM users ORDER BY username COLLATE NOCASE").fetchall()
        registered_keys = db.execute("SELECT k.id,k.fingerprint,k.status,k.created_at,u.username FROM user_keys k JOIN users u ON u.id=k.user_id ORDER BY u.username,k.id DESC").fetchall()
        eligible_recipients = db.execute("SELECT u.id,u.username,k.fingerprint FROM users u JOIN user_keys k ON k.user_id=u.id WHERE u.active=1 AND k.status='active' AND k.id=(SELECT MAX(k2.id) FROM user_keys k2 WHERE k2.user_id=u.id AND k2.status='active') ORDER BY u.username").fetchall()
    return render_template_string(PAGE, stats=STATS, files=files, hosts=load_hosts(), max_mb=MAX_MB, scan_result=scan, key_fingerprint=fingerprint, version=APP_VERSION, username=session.get("username"), role=session.get("role"), users=users, registered_keys=registered_keys, eligible_recipients=eligible_recipients, csrf_token=session["csrf_token"], csrf_field=f'<input type="hidden" name="csrf_token" value="{session["csrf_token"]}">')


@app.post("/keys/me")
@login_required
def register_my_key():
    uploaded = request.files.get("public_key")
    if not uploaded or not uploaded.filename:
        flash("Choose your RSA public-key PEM file.")
        return redirect(url_for("index"))
    try:
        normalized, fingerprint = normalize_public_key(uploaded.read(64 * 1024 + 1))
        now = datetime.now(timezone.utc).isoformat()
        with db_connect() as db:
            existing = db.execute("SELECT id FROM user_keys WHERE user_id=? AND fingerprint=?", (session["user_id"], fingerprint)).fetchone()
            if existing:
                prior = db.execute("SELECT status FROM user_keys WHERE id=?", (existing["id"],)).fetchone()
                if prior["status"] == "revoked":
                    raise ValueError("This fingerprint was revoked and cannot be reactivated. Generate a new key pair.")
                db.execute("UPDATE user_keys SET status='retired' WHERE user_id=? AND status='active'", (session["user_id"],))
                db.execute("UPDATE user_keys SET status='active' WHERE id=?", (existing["id"],))
            else:
                db.execute("UPDATE user_keys SET status='retired' WHERE user_id=? AND status='active'", (session["user_id"],))
                db.execute("INSERT INTO user_keys(user_id,fingerprint,public_key_pem,status,created_at) VALUES(?,?,?,'active',?)", (session["user_id"], fingerprint, normalized, now))
        audit_event(session["user_id"], "key.register", details={"fingerprint": fingerprint})
        flash(f"Public key registered. Verify fingerprint out-of-band: {fingerprint}")
    except Exception as exc:
        flash(f"Key registration failed: {exc}")
    return redirect(url_for("index"))


@app.post("/admin/keys/<int:key_id>/revoke")
@admin_required
def revoke_user_key(key_id):
    with db_connect() as db:
        row = db.execute("SELECT id FROM user_keys WHERE id=? AND status IN ('active','retired')", (key_id,)).fetchone()
        if not row:
            abort(404)
        key_owner = db.execute("SELECT user_id,fingerprint FROM user_keys WHERE id=?", (key_id,)).fetchone()
        db.execute("UPDATE user_keys SET status='revoked',revoked_at=? WHERE id=?", (datetime.now(timezone.utc).isoformat(), key_id))
        db.execute("UPDATE file_permissions SET status='revoked',revoked_at=? WHERE envelope_fingerprint=? AND status='active'", (datetime.now(timezone.utc).isoformat(), key_owner["fingerprint"]))
    audit_event(session["user_id"], "key.revoke", target_user_id=key_owner["user_id"], details={"fingerprint": key_owner["fingerprint"], "affected_permissions":"revoked"})
    flash("Key revoked for future recipient selection. Previously downloaded copies and existing private-key material cannot be recalled.")
    return redirect(url_for("index"))


@app.post("/keys/recipient")
@admin_required
def set_recipient_key():
    uploaded = request.files.get("public_key")
    if not uploaded or not uploaded.filename:
        flash("Choose a recipient public-key PEM file.")
        return redirect(url_for("index"))
    pem = uploaded.read(64 * 1024 + 1)
    if len(pem) > 64 * 1024:
        flash("Public key file is too large.")
        return redirect(url_for("index"))
    try:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
            raise ValueError("Use an RSA public key of at least 3072 bits.")
        # Normalize to a standard public-key PEM representation.
        normalized = key.public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
        PUBLIC_KEY_PATH.write_bytes(normalized)
        try:
            os.chmod(PUBLIC_KEY_PATH, 0o644)
        except OSError:
            pass
        flash("Recipient public key saved. Verify its displayed fingerprint out-of-band.")
    except Exception as exc:
        flash(f"Invalid public key: {exc}")
    return redirect(url_for("index"))

@app.get("/api/files")
@login_required
def api_list_files():
    uid = session["user_id"]
    with db_connect() as db:
        rows = db.execute("""SELECT DISTINCT f.id,f.original_name,f.encrypted,f.size_bytes,f.sha256,f.created_at,f.owner_id,
            CASE WHEN f.owner_id=? THEN 'owner' ELSE p.role END AS access_role
            FROM files f LEFT JOIN file_permissions p ON p.file_id=f.id AND p.user_id=? AND p.status='active'
            WHERE f.deleted_at IS NULL AND (?='admin' OR f.owner_id=? OR p.status='active') ORDER BY f.created_at DESC""",
            (uid,uid,session.get("role"),uid)).fetchall()
    return {"files": [dict(r) for r in rows]}


@app.post("/api/files")
@login_required
def api_upload_file():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        abort(400, "File is required.")
    original = secure_filename(uploaded.filename)
    if not original:
        abort(400, "Invalid filename.")
    data = uploaded.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    if len(data) > app.config["MAX_CONTENT_LENGTH"]:
        abort(413)
    storage_name = secrets.token_hex(16) + "_" + original
    target = STORAGE / storage_name
    target.write_bytes(data)
    try:
        with db_connect() as db:
            file_id = record_file(db, storage_name, original, session["user_id"], False, data)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    audit_event(session["user_id"], "file.upload", file_id=file_id, details={"encrypted": False, "bytes": len(data)})
    return {"id": file_id, "name": original, "encrypted": False}, 201


@app.post("/api/files/encrypted")
@login_required
def api_upload_encrypted():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        abort(400, "File is required.")
    original = secure_filename(uploaded.filename)
    if not original:
        abort(400, "Invalid filename.")
    recipient_ids = list(dict.fromkeys(request.form.getlist("recipient_ids")))
    # The owner must retain cryptographic access to their own encrypted upload.
    owner_id = str(session["user_id"])
    if owner_id not in recipient_ids:
        recipient_ids.append(owner_id)
    if not recipient_ids:
        abort(400, "Select at least one recipient.")
    placeholders = ",".join("?" for _ in recipient_ids)
    with db_connect() as db:
        keys = db.execute(f"""SELECT u.id,k.fingerprint,k.public_key_pem FROM users u JOIN user_keys k ON k.user_id=u.id
            WHERE u.active=1 AND k.status='active' AND u.id IN ({placeholders})
            AND k.id=(SELECT MAX(k2.id) FROM user_keys k2 WHERE k2.user_id=u.id AND k2.status='active')""", recipient_ids).fetchall()
    if len(keys) != len(recipient_ids):
        abort(400, "Every recipient must have an active registered RSA key.")
    recipients = {str(k["id"]): (k["fingerprint"], bytes(k["public_key_pem"])) for k in keys}
    try:
        plaintext = uploaded.read(app.config["MAX_CONTENT_LENGTH"] + 1)
        if len(plaintext) > app.config["MAX_CONTENT_LENGTH"]:
            abort(413)
        encrypted = encrypt_for_recipients(plaintext, original, recipients)
        validate_cfs_v2_envelopes(encrypted, recipients)
    except ValueError as exc:
        abort(400, str(exc))
    storage_name = secrets.token_hex(16) + "_" + original + ".cfs"
    target = STORAGE / storage_name
    target.write_bytes(encrypted)
    try:
        with db_connect() as db:
            file_id = record_file(db, storage_name, original, session["user_id"], True, encrypted)
            for uid, (fingerprint, pem) in recipients.items():
                db.execute("""INSERT INTO file_permissions(file_id,user_id,role,status,granted_by,granted_at,envelope_fingerprint,envelope_public_key_pem)
                    VALUES(?,?,'download','active',?,?,?,?)""",
                    (file_id, int(uid), session["user_id"], datetime.now(timezone.utc).isoformat(), fingerprint, pem))
    except Exception:
        target.unlink(missing_ok=True)
        raise
    audit_event(session["user_id"], "file.upload_encrypted", file_id=file_id, details={"recipient_count":len(recipients),"bytes":len(encrypted)})
    return {"id": file_id, "name": original, "encrypted": True, "recipients": sorted(recipients)}, 201


@app.get("/api/files/<int:file_id>/permissions")
@login_required
def api_get_permissions(file_id):
    with db_connect() as db:
        f = db.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f:
            abort(404)
        if f["owner_id"] != session["user_id"] and session.get("role") != "admin":
            abort(403)
        rows = db.execute("""SELECT p.user_id,u.username,p.role,p.status,p.granted_at,p.revoked_at,p.envelope_fingerprint
            FROM file_permissions p JOIN users u ON u.id=p.user_id WHERE p.file_id=? ORDER BY u.username""", (file_id,)).fetchall()
    return {"file_id": file_id, "permissions": [dict(r) for r in rows]}


@app.post("/api/files/<int:file_id>/permissions")
@login_required
def api_grant_permission(file_id):
    body = request.get_json(silent=True) or request.form
    try:
        recipient_id = int(body.get("user_id", ""))
    except (TypeError, ValueError):
        abort(400, "A valid recipient user_id is required.")
    permission_role = body.get("role", "download")
    if permission_role not in ("viewer", "download"):
        abort(400, "Role must be viewer or download.")
    with db_connect() as db:
        f = db.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f:
            abort(404)
        if f["owner_id"] != session["user_id"] and session.get("role") != "admin":
            abort(403)
        recipient = db.execute("SELECT id,active FROM users WHERE id=?", (recipient_id,)).fetchone()
        if not recipient or not recipient["active"]:
            abort(400, "Recipient account is not active.")
        fingerprint = pem = None
        if f["encrypted"]:
            key = current_active_key(db, recipient_id)
            if not key:
                abort(400, "Encrypted-file recipients must have an active registered RSA key.")
            fingerprint, pem = key["fingerprint"], bytes(key["public_key_pem"])
            try:
                # For an existing ciphertext, its envelope set must match the stored immutable
                # envelope records. The new recipient must already be present and key-matched.
                old_rows = db.execute("SELECT user_id,envelope_fingerprint,envelope_public_key_pem FROM file_permissions WHERE file_id=? AND envelope_fingerprint IS NOT NULL", (file_id,)).fetchall()
                expected = {str(r["user_id"]):(r["envelope_fingerprint"],bytes(r["envelope_public_key_pem"])) for r in old_rows}
                doc = validate_cfs_v2_envelopes((STORAGE/f["storage_name"]).read_bytes(), expected) if expected else None
                matches = [e for e in (doc or {}).get("recipients",[]) if str(e.get("user_id"))==str(recipient_id) and e.get("fingerprint")==fingerprint]
                if len(matches) != 1:
                    abort(409, "Grant denied: this CFS v2 file has no envelope for the recipient's current registered RSA key. Re-encrypt and upload with that recipient selected.")
            except ValueError as exc:
                abort(409, f"Stored CFS v2 envelope validation failed: {exc}")
            db.execute("""INSERT INTO file_permissions(file_id,user_id,role,status,granted_by,granted_at,envelope_fingerprint,envelope_public_key_pem)
                VALUES(?,?,?,'active',?,?,?,?) ON CONFLICT(file_id,user_id) DO UPDATE SET role=excluded.role,status='active',granted_by=excluded.granted_by,granted_at=excluded.granted_at,revoked_at=NULL,envelope_fingerprint=excluded.envelope_fingerprint,envelope_public_key_pem=excluded.envelope_public_key_pem""",
                (file_id,recipient_id,permission_role,session["user_id"],datetime.now(timezone.utc).isoformat(),fingerprint,pem))
        else:
            db.execute("""INSERT INTO file_permissions(file_id,user_id,role,status,granted_by,granted_at)
                VALUES(?,?,?,'active',?,?) ON CONFLICT(file_id,user_id) DO UPDATE SET role=excluded.role,status='active',granted_by=excluded.granted_by,granted_at=excluded.granted_at,revoked_at=NULL""",
                (file_id,recipient_id,permission_role,session["user_id"],datetime.now(timezone.utc).isoformat()))
    audit_event(session["user_id"], "permission.grant", file_id=file_id, target_user_id=recipient_id, details={"role":permission_role,"encrypted":bool(f["encrypted"])})
    return {"status":"granted","file_id":file_id,"user_id":recipient_id,"role":permission_role}, 201


@app.delete("/api/files/<int:file_id>/permissions/<int:recipient_id>")
@login_required
def api_revoke_permission(file_id, recipient_id):
    with db_connect() as db:
        f = db.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f:
            abort(404)
        if f["owner_id"] != session["user_id"] and session.get("role") != "admin":
            abort(403)
        row = db.execute("SELECT status FROM file_permissions WHERE file_id=? AND user_id=?", (file_id,recipient_id)).fetchone()
        if not row or row["status"] != "active":
            abort(404)
        db.execute("UPDATE file_permissions SET status='revoked',revoked_at=? WHERE file_id=? AND user_id=?", (datetime.now(timezone.utc).isoformat(),file_id,recipient_id))
    audit_event(session["user_id"], "permission.revoke", file_id=file_id, target_user_id=recipient_id)
    return {"status":"revoked","file_id":file_id,"user_id":recipient_id}


@app.get("/api/files/<int:file_id>/download")
@login_required
def api_download_file(file_id):
    with db_connect() as db:
        f = file_access_row(db,file_id,session["user_id"])
        if not f or not can_download_file(f,session["user_id"],session.get("role")):
            abort(404)
        try:
            validate_file_envelopes(f)
        except ValueError as exc:
            audit_event(session["user_id"],"file.download",outcome="denied",file_id=file_id,details={"reason":"envelope_validation"})
            abort(403, str(exc))
        target = STORAGE / f["storage_name"]
        if not target.is_file():
            abort(404)
        stored_bytes = target.read_bytes()
        if len(stored_bytes) != f["size_bytes"] or not hmac.compare_digest(hashlib.sha256(stored_bytes).hexdigest(), f["sha256"]):
            audit_event(session["user_id"], "file.download", outcome="denied", file_id=file_id, details={"reason":"storage_integrity_check"})
            abort(409, "Stored file integrity check failed.")
    audit_event(session["user_id"], "file.download", file_id=file_id, details={"encrypted":bool(f["encrypted"])})
    return send_from_directory(STORAGE, f["storage_name"], as_attachment=True, download_name=f["original_name"] + (".cfs" if f["encrypted"] else ""))


@app.post("/api/files/<int:file_id>/delete")
@login_required
def api_delete_file(file_id):
    with db_connect() as db:
        f = db.execute("SELECT * FROM files WHERE id=? AND deleted_at IS NULL", (file_id,)).fetchone()
        if not f:
            abort(404)
        if f["owner_id"] != session["user_id"] and session.get("role") != "admin":
            abort(403)
        db.execute("UPDATE files SET deleted_at=? WHERE id=?", (datetime.now(timezone.utc).isoformat(),file_id))
    (STORAGE/f["storage_name"]).unlink(missing_ok=True)
    audit_event(session["user_id"], "file.delete", file_id=file_id)
    return {"status":"deleted","file_id":file_id}


@app.get("/admin/audit")
@admin_required
def admin_audit():
    events=[]
    if AUDIT_PATH.exists():
        for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines()[-500:]:
            try: events.append(json.loads(line))
            except json.JSONDecodeError: continue
    return render_template_string("""<!doctype html><meta charset='utf-8'><title>Audit log</title><h1>Audit events</h1><p>Append-only JSONL · latest 500 events</p><table border='1' cellpadding='6'><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Outcome</th><th>File</th><th>Target user</th></tr>{% for e in events|reverse %}<tr><td>{{e.timestamp}}</td><td>{{e.actor_user_id}}</td><td>{{e.action}}</td><td>{{e.outcome}}</td><td>{{e.file_id}}</td><td>{{e.target_user_id}}</td></tr>{% endfor %}</table><p><a href='/'>Dashboard</a></p>""", events=events)


@app.post("/upload-encrypted")
@admin_required
def upload_encrypted():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Choose a file first.")
        return redirect(url_for("index"))
    name = secure_filename(uploaded.filename)
    if not name:
        flash("Invalid filename.")
        return redirect(url_for("index"))
    target_name = name + ".cfs"
    target = STORAGE / target_name
    if target.exists():
        flash("An encrypted file with that name already exists.")
        return redirect(url_for("index"))
    selected = list(dict.fromkeys(request.form.getlist("recipient_ids")))
    try:
        if not selected:
            raise ValueError("Select at least one recipient.")
        placeholders = ",".join("?" for _ in selected)
        with db_connect() as db:
            rows = db.execute(f"SELECT u.id,k.fingerprint,k.public_key_pem FROM users u JOIN user_keys k ON k.user_id=u.id WHERE u.active=1 AND k.status='active' AND k.id=(SELECT MAX(k2.id) FROM user_keys k2 WHERE k2.user_id=u.id AND k2.status='active') AND u.id IN ({placeholders})", selected).fetchall()
        if len(rows) != len(selected):
            raise ValueError("One or more selected users do not have an active key.")
        recipients = {str(r["id"]): (r["fingerprint"], bytes(r["public_key_pem"])) for r in rows}
        encrypted = encrypt_for_recipients(uploaded.read(), name, recipients)
        validate_cfs_v2_envelopes(encrypted, recipients)
        target.write_bytes(encrypted)
        audit_event(session["user_id"], "legacy.file.upload_encrypted", details={"filename":target_name,"recipient_count":len(recipients)})
        flash(f"Encrypted and stored {target_name} for {len(recipients)} recipient(s).")
    except Exception as exc:
        flash(f"Encryption failed: {exc}")
    return redirect(url_for("index"))

@app.post("/upload")
@admin_required
def upload():
    f=request.files.get("file")
    if not f or not f.filename: flash("Choose a file first."); return redirect(url_for("index"))
    name=secure_filename(f.filename)
    if not name: flash("Invalid filename."); return redirect(url_for("index"))
    target=STORAGE/name
    if target.exists(): flash("A file with that name already exists. Rename it before uploading."); return redirect(url_for("index"))
    f.save(target); audit_event(session["user_id"], "legacy.file.upload", details={"filename":name}); flash(f"Uploaded {name}."); return redirect(url_for("index"))

@app.get("/download/<path:filename>")
@admin_required
def download(filename):
    safe=secure_filename(filename)
    if safe != filename or not (STORAGE/safe).is_file(): abort(404)
    audit_event(session["user_id"], "legacy.file.download", details={"filename":safe})
    return send_from_directory(STORAGE, safe, as_attachment=True)

@app.post("/delete/<path:filename>")
@admin_required
def delete_file(filename):
    safe=secure_filename(filename)
    target=STORAGE/safe
    if safe != filename or not target.is_file(): abort(404)
    target.unlink(); audit_event(session["user_id"], "legacy.file.delete", details={"filename":safe}); flash(f"Deleted {safe}."); return redirect(url_for("index"))

@app.post("/hosts")
@admin_required
def add_host():
    host=request.form.get("host","").strip()
    notes=request.form.get("notes","").strip()
    if not host or len(host)>253: flash("Enter a valid host label or IP."); return redirect(url_for("index"))
    hosts=load_hosts()
    if any(x.get("host","").lower()==host.lower() for x in hosts): flash("Host already exists.")
    else:
        hosts.append({"host":host,"notes":notes[:500],"added":datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")})
        (ROOT/"hosts.json").write_text(json.dumps(hosts,indent=2)); flash("Host added.")
    return redirect(url_for("index"))

@app.post("/scan")
@admin_required
def scan():
    network=request.form.get("network","").strip()
    try:
        net=ip_network(network, strict=False)
        if net.version != 4 or not net.is_private: raise ValueError()
        if net.num_addresses > 1024: flash("For safety, scan ranges are limited to 1,024 addresses."); return redirect(url_for("index"))
    except ValueError:
        flash("Enter a valid private IPv4 CIDR range (maximum 1,024 addresses)."); return redirect(url_for("index"))
    if not shutil.which("nmap"):
        flash("Nmap is not installed or not on PATH. Install Nmap, then restart this app."); return redirect(url_for("index"))
    try:
        result=subprocess.run(["nmap","-sn","-n",str(net)],capture_output=True,text=True,timeout=120,check=False)
        output=(result.stdout or result.stderr or "Nmap returned no output.")[-12000:]
        (ROOT/"last_scan.txt").write_text(output)
        flash("Discovery scan completed. Review the output below.")
    except subprocess.TimeoutExpired:
        flash("Scan timed out after 120 seconds.")
    return redirect(url_for("index"))

@app.errorhandler(413)
def too_large(_):
    return f"Upload exceeds the {MAX_MB} MB limit.", 413

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        username = input("Administrator username: ").strip()
        password = getpass.getpass("Administrator password (12+ characters): ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise SystemExit("Passwords do not match.")
        create_user(username, password, "admin")
        print(f"Administrator account '{username}' created.")
    else:
        # Localhost binding is deliberate: no network exposure by default.
        app.run(host="127.0.0.1", port=int(os.environ.get("PORT","5000")), debug=False)
