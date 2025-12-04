from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
from datetime import datetime, timedelta
import os, sqlite3, secrets, string
from contextlib import closing
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

# Load env
load_dotenv(override=True)

def _clean(s: str) -> str:
    s = (s or "").strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    return s

ADMIN_USER = _clean(os.getenv("ADMIN_USER", "admin"))
ADMIN_PASSWORD = _clean(os.getenv("ADMIN_PASSWORD", "fluxadmin"))
SECRET_KEY = _clean(os.getenv("SECRET_KEY", "change-this-secret"))
DATABASE = _clean(os.getenv("DATABASE", "flux.db"))

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "static"), template_folder=os.path.join(BASE_DIR, "templates"))
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB uploads
ALLOWED_LOGO_EXT = {"png", "jpg", "jpeg", "webp", "ico"}

# ---------- DB helpers ----------
def get_db():
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_db()) as db:
        cur = db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lic_key TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP,
                max_activations INTEGER NOT NULL DEFAULT 1,
                revoked INTEGER NOT NULL DEFAULT 0,
                notes TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id INTEGER NOT NULL,
                machine_id TEXT NOT NULL,
                activated_at TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                UNIQUE(license_id, machine_id),
                FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        # defaults
        cur.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('site_name','Flux Licensing')")
        cur.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('accent','fuchsia')")
        db.commit()

@app.before_request
def ensure_db():
    init_db()

# ---------- Settings helpers ----------
def get_setting(key, default=""):
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

def set_setting(key, value):
    with get_db() as db:
        db.execute("INSERT INTO settings(key,value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
        db.commit()

def logged_in():
    return session.get("user") == ADMIN_USER

# ---------- Auth ----------
@app.get("/login")
def login_form():
    if logged_in():
        return redirect(url_for("dashboard"))
    return render_template("login.html", site_name=get_setting("site_name"))

@app.post("/login")
def login():
    user = _clean(request.form.get("username",""))
    pw = _clean(request.form.get("password",""))
    if user == ADMIN_USER and pw == ADMIN_PASSWORD:
        session["user"] = user
        return redirect(url_for("dashboard"))
    flash("Invalid credentials", "error")
    return redirect(url_for("login_form"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_form"))

# ---------- Pages ----------
@app.get("/")
def home():
    if not logged_in():
        return redirect(url_for("login_form"))
    return redirect(url_for("dashboard"))

@app.get("/dashboard")
def dashboard():
    if not logged_in():
        return redirect(url_for("login_form"))
    with get_db() as db:
        keys = db.execute("""
            SELECT l.*,
                   (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id) as activation_count
            FROM licenses l
            ORDER BY l.created_at DESC
        """).fetchall()
    return render_template("dashboard.html", keys=keys, site_name=get_setting("site_name"))

@app.get("/validate")
def validate_page():
    return render_template("validate.html", site_name=get_setting("site_name"))

@app.get("/settings")
def settings_page():
    if not logged_in():
        return redirect(url_for("login_form"))
    data = {
        "site_name": get_setting("site_name"),
        "accent": get_setting("accent"),
    }
    # check if logo exists
    logo_exists = os.path.exists(os.path.join(app.static_folder, "logo.png"))
    return render_template("settings.html", data=data, logo_exists=logo_exists, site_name=data["site_name"])

@app.post("/settings")
def settings_save():
    if not logged_in():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    site_name = _clean(request.form.get("site_name","Flux Licensing"))
    accent = _clean(request.form.get("accent","fuchsia"))
    set_setting("site_name", site_name)
    set_setting("accent", accent)
    flash("Settings saved", "ok")
    return redirect(url_for("settings_page"))

@app.post("/upload_logo")
def upload_logo():
    if not logged_in():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    f = request.files.get("logo")
    if not f or f.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("settings_page"))
    ext = f.filename.rsplit(".",1)[-1].lower()
    if ext not in ALLOWED_LOGO_EXT:
        flash("Unsupported file type", "error")
        return redirect(url_for("settings_page"))
    filename = "logo.png" if ext == "png" else "logo." + ext
    path = os.path.join(app.static_folder, filename)
    f.save(path)
    # standardize to logo.png to match template reference
    if filename != "logo.png":
        # convert name by just copying (no image processing)
        try:
            os.replace(path, os.path.join(app.static_folder, "logo.png"))
        except Exception:
            pass
    flash("Logo uploaded", "ok")
    return redirect(url_for("settings_page"))

# ---------- Utilities ----------
def generate_key(prefix="FLUX", groups=4, group_len=5):
    alphabet = string.ascii_uppercase + string.digits
    parts = []
    for _ in range(groups):
        parts.append("".join(secrets.choice(alphabet) for _ in range(group_len)))
    return f"{prefix}-" + "-".join(parts)

def parse_days(days_str):
    try:
        d = int(days_str)
        if d <= 0:
            return None
        return d
    except:
        return None

# ---------- Admin APIs ----------
@app.post("/api/create_key")
def api_create_key():
    if not logged_in():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    days = parse_days(request.form.get("days",""))
    max_activations = _clean(request.form.get("max_activations","1"))
    notes = _clean(request.form.get("notes",""))
    try:
        max_activations = max(1, int(max_activations))
    except:
        max_activations = 1
    lic_key = generate_key()
    now = datetime.utcnow()
    expires_at = (now + timedelta(days=days)) if days else None
    with get_db() as db:
        db.execute("""
            INSERT INTO licenses(lic_key, created_at, expires_at, max_activations, revoked, notes)
            VALUES (?, ?, ?, ?, 0, ?)
        """, (lic_key, now, expires_at, max_activations, notes))
        db.commit()
    return jsonify({"ok": True, "key": lic_key})

@app.post("/api/revoke/<int:lic_id>")
def api_revoke(lic_id):
    if not logged_in():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    with get_db() as db:
        db.execute("UPDATE licenses SET revoked = 1 WHERE id = ?", (lic_id,))
        db.commit()
    return jsonify({"ok": True})

@app.post("/api/delete/<int:lic_id>")
def api_delete(lic_id):
    if not logged_in():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    with get_db() as db:
        db.execute("DELETE FROM licenses WHERE id = ?", (lic_id,))
        db.commit()
    return jsonify({"ok": True})

@app.get("/api/keys")
def api_keys():
    if not logged_in():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    with get_db() as db:
        rows = db.execute("""
            SELECT l.*,
                   (SELECT COUNT(*) FROM activations a WHERE a.license_id = l.id) as activation_count
            FROM licenses l
            ORDER BY l.created_at DESC
        """).fetchall()
    items = [dict(r) for r in rows]
    return jsonify({"ok": True, "items": items})

# ---------- Public validation API ----------
@app.post("/api/validate")
def api_validate():
    payload = request.get_json(silent=True) or request.form
    lic_key = _clean((payload.get("key") or "")).upper()
    machine_id = _clean(payload.get("machine_id") or "")
    now = datetime.utcnow()

    if not lic_key:
        return jsonify({"valid": False, "reason": "missing_key"}), 400
    if not machine_id:
        return jsonify({"valid": False, "reason": "missing_machine_id"}), 400

    with get_db() as db:
        lic = db.execute("SELECT * FROM licenses WHERE lic_key = ?", (lic_key,)).fetchone()
        if not lic:
            return jsonify({"valid": False, "reason": "not_found"}), 404
        if lic["revoked"]:
            return jsonify({"valid": False, "reason": "revoked"}), 403
        if lic["expires_at"] is not None:
            expires_at = lic["expires_at"]
            if isinstance(expires_at, str):
                try:
                    expires_at = datetime.fromisoformat(expires_at)
                except Exception:
                    return jsonify({"valid": False, "reason": "expired"}), 403
            if now > expires_at:
                return jsonify({"valid": False, "reason": "expired"}), 403

        activation_count = db.execute("SELECT COUNT(*) FROM activations WHERE license_id = ?", (lic["id"],)).fetchone()[0]
        existing = db.execute("SELECT * FROM activations WHERE license_id = ? AND machine_id = ?",
                              (lic["id"], machine_id)).fetchone()
        if existing:
            db.execute("UPDATE activations SET last_seen = ? WHERE id = ?", (now, existing["id"]))
            db.commit()
        else:
            if activation_count >= lic["max_activations"]:
                return jsonify({"valid": False, "reason": "activation_limit"}), 403
            db.execute("""
                INSERT INTO activations(license_id, machine_id, activated_at, last_seen)
                VALUES (?, ?, ?, ?)
            """, (lic["id"], machine_id, now, now))
            db.commit()

        remaining = lic["max_activations"] - db.execute("SELECT COUNT(*) FROM activations WHERE license_id = ?", (lic["id"],)).fetchone()[0]
        return jsonify({
            "valid": True,
            "key": lic_key,
            "expires_at": lic["expires_at"],
            "remaining_activations": max(0, remaining),
            "notes": lic["notes"]
        })

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    print("STATIC FOLDER:", app.static_folder)
    print(f"Flux Licensing Server running on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=True)
