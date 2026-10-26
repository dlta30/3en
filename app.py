```python
import os
import hmac
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET", "")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SCANNER_API_KEY = os.environ.get("SCANNER_API_KEY", "")

db = SQLAlchemy(app)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player = db.Column(db.String(100), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    total_files = db.Column(db.Integer, nullable=False, default=0)
    flagged_files = db.Column(db.Integer, nullable=False, default=0)
    results = db.Column(db.JSON, nullable=False, default=list)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def check_configuration():
    if request.endpoint in ("health", "static"):
        return None
    if not app.config["SECRET_KEY"] or not ADMIN_PASSWORD:
        return (
            "الموقع يحتاج ضبط APP_SECRET و ADMIN_PASSWORD في Render Environment.",
            503
        )
    return None


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/login")
@app.post("/login")
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password, ADMIN_PASSWORD):
            session.clear()
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("كلمة المرور غير صحيحة.")
    return render_template("login.html")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@admin_required
def dashboard():
    scans = Scan.query.order_by(desc(Scan.created_at)).limit(200).all()
    total_scans = Scan.query.count()
    flagged_total = db.session.query(
        db.func.coalesce(db.func.sum(Scan.flagged_files), 0)
    ).scalar()
    return render_template(
        "dashboard.html",
        scans=scans,
        total_scans=total_scans,
        flagged_total=flagged_total
    )


@app.get("/scan/<int:scan_id>")
@admin_required
def scan_detail(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)
    return render_template("scan_detail.html", scan=scan)


@app.post("/api/scan-results")
def receive_scan():
    if not SCANNER_API_KEY:
        return jsonify({
            "ok": False,
            "error": "Scanner API key is not configured"
        }), 503

    supplied_key = request.headers.get("X-Scanner-Key", "")
    if not hmac.compare_digest(supplied_key, SCANNER_API_KEY):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    if not request.is_json:
        return jsonify({"ok": False, "error": "JSON required"}), 400

    payload = request.get_json(silent=True) or {}
    player = str(payload.get("player", "")).strip()[:100]
    results = payload.get("results", [])

    if not player:
        return jsonify({"ok": False, "error": "Player name required"}), 400

    if not isinstance(results, list) or len(results) > 5000:
        return jsonify({"ok": False, "error": "Invalid results"}), 400

    safe_results = []
    flagged = 0

    for item in results:
        if not isinstance(item, dict):
            continue

        filename = str(item.get("file", ""))[:255]
        hits = item.get("hits", [])

        if not isinstance(hits, list):
            hits = []

        hits = [str(hit)[:100] for hit in hits[:30]]
        if hits:
            flagged += 1

        safe_results.append({
            "file": filename,
            "hits": hits
        })

    scan = Scan(
        player=player,
        total_files=len(safe_results),
        flagged_files=flagged,
        results=safe_results
    )
    db.session.add(scan)
    db.session.commit()

    return jsonify({"ok": True, "scan_id": scan.id}), 201


with app.app_context():
    if not app.config["SQLALCHEMY_DATABASE_URI"]:
        raise RuntimeError("DATABASE_URL is missing; configure PostgreSQL in Render.")
    if not app.config["SECRET_KEY"] or not ADMIN_PASSWORD:
        raise RuntimeError(
            "Set APP_SECRET and ADMIN_PASSWORD in Render Environment."
        )
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
```
