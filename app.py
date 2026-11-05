import ipaddress
import os
import re
import sqlite3
from datetime import datetime
from urllib.parse import urlsplit

from flask import Flask, flash, redirect, render_template, request, url_for

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-key")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "signin", "confirm", "wallet", "billing", "recover",
    "authenticate", "webscr", "unlock"
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
}
SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".work", ".country"}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                category TEXT NOT NULL,
                reasons TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)


def normalize_and_validate(raw_url):
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if len(value) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    # Require an explicit scheme to avoid ambiguous input.
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("URL must start with http:// or https://.")
    if not parts.hostname:
        raise ValueError("The URL must contain a valid hostname.")
    if any(ch.isspace() for ch in value):
        raise ValueError("URL must not contain spaces.")
    try:
        # Accessing .port also validates malformed port values.
        _ = parts.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")
    return value, parts


def analyze_url(raw_url):
    url, parts = normalize_and_validate(raw_url)
    host = (parts.hostname or "").lower().rstrip(".")
    score = 0
    reasons = []

    def flag(points, message):
        nonlocal score
        score += points
        reasons.append(message)

    if parts.scheme.lower() != "https":
        flag(10, "The URL does not use HTTPS. This is a caution, not proof of phishing.")

    try:
        ipaddress.ip_address(host.strip("[]"))
        flag(25, "The hostname is an IP address instead of a regular domain.")
    except ValueError:
        pass

    if "@" in parts.netloc:
        flag(25, "The URL contains '@' in its network location, which can disguise the destination.")

    if len(url) > 100:
        flag(10, "The URL is unusually long (over 100 characters).")
    if len(host.split(".")) >= 5:
        flag(10, "The hostname has many subdomain levels.")

    host_labels = host.split(".")
    if any(label.startswith("xn--") for label in host_labels):
        flag(15, "The hostname contains an internationalized/punycode label; inspect it carefully.")

    matched_keywords = sorted(k for k in SUSPICIOUS_KEYWORDS if k in url.lower())
    if matched_keywords:
        flag(min(20, 5 + 3 * len(matched_keywords)),
             "Potentially sensitive keywords found: " + ", ".join(matched_keywords) + ".")

    if host in SHORTENERS:
        flag(15, "The hostname belongs to a known URL-shortening service, which hides the final destination.")

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flag(10, "The hostname uses a TLD that may deserve extra scrutiny.")

    # Hyphens are common on legitimate domains, so the weight is intentionally low.
    if host.count("-") >= 2:
        flag(5, "The hostname contains multiple hyphens.")

    score = min(score, 100)
    if score >= 50:
        category = "High Risk"
    elif score >= 25:
        category = "Suspicious"
    else:
        category = "Lower Risk"

    if not reasons:
        reasons.append("No configured warning rules were triggered. This does not guarantee the URL is safe.")

    return {
        "url": url,
        "host": host,
        "score": score,
        "category": category,
        "reasons": reasons,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        raw_url = request.form.get("url", "")
        try:
            result = analyze_url(raw_url)
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO scans (url, score, category, reasons, scanned_at) VALUES (?, ?, ?, ?, ?)",
                    (result["url"], result["score"], result["category"],
                     "\n".join(result["reasons"]), result["scanned_at"])
                )
        except ValueError as exc:
            flash(str(exc), "error")
    with get_db() as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high_risk = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE category = ?", ("High Risk",)
        ).fetchone()[0]
        suspicious = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE category = ?", ("Suspicious",)
        ).fetchone()[0]
        recent = conn.execute(
            "SELECT id, url, score, category, scanned_at FROM scans ORDER BY id DESC LIMIT 5"
        ).fetchall()
    return render_template(
        "index.html", result=result, total_scans=total_scans,
        high_risk=high_risk, suspicious=suspicious, recent=recent
    )


@app.route("/history")
def history():
    with get_db() as conn:
        scans = conn.execute(
            "SELECT id, url, score, category, reasons, scanned_at FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return render_template("history.html", scans=scans)


@app.route("/history/clear", methods=["POST"])
def clear_history():
    with get_db() as conn:
        conn.execute("DELETE FROM scans")
    flash("Scan history cleared.", "success")
    return redirect(url_for("history"))


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


init_db()

if __name__ == "__main__":
    # Debug mode is for local development only. Do not expose this server to the internet.
    app.run(debug=True)
