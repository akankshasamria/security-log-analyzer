
import sqlite3
from pathlib import Path
from flask import Flask, render_template, request, Response
import csv
import io

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "data" / "security_logs.db"



@app.route("/")
def dashboard():
    if not DB_FILE.exists():
        return "Database not found. Run python database.py first.", 500

    ip_filter = request.args.get("ip", "").strip()
    username_filter = request.args.get("username", "").strip()
    status_filter = request.args.get("status", "").strip().lower()

    query = """
        SELECT timestamp, ip_address, username, status
        FROM logs
        WHERE 1=1
    """
    params = []

    if ip_filter:
        query += " AND ip_address LIKE ?"
        params.append(f"%{ip_filter}%")

    if username_filter:
        query += " AND username LIKE ?"
        params.append(f"%{username_filter}%")

    if status_filter in ("success", "failure"):
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY timestamp DESC LIMIT 500"

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row

        total_logs = conn.execute(
            "SELECT COUNT(*) FROM logs"
        ).fetchone()[0]

        failed_logins = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE status = 'failure'"
        ).fetchone()[0]

        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        recent_logs = conn.execute(query, params).fetchall()

        alerts = conn.execute("""
            SELECT ip_address, failed_attempts, alert_type, severity
            FROM alerts
            ORDER BY failed_attempts DESC
        """).fetchall()

    return render_template(
        "index.html",
        total_logs=total_logs,
        failed_logins=failed_logins,
        total_alerts=total_alerts,
        recent_logs=recent_logs,
        alerts=alerts,
        ip_filter=ip_filter,
        username_filter=username_filter,
        status_filter=status_filter
    )

@app.route("/export")
def export_logs():
    if not DB_FILE.exists():
        return "Database not found. Run python database.py first.", 500

    ip_filter = request.args.get("ip", "").strip()
    username_filter = request.args.get("username", "").strip()
    status_filter = request.args.get("status", "").strip().lower()

    query = """
        SELECT timestamp, ip_address, username, status
        FROM logs
        WHERE 1=1
    """
    params = []

    if ip_filter:
        query += " AND ip_address LIKE ?"
        params.append(f"%{ip_filter}%")

    if username_filter:
        query += " AND username LIKE ?"
        params.append(f"%{username_filter}%")

    if status_filter in ("success", "failure"):
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY timestamp DESC"

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(query, params).fetchall()

    output = io.StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow(["Timestamp", "IP Address", "Username", "Status"])
    writer.writerows(rows)

    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )
    response.headers["Content-Disposition"] = (
        "attachment; filename=security_logs.csv"
    )
    return response

@app.route("/health")
def health():
    return {
        "status": "success",
        "message": "Security Log Analyzer backend is running"
    }


if __name__ == "__main__":
    app.run(port=5001, debug=True)

