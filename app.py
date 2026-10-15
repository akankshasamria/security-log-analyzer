
import sqlite3
from pathlib import Path
from flask import Flask, render_template

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "data" / "security_logs.db"


@app.route("/health")
def health():
    return {
        "status": "success",
        "message": "Security Log Analyzer backend is running"
    }


@app.route("/")
def dashboard():
    if not DB_FILE.exists():
        return "Database not found. Run python database.py first.", 500

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

        recent_logs = conn.execute("""
            SELECT timestamp, ip_address, username, status
            FROM logs
            ORDER BY timestamp DESC
            LIMIT 10
        """).fetchall()

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
        alerts=alerts
    )


if __name__ == "__main__":
    app.run(port=5001, debug=True)
