
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "data" / "security_logs.db"


def initialize_db():
    """Create database tables if they do not exist."""
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                status TEXT NOT NULL,
                UNIQUE(timestamp, ip_address, username, status)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                UNIQUE(ip_address, alert_type)
            )
        """)


def save_logs(logs):
    """Save parsed logs without inserting duplicate records."""
    records = [
        (
            str(row["timestamp"]),
            str(row["ip_address"]),
            str(row["username"]),
            str(row["status"])
        )
        for _, row in logs.iterrows()
    ]

    with sqlite3.connect(DB_FILE) as conn:
        conn.executemany("""
            INSERT OR IGNORE INTO logs
            (timestamp, ip_address, username, status)
            VALUES (?, ?, ?, ?)
        """, records)


def save_alerts(alerts):
    """Save detected security alerts."""
    records = [
        (
            str(row["ip_address"]),
            int(row["failed_attempts"]),
            str(row["alert_type"]),
            str(row["severity"])
        )
        for _, row in alerts.iterrows()
    ]

    with sqlite3.connect(DB_FILE) as conn:
        conn.executemany("""
            INSERT INTO alerts
            (ip_address, failed_attempts, alert_type, severity)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address, alert_type)
            DO UPDATE SET
                failed_attempts = excluded.failed_attempts,
                severity = excluded.severity
        """, records)


if __name__ == "__main__":
    from parse_logs import parse_logs, LOG_FILE
    from detect_attacks import detect_suspicious_ips

    initialize_db()

    logs = parse_logs(LOG_FILE)
    alerts = detect_suspicious_ips(logs)

    save_logs(logs)
    save_alerts(alerts)

    print("Database initialized successfully!")
    print(f"Database location: {DB_FILE}")
    print(f"Parsed logs processed: {len(logs)}")
    print(f"Security alerts processed: {len(alerts)}")
