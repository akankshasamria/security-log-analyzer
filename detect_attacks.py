
from pathlib import Path
import pandas as pd
from parse_logs import parse_logs, LOG_FILE

def detect_suspicious_ips(logs, threshold=3):
    # Keep only failed login attempts
    failed_logs = logs[logs["status"] == "failure"]

    # Count failures from each IP address
    failure_counts = (
        failed_logs.groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
    )

    # Flag IP addresses with 3 or more failures
    alerts = failure_counts[
        failure_counts["failed_attempts"] >= threshold
    ].copy()

    alerts["alert_type"] = "Multiple Failed Logins"
    alerts["severity"] = "High"

    return alerts


if __name__ == "__main__":
    logs = parse_logs(LOG_FILE)
    alerts = detect_suspicious_ips(logs)

    print("\n--- Security Alerts ---")

    if alerts.empty:
        print("No suspicious activity detected.")
    else:
        print(alerts.to_string(index=False))

    print(f"\nTotal alerts: {len(alerts)}")
