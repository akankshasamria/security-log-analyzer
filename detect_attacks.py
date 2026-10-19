
import pandas as pd


def detect_suspicious_ips(logs, threshold=3):
    """
    Detect IP addresses with repeated failed login attempts.

    Args:
        logs: DataFrame containing ip_address and status columns.
        threshold: Minimum failed attempts required for an alert.

    Returns:
        DataFrame containing suspicious IP addresses and alert details.
    """
    required_columns = {"ip_address", "status"}

    if not required_columns.issubset(logs.columns):
        raise ValueError("Logs must contain ip_address and status columns.")

    failures = logs[
        logs["status"].astype(str).str.strip().str.lower() == "failure"
    ]

    suspicious = (
        failures.groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
    )

    suspicious = suspicious[suspicious["failed_attempts"] >= threshold].copy()

    suspicious["alert_type"] = "Multiple Failed Logins"
    suspicious["severity"] = "High"

    return suspicious.reset_index(drop=True)
