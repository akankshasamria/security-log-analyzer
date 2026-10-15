
import pandas as pd

from parse_logs import parse_logs
from detect_attacks import detect_suspicious_ips


def test_parse_logs_removes_duplicates(tmp_path):
    csv_file = tmp_path / "logs.csv"

    csv_file.write_text(
        "timestamp,ip_address,username,status\n"
        "2026-10-15 09:00:00,10.0.0.1,alice,success\n"
        "2026-10-15 09:00:00,10.0.0.1,alice,success\n",
        encoding="utf-8"
    )

    logs = parse_logs(csv_file)

    assert len(logs) == 1
    assert logs.iloc[0]["status"] == "success"


def test_detect_suspicious_ips():
    logs = pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-10-15 09:00:00",
            "2026-10-15 09:01:00",
            "2026-10-15 09:02:00",
        ]),
        "ip_address": ["10.0.0.5", "10.0.0.5", "10.0.0.5"],
        "username": ["bob", "bob", "bob"],
        "status": ["failure", "failure", "failure"],
    })

    alerts = detect_suspicious_ips(logs, threshold=3)

    assert len(alerts) == 1
    assert alerts.iloc[0]["ip_address"] == "10.0.0.5"
    assert alerts.iloc[0]["failed_attempts"] == 3
