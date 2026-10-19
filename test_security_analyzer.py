
import pandas as pd
from detect_attacks import detect_suspicious_ips
from app import app


def test_detects_suspicious_ip():
    logs = pd.DataFrame({
        "ip_address": [
            "192.168.1.20",
            "192.168.1.20",
            "192.168.1.20",
            "192.168.1.10",
        ],
        "status": ["failure", "failure", "failure", "success"],
    })

    alerts = detect_suspicious_ips(logs, threshold=3)

    assert len(alerts) == 1
    assert alerts.iloc[0]["ip_address"] == "192.168.1.20"
    assert alerts.iloc[0]["failed_attempts"] == 3


def test_no_alert_below_threshold():
    logs = pd.DataFrame({
        "ip_address": ["192.168.1.20", "192.168.1.20"],
        "status": ["failure", "failure"],
    })

    alerts = detect_suspicious_ips(logs, threshold=3)

    assert len(alerts) == 0


def test_health_endpoint():
    app.config["TESTING"] = True
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"
