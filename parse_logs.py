
from pathlib import Path
import pandas as pd

# Locate the sample log file
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "sample_logs.csv"

def parse_logs(file_path):
    # Load CSV data
    df = pd.read_csv(file_path)

    # Required columns
    required_columns = [
        "timestamp",
        "ip_address",
        "username",
        "status"
    ]

    # Check that all required columns exist
    missing_columns = set(required_columns) - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    # Keep only the required columns
    df = df[required_columns].copy()

    # Clean text fields
    for column in ["ip_address", "username", "status"]:
        df[column] = df[column].astype("string").str.strip()

    # Standardize login status
    df["status"] = df["status"].str.lower()

    # Convert timestamps
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    # Remove rows with missing or invalid values
    df = df.dropna(subset=required_columns)

    # Keep only valid login statuses
    df = df[df["status"].isin(["success", "failure"])]

    # Remove duplicate records
    df = df.drop_duplicates()

    # Sort logs chronologically
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


if __name__ == "__main__":
    logs = parse_logs(LOG_FILE)

    print("\n--- Parsed Security Logs ---")
    print(logs.to_string(index=False))

    print("\n--- Summary ---")
    print(f"Total valid log records: {len(logs)}")
    print(f"Successful logins: {(logs['status'] == 'success').sum()}")
    print(f"Failed logins: {(logs['status'] == 'failure').sum()}")
    print(f"Unique IP addresses: {logs['ip_address'].nunique()}")
    print(f"Unique usernames: {logs['username'].nunique()}")
