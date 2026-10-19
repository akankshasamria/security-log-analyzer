# Security Log Analyzer

A Python-based security monitoring application that analyzes login logs, detects suspicious login activity, and displays security alerts through a Flask web dashboard.

## Overview

The Security Log Analyzer helps identify potentially suspicious login behavior by examining login records and counting failed attempts from individual IP addresses. It stores log data in SQLite and provides a dashboard for reviewing login activity.

## Features

- Parse and clean login log data using Pandas.
- Detect IP addresses with repeated failed login attempts.
- Generate alerts for suspicious login activity.
- Store login records and alerts in an SQLite database.
- View recent login activity in a Flask dashboard.
- Filter login records by IP address and status.
- Export filtered login records as CSV.
- Run automated tests with pytest.

## Technologies Used

- Python
- Flask
- Pandas
- SQLite
- HTML and CSS
- pytest
- Git and GitHub

## Project Structure

```text
security-log-analyzer/
├── app.py
├── database.py
├── parse_logs.py
├── detect_attacks.py
├── test_security_analyzer.py
├── tests/
├── templates/
├── screenshots/
├── data/
│   └── sample_logs.csv
├── .gitignore
└── README.md
```

## Installation and Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/akankshasamria/security-log-analyzer.git
   cd security-log-analyzer
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   ```

   On Windows PowerShell:

   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

3. Install the required packages:

   ```bash
   python -m pip install flask pandas pytest
   ```

   Install any additional dependencies required by the project.

4. Initialize the database and process the sample logs:

   ```bash
   python database.py
   ```

5. Start the Flask application:

   ```bash
   python app.py
   ```

6. Open the dashboard at:

   `http://127.0.0.1:5001/`

## How Detection Works

1. Login records are loaded and cleaned.
2. Failed login events are grouped by IP address.
3. The application counts the failed attempts for each IP.
4. IP addresses reaching the configured threshold are flagged.
5. Alerts are saved to SQLite and displayed on the dashboard.

The current detection rule is based on repeated failed login attempts. It is a basic rule-based demonstration, not a complete intrusion detection system.

## Screenshots

### Main Dashboard

![Security Log Analyzer dashboard](screenshots/dashboard.png)

### Filtered Login Records

![Filtered login records](screenshots/filtered-logs.png)

## Running Tests

Run the automated test suite:

```bash
python -m pytest -v
```

The current test suite contains five tests covering log parsing, suspicious IP detection, threshold behavior, and the Flask health endpoint.

## Limitations

- Uses sample login data rather than live production security logs.
- Detects suspicious behavior using a configurable failed-login threshold.
- Does not replace a production SIEM or comprehensive security monitoring platform.

## Future Improvements

- Add charts for login activity over time.
- Support uploading log files through the dashboard.
- Add date-range filters and additional detection rules.
- Improve dashboard reporting and alert prioritization.

## Author

Akanksha Samria

GitHub: https://github.com/akankshasamria
