# HIPAA Security Rule Audit and Configuration Monitoring Suite

This suite is a defensive compliance verification tool designed to automate the checking of administrative, physical, and technical safeguards required under the HIPAA Security Rule.

It works by auditing configurations, scanning logs, and verifying encryption settings, and outputs a professional PDF report detailing its findings.

## Installation

Ensure you have Python 3.12+ installed.
Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

You can run the suite using the main orchestrator script, `audit_runner.py`.

```bash
python audit_runner.py --help
```

### Example

To run the suite with the included mock data (simulating a local audit):

```bash
python audit_runner.py --target-url https://example.com --output My_HIPAA_Report.pdf
```

## Modules

* **Data at Rest Auditor (`auditors/data_at_rest.py`)**: Checks database configurations (currently mock Postgres/Mongo configs) for Volume/TDE encryption settings.
* **Data in Transit Auditor (`auditors/data_in_transit.py`)**: Connects to a target web endpoint and verifies that it negotiates a strong TLS version (1.2 or 1.3).
* **Audit Controls Monitor (`log_monitors/audit_logger.py`)**: Parses application JSON logs to verify that user actions are recorded with a User ID and timestamp, and flags unauthenticated access.
* **Access Control Config Check (`config_checks/access_control.py`)**: Analyzes an IAM/Roles JSON configuration to identify violations of the Principle of Least Privilege.
* **Report Generator (`compliance_reports/report_generator.py`)**: Aggregates all findings into a PDF using ReportLab.
