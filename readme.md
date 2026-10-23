# Network Security Monitor & Threat Detection

A Python cybersecurity portfolio prototype that analyses synthetic
network connection logs stored in CSV files.

The application identifies potentially suspicious activity and
displays security alerts in a local Flask dashboard.

## Features

- Load and validate network traffic CSV records
- Detect potential port scanning
- Detect repeated failed connection attempts
- Detect unusually high connection volumes
- Analyse traffic using configurable time windows
- Generate security alerts with severity levels
- Save alerts to JSON
- Display alerts and statistics in a Flask dashboard
- Run automated tests with pytest

## Technologies

- Python
- CSV and JSON
- Flask
- HTML and CSS
- pytest
- Git and GitHub

## Installation

Install the required Python packages:

```bash
python -m pip install -r requirements.txt
```

## Running the analyser

```bash
python main.py
```

The program reads traffic.csv, analyses the connections,
displays potential security alerts and saves them to alerts.json.

## Running the dashboard

```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Running tests

```bash
python -m pytest -q
```

## Detection rules

Potential Port Scan:
Five or more different destination ports contacted by the
same source IP on the same destination IP within five minutes.

Repeated Failed Connections:
Five or more failed connections within five minutes.

High Connection Volume:
Twelve or more connections within five minutes.

These thresholds are configurable and intended for demonstration.

## Limitations

This is an educational cybersecurity prototype.

It analyses saved CSV connection logs rather than capturing
live network packets. Detection results indicate potentially
suspicious activity and do not prove that an attack occurred.

The dashboard is intended for local use only.

## Future improvements

- Import authorised PCAP-derived network traffic
- Add interactive filtering to the dashboard
- Store alerts in a database
- Add more detection rules
- Improve false-positive handling

## Responsible use

Use synthetic traffic or network data that you own or
are explicitly authorised to analyse.