"""Network Security Monitor: analysis of  CSV connection logs and flags suspicious patterns."""

import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REQUIRED_COLUMNS = {"timestamp", "source_ip", "destination_ip", "port", "status"}


def load_traffic(path=BASE_DIR / "traffic.csv"):
    """Return the validated connection records from a CSV file."""
    records = []

    with open(path, newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
            raise ValueError(
                f"CSV must contain columns: {', '.join(sorted(REQUIRED_COLUMNS))}"
            )

        for line_number, row in enumerate(reader, start=2):
            try:
                record = {
                    "timestamp": datetime.fromisoformat(row["timestamp"].strip()),
                    "source_ip": row["source_ip"].strip(),
                    "destination_ip": row["destination_ip"].strip(),
                    "port": int(row["port"].strip()),
                    "status": row["status"].strip().lower(),
                }

                if not (0 <= record["port"] <= 65535):
                    raise ValueError("port out of range")

                if not record["source_ip"] or not record["destination_ip"]:
                    raise ValueError("IP address missing")

                if record["status"] not in {"success", "failed"}:
                    raise ValueError("status must be success or failed")

            except (ValueError, AttributeError, TypeError) as exc:
                raise ValueError(
                    f"Invalid CSV record on line {line_number}: {exc}"
                ) from exc

            records.append(record)

    return sorted(records, key=lambda record: record["timestamp"])


def make_alert(
    threat_type,
    severity,
    source_ip,
    destination_ip,
    count,
    start,
    end,
    explanation,
):
    return {
        "threat_type": threat_type,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "count": count,
        "first_seen": start.isoformat(sep=" "),
        "last_seen": end.isoformat(sep=" "),
        "explanation": explanation,
    }


def detect_threats(
    traffic,
    window_minutes=5,
    port_threshold=5,
    failure_threshold=5,
    volume_threshold=12,
):
    """Detects the suspicious activity within rolling time windows."""

    if window_minutes <= 0 or min(
        port_threshold, failure_threshold, volume_threshold
    ) < 1:
        raise ValueError(
            "Window must be positive and thresholds must be at least 1"
        )

    groups = defaultdict(list)

    for record in traffic:
        groups[
            (record["source_ip"], record["destination_ip"])
        ].append(record)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for (source_ip, destination_ip), records in groups.items():
        records = sorted(records, key=lambda item: item["timestamp"])

        found = set()
        left = 0

        for right, current in enumerate(records):
            while current["timestamp"] - records[left]["timestamp"] > window:
                left += 1

            recent = records[left:right + 1]

            ports = {item["port"] for item in recent}

            failures = sum(
                item["status"] == "failed" for item in recent
            )

            checks = [
                (
                    "Potential Port Scan",
                    len(ports) >= port_threshold,
                    len(ports),
                    "HIGH",
                    f"Contacted {len(ports)} different destination ports "
                    f"within {window_minutes} minutes.",
                ),
                (
                    "Repeated Failed Connections",
                    failures >= failure_threshold,
                    failures,
                    "MEDIUM",
                    f"Made {failures} failed connection attempts "
                    f"within {window_minutes} minutes.",
                ),
                (
                    "High Connection Volume",
                    len(recent) >= volume_threshold,
                    len(recent),
                    "MEDIUM",
                    f"Made {len(recent)} connections "
                    f"within {window_minutes} minutes.",
                ),
            ]

            for threat_type, triggered, count, severity, explanation in checks:
                if triggered and threat_type not in found:
                    alerts.append(
                        make_alert(
                            threat_type,
                            severity,
                            source_ip,
                            destination_ip,
                            count,
                            recent[0]["timestamp"],
                            current["timestamp"],
                            explanation,
                        )
                    )
                    found.add(threat_type)

            if len(found) == 3:
                break

    return sorted(
        alerts,
        key=lambda alert: (alert["first_seen"], alert["threat_type"]),
    )


def save_alerts(alerts, path=BASE_DIR / "alerts.json"):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)

    return path


def analyse(
    path=BASE_DIR / "traffic.csv",
    window_minutes=5,
    port_threshold=5,
    failure_threshold=5,
    volume_threshold=12,
):
    traffic = load_traffic(path)

    alerts = detect_threats(
        traffic,
        window_minutes,
        port_threshold,
        failure_threshold,
        volume_threshold,
    )

    return traffic, alerts


def main():
    parser = argparse.ArgumentParser(
        description="Analyse CSV network connection logs"
    )

    parser.add_argument("--file", default=str(BASE_DIR / "traffic.csv"))
    parser.add_argument("--window", type=int, default=5)
    parser.add_argument("--ports", type=int, default=5)
    parser.add_argument("--failures", type=int, default=5)
    parser.add_argument("--volume", type=int, default=12)

    args = parser.parse_args()

    try:
        traffic, alerts = analyse(
            args.file,
            args.window,
            args.ports,
            args.failures,
            args.volume,
        )

        output = save_alerts(alerts)

    except (OSError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")

    print(f"Analysed {len(traffic)} network connections")
    print(f"Found {len(alerts)} potential security alerts")

    for alert in alerts:
        print(
            f"[{alert['severity']}] {alert['threat_type']} | "
            f"{alert['source_ip']} -> {alert['destination_ip']} | "
            f"{alert['explanation']}"
        )

    print(f"Alerts saved to {output}")


if __name__ == "__main__":
    main()