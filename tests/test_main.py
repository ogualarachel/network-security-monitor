from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import load_traffic, detect_threats


def record(
    minute,
    port,
    status="success",
    source="10.0.0.2",
    destination="10.0.0.1",
):
    return {
        "timestamp": datetime(2026, 1, 1) + timedelta(minutes=minute),
        "source_ip": source,
        "destination_ip": destination,
        "port": port,
        "status": status,
    }


def test_load_sample_csv():
    traffic = load_traffic()

    assert len(traffic) == 24
    assert isinstance(traffic[0]["port"], int)


def test_port_scan():
    traffic = [record(0, port) for port in (21, 22, 23, 80, 443)]

    alerts = detect_threats(traffic)

    assert any(
        alert["threat_type"] == "Potential Port Scan"
        for alert in alerts
    )


def test_repeated_failures():
    traffic = [record(0, 22, "failed") for _ in range(5)]

    alerts = detect_threats(traffic)

    assert any(
        alert["threat_type"] == "Repeated Failed Connections"
        for alert in alerts
    )


def test_high_volume():
    traffic = [record(0, 443) for _ in range(12)]

    alerts = detect_threats(traffic)

    assert any(
        alert["threat_type"] == "High Connection Volume"
        for alert in alerts
    )


def test_normal_traffic():
    traffic = [
        record(0, 443),
        record(1, 443),
        record(2, 80),
    ]

    assert detect_threats(traffic) == []


def test_window_and_destination_isolation():
    traffic = [
        record(i * 10, 100 + i)
        for i in range(5)
    ]

    assert detect_threats(traffic) == []

    traffic = [
        record(
            0,
            100 + i,
            destination=f"10.0.0.{i + 1}",
        )
        for i in range(5)
    ]

    assert detect_threats(traffic) == []


def test_invalid_csv(tmp_path):
    file = tmp_path / "bad.csv"

    file.write_text(
        "source_ip,port\n10.0.0.1,22\n"
    )

    try:
        load_traffic(file)

    except ValueError as exc:
        assert "columns" in str(exc)

    else:
        raise AssertionError("Expected ValueError")