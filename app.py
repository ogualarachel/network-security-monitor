"""Read-only Flask dashboard for sample network security analysis."""

from collections import Counter
from flask import Flask, render_template
from main import analyse

app = Flask(__name__)


@app.route("/")
def dashboard():
    try:
        traffic, alerts = analyse()
        error = None

    except (OSError, ValueError) as exc:
        traffic, alerts = [], []
        error = str(exc)

    sources = Counter(row["source_ip"] for row in traffic)
    threats = Counter(alert["threat_type"] for alert in alerts)

    return render_template(
        "dashboard.html",
        traffic=traffic,
        alerts=alerts,
        sources=sources.most_common(5),
        threats=threats,
        unique_ips=len(sources),
        error=error,
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1")