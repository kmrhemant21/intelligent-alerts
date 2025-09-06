import os, sys, json, logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    stream=sys.stdout,
)

app = Flask(__name__)

@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200

@app.post("/alertmanager/webhook")
def alertmanager_webhook():
    """
    Receives Alertmanager webhook payload and prints to stdout.
    Docs: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
    """
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception as e:
        logging.exception("Invalid JSON payload")
        return jsonify({"error": str(e)}), 400

    # 1) Print raw JSON line (structured logging)
    try:
        print(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "alertmanager_webhook",
            "payload": payload
        }), flush=True)
    except Exception:
        logging.exception("Failed to print raw payload")

    # 2) Also print a concise, human‑readable line per alert
    alerts = payload.get("alerts", [])
    for a in alerts:
        status = a.get("status")
        labels = a.get("labels", {})
        annotations = a.get("annotations", {})
        startsAt = a.get("startsAt")
        endsAt = a.get("endsAt")

        # Common quick fields
        name = labels.get("alertname", "unknown")
        severity = labels.get("severity", "unknown")
        instance = labels.get("instance") or labels.get("pod") or labels.get("job", "n/a")
        summary = annotations.get("summary") or annotations.get("description") or ""

        logging.info(
            "[%s] alertname=%s severity=%s instance=%s startsAt=%s endsAt=%s summary=%s",
            status, name, severity, instance, startsAt, endsAt, summary.replace("\n", " ")[:500]
        )

    return jsonify({"received": len(alerts)}), 200

if __name__ == "__main__":
    # For local/dev only. In containers we use Gunicorn.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
