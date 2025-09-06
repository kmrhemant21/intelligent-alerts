# alert-printer

A tiny webhook receiver that prints **Alertmanager** alerts to stdout.

## Endpoints
- `GET /healthz` – health probe
- `POST /alertmanager/webhook` – Alertmanager webhook target

## Run locally
```bash
cd app
pip install -r requirements.txt
python main.py
# POST a sample payload
curl -XPOST localhost:8080/alertmanager/webhook \
  -H 'Content-Type: application/json' \
  -d @sample.json


receivers:
  - name: "stdout-printer"
    webhook_configs:
      - url: "http://alert-printer.alerting.svc.cluster.local/alertmanager/webhook"
        send_resolved: true
