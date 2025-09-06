# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# health endpoint is /healthz
EXPOSE 8080
CMD ["gunicorn", "--workers", "2", "--threads", "4", "--timeout", "30", "-b", "0.0.0.0:8080", "main:app"]
