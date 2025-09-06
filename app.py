#!/usr/bin/env python3
from __future__ import annotations
import os, json, logging, asyncio, datetime as dt, re, hashlib
from typing import Tuple, Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from dateutil import parser as dateparser

# -------- Config from env --------
PORT                     = int(os.getenv("PORT", "8080"))
ALERT_WEBHOOK_PATH       = os.getenv("ALERT_WEBHOOK_PATH", "/alert")

LOKI_URL                 = (os.getenv("LOKI_URL", "http://loki:3100")).rstrip("/")
LOKI_TENANT_ID           = os.getenv("LOKI_TENANT_ID") or None
LOKI_BEARER_TOKEN        = os.getenv("LOKI_BEARER_TOKEN") or None
LOKI_BASIC_USER          = os.getenv("LOKI_BASIC_USER") or None  # NEW
LOKI_BASIC_PASS          = os.getenv("LOKI_BASIC_PASS") or None  # NEW

OLLAMA_URL               = (os.getenv("OLLAMA_URL", "http://ollama:11434")).rstrip("/")
OLLAMA_MODEL             = os.getenv("OLLAMA_MODEL", "llama3.2:latest")

PROM2TEAMS_BASE          = (os.getenv("PROM2TEAMS_BASE", "http://prom2teams:8089")).rstrip("/")
PROM2TEAMS_CONNECTOR     = (os.getenv("PROM2TEAMS_CONNECTOR", "Connector")).rstrip("/")

LOG_WINDOW_BEFORE_SEC    = int(os.getenv("LOG_WINDOW_BEFORE_SEC", "900"))   # 15m before startsAt
LOG_WINDOW_AFTER_SEC     = int(os.getenv("LOG_WINDOW_AFTER_SEC", "300"))    # 5m after endsAt/now
MAX_LOG_LINES            = int(os.getenv("MAX_LOG_LINES", "100"))

OLLAMA_TIMEOUT_S = float(os.getenv("OLLAMA_TIMEOUT_S", "180"))  # bump default timeout
OLLAMA_API_STYLE = "generate" #os.getenv("OLLAMA_API_STYLE", "auto") 

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("intelligent-alert")

app = FastAPI(title="intelligent-alert", version="1.1.0")

# -------- Helpers --------
def clamp(s: str, max_chars: int = 12000) -> str:
    if len(s) <= max_chars:
        return s
    return s[: max_chars // 2] + "\n...\n" + s[-max_chars // 2 :]

def to_ns(t: dt.datetime) -> int:
    return int(t.timestamp() * 1_000_000_000)

def parse_time(iso: str) -> dt.datetime:
    return dateparser.isoparse(iso)

def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()

import os, re

LLM_MAX_PROMPT_CHARS = int(os.getenv("LLM_MAX_PROMPT_CHARS", "4000"))  # clamp for LLM
LOG_FILTER_REGEX     = os.getenv("LOG_FILTER_REGEX", r"(error|exception|timeout|refused|unhealthy|oom|panic|fail|deadline)")  # optional
OLLAMA_NUM_CTX       = int(os.getenv("OLLAMA_NUM_CTX", "4096"))  # used if model supports

def clamp_for_llm(text: str) -> str:
    # keep only lines that match regex (if provided), then clamp to char budget
    try:
        pat = re.compile(LOG_FILTER_REGEX, re.IGNORECASE) if LOG_FILTER_REGEX else None
    except re.error:
        pat = None
    lines = text.splitlines()
    if pat:
        filt = [ln for ln in lines if pat.search(ln)]
        # if filtering kills everything, fall back to the last ~200 lines
        if len(filt) < 5:
            filt = lines[-200:]
    else:
        filt = lines[-200:]
    joined = "\n".join(filt)
    return joined if len(joined) <= LLM_MAX_PROMPT_CHARS else joined[:LLM_MAX_PROMPT_CHARS]

def extract_first_json_object(s: str) -> dict | None:
    """
    Robustly extract the first top-level JSON object { ... } from free text.
    Handles braces inside strings and escapes. Returns dict or None.
    """
    in_str = False
    esc = False
    depth = 0
    start = -1
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        else:
            if ch == '"':
                in_str = True
            elif ch == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == '}':
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start != -1:
                        blob = s[start:i+1]
                        try:
                            return json.loads(blob)
                        except Exception:
                            # keep scanning in case later object is parseable
                            start = -1
    return None


def build_logql_selector(labels: Dict[str, str]) -> str:
    """
    Prefer pod+namespace, else namespace+job, else job, else instance.
    """
    ns = labels.get("namespace")
    pod = labels.get("pod")
    job = labels.get("job")
    inst = labels.get("instance")
    if ns and pod:
        return f'{{namespace="{ns}", pod="{pod}"}}'
    if ns and job:
        return f'{{namespace="{ns}", job="{job}"}}'
    if job:
        return f'{{job="{job}"}}'
    if inst:
        return f'{{instance="{inst}"}}'
    return '{job=~".*"}'  # fallback (kept safe by tight time window)

async def fetch_loki_logs(labels: Dict[str, str], starts_at: str, ends_at: str) -> Tuple[str, int]:
    """
    Query Loki /loki/api/v1/query_range within a small window around startsAt/endsAt.
    Supports either Bearer token or BasicAuth (Basic used only if Bearer not set).
    Returns (joined_text, line_count).
    """
    try:
        start_dt = parse_time(starts_at)
    except Exception:
        start_dt = dt.datetime.utcnow() - dt.timedelta(minutes=15)

    # decide end bound
    if ends_at and ends_at != "0001-01-01T00:00:00Z":
        end_dt = parse_time(ends_at)
    else:
        end_dt = dt.datetime.utcnow()

    start = start_dt - dt.timedelta(seconds=LOG_WINDOW_BEFORE_SEC)
    end   = end_dt + dt.timedelta(seconds=LOG_WINDOW_AFTER_SEC)

    params = {
        "query": build_logql_selector(labels),
        "start": str(to_ns(start)),
        "end":   str(to_ns(end)),
        "limit": str(MAX_LOG_LINES),
        "direction": "backward",  # newest first
    }

    headers: Dict[str, str] = {}
    if LOKI_TENANT_ID:
        headers["X-Scope-OrgID"] = LOKI_TENANT_ID
    if LOKI_BEARER_TOKEN:
        headers["Authorization"] = f"Bearer {LOKI_BEARER_TOKEN}"

    # Decide auth mechanism: Bearer takes precedence; otherwise Basic if provided
    auth = None
    if not LOKI_BEARER_TOKEN and LOKI_BASIC_USER and LOKI_BASIC_PASS:  # NEW
        auth = httpx.BasicAuth(LOKI_BASIC_USER, LOKI_BASIC_PASS)

    url = f"{LOKI_URL}/loki/api/v1/query_range"
    async with httpx.AsyncClient(timeout=20, auth=auth) as client:  # NEW (auth=auth)
        r = await client.get(url, params=params, headers=headers)
        r.raise_for_status()
        data = r.json()

    lines: List[str] = []
    for stream in data.get("data", {}).get("result", []):
        for _, line in stream.get("values", []):
            lines.append(line)
    lines = lines[:MAX_LOG_LINES]

    return "\n".join(lines), len(lines)

def make_user_prompt(alert: Dict[str, Any], logs_text: str) -> str:
    body = {
        "status": alert.get("status"),
        "labels": alert.get("labels", {}),
        "annotations": alert.get("annotations", {}),
    }
    return (
        "ALERT:\n" + json.dumps(body, ensure_ascii=False) +
        "\n\nRECENT LOG LINES (truncated):\n" + clamp(logs_text, 12000)
    )

def _build_prompt_for_generate(alert: dict, logs_text: str) -> str:
    # Collapse system+user into a single prompt for /api/generate
    SYSTEM_PROMPT = (
        "You are an SRE/DevOps assistant. Given a Prometheus Alert and recent logs, "
        "produce ONLY a JSON object with fields: "
        "summary, root_causes (array), runbook (array), confidence (0..1). "
        "If evidence is weak, say so. Prefer safe, low-risk checks first. "
        "No prose outside JSON.\n"
    )
    from json import dumps
    user = (
        "ALERT:\n" + dumps({
            "status": alert.get("status"),
            "labels": alert.get("labels", {}),
            "annotations": alert.get("annotations", {}),
        }, ensure_ascii=False)
        + "\n\nRECENT LOG LINES (truncated):\n" + logs_text
        + "\n\nReturn ONLY valid JSON."
    )
    return SYSTEM_PROMPT + "\n" + user

async def call_ollama(alert: dict, logs_text: str) -> dict | None:

    logs_for_llm = clamp_for_llm(logs_text)  # <-- clamp aggressively

    async def _chat() -> dict | None:
        url = f"{OLLAMA_URL}/api/chat"
        payload = {
            "model": OLLAMA_MODEL,
            "stream": False,
            "options": {"num_ctx": OLLAMA_NUM_CTX},  # hint; model may cap lower
            "messages": [
                {"role": "system", "content":
                    "You are an SRE/DevOps assistant. Return ONLY JSON with "
                    "fields: summary, root_causes[], runbook[], confidence (0..1)."},
                {"role": "user", "content":
                    "ALERT:\n" + json.dumps({
                        "status": alert.get("status"),
                        "labels": alert.get("labels", {}),
                        "annotations": alert.get("annotations", {}),
                    }, ensure_ascii=False)
                    + "\n\nRECENT LOG LINES (truncated):\n" + logs_for_llm
                    + "\n\nReturn ONLY valid JSON."}
            ]
        }
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_S) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
        content = (data.get("message") or {}).get("content", "").strip()
        # robust parse
        obj = extract_first_json_object(content)
        return obj

    def _build_prompt_for_generate() -> str:
        sys = (
            "You are an SRE/DevOps assistant. Given a Prometheus Alert and recent logs, "
            "produce ONLY a JSON object with fields: "
            "summary, root_causes (array), runbook (array), confidence (0..1). "
            "If evidence is weak, say so. Prefer safe checks first. No prose outside JSON.\n"
        )
        usr = (
            "ALERT:\n" + json.dumps({
                "status": alert.get("status"),
                "labels": alert.get("labels", {}),
                "annotations": alert.get("annotations", {}),
            }, ensure_ascii=False)
            + "\n\nRECENT LOG LINES (truncated):\n" + logs_for_llm
            + "\n\nReturn ONLY valid JSON."
        )
        return sys + "\n" + usr

    async def _generate() -> dict | None:
        url = f"{OLLAMA_URL}/api/generate"
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": _build_prompt_for_generate(),
            "stream": False,
            "options": {"num_ctx": OLLAMA_NUM_CTX},  # hint
        }
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_S) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
        content = (data.get("response") or "").strip()
        obj = extract_first_json_object(content)  # robust parse
        return obj

    try:
        if OLLAMA_API_STYLE == "chat":
            return await _chat()
        elif OLLAMA_API_STYLE == "generate":
            return await _generate()
        else:
            try:
                return await _chat()
            except Exception as e:
                log.warning("chat endpoint failed (%s), falling back to /api/generate", e)
                return await _generate()
    except httpx.ReadTimeout as e:
        log.error("Ollama timeout: %s; falling back/returning None", e)
        if OLLAMA_API_STYLE == "chat":
            try:
                return await _generate()
            except Exception:
                return None
        elif OLLAMA_API_STYLE == "generate":
            try:
                return await _chat()
            except Exception:
                return None
        return None
    except Exception as e:
        log.exception("Ollama request failed: %s", e)
        return None


async def forward_to_prom2teams(enriched_payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Forward the fully enriched payload (with per-alert annotations containing llm* fields)
    to prom2teams /v2/<connector>.
    """
    url = f"{PROM2TEAMS_BASE}/"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, json=enriched_payload)
            text = ""
            try:
                text = (await r.aread()).decode("utf-8", errors="ignore")[:2048]
            except Exception:
                pass
            return r.status_code, text
    except Exception as e:
        log.exception("forward to prom2teams failed: %s", e)
        return 0, str(e)

# -------- FastAPI endpoints --------
@app.get("/health")
async def health():
    return {"ok": True}

@app.post(ALERT_WEBHOOK_PATH)
async def alert_receiver(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    alerts: List[Dict[str, Any]] = payload.get("alerts", [])

    async def enrich(a: Dict[str, Any]) -> bool:
        """
        Enrich a single alert with llm* fields and a combined `llm_response` string in annotations.
        """
        try:
            labels   = a.get("labels", {})
            startsAt = a.get("startsAt", "")
            endsAt   = a.get("endsAt", "")
            logs_text, line_count = await fetch_loki_logs(labels, startsAt, endsAt)
            llm_json = await call_ollama(a, logs_text)

            ann = a.setdefault("annotations", {})
            if llm_json:
                summary     = llm_json.get("summary", "")
                root_causes = llm_json.get("root_causes") or []
                runbook     = llm_json.get("runbook") or []
                try:
                    conf = float(llm_json.get("confidence", 0.0))
                except Exception:
                    conf = 0.0

                # Individual llm* fields
                ann["llm_summary"]      = summary
                ann["llm_root_causes"]  = " • ".join(map(str, root_causes[:6]))
                # ann["llm_runbook"]      = "\n".join(f"{i+1}. {step}" for i, step in enumerate(map(str, runbook[:12])))
                # ann["llm_confidence"]   = f"{conf:.2f}"
                # ann["llm_model"]        = OLLAMA_MODEL
                # # ann["llm_logs_used"]    = f"{'\n'.join(logs_text.splitlines()[:5])}\n...[{line_count} lines], sha1={sha1(logs_text)}"
                # sample = "\n".join(logs_text.splitlines()[:5])
                # ann["llm_logs_used"]    = f"{sample}\n...[{line_count} lines], sha1={sha1(logs_text)}"

                # Combined single-field string (for easy consumption)  # NEW
                combined = {
                    "summary": summary,
                    "root_causes": root_causes,
                    "runbook": runbook,
                    "confidence": conf,
                    "model": OLLAMA_MODEL,
                }
                # ann["llm_response"] = json.dumps(combined, ensure_ascii=False)  # NEW
            else:
                ann["llm_summary"]     = "AI suggestion unavailable (empty logs or model error)."
                ann["llm_root_causes"] = ""
                # ann["llm_runbook"]     = ""
                # ann["llm_confidence"]  = "0.00"
                # ann["llm_model"]       = OLLAMA_MODEL
                # # ann["llm_logs_used"]   = f"{'\n'.join(logs_text.splitlines()[:5])}\n...[{line_count} lines], sha1={sha1(logs_text)}"
                # sample = "\n".join(logs_text.splitlines()[:5])
                # ann["llm_logs_used"]    = f"{sample}\n...[{line_count} lines], sha1={sha1(logs_text)}"
                # ann["llm_response"]    = json.dumps({  # NEW
                #     "summary": ann["llm_summary"],
                #     "root_causes": [],
                #     "runbook": [],
                #     "confidence": 0.0,
                #     "model": OLLAMA_MODEL,
                # }, ensure_ascii=False)

            return True
        except Exception as e:
            log.exception("enrich failed: %s", e)
            return False

    results = await asyncio.gather(*(enrich(a) for a in alerts))

    # Forward the SAME 'payload' object; each alert now has llm* inside annotations
    status, pt_text = await forward_to_prom2teams(payload)

    return JSONResponse({
        "enriched_alerts": sum(1 for x in results if x),
        "prom2teams_status": status,
        "prom2teams_reply": pt_text,
    }, status_code=200)

# Run with: uvicorn app:app --host 0.0.0.0 --port 8080
