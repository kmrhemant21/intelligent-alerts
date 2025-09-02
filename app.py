# app.py
import os
import re
import json
import time
import asyncio
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ------------------ Logging ------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_JSON = os.getenv("LOG_JSON", "false").lower() == "true"
LOG_PAYLOAD_FULL = os.getenv("LOG_PAYLOAD_FULL", "true").lower() == "true"
LOG_EXCERPT_CHARS = int(os.getenv("LOG_EXCERPT_CHARS", "800"))
LOG_LINES_SAMPLE = int(os.getenv("LOG_LINES_SAMPLE", "20"))

def _setup_logger():
    level = getattr(logging, LOG_LEVEL, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    return logging.getLogger("llm-relay")

logger = _setup_logger()

def _truncate(s: str, n: int = LOG_EXCERPT_CHARS) -> str:
    if s is None:
        return ""
    return s if len(s) <= n else s[: n - 3] + "..."

def _j(event: str, **fields):
    """Emit a structured log line."""
    try:
        if LOG_JSON:
            payload = {"event": event, **fields}
            logger.info(json.dumps(payload, default=str, ensure_ascii=False))
        else:
            logger.info("%s | %s", event, _truncate(json.dumps(fields, default=str, ensure_ascii=False)))
    except Exception as e:
        logger.warning("log_emit_failed %s %s", event, e)

# ---- LangChain (Ollama) ----
from langchain_ollama import ChatOllama
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# ------------------ ENV ------------------
LOKI_URL: str = os.getenv("LOKI_URL", "http://loki:3100")
LOKI_BEARER_TOKEN: Optional[str] = os.getenv("LOKI_BEARER_TOKEN")
LOKI_BASIC_USER: Optional[str] = os.getenv("LOKI_BASIC_USER")
LOKI_BASIC_PASS: Optional[str] = os.getenv("LOKI_BASIC_PASS")
LOKI_TENANT_ID: Optional[str] = os.getenv("LOKI_TENANT_ID")

OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1")
OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_TEMPERATURE: float = float(os.getenv("OLLAMA_TEMPERATURE", "0"))
LLM_TIMEOUT_SEC: float = float(os.getenv("LLM_TIMEOUT_SEC", "25"))

P2T_BASE: str = os.getenv("P2T_BASE", "http://prom2teams.monitoring.svc.cluster.local:8089")
P2T_CONNECTOR: str = os.getenv("P2T_CONNECTOR", "default")

LOG_WINDOW_MIN: int = int(os.getenv("LOG_WINDOW_MIN", "15"))
PRE_ROLL_MIN: int = int(os.getenv("PRE_ROLL_MIN", "1"))
LOKI_LIMIT: int = int(os.getenv("LOKI_LIMIT", "2000"))
MAX_LOG_CHARS: int = int(os.getenv("MAX_LOG_CHARS", "6000"))

RATE_LIMIT_MAX: int = int(os.getenv("RATE_LIMIT_MAX", "8"))
RATE_LIMIT_WINDOW_SEC: int = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))

REQUEST_TIMEOUT_SEC: float = float(os.getenv("REQUEST_TIMEOUT_SEC", "30"))
LOKI_RETRY_ATTEMPTS: int = int(os.getenv("LOKI_RETRY_ATTEMPTS", "2"))
LOKI_RETRY_BACKOFF_SEC: float = float(os.getenv("LOKI_RETRY_BACKOFF_SEC", "1.0"))

PROCESS_RESOLVED: bool = os.getenv("PROCESS_RESOLVED", "false").lower() == "true"

LOG_FILTER_REGEX: str = os.getenv(
    "LOG_FILTER_REGEX",
    r"error|exception|timeout|fail|unavailable|panic|SEVERE|CRITICAL"
)

DEFAULT_FALLBACKS = [
    '{{job="{job}"}}',
    '{{service="{service}"}}',
    '{{instance="{instance}"}}',
    '{{namespace="{namespace}"}}',
    '{{pod="{pod}"}}',
    '{{container="{container}"}}',
    '{{app="{app}"}}',
    '{{job=~".+"}}'  # non-empty regex → always valid
]
try:
    LOKI_FALLBACK_QUERIES: List[str] = json.loads(os.getenv("LOKI_FALLBACK_QUERIES", "[]"))
    if not isinstance(LOKI_FALLBACK_QUERIES, list):
        LOKI_FALLBACK_QUERIES = []
except Exception:
    LOKI_FALLBACK_QUERIES = []

LOKI_CACHE_TTL_SEC: int = int(os.getenv("LOKI_CACHE_TTL_SEC", "20"))

# ------------------ FastAPI ------------------
app = FastAPI(title="LLM Relay (LangChain) → prom2teams", version="1.2.0")

# ------------------ LangChain setup ------------------
llm = ChatOllama(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_URL,
    temperature=OLLAMA_TEMPERATURE,
)

SYSTEM_PROMPT = """You are a senior SRE assistant.
Given an Alertmanager payload and recent logs, return **Markdown** with four sections:

# What happened
- 3–6 bullets, concise and factual

# Most likely causes (ranked)
1. ...
2. ...
3. ...

# Recommended actions (step-by-step)
- Start with fastest checks / mitigations
- Include commands or dashboards if relevant

# Useful follow-up queries
- LogQL: ...
- PromQL: ...
If information is missing, say exactly what to check or where to look.
"""

prompt = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human",
     "Alert (JSON):\n{alert_json}\n\n"
     "LogQL used:\n{logql}\n\n"
     "Log summary:\n{log_stats}\n\n"
     "Recent logs (newest first, truncated):\n{logs_excerpt}\n")
])
chain = prompt | llm | StrOutputParser()

# ------------------ Pydantic models ------------------
class Alert(BaseModel):
    status: str
    labels: Dict[str, Any] = Field(default_factory=dict)
    annotations: Dict[str, Any] = Field(default_factory=dict)
    startsAt: str
    endsAt: Optional[str] = None
    generatorURL: Optional[str] = None
    fingerprint: Optional[str] = None

class AlertBatch(BaseModel):
    receiver: Optional[str] = "llm-relay"
    status: str
    alerts: List[Alert]
    groupLabels: Optional[Dict[str, Any]] = None
    commonLabels: Optional[Dict[str, Any]] = None
    commonAnnotations: Optional[Dict[str, Any]] = None
    externalURL: Optional[str] = None
    version: Optional[str] = None
    groupKey: Optional[str] = None

# ------------------ Rate limiter ------------------
_rate_cache: Dict[str, List[float]] = {}
def rate_limited(key: str) -> bool:
    now = time.time()
    q = [t for t in _rate_cache.get(key, []) if now - t <= RATE_LIMIT_WINDOW_SEC]
    if len(q) >= RATE_LIMIT_MAX:
        _rate_cache[key] = q
        return True
    q.append(now); _rate_cache[key] = q
    return False

# ------------------ Loki helpers ------------------
def to_dt(rfc3339: str) -> datetime:
    return datetime.fromisoformat(rfc3339.replace("Z", "+00:00"))

def parse_ends_at(ends_at: Optional[str]) -> Optional[datetime]:
    if not ends_at:
        return None
    try:
        dt = to_dt(ends_at)
        if dt.year < 1971:
            return None
        return dt
    except Exception:
        return None

def ns_epoch(dt: datetime) -> str:
    return str(int(dt.timestamp() * 1e9))

def _append_regex(selector: str) -> str:
    regex = LOG_FILTER_REGEX.strip()
    return f'{selector} |~ "{regex}"' if regex else selector

def build_logql_candidates(labels: Dict[str, Any]) -> List[str]:
    ns = labels.get("namespace") or labels.get("kubernetes_namespace") or ""
    pod = labels.get("pod") or labels.get("kubernetes_pod_name") or ""
    app_label = labels.get("app") or labels.get("app_kubernetes_io_name") or labels.get("job") or ""
    container = labels.get("container") or labels.get("container_name") or ""
    cluster = labels.get("cluster") or ""
    job = labels.get("job") or ""
    service = labels.get("service") or ""
    instance = labels.get("instance") or ""

    parts = []
    if ns: parts.append(f'namespace="{ns}"')
    if pod: parts.append(f'pod="{pod}"')
    if container: parts.append(f'container="{container}"')
    if app_label: parts.append(f'app="{app_label}"')
    if cluster: parts.append(f'cluster="{cluster}"')
    primary = "{" + ",".join(parts) + "}" if parts else '{job=~".+"}'

    fallbacks = LOKI_FALLBACK_QUERIES or DEFAULT_FALLBACKS
    fmt = {"namespace": ns, "pod": pod, "container": container, "app": app_label,
           "cluster": cluster, "job": job, "service": service, "instance": instance}
    rendered: List[str] = []
    for tpl in fallbacks:
        try:
            s = tpl.format(**fmt)
            if ('=""' in s) or ('=~""' in s) or ('=~".*"' in s):
                continue
            if s and s not in rendered:
                rendered.append(s)
        except Exception:
            continue

    candidates = [primary] + [s for s in rendered if s != primary]
    candidates = [_append_regex(s) for s in candidates]
    logger.debug("logql_candidates | %s", json.dumps({"candidates": candidates}, ensure_ascii=False))
    return candidates

_IP_PORT_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?\b")

def normalize_line(line: str) -> str:
    line = re.sub(r"\b[0-9a-f]{7,40}\b", "<id>", line, flags=re.IGNORECASE)
    line = re.sub(r"\b[0-9]{4,}\b", "<num>", line)
    line = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?", "<ts>", line)
    line = _IP_PORT_RE.sub("<ip>", line)
    return line.strip()

def summarize_logs(raw_lines: List[str], top_n: int = 8) -> Tuple[str, str]:
    if not raw_lines:
        return "No matching logs in the time window.", ""
    levels = {"error": 0, "warn": 0, "info": 0, "debug": 0}
    for ln in raw_lines:
        l = ln.lower()
        if any(l.startswith(x) or f" {x} " in f" {l} " for x in ["error", "err", "level=error"]):
            levels["error"] += 1
        elif any(x in l for x in [" warn", "level=warn", "warning"]):
            levels["warn"] += 1
        elif any(x in l for x in [" info", "level=info"]):
            levels["info"] += 1
        elif any(x in l for x in [" debug", "level=debug"]):
            levels["debug"] += 1

    c = Counter(normalize_line(ln) for ln in raw_lines)
    top = c.most_common(top_n)

    stats = [
        f"- Counts by level: error={levels['error']}, warn={levels['warn']}, info={levels['info']}, debug={levels['debug']}",
        "- Top repeating messages:"
    ]
    for msg, cnt in top:
        if not msg: continue
        preview = msg if len(msg) < 160 else msg[:157] + "..."
        stats.append(f"  - ({cnt}×) {preview}")

    text = "\n".join(raw_lines)
    excerpt = text[-MAX_LOG_CHARS:] if len(text) > MAX_LOG_CHARS else text
    return "\n".join(stats), excerpt

# ---- Loki query (timeout-safe) ----
_loki_cache: Dict[str, Tuple[float, List[str]]] = {}

def _httpx_timeout() -> httpx.Timeout:
    return httpx.Timeout(connect=min(REQUEST_TIMEOUT_SEC, 10.0),
                         read=REQUEST_TIMEOUT_SEC,
                         write=REQUEST_TIMEOUT_SEC,
                         pool=None)

async def _do_loki_request(params: Dict[str, str], headers: Dict[str, str], auth: Optional[Tuple[str, str]]) -> Dict[str, Any]:
    timeout = _httpx_timeout()
    async with httpx.AsyncClient(timeout=timeout) as client:
        last_exc: Optional[Exception] = None
        for attempt in range(1, LOKI_RETRY_ATTEMPTS + 1):
            try:
                r = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, headers=headers, auth=auth)
                if r.status_code != 200:
                    raise HTTPException(502, f"Loki error: {r.text}")
                return r.json()
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.WriteTimeout) as e:
                last_exc = e
                logger.warning("loki_timeout | %s", json.dumps({"attempt": attempt, "params": params}, ensure_ascii=False))
            except httpx.RequestError as e:
                last_exc = e
                logger.warning("loki_request_error | %s", json.dumps({"attempt": attempt, "error": str(e)}, ensure_ascii=False))
            if attempt < LOKI_RETRY_ATTEMPTS:
                await asyncio.sleep(LOKI_RETRY_BACKOFF_SEC * attempt)
        if isinstance(last_exc, httpx.ReadTimeout):
            raise HTTPException(504, f"Loki timeout after {LOKI_RETRY_ATTEMPTS} attempt(s)")
        raise HTTPException(502, f"Loki request failed: {type(last_exc).__name__}: {last_exc}")

async def query_loki(logql: str, start: datetime, end: datetime) -> List[str]:
    key = f"{logql}|{int(start.timestamp())}|{int(end.timestamp())}"
    now = time.time()
    cached = _loki_cache.get(key)
    if cached and now - cached[0] <= LOKI_CACHE_TTL_SEC:
        logger.debug("loki_cache_hit | %s", json.dumps({"key": key}, ensure_ascii=False))
        return cached[1]

    headers: Dict[str, str] = {}
    if LOKI_TENANT_ID:
        headers["X-Scope-OrgID"] = LOKI_TENANT_ID
    auth = None
    if LOKI_BEARER_TOKEN:
        headers["Authorization"] = f"Bearer {LOKI_BEARER_TOKEN}"
    elif LOKI_BASIC_USER and LOKI_BASIC_PASS:
        auth = (LOKI_BASIC_USER, LOKI_BASIC_PASS)

    params = {
        "query": logql,
        "start": ns_epoch(start),
        "end": ns_epoch(end),
        "direction": "backward",
        "limit": str(LOKI_LIMIT),
    }
    data = await _do_loki_request(params, headers, auth)
    streams = data.get("data", {}).get("result", [])

    lines: List[str] = []
    for st in streams:
        for _ts, line in st.get("values", []):
            lines.append(line.rstrip())

    _loki_cache[key] = (now, lines)
    _j("loki_query_done", logql=logql, start=start.isoformat(), end=end.isoformat(), lines=len(lines))
    if lines and LOG_LINES_SAMPLE > 0:
        sample = lines[:LOG_LINES_SAMPLE]
        logger.debug("loki_lines_sample | %s", _truncate("\n".join(sample)))
    return lines

async def query_loki_with_fallbacks(labels: Dict[str, Any], starts_at: datetime, ends_at: Optional[datetime]) -> Tuple[str, List[str]]:
    end = ends_at or datetime.now(timezone.utc)
    start = max(starts_at - timedelta(minutes=PRE_ROLL_MIN), end - timedelta(minutes=LOG_WINDOW_MIN))
    candidates = build_logql_candidates(labels)
    _j("loki_candidates_built", candidates=candidates, start=start.isoformat(), end=end.isoformat())

    for candidate in candidates:
        try:
            lines = await query_loki(candidate, start, end)
        except HTTPException as e:
            _j("loki_candidate_failed", candidate=candidate, error=str(e))
            continue
        if lines:
            _j("loki_candidate_selected", candidate=candidate, lines=len(lines))
            return candidate, lines

    base = candidates[0]
    if '|~' in base:
        plain = base.split('|~')[0].strip()
        try:
            lines = await query_loki(plain, start, end)
            if lines:
                _j("loki_no_regex_fallback_selected", candidate=plain, lines=len(lines))
                return plain, lines
        except HTTPException as e:
            _j("loki_no_regex_fallback_failed", candidate=plain, error=str(e))

    _j("loki_no_lines_found", candidate=base)
    return base, []

# ------------------ prom2teams forward ------------------
async def forward_to_prom2teams(batch: Dict[str, Any]) -> int:
    url = f"{P2T_BASE}/v2/{P2T_CONNECTOR}"
    try:
        async with httpx.AsyncClient(timeout=_httpx_timeout()) as client:
            r = await client.post(url, json=batch)
            _j("forward_to_prom2teams_done", status=r.status_code)
            return r.status_code
    except httpx.HTTPError as e:
        _j("forward_to_prom2teams_error", error=str(e))
        return -1

# ------------------ Routes ------------------
@app.get("/healthz")
async def healthz():
    _j("healthz", model=OLLAMA_MODEL)
    return {
        "ok": True,
        "model": OLLAMA_MODEL,
        "process_resolved": PROCESS_RESOLVED,
        "log_filter_regex": LOG_FILTER_REGEX,
        "cache_ttl_sec": LOKI_CACHE_TTL_SEC,
        "loki_retries": LOKI_RETRY_ATTEMPTS,
        "loki_backoff_sec": LOKI_RETRY_BACKOFF_SEC,
    }

# ---- Ad-hoc explainer ----
class ExplainReq(BaseModel):
    labels: Dict[str, Any] = Field(default_factory=dict)
    startsAt: Optional[str] = None
    endsAt: Optional[str] = None
    minutes: int = LOG_WINDOW_MIN

@app.post("/explain")
async def explain(req: ExplainReq):
    starts_at = to_dt(req.startsAt) if req.startsAt else (datetime.now(timezone.utc) - timedelta(minutes=req.minutes))
    ends_at = parse_ends_at(req.endsAt)
    _j("explain_request", labels=req.labels, startsAt=starts_at.isoformat(), endsAt=(ends_at.isoformat() if ends_at else None))

    try:
        logql, lines = await query_loki_with_fallbacks(req.labels, starts_at, ends_at)
        log_stats, excerpt = summarize_logs(lines)
    except HTTPException as e:
        logql = "(invalid or rejected by Loki)"
        log_stats = f"Loki query failed: {getattr(e, 'detail', str(e))}"
        excerpt = ""

    try:
        _j("llm_invoke_start", route="explain")
        t0 = time.time()
        text = await asyncio.wait_for(chain.ainvoke({
            "alert_json": json.dumps({"labels": req.labels, "startsAt": starts_at.isoformat(), "endsAt": (ends_at.isoformat() if ends_at else None)}, indent=2),
            "logql": logql,
            "log_stats": log_stats,
            "logs_excerpt": excerpt or "(no logs)",
        }), timeout=LLM_TIMEOUT_SEC)
        dt_ms = int((time.time() - t0) * 1000)
        _j("llm_invoke_done", latency_ms=dt_ms, preview=_truncate(text))
    except asyncio.TimeoutError:
        text = ("LLM timeout while generating explanation. Review the log summary and try again with a narrower window.")
        _j("llm_timeout", route="explain")
    except Exception as e:
        text = f"LLM generation failed: {type(e).__name__}: {e}"
        _j("llm_error", error=str(e), route="explain")

    return {"logql": logql, "stats": log_stats, "explanation": text}

# ------------------ Alert path ------------------
@app.post("/alert")
async def handle_alert(batch: AlertBatch):
    # Batch-level log
    summary = {
        "receiver": batch.receiver,
        "status": batch.status,
        "alerts": len(batch.alerts),
        "groupKey": batch.groupKey,
        "groupLabels": batch.groupLabels,
    }
    _j("alert_batch_received", **summary)
    if LOG_PAYLOAD_FULL:
        # Full payload (truncated to avoid huge lines)
        logger.debug("alert_batch_payload | %s", _truncate(json.dumps(batch.model_dump(), default=str, ensure_ascii=False), 10 * LOG_EXCERPT_CHARS))

    async def process_alert(a: Alert) -> Alert:
        is_resolved = (a.status or "").lower() == "resolved"
        key = f"{a.labels.get('alertname','')}|{a.labels.get('namespace','')}|{a.labels.get('instance','')}"
        limited = rate_limited(key)
        try:
            starts_at = to_dt(a.startsAt)
        except Exception:
            starts_at = datetime.now(timezone.utc) - timedelta(minutes=LOG_WINDOW_MIN)
        ends_at = parse_ends_at(a.endsAt)

        _j("alert_processing_start",
           key=key, resolved=is_resolved, rate_limited=limited,
           startsAt=starts_at.isoformat(), endsAt=(ends_at.isoformat() if ends_at else None),
           labels=a.labels)

        # Skip resolved unless configured
        if is_resolved and not PROCESS_RESOLVED:
            a.annotations = a.annotations or {}
            a.annotations["llm_recommendation"] = "Alert is resolved; skipping analysis."
            a.annotations["llm_logql"] = "(skipped)"
            a.annotations["llm_log_stats"] = "Resolved alert; no action required."
            _j("alert_skipped_resolved", key=key)
            return a

        recommendation = ""
        logql_used = ""
        excerpt = ""
        log_stats = "Rate-limited; skipping LLM/logs." if limited else ""

        if limited:
            recommendation = "Rate limit reached for this alert key. LLM suggestion was skipped to protect capacity."
            _j("alert_rate_limited", key=key)
        else:
            try:
                logql_used, lines = await query_loki_with_fallbacks(a.labels, starts_at, ends_at)
                log_stats, excerpt = summarize_logs(lines)
                _j("loki_summary",
                   key=key, logql=logql_used, lines=len(lines),
                   stats_preview=_truncate(log_stats))
            except HTTPException as e:
                logql_used = "(invalid or rejected by Loki)"
                log_stats = f"Loki query failed: {getattr(e, 'detail', str(e))}"
                excerpt = ""
                _j("loki_error", key=key, error=str(e))

            inputs = {
                "alert_json": json.dumps(a.model_dump(), indent=2, default=str),
                "logql": logql_used or "(no query)",
                "log_stats": log_stats,
                "logs_excerpt": excerpt or "(no matching logs found)",
            }
            try:
                _j("llm_invoke_start", route="alert", key=key)
                t0 = time.time()
                recommendation = await asyncio.wait_for(chain.ainvoke(inputs), timeout=LLM_TIMEOUT_SEC)
                dt_ms = int((time.time() - t0) * 1000)
                _j("llm_invoke_done", route="alert", key=key, latency_ms=dt_ms, preview=_truncate(recommendation))
                log_stats += f"\n- LLM latency: {dt_ms} ms"
            except asyncio.TimeoutError:
                recommendation = "LLM generation timed out. Use the follow-up queries to continue the investigation."
                _j("llm_timeout", route="alert", key=key)
            except Exception as e:
                recommendation = f"LLM generation failed: {type(e).__name__}: {e}"
                _j("llm_error", route="alert", key=key, error=str(e))

        a.annotations = a.annotations or {}
        a.annotations["llm_recommendation"] = recommendation
        a.annotations["llm_logql"] = logql_used or "(no query)"
        a.annotations["llm_log_stats"] = log_stats
        _j("alert_processing_done", key=key, has_recommendation=bool(recommendation))
        return a

    processed_alerts = await asyncio.gather(*(process_alert(a) for a in batch.alerts))
    out_batch = batch.model_dump()
    out_batch["alerts"] = [a.model_dump() for a in processed_alerts]

    forward_status = await forward_to_prom2teams(out_batch)
    _j("alert_batch_forwarded", count=len(processed_alerts), status=forward_status)
    # Always 200 so Alertmanager doesn't retry the webhook forever
    return {"ok": True, "forward_status": forward_status, "alerts": len(processed_alerts)}
