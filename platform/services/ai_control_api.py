#!/usr/bin/env python3
import os
import re
import json
import datetime
import subprocess
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

from ai_action_ledger import (
    CentralizedActionLedger,
    DEFAULT_ALERTS_FILE,
    RESPONSE_ID as LEDGER_RESPONSE_ID,
    json_loads_safe,
)

APP = Flask(__name__)
CORS(APP)

RESPONSE_ID = os.getenv("AI_RESPONSE_ID", LEDGER_RESPONSE_ID)
ALERTS_FILE = os.getenv("AI_ALERTS_FILE", DEFAULT_ALERTS_FILE)
AUDIT_FILE = os.getenv("AI_CONTROL_AUDIT_FILE", "/var/ossec/logs/ai-control-api.jsonl")

CONTROL_SETTINGS_FILE = os.getenv(
    "AI_CONTROL_SETTINGS_FILE",
    "/var/ossec/logs/ai-control-settings.json",
)

MODEL_PRESETS = ["llama3.2", "gpt-oss:120b-cloud", "other"]

DEFAULT_CONTROL_SETTINGS = {
    "rag_detection": {
        "model_type": "llama3.2",
        "custom_model": "",
        "max_threads": 2,
    },
    "rag_response": {
        "model_type": "llama3.2",
        "custom_model": "",
        "max_threads": 2,
        "auto_response_min_level": 15,
    },
}

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://192.168.56.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "45"))

AI_RAG_DETECTION_UNIT = os.getenv("AI_RAG_DETECTION_UNIT", "ai-rag-detection.service")
AI_RAG_RESPONSE_UNIT = os.getenv("AI_RAG_RESPONSE_UNIT", "ai-rag-response.service")

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333").rstrip("/")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "RAG_response_knowledge")
QDRANT_TIMEOUT = int(os.getenv("QDRANT_TIMEOUT", "10"))
QDRANT_SCROLL_LIMIT = int(os.getenv("QDRANT_SCROLL_LIMIT", "200"))

DISPATCHER_BIN = os.getenv(
    "AI_RESPONSE_DISPATCHER_BIN",
    "/var/ossec/active-response/bin/ai_response_dispatcher.py",
)
PYTHON_BIN = os.getenv("AI_PYTHON_BIN", "/usr/bin/python3")

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
WAZUH_INDEXER_INDEX_PATTERN = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")
WAZUH_INDEXER_TIMEOUT = int(os.getenv("WAZUH_INDEXER_TIMEOUT", "15"))
WAZUH_INDEXER_VERIFY_TLS = str(
    os.getenv("WAZUH_INDEXER_VERIFY_TLS", "false")
).strip().lower() in ("1", "true", "yes", "on")

ACTION_TO_REMOTE_COMMAND = {
    "block_ip": "ai-block-ip0",
    "kill_process": "ai-kill-process0",
    "quarantine_file": "ai-quarantine-file0",
    "disable_user": "ai-disable-user0",
    "isolate_host": "ai-isolate-host0",
}

ACTION_TO_LOCAL_COMMAND = {
    "block_ip": "ai-block-ip",
    "kill_process": "ai-kill-process",
    "quarantine_file": "ai-quarantine-file",
    "disable_user": "ai-disable-user",
    "isolate_host": "ai-isolate-host",
}

ROLLBACK_SUPPORTED = {
    "block_ip",
    "quarantine_file",
    "disable_user",
    "isolate_host",
}



def _json_response(ok: bool, **kwargs):
    payload = {"ok": ok}
    payload.update(kwargs)
    return jsonify(payload)


def _now_utc_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _write_audit(entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
    item = dict(entry)
    item["timestamp"] = _now_utc_iso()
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_bool(value: Any) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _parse_ts(value: str) -> Optional[datetime.datetime]:
    if not value:
        return None
    raw = str(value).strip()
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        elif raw.endswith("+0000"):
            raw = raw[:-5] + "+00:00"
        return datetime.datetime.fromisoformat(raw)
    except Exception:
        return None


def _get_sortable_ts(value: str) -> Tuple[int, str]:
    dt = _parse_ts(value)
    if not dt:
        return (0, value or "")
    return (1, dt.isoformat())


def _ensure_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _ensure_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_parameters(parameters: Dict[str, Any]) -> Dict[str, str]:
    parameters = _ensure_dict(parameters)
    return {
        "ip": _normalize_text(parameters.get("ip", "")),
        "path": _normalize_text(parameters.get("path", "")),
        "user": _normalize_text(parameters.get("user", "")),
        "tty": _normalize_text(parameters.get("tty", "")),
        "service_name": _normalize_text(parameters.get("service_name", "")),
    }


def _load_alerts() -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    if not os.path.exists(ALERTS_FILE):
        return alerts

    with open(ALERTS_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json_loads_safe(line)
            if obj:
                alerts.append(obj)

    alerts.sort(key=lambda a: _get_sortable_ts(_normalize_text(a.get("timestamp", ""))))
    return alerts


def _alert_data(alert: Dict[str, Any]) -> Dict[str, Any]:
    data = alert.get("data", {})
    return data if isinstance(data, dict) else {}


def _alert_rule(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = alert.get("rule", {})
    return rule if isinstance(rule, dict) else {}


def _alert_ref_string(alert: Dict[str, Any]) -> str:
    if _normalize_text(alert.get("id")):
        return _normalize_text(alert.get("id"))
    if _normalize_text(alert.get("_document_id")):
        return _normalize_text(alert.get("_document_id"))
    sort_value = alert.get("_sort")
    if isinstance(sort_value, list) and sort_value:
        return _normalize_text(sort_value[0])
    return ""


def _find_alert_by_ref(alerts: List[Dict[str, Any]], alert_ref: str) -> Optional[Dict[str, Any]]:
    alert_ref = _normalize_text(alert_ref)
    if not alert_ref:
        return None

    for alert in alerts:
        if _normalize_text(alert.get("id")) == alert_ref:
            return alert
        if _normalize_text(alert.get("_document_id")) == alert_ref:
            return alert
        sort_value = alert.get("_sort")
        if isinstance(sort_value, list) and sort_value and _normalize_text(sort_value[0]) == alert_ref:
            return alert
    return None


def _ledger_snapshot() -> Dict[str, Any]:
    ledger = CentralizedActionLedger(alerts_file=ALERTS_FILE, response_id=RESPONSE_ID)

    if _indexer_enabled():
        indexer_alerts = _indexer_load_response_alerts(response_id=RESPONSE_ID, limit=5000)

        if indexer_alerts:
            snapshot = ledger.load_from_alerts(indexer_alerts, source="wazuh_indexer")
            snapshot["source_detail"] = {
                "indexer_url": WAZUH_INDEXER_URL,
                "index_pattern": WAZUH_INDEXER_INDEX_PATTERN,
                "hits": len(indexer_alerts),
            }
            return snapshot

        _write_audit({
            "event": "ledger_fallback_to_archive",
            "reason": "indexer_enabled_but_no_response_alerts_found",
            "response_id": RESPONSE_ID,
        })

    return ledger.load()


def _indexer_enabled() -> bool:
    return bool(WAZUH_INDEXER_URL)


def _indexer_auth():
    if WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD:
        return (WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD)
    return None


def _indexer_request(method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not _indexer_enabled():
        raise RuntimeError("Indexer is not configured")

    url = f"{WAZUH_INDEXER_URL}{path}"
    kwargs: Dict[str, Any] = {
        "timeout": WAZUH_INDEXER_TIMEOUT,
        "verify": WAZUH_INDEXER_VERIFY_TLS,
    }

    auth = _indexer_auth()
    if auth:
        kwargs["auth"] = auth

    if body is not None:
        kwargs["json"] = body
        kwargs["headers"] = {"Content-Type": "application/json"}

    response = requests.request(method, url, **kwargs)
    response.raise_for_status()

    if not response.text.strip():
        return {}
    return response.json()


def _indexer_hit_to_alert(hit: Dict[str, Any]) -> Dict[str, Any]:
    source = _ensure_dict(hit.get("_source"))
    alert = dict(source)
    alert["_document_id"] = _normalize_text(hit.get("_id"))
    alert["_index_name"] = _normalize_text(hit.get("_index"))
    alert["_sort"] = _ensure_list(hit.get("sort"))
    return alert


def _indexer_search_hits(body: Dict[str, Any], limit: int = 10) -> List[Dict[str, Any]]:
    if not _indexer_enabled():
        return []

    search_body = dict(body)
    search_body.setdefault("size", limit)
    search_body.setdefault("_source", True)

    result = _indexer_request("POST", f"/{WAZUH_INDEXER_INDEX_PATTERN}/_search", search_body)
    hits = _ensure_dict(result.get("hits")).get("hits", []) or []
    output: List[Dict[str, Any]] = []

    for hit in hits:
        if isinstance(hit, dict):
            output.append(_indexer_hit_to_alert(hit))

    return output


def _indexer_total_alerts() -> Optional[int]:
    if not _indexer_enabled():
        return None

    try:
        result = _indexer_request(
            "POST",
            f"/{WAZUH_INDEXER_INDEX_PATTERN}/_count",
            {"query": {"match_all": {}}},
        )
        return _safe_int(result.get("count"), 0)
    except Exception as exc:
        _write_audit({
            "event": "indexer_count_failed",
            "error": str(exc),
        })
        return None


def _is_epoch_millis(text: str) -> bool:
    text = _normalize_text(text)
    return text.isdigit() and len(text) >= 10


def _epoch_millis_to_utc_iso(ms_text: str) -> Optional[str]:
    try:
        value = int(ms_text)
        dt = datetime.datetime.fromtimestamp(value / 1000.0, tz=datetime.timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _indexer_find_alert_by_ref(alert_ref: str) -> Optional[Dict[str, Any]]:
    alert_ref = _normalize_text(alert_ref)
    if not alert_ref or not _indexer_enabled():
        return None

    try:
        hits = _indexer_search_hits(
            {
                "size": 1,
                "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": {
                    "ids": {
                        "values": [alert_ref],
                    }
                },
            },
            limit=1,
        )
        if hits:
            return hits[0]
    except Exception as exc:
        _write_audit({
            "event": "indexer_find_by_document_id_failed",
            "alert_ref": alert_ref,
            "error": str(exc),
        })

    try:
        hits = _indexer_search_hits(
            {
                "size": 3,
                "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"id.keyword": alert_ref}},
                            {"term": {"id": alert_ref}},
                            {"term": {"data.id.keyword": alert_ref}},
                            {"term": {"data.id": alert_ref}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            },
            limit=3,
        )
        if hits:
            return hits[0]
    except Exception as exc:
        _write_audit({
            "event": "indexer_find_by_source_id_failed",
            "alert_ref": alert_ref,
            "error": str(exc),
        })

    if _is_epoch_millis(alert_ref):
        pivot = _epoch_millis_to_utc_iso(alert_ref)
        if pivot:
            try:
                pivot_dt = _parse_ts(pivot)
                if pivot_dt:
                    start = (pivot_dt - datetime.timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
                    end = (pivot_dt + datetime.timedelta(seconds=5)).isoformat().replace("+00:00", "Z")

                    hits = _indexer_search_hits(
                        {
                            "size": 10,
                            "sort": [{"timestamp": {"order": "asc", "unmapped_type": "date"}}],
                            "query": {
                                "range": {
                                    "timestamp": {
                                        "gte": start,
                                        "lte": end,
                                    }
                                }
                            },
                        },
                        limit=10,
                    )

                    for hit in hits:
                        sort_value = hit.get("_sort")
                        if isinstance(sort_value, list) and sort_value and _normalize_text(sort_value[0]) == alert_ref:
                            return hit

                    if hits:
                        return hits[0]
            except Exception as exc:
                _write_audit({
                    "event": "indexer_find_by_sort_failed",
                    "alert_ref": alert_ref,
                    "error": str(exc),
                })

    return None


def _indexer_search_alerts(question: str, agent_id: str = "", limit: int = 5) -> List[Dict[str, Any]]:
    if not _indexer_enabled():
        return []

    must: List[Dict[str, Any]] = []
    filters: List[Dict[str, Any]] = []

    if _normalize_text(question):
        must.append({
            "simple_query_string": {
                "query": question,
                "fields": [
                    "full_log^3",
                    "rule.description^2",
                    "rule.groups",
                    "agent.name^2",
                    "agent.id^2",
                    "manager.name",
                    "location",
                    "data.*",
                ],
                "default_operator": "and",
            }
        })
    else:
        must.append({"match_all": {}})

    if _normalize_text(agent_id):
        filters.append({
            "bool": {
                "should": [
                    {"term": {"agent.id": agent_id}},
                    {"term": {"data.target_agent_id": agent_id}},
                    {"term": {"data.ai_agent_info.id": agent_id}},
                    {"term": {"data.target_endpoint.agent_id": agent_id}},
                ],
                "minimum_should_match": 1,
            }
        })

    try:
        return _indexer_search_hits(
            {
                "size": limit,
                "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": {
                    "bool": {
                        "must": must,
                        "filter": filters,
                    }
                },
            },
            limit=limit,
        )
    except Exception as exc:
        _write_audit({
            "event": "indexer_search_failed",
            "question": question,
            "agent_id": agent_id,
            "error": str(exc),
        })
        return []

def _indexer_load_response_alerts(response_id: str = RESPONSE_ID, limit: int = 5000) -> List[Dict[str, Any]]:
    if not _indexer_enabled():
        return []

    size = min(max(limit, 1), 5000)

    body = {
        "size": size,
        "sort": [
            {"timestamp": {"order": "asc", "unmapped_type": "date"}}
        ],
        "query": {
            "bool": {
                "should": [
                    {"term": {"data.response_id.keyword": response_id}},
                    {"term": {"data.response_id": response_id}},
                    {"match_phrase": {"data.response_id": response_id}}
                ],
                "minimum_should_match": 1
            }
        }
    }

    try:
        hits = _indexer_search_hits(body, limit=size)

        _write_audit({
            "event": "indexer_load_response_alerts",
            "response_id": response_id,
            "hits": len(hits),
            "index_pattern": WAZUH_INDEXER_INDEX_PATTERN,
        })

        return hits

    except Exception as exc:
        _write_audit({
            "event": "indexer_load_response_alerts_failed",
            "response_id": response_id,
            "error": str(exc),
            "index_pattern": WAZUH_INDEXER_INDEX_PATTERN,
        })
        return []

def _resolve_alert_by_ref(alerts: List[Dict[str, Any]], alert_ref: str) -> Tuple[Optional[Dict[str, Any]], str]:
    alert_ref = _normalize_text(alert_ref)
    if not alert_ref:
        return None, ""

    local_alert = _find_alert_by_ref(alerts, alert_ref)
    if local_alert:
        return local_alert, "archive"

    indexer_alert = _indexer_find_alert_by_ref(alert_ref)
    if indexer_alert:
        return indexer_alert, "indexer"

    return None, ""


def _build_all_alerts_summary(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    local_total_alerts = len(alerts)
    indexed_total_alerts = _indexer_total_alerts()

    total_alerts = indexed_total_alerts if indexed_total_alerts is not None else local_total_alerts
    source_mode = "indexer" if indexed_total_alerts is not None else "archive_file"

    by_level = Counter()
    by_agent = Counter()
    by_rule_id = Counter()
    by_rule_description = Counter()

    oldest_ts = ""
    newest_ts = ""

    if alerts:
        oldest_ts = _normalize_text(alerts[0].get("timestamp"))
        newest_ts = _normalize_text(alerts[-1].get("timestamp"))

    for alert in alerts[-5000:]:
        rule = _alert_rule(alert)
        agent = _ensure_dict(alert.get("agent"))

        level = _normalize_text(rule.get("level", "unknown"))
        rule_id = _normalize_text(rule.get("id", "unknown"))
        description = _normalize_text(rule.get("description", "unknown"))
        agent_key = _normalize_text(agent.get("id")) or _normalize_text(_alert_data(alert).get("target_agent_id")) or "unknown"

        by_level[level] += 1
        by_rule_id[rule_id] += 1
        by_rule_description[description] += 1
        by_agent[agent_key] += 1

    if source_mode == "indexer":
        summary = (
            "Indexer summary: %s alerts available in the Wazuh indexer. "
            "Local archive file currently loaded contains %s alerts."
            % (total_alerts, local_total_alerts)
        )
    else:
        summary = (
            "Archive summary: %s alerts available in the local archive file. Oldest=%s, newest=%s."
            % (total_alerts, oldest_ts or "unknown", newest_ts or "unknown")
        )

    return {
        "source_mode": source_mode,
        "total_alerts": total_alerts,
        "indexed_total_alerts": indexed_total_alerts,
        "local_archive_alerts": local_total_alerts,
        "oldest_timestamp_in_loaded_archive": oldest_ts,
        "newest_timestamp_in_loaded_archive": newest_ts,
        "by_level_from_loaded_archive": dict(by_level),
        "top_agents_from_loaded_archive": by_agent.most_common(10),
        "top_rule_ids_from_loaded_archive": by_rule_id.most_common(10),
        "top_rule_descriptions_from_loaded_archive": by_rule_description.most_common(10),
        "summary": summary,
    }


def _build_alert_context(alert: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "alert_ref": _alert_ref_string(alert),
        "alert_id": _normalize_text(alert.get("id")),
        "document_id": _normalize_text(alert.get("_document_id")),
        "sort": alert.get("_sort"),
        "index_name": _normalize_text(alert.get("_index_name")),
        "timestamp": _normalize_text(alert.get("timestamp")),
        "agent": _ensure_dict(alert.get("agent")),
        "manager": _ensure_dict(alert.get("manager")),
        "rule": {
            "id": _normalize_text(_alert_rule(alert).get("id")),
            "level": _normalize_text(_alert_rule(alert).get("level")),
            "description": _normalize_text(_alert_rule(alert).get("description")),
            "groups": _ensure_list(_alert_rule(alert).get("groups")),
        },
        "location": _normalize_text(alert.get("location")),
        "decoder": _ensure_dict(alert.get("decoder")),
        "data": _alert_data(alert),
        "full_log": _normalize_text(alert.get("full_log"))[:8000],
    }


def _alert_agent_id(alert: Dict[str, Any]) -> str:
    data = _alert_data(alert)
    if _normalize_text(_ensure_dict(alert.get("agent")).get("id")):
        return _normalize_text(_ensure_dict(alert.get("agent")).get("id"))
    if _normalize_text(data.get("target_agent_id")):
        return _normalize_text(data.get("target_agent_id"))
    if _normalize_text(_ensure_dict(data.get("target_endpoint")).get("agent_id")):
        return _normalize_text(_ensure_dict(data.get("target_endpoint")).get("agent_id"))
    if _normalize_text(_ensure_dict(data.get("ai_agent_info")).get("id")):
        return _normalize_text(_ensure_dict(data.get("ai_agent_info")).get("id"))
    return ""


def _recent_detection_alerts(alerts: List[Dict[str, Any]], agent_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for alert in reversed(alerts):
        data = _alert_data(alert)
        if _normalize_text(data.get("response_id", "")) == RESPONSE_ID:
            continue
        if _alert_agent_id(alert) != agent_id:
            continue

        rule = _alert_rule(alert)
        description = _normalize_text(rule.get("description"))
        if not description:
            description = _normalize_text(_ensure_dict(data.get("source_ai_alert")).get("description"))

        results.append({
            "timestamp": _normalize_text(alert.get("timestamp")),
            "level": _normalize_text(rule.get("level")),
            "description": description,
            "alert_ref": _alert_ref_string(alert),
        })
        if len(results) >= limit:
            break
    return results


def _build_agent_summary(alerts: List[Dict[str, Any]], response_entries: List[Dict[str, Any]], agent_id: str) -> Dict[str, Any]:
    filtered_entries = [x for x in response_entries if _normalize_text(x.get("target_agent_id")) == agent_id]
    platform = ""
    agent_name = ""
    response_status_counts = Counter()
    response_action_counts = Counter()

    for item in filtered_entries:
        if item.get("target_platform"):
            platform = item["target_platform"]
        if item.get("target_agent_name"):
            agent_name = item["target_agent_name"]
        response_status_counts[_normalize_text(item.get("latest_status", "unknown"))] += 1
        response_action_counts[_normalize_text(item.get("recommended_action", "unknown"))] += 1

    detection_alerts = _recent_detection_alerts(alerts, agent_id, limit=10)

    return {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "platform": platform,
        "response_entries": len(filtered_entries),
        "response_status_counts": dict(response_status_counts),
        "response_action_counts": dict(response_action_counts),
        "recent_detection_alerts": detection_alerts,
    }


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[\w\u0600-\u06FF]+", (text or "").lower())


def _flatten_payload_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(_flatten_payload_text(x) for x in value)
    if isinstance(value, dict):
        parts = []
        for k, v in value.items():
            parts.append(str(k))
            parts.append(_flatten_payload_text(v))
        return " ".join(parts)
    return str(value)


def _qdrant_scroll_points(limit: int = 200) -> List[Dict[str, Any]]:
    url = f"{QDRANT_URL}/collections/{QDRANT_COLLECTION}/points/scroll"
    points: List[Dict[str, Any]] = []
    offset = None

    while len(points) < limit:
        body: Dict[str, Any] = {
            "limit": min(64, limit - len(points)),
            "with_payload": True,
            "with_vectors": False,
        }
        if offset is not None:
            body["offset"] = offset

        response = requests.post(url, json=body, timeout=QDRANT_TIMEOUT)
        response.raise_for_status()
        result = response.json().get("result", {}) or {}
        batch = result.get("points", []) or []
        if not batch:
            break

        points.extend(batch)
        offset = result.get("next_page_offset")
        if offset is None:
            break

    return points[:limit]


def _score_knowledge(query_text: str, payload_text: str) -> int:
    query_tokens = _tokenize(query_text)
    payload_tokens = set(_tokenize(payload_text))
    if not query_tokens or not payload_tokens:
        return 0

    score = 0
    for token in query_tokens:
        if token in payload_tokens:
            score += 3
        if len(token) >= 4 and token in payload_text.lower():
            score += 1

    if query_text.strip() and query_text.lower() in payload_text.lower():
        score += 5

    return score


def _qdrant_search_knowledge(query_text: str, limit: int = 5) -> List[Dict[str, Any]]:
    try:
        points = _qdrant_scroll_points(limit=QDRANT_SCROLL_LIMIT)
    except Exception as exc:
        _write_audit({
            "event": "qdrant_search_failed",
            "error": str(exc),
            "query": query_text,
            "collection": QDRANT_COLLECTION,
        })
        return []

    ranked: List[Dict[str, Any]] = []
    for point in points:
        payload = _ensure_dict(point.get("payload"))
        payload_text = _flatten_payload_text(payload)
        if not payload_text.strip():
            continue

        score = _score_knowledge(query_text, payload_text)
        if score <= 0:
            continue

        ranked.append({
            "id": point.get("id"),
            "score": score,
            "payload": payload,
            "text": payload_text[:2500],
        })

    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked[:limit]


def _call_ollama(prompt: str) -> Optional[Dict[str, Any]]:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_ctx": 4096,
        },
    }
    response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
    response.raise_for_status()
    outer = response.json()
    text = _normalize_text(outer.get("response", ""))
    if not text:
        return None

    try:
        return json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end])
            except Exception:
                return None
    return None


def _detect_language(question: str) -> str:
    q = question or ""
    if re.search(r"[\u0600-\u06FF]", q):
        return "ar"
    if re.search(r"[A-Za-z]", q):
        return "en"
    return "same"


def _msg(lang: str, ar: str, en: str) -> str:
    return ar if lang == "ar" else en


def _contains_arabic(text: str) -> bool:
    return bool(re.search(r"[\u0600-\u06FF]", text or ""))


def _contains_latin(text: str) -> bool:
    return bool(re.search(r"[A-Za-z]", text or ""))


def _language_matches_expected(lang: str, answer: str) -> bool:
    if lang == "ar":
        return _contains_arabic(answer)
    if lang == "en":
        return _contains_latin(answer) and not _contains_arabic(answer)
    return True


def _is_count_question(question: str) -> bool:
    q = (question or "").lower()
    patterns = [
        r"\bhow many\b",
        r"\bcount\b",
        r"\btotal\b",
        r"كم",
        r"عدد",
        r"قديش",
    ]
    return any(re.search(p, q) for p in patterns)


def _fallback_chat_answer(
    question: str,
    agent_id: str,
    alert_ref: str,
    response_id: str,
    alerts: List[Dict[str, Any]],
    response_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    lang = _detect_language(question)
    all_alerts_summary = _build_all_alerts_summary(alerts)

    filtered_entries = response_entries
    if response_id:
        filtered_entries = [x for x in filtered_entries if _normalize_text(x.get("response_id")) == response_id]
    if agent_id:
        filtered_entries = [x for x in filtered_entries if _normalize_text(x.get("target_agent_id")) == agent_id]

    if _is_count_question(question):
        total_alerts = all_alerts_summary["total_alerts"]
        source_mode = all_alerts_summary["source_mode"]

        if source_mode == "indexer":
            answer = _msg(
                lang,
                f"إجمالي التنبيهات في الـ indexer هو {total_alerts} تنبيه. وعدد عناصر response ledger الحالية هو {len(response_entries)}.",
                f"The total number of alerts in the indexer is {total_alerts}. The current response ledger contains {len(response_entries)} entries.",
            )
        else:
            answer = _msg(
                lang,
                f"إجمالي التنبيهات في ملف الأرشيف الحالي هو {total_alerts} تنبيه. وعدد عناصر response ledger الحالية هو {len(response_entries)}.",
                f"The current local archive file contains {total_alerts} alerts. The current response ledger contains {len(response_entries)} entries.",
            )

        return {
            "answer": answer,
            "confidence": "high",
            "recommended_next_step": _msg(
                lang,
                "إذا أردت العدّ لوكيل محدد أو نوع تنبيه محدد فأرسل agent_id أو alert_id.",
                "If you want a count for a specific agent or a specific alert type, provide agent_id or alert_id.",
            ),
        }

    if alert_ref:
        alert, source_name = _resolve_alert_by_ref(alerts, alert_ref)
        if alert:
            ctx = _build_alert_context(alert)
            description = _normalize_text(ctx["rule"].get("description"))
            ts = ctx["timestamp"]
            doc_id = _normalize_text(ctx.get("document_id"))

            if source_name == "indexer" and doc_id:
                answer = _msg(
                    lang,
                    f"التنبيه {alert_ref} موجود في الـ indexer. وقته {ts}. الوصف: {description or 'لا يوجد وصف واضح'}. document_id={doc_id}.",
                    f"Alert {alert_ref} exists in the indexer. Timestamp: {ts}. Description: {description or 'No clear description available'}. document_id={doc_id}.",
                )
            else:
                answer = _msg(
                    lang,
                    f"التنبيه {alert_ref} موجود. وقته {ts}. الوصف: {description or 'لا يوجد وصف واضح'}.",
                    f"Alert {alert_ref} exists. Timestamp: {ts}. Description: {description or 'No clear description available'}.",
                )

            return {
                "answer": answer,
                "confidence": "high",
                "recommended_next_step": _msg(
                    lang,
                    "اسألني عن سبب التنبيه أو كيف تتعامل معه وسأبني الجواب على تفاصيله.",
                    "Ask me why this alert happened or how to handle it, and I will answer from its details.",
                ),
            }

        return {
            "answer": _msg(
                lang,
                f"لم أجد التنبيه {alert_ref} لا في الملف المحلي الحالي ولا في بحث الـ indexer المتاح.",
                f"I could not find alert {alert_ref} in the current local archive file or in the available indexer search.",
            ),
            "confidence": "low",
            "recommended_next_step": _msg(
                lang,
                "تأكد من قيمة alert_id أو document_id أو sort value ثم أعد المحاولة.",
                "Verify the alert_id, document_id, or sort value and try again.",
            ),
        }

    if filtered_entries:
        latest = sorted(
            filtered_entries,
            key=lambda x: _get_sortable_ts(_normalize_text(x.get("latest_status_timestamp", ""))),
            reverse=True,
        )[0]
        action = _normalize_text(latest.get("recommended_action"))
        agent_name = _normalize_text(latest.get("target_agent_name"))
        latest_status = _normalize_text(latest.get("latest_status"))
        ts = _normalize_text(latest.get("latest_status_timestamp"))
        params = _normalize_parameters(latest.get("parameters", {}))

        focus = ""
        if params.get("service_name"):
            focus = _msg(lang, f" على العملية/الخدمة {params['service_name']}", f" for process/service {params['service_name']}")
        elif params.get("ip"):
            focus = _msg(lang, f" على الـ IP {params['ip']}", f" for IP {params['ip']}")
        elif params.get("user"):
            focus = _msg(lang, f" على المستخدم {params['user']}", f" for user {params['user']}")
        elif params.get("path"):
            focus = _msg(lang, f" على الملف {params['path']}", f" for file {params['path']}")

        answer = _msg(
            lang,
            f"آخر إجراء response على {agent_name or ('الوكيل ' + agent_id if agent_id else 'المنظومة')} كان {action}{focus}. الحالة الحالية: {latest_status}. آخر تحديث كان في {ts}.",
            f"The latest response action on {agent_name or ('agent ' + agent_id if agent_id else 'the environment')} was {action}{focus}. Current status: {latest_status}. Last update was at {ts}.",
        )

        if latest_status == "rolled_back":
            next_step = _msg(lang, "تحقق أن التراجع اكتمل فعلاً ولا توجد آثار متبقية.", "Verify that the rollback fully completed and no residual changes remain.")
        elif latest_status == "executed":
            next_step = _msg(lang, "راجع آثار التنفيذ وحدد إن كنت تحتاج rollback.", "Review the execution impact and decide whether a rollback is needed.")
        elif latest_status == "planned":
            next_step = _msg(lang, "الإجراء ما زال توصية فقط ولم يُنفّذ بعد.", "This action is still only a recommendation and has not been executed yet.")
        else:
            next_step = _msg(lang, "راجع تفاصيل الحالة في Control.", "Review the current state in Control.")

        return {
            "answer": answer,
            "confidence": "high",
            "recommended_next_step": next_step,
        }

    return {
        "answer": _msg(lang, all_alerts_summary["summary"], all_alerts_summary["summary"]),
        "confidence": "medium",
        "recommended_next_step": _msg(
            lang,
            "حدد alert_id أو agent_id للحصول على جواب أدق.",
            "Provide alert_id or agent_id for a more precise answer.",
        ),
    }


def _chat_answer(
    question: str,
    agent_id: str,
    alert_ref: str,
    response_id: str,
    alerts: List[Dict[str, Any]],
    response_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    question_language = _detect_language(question)
    all_alerts_summary = _build_all_alerts_summary(alerts)

    filtered_entries = response_entries
    if response_id:
        filtered_entries = [x for x in filtered_entries if _normalize_text(x.get("response_id")) == response_id]
    if agent_id:
        filtered_entries = [x for x in filtered_entries if _normalize_text(x.get("target_agent_id")) == agent_id]

    target_alert_context = None
    knowledge_hits: List[Dict[str, Any]] = []
    indexer_hits: List[Dict[str, Any]] = []

    if alert_ref:
        target_alert, _source_name = _resolve_alert_by_ref(alerts, alert_ref)
        if target_alert:
            target_alert_context = _build_alert_context(target_alert)

            rule_desc = _normalize_text(target_alert_context["rule"].get("description"))
            full_log = _normalize_text(target_alert_context.get("full_log"))
            knowledge_query = " ".join(x for x in [question, rule_desc, full_log[:1000]] if x).strip()
            knowledge_hits = _qdrant_search_knowledge(knowledge_query, limit=5)

    indexer_hits = _indexer_search_alerts(question, agent_id=agent_id, limit=5)

    context = {
        "question": question,
        "question_language": question_language,
        "response_id": response_id or None,
        "agent_id": agent_id or None,
        "alert_ref": alert_ref or None,
        "all_alerts_summary": all_alerts_summary,
        "agent_summary": _build_agent_summary(alerts, response_entries, agent_id) if agent_id else None,
        "response_entries": filtered_entries[:8],
        "target_alert": target_alert_context,
        "indexer_hits": [_build_alert_context(x) for x in indexer_hits[:5]],
        "knowledge_hits": knowledge_hits,
    }

    prompt = (
        "You are a SOC assistant inside Wazuh.\n"
        "You must answer in the SAME language as question_language.\n"
        "If question_language='en', answer ONLY in English.\n"
        "If question_language='ar', answer ONLY in Arabic.\n"
        "If question_language='same', answer in the user's apparent language.\n"
        "You can answer about any alert in the archive or in the Wazuh indexer, not only custom AI response alerts.\n"
        "If alert_ref is provided, explain that specific alert.\n"
        "Use indexer_hits when the requested alert is old or not present in the currently loaded local archive file.\n"
        "If the alert is not one of the custom AI alerts, use knowledge_hits as best-effort guidance.\n"
        "Do not invent facts.\n"
        "Do not use markdown.\n"
        "Return JSON only in this exact shape:\n"
        "{"
        "\"answer\":\"...\","
        "\"confidence\":\"low|medium|high\","
        "\"recommended_next_step\":\"...\""
        "}\n\n"
        "Context:\n%s" % json.dumps(context, ensure_ascii=False)
    )

    try:
        result = _call_ollama(prompt)
        if isinstance(result, dict) and result.get("answer"):
            answer_text = _normalize_text(result.get("answer"))
            if _language_matches_expected(question_language, answer_text):
                return {
                    "answer": answer_text,
                    "confidence": _normalize_text(result.get("confidence")) or "medium",
                    "recommended_next_step": _normalize_text(result.get("recommended_next_step")) or "Review the alert details.",
                }

            _write_audit({
                "event": "chat_language_mismatch_fallback",
                "question_language": question_language,
                "model_answer": answer_text,
                "agent_id": agent_id,
                "alert_ref": alert_ref,
                "response_id": response_id,
            })
    except Exception as exc:
        _write_audit({
            "event": "chat_fallback_triggered",
            "reason": str(exc),
            "agent_id": agent_id,
            "alert_ref": alert_ref,
            "response_id": response_id,
        })

    return _fallback_chat_answer(question, agent_id, alert_ref, response_id, alerts, response_entries)


def _command_for_target(action: str, target_agent_id: str) -> str:
    if target_agent_id == "000":
        return ACTION_TO_LOCAL_COMMAND.get(action, "")
    return ACTION_TO_REMOTE_COMMAND.get(action, "")


def _run_dispatcher_control(payload: Dict[str, Any], requested_command: str) -> Dict[str, Any]:
    if not os.path.exists(DISPATCHER_BIN):
        raise RuntimeError(f"Dispatcher not found: {DISPATCHER_BIN}")

    wrapper = {
        "version": 1,
        "origin": {"name": "ai_control_api.py", "module": "api"},
        "command": requested_command,
        "parameters": {
            "control_direct": True,
            "extra_args": [json.dumps(payload, ensure_ascii=False)],
            "alert": {},
            "program": "ai_response_dispatcher.py",
        },
    }

    proc = subprocess.run(
        [PYTHON_BIN, DISPATCHER_BIN],
        input=(json.dumps(wrapper, ensure_ascii=False) + "\n"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=90,
    )

    result = {
        "mode": "dispatcher_control",
        "dispatcher_bin": DISPATCHER_BIN,
        "requested_command": requested_command,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
    }

    if proc.returncode != 0:
        raise RuntimeError(
            "Dispatcher execution failed | rc=%s | stdout=%s | stderr=%s"
            % (proc.returncode, result["stdout"], result["stderr"])
        )

    return result


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl"] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def _service_status(unit_name: str) -> Dict[str, Any]:
    enabled = _systemctl("is-enabled", unit_name)
    active = _systemctl("is-active", unit_name)

    return {
        "unit": unit_name,
        "enabled": enabled.returncode == 0,
        "enabled_raw": _normalize_text(enabled.stdout or enabled.stderr),
        "active": active.returncode == 0,
        "active_raw": _normalize_text(active.stdout or active.stderr),
    }


def _service_set(unit_name: str, enabled: bool) -> Dict[str, Any]:
    if enabled:
        cmd = _systemctl("enable", "--now", unit_name)
    else:
        cmd = _systemctl("disable", "--now", unit_name)

    status = _service_status(unit_name)
    status["changed_to"] = enabled
    status["command_returncode"] = cmd.returncode
    status["command_stdout"] = _normalize_text(cmd.stdout)
    status["command_stderr"] = _normalize_text(cmd.stderr)
    return status


def _build_execute_payload(body: Dict[str, Any]) -> Dict[str, Any]:
    action = _normalize_text(body.get("action"))
    target_agent_id = _normalize_text(body.get("target_agent_id"))
    target_agent_name = _normalize_text(body.get("target_agent_name")) or "unknown"
    target_platform = _normalize_text(body.get("target_platform")).lower() or "unknown"

    command_name = _command_for_target(action, target_agent_id)
    if not command_name:
        raise ValueError("Unsupported action: %s" % action)

    parameters = _normalize_parameters(body.get("parameters", {}))
    summary = _normalize_text(body.get("summary")) or ("Manual execute for %s" % action)
    recommendation_alert_id = _normalize_text(body.get("recommendation_alert_id"))

    return {
        "response_id": RESPONSE_ID,
        "response_origin": "ai_control_api_manual",
        "target_agent_id": target_agent_id,
        "target_agent_name": target_agent_name,
        "target_platform": target_platform,
        "recommended_action": action,
        "response_command": command_name,
        "policy_name": "dashboard_manual_execute",
        "policy_reason": "Manual execute requested from dashboard",
        "source_level": _safe_int(body.get("source_level"), 15),
        "summary": summary,
        "confidence": _normalize_text(body.get("confidence")) or "high",
        "reasoning": _normalize_text(body.get("reasoning")) or "Manual execute requested from dashboard",
        "parameters": parameters,
        "manual_steps": _ensure_list(body.get("manual_steps")),
        "evidence_to_collect": _ensure_list(body.get("evidence_to_collect")),
        "recommendation_alert_id": recommendation_alert_id,
        "original_alert_id": recommendation_alert_id,
        "control_operation": "execute",
        "requested_command": "add",
    }


def _build_rollback_payload(body: Dict[str, Any]) -> Dict[str, Any]:
    action = _normalize_text(body.get("action"))
    target_agent_id = _normalize_text(body.get("target_agent_id"))
    target_agent_name = _normalize_text(body.get("target_agent_name")) or "unknown"
    target_platform = _normalize_text(body.get("target_platform")).lower() or "unknown"

    if action not in ROLLBACK_SUPPORTED:
        raise ValueError("Rollback is not supported for action=%s" % action)

    command_name = _command_for_target(action, target_agent_id)
    if not command_name:
        raise ValueError("No command mapped for action=%s" % action)

    recommendation_alert_id = _normalize_text(body.get("recommendation_alert_id"))

    return {
        "response_id": RESPONSE_ID,
        "response_origin": "ai_control_api_manual",
        "target_agent_id": target_agent_id,
        "target_agent_name": target_agent_name,
        "target_platform": target_platform,
        "recommended_action": action,
        "response_command": command_name,
        "policy_name": "dashboard_manual_rollback",
        "policy_reason": "Manual rollback requested from dashboard",
        "source_level": _safe_int(body.get("source_level"), 15),
        "summary": _normalize_text(body.get("summary")) or ("Manual rollback for %s" % action),
        "confidence": _normalize_text(body.get("confidence")) or "high",
        "parameters": _normalize_parameters(body.get("parameters", {})),
        "recommendation_alert_id": recommendation_alert_id,
        "original_alert_id": recommendation_alert_id,
        "requested_command": "delete",
        "control_operation": "rollback",
        "rollback": True,
    }


def _paginate(items: List[Dict[str, Any]], offset: int, limit: int) -> Tuple[List[Dict[str, Any]], int, bool]:
    total = len(items)
    start = max(offset, 0)
    end = max(start + limit, start)
    page = items[start:end]
    has_more = end < total
    return page, total, has_more


@APP.get("/health")
def health():
    return _json_response(
        True,
        service="ai_control_api",
        alerts_file=ALERTS_FILE,
        response_id=RESPONSE_ID,
        qdrant_url=QDRANT_URL,
        qdrant_collection=QDRANT_COLLECTION,
        dispatcher_bin=DISPATCHER_BIN,
        indexer_enabled=_indexer_enabled(),
        indexer_url=WAZUH_INDEXER_URL or None,
        indexer_index_pattern=WAZUH_INDEXER_INDEX_PATTERN if _indexer_enabled() else None,
    )


@APP.get("/api/ai/actions")
def actions_list():
    snapshot = _ledger_snapshot()
    entries = list(snapshot["items"])

    response_id = _normalize_text(request.args.get("response_id", ""))
    agent_id = _normalize_text(request.args.get("agent_id", ""))
    control_only = _normalize_bool(request.args.get("control_only", "true"))
    offset = max(_safe_int(request.args.get("offset", 0), 0), 0)
    limit = min(max(_safe_int(request.args.get("limit", 10), 10), 1), 100)

    if response_id:
        entries = [x for x in entries if _normalize_text(x.get("response_id")) == response_id]
    if agent_id:
        entries = [x for x in entries if _normalize_text(x.get("target_agent_id")) == agent_id]
    if control_only:
        entries = [x for x in entries if bool(x.get("control_visible"))]

    page, total_entries, has_more = _paginate(entries, offset, limit)

    return _json_response(
        True,
        item={
            "generated_at": snapshot["generated_at"],
            "source": snapshot["source"],
            "response_id": snapshot["response_id"],
            "recommendations_seen": snapshot["counts"]["recommendations_seen"],
            "action_events_seen": snapshot["counts"]["action_events_seen"],
            "ledger_entries": snapshot["counts"]["ledger_entries"],
            "control_visible_entries": snapshot["counts"].get("control_visible_entries", 0),
            "by_latest_status": snapshot["counts"]["by_latest_status"],
            "offset": offset,
            "limit": limit,
            "returned_entries": len(page),
            "total_entries": total_entries,
            "has_more": has_more,
            "entries": page,
        },
    )


@APP.get("/api/ai/actions/<response_id>")
def actions_by_response(response_id: str):
    snapshot = _ledger_snapshot()
    entries = list(snapshot["items"])

    agent_id = _normalize_text(request.args.get("agent_id", ""))
    recommendation_alert_id = _normalize_text(request.args.get("recommendation_alert_id", ""))
    control_only = _normalize_bool(request.args.get("control_only", "false"))

    entries = [x for x in entries if _normalize_text(x.get("response_id")) == _normalize_text(response_id)]
    if agent_id:
        entries = [x for x in entries if _normalize_text(x.get("target_agent_id")) == agent_id]
    if recommendation_alert_id:
        entries = [x for x in entries if _normalize_text(x.get("recommendation_alert_id")) == recommendation_alert_id]
    if control_only:
        entries = [x for x in entries if bool(x.get("control_visible"))]

    return _json_response(True, item=entries)


@APP.get("/api/ai/system/summary")
def system_summary():
    alerts = _load_alerts()
    snapshot = _ledger_snapshot()
    return _json_response(
        True,
        item={
            "alerts_summary": _build_all_alerts_summary(alerts),
            "response_summary": snapshot["counts"],
        },
    )


@APP.get("/api/ai/agents/<agent_id>/summary")
def agent_summary(agent_id: str):
    alerts = _load_alerts()
    snapshot = _ledger_snapshot()
    item = _build_agent_summary(alerts, snapshot["items"], agent_id)
    return _json_response(True, item=item)


@APP.post("/api/ai/chat")
def ai_chat():
    body = request.get_json(force=True, silent=True) or {}
    question = _normalize_text(body.get("question"))
    if not question:
        return _json_response(False, error="BadRequest", message="Missing question"), 400

    response_id = _normalize_text(body.get("response_id"))
    target_agent_id = _normalize_text(body.get("target_agent_id"))
    alert_ref = _normalize_text(body.get("alert_id")) or _normalize_text(body.get("alert_ref"))

    alerts = _load_alerts()
    snapshot = _ledger_snapshot()

    answer = _chat_answer(
        question=question,
        agent_id=target_agent_id,
        alert_ref=alert_ref,
        response_id=response_id,
        alerts=alerts,
        response_entries=snapshot["items"],
    )

    return _json_response(
        True,
        response_id=response_id or None,
        agent_id=target_agent_id or None,
        alert_ref=alert_ref or None,
        answer=answer,
    )


@APP.post("/api/ai/control/execute")
def control_execute():
    body = request.get_json(force=True, silent=True) or {}
    try:
        payload = _build_execute_payload(body)
        result = _run_dispatcher_control(payload, requested_command="add")

        _write_audit({
            "event": "manual_execute_requested",
            "recommendation_alert_id": _normalize_text(body.get("recommendation_alert_id")),
            "target_agent_id": _normalize_text(body.get("target_agent_id")),
            "target_agent_name": _normalize_text(body.get("target_agent_name")),
            "target_platform": _normalize_text(body.get("target_platform")),
            "action": _normalize_text(body.get("action")),
            "response_command": payload.get("response_command", ""),
            "parameters": payload["parameters"],
            "result": result,
        })

        return _json_response(
            True,
            message="Manual execute dispatched through dispatcher",
            item={
                "payload": payload,
                "result": result,
            },
        )
    except Exception as exc:
        _write_audit({
            "event": "manual_execute_failed",
            "error": str(exc),
            "recommendation_alert_id": _normalize_text(body.get("recommendation_alert_id")),
            "target_agent_id": _normalize_text(body.get("target_agent_id")),
            "target_agent_name": _normalize_text(body.get("target_agent_name")),
            "target_platform": _normalize_text(body.get("target_platform")),
            "action": _normalize_text(body.get("action")),
        })
        return _json_response(False, error=exc.__class__.__name__, message=str(exc)), 500


@APP.post("/api/ai/control/rollback")
def control_rollback():
    body = request.get_json(force=True, silent=True) or {}
    try:
        payload = _build_rollback_payload(body)
        result = _run_dispatcher_control(payload, requested_command="delete")

        _write_audit({
            "event": "manual_rollback_dispatched",
            "recommendation_alert_id": _normalize_text(body.get("recommendation_alert_id")),
            "target_agent_id": _normalize_text(body.get("target_agent_id")),
            "target_agent_name": _normalize_text(body.get("target_agent_name")),
            "target_platform": _normalize_text(body.get("target_platform")),
            "action": _normalize_text(body.get("action")),
            "response_command": payload.get("response_command", ""),
            "parameters": payload["parameters"],
            "result": result,
        })

        return _json_response(
            True,
            message="Rollback dispatched through dispatcher",
            item={
                "payload": payload,
                "result": result,
            },
        )
    except Exception as exc:
        _write_audit({
            "event": "manual_rollback_failed",
            "error": str(exc),
            "recommendation_alert_id": _normalize_text(body.get("recommendation_alert_id")),
            "target_agent_id": _normalize_text(body.get("target_agent_id")),
            "target_agent_name": _normalize_text(body.get("target_agent_name")),
            "target_platform": _normalize_text(body.get("target_platform")),
            "action": _normalize_text(body.get("action")),
        })
        return _json_response(False, error=exc.__class__.__name__, message=str(exc)), 500

def _clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _selected_model(config: Dict[str, Any]) -> str:
    model_type = _normalize_text(config.get("model_type"))
    custom_model = _normalize_text(config.get("custom_model"))

    if model_type == "other":
        return custom_model

    if model_type in ("llama3.2", "gpt-oss:120b-cloud"):
        return model_type

    return "llama3.2"


def _load_control_settings() -> Dict[str, Any]:
    settings = json.loads(json.dumps(DEFAULT_CONTROL_SETTINGS))

    if not os.path.exists(CONTROL_SETTINGS_FILE):
        return settings

    try:
        with open(CONTROL_SETTINGS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)

        if isinstance(raw, dict):
            if isinstance(raw.get("rag_detection"), dict):
                settings["rag_detection"].update(raw["rag_detection"])
            if isinstance(raw.get("rag_response"), dict):
                settings["rag_response"].update(raw["rag_response"])

    except Exception as exc:
        _write_audit({
            "event": "control_settings_load_failed",
            "error": str(exc),
        })

    return settings


def _save_control_settings(settings: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CONTROL_SETTINGS_FILE), exist_ok=True)
    with open(CONTROL_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)


def _validate_model_config(body: Dict[str, Any]) -> Dict[str, Any]:
    model_type = _normalize_text(body.get("model_type")) or "llama3.2"
    custom_model = _normalize_text(body.get("custom_model"))
    max_threads = _clamp_int(body.get("max_threads"), 1, 64, 2)

    if model_type not in MODEL_PRESETS:
        raise ValueError("Invalid model_type")

    if model_type == "other" and not custom_model:
        raise ValueError("custom_model is required when model_type=other")

    return {
        "model_type": model_type,
        "custom_model": custom_model,
        "max_threads": max_threads,
    }


def _validate_auto_response_level(value: Any) -> int:
    return _clamp_int(value, 0, 15, 15)


def _shell_escape_systemd_env(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def _write_systemd_dropin(unit_name: str, env_vars: Dict[str, Any]) -> str:
    dropin_dir = f"/etc/systemd/system/{unit_name}.d"
    dropin_path = f"{dropin_dir}/10-ai-control.conf"

    os.makedirs(dropin_dir, exist_ok=True)

    env_items = []
    for key, value in env_vars.items():
        env_items.append(f'"{key}={_shell_escape_systemd_env(value)}"')

    content = "[Service]\n"
    content += "Environment=" + " ".join(env_items) + "\n"

    with open(dropin_path, "w", encoding="utf-8") as f:
        f.write(content)

    return dropin_path


def _systemctl_checked(*args: str) -> Dict[str, Any]:
    proc = _systemctl(*args)
    result = {
        "command": "systemctl " + " ".join(args),
        "returncode": proc.returncode,
        "stdout": _normalize_text(proc.stdout),
        "stderr": _normalize_text(proc.stderr),
    }

    if proc.returncode != 0:
        raise RuntimeError(
            "systemctl failed: %s | stdout=%s | stderr=%s"
            % (result["command"], result["stdout"], result["stderr"])
        )

    return result


def _apply_detection_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    model = _selected_model(config)
    if not model:
        raise ValueError("Selected detection model is empty")

    max_threads = _clamp_int(config.get("max_threads"), 1, 64, 2)

    dropin_path = _write_systemd_dropin(
        AI_RAG_DETECTION_UNIT,
        {
            "OLLAMA_MODEL": model,
            "AI_MODEL": model,
            "AI_RAG_DETECTION_MODEL": model,
            "MAX_THREADS": max_threads,
            "AI_MAX_THREADS": max_threads,
            "AI_RAG_DETECTION_MAX_THREADS": max_threads,
        },
    )

    daemon_reload = _systemctl_checked("daemon-reload")
    restart = _systemctl_checked("restart", AI_RAG_DETECTION_UNIT)

    return {
        "unit": AI_RAG_DETECTION_UNIT,
        "dropin_path": dropin_path,
        "model": model,
        "max_threads": max_threads,
        "daemon_reload": daemon_reload,
        "restart": restart,
        "status": _service_status(AI_RAG_DETECTION_UNIT),
    }


def _apply_response_settings(config: Dict[str, Any]) -> Dict[str, Any]:
    model = _selected_model(config)
    if not model:
        raise ValueError("Selected response model is empty")

    max_threads = _clamp_int(config.get("max_threads"), 1, 64, 2)
    auto_level = _validate_auto_response_level(config.get("auto_response_min_level"))

    dropin_path = _write_systemd_dropin(
        AI_RAG_RESPONSE_UNIT,
        {
            "OLLAMA_MODEL": model,
            "AI_MODEL": model,
            "AI_RAG_RESPONSE_MODEL": model,
            "MAX_THREADS": max_threads,
            "AI_MAX_THREADS": max_threads,
            "AI_RAG_RESPONSE_MAX_THREADS": max_threads,
            "AI_AUTO_RESPONSE_MIN_LEVEL": auto_level,
        },
    )

    daemon_reload = _systemctl_checked("daemon-reload")
    restart = _systemctl_checked("restart", AI_RAG_RESPONSE_UNIT)

    return {
        "unit": AI_RAG_RESPONSE_UNIT,
        "dropin_path": dropin_path,
        "model": model,
        "max_threads": max_threads,
        "auto_response_min_level": auto_level,
        "daemon_reload": daemon_reload,
        "restart": restart,
        "status": _service_status(AI_RAG_RESPONSE_UNIT),
    }

@APP.get("/api/ai/settings")
def get_settings():
    settings = _load_control_settings()

    detection_config = _ensure_dict(settings.get("rag_detection"))
    response_config = _ensure_dict(settings.get("rag_response"))

    return _json_response(
        True,
        item={
            "settings_file": CONTROL_SETTINGS_FILE,
            "model_presets": MODEL_PRESETS,
            "rag_detection": {
                **_service_status(AI_RAG_DETECTION_UNIT),
                "config": detection_config,
                "effective_model": _selected_model(detection_config),
            },
            "rag_response": {
                **_service_status(AI_RAG_RESPONSE_UNIT),
                "config": response_config,
                "effective_model": _selected_model(response_config),
            },
        },
    )


@APP.post("/api/ai/settings/rag-detection")
def set_rag_detection():
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled", False))
    try:
        return _json_response(True, item=_service_set(AI_RAG_DETECTION_UNIT, enabled))
    except Exception as exc:
        return _json_response(False, error=exc.__class__.__name__, message=str(exc)), 500


@APP.post("/api/ai/settings/rag-response")
def set_rag_response():
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled", False))
    try:
        return _json_response(True, item=_service_set(AI_RAG_RESPONSE_UNIT, enabled))
    except Exception as exc:
        return _json_response(False, error=exc.__class__.__name__, message=str(exc)), 500

@APP.post("/api/ai/settings/rag-detection/config")
def set_rag_detection_config():
    body = request.get_json(force=True, silent=True) or {}

    try:
        config = _validate_model_config(body)

        settings = _load_control_settings()
        settings["rag_detection"].update(config)
        _save_control_settings(settings)

        apply_result = _apply_detection_settings(settings["rag_detection"])

        _write_audit({
            "event": "rag_detection_config_updated",
            "config": settings["rag_detection"],
            "apply_result": apply_result,
        })

        return _json_response(
            True,
            message="RAG Detection settings updated and service restarted",
            item={
                "config": settings["rag_detection"],
                "effective_model": _selected_model(settings["rag_detection"]),
                "apply_result": apply_result,
            },
        )

    except Exception as exc:
        _write_audit({
            "event": "rag_detection_config_update_failed",
            "error": str(exc),
            "body": body,
        })
        return _json_response(False, error=exc.__class__.__name__, message=str(exc)), 500


@APP.post("/api/ai/settings/rag-response/config")
def set_rag_response_config():
    body = request.get_json(force=True, silent=True) or {}

    try:
        config = _validate_model_config(body)
        config["auto_response_min_level"] = _validate_auto_response_level(
            body.get("auto_response_min_level")
        )

        settings = _load_control_settings()
        settings["rag_response"].update(config)
        _save_control_settings(settings)

        apply_result = _apply_response_settings(settings["rag_response"])

        _write_audit({
            "event": "rag_response_config_updated",
            "config": settings["rag_response"],
            "apply_result": apply_result,
        })

        return _json_response(
            True,
            message="RAG Response settings updated and service restarted",
            item={
                "config": settings["rag_response"],
                "effective_model": _selected_model(settings["rag_response"]),
                "apply_result": apply_result,
            },
        )

    except Exception as exc:
        _write_audit({
            "event": "rag_response_config_update_failed",
            "error": str(exc),
            "body": body,
        })
        return _json_response(False, error=exc.__class__.__name__, message=str(exc)), 500

if __name__ == "__main__":
    bind = os.getenv("AI_CONTROL_API_BIND", "127.0.0.1")
    port = int(os.getenv("AI_CONTROL_API_PORT", "8777"))
    APP.run(host=bind, port=port, debug=False)