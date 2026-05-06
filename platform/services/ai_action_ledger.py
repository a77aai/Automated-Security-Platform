#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from collections import Counter

DEFAULT_ALERTS_FILE = "/var/ossec/logs/archives/archives.json"
RESPONSE_ID = "000_response_ai"
RECOMMENDATION_RULE_IDS = {"200019", "200020", "200021"}

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

ACTIONABLE_ACTIONS = set(ACTION_TO_REMOTE_COMMAND) | set(ACTION_TO_LOCAL_COMMAND)


def _unwrap_alert_object(value: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("_source"), dict):
        merged = dict(value["_source"])
        if "_id" in value:
            merged["_document_id"] = value["_id"]
        if "sort" in value:
            merged["_sort"] = value["sort"]
        return merged
    return value


def json_loads_safe(line: str) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(line)
        if not isinstance(value, dict):
            return None
        return _unwrap_alert_object(value)
    except Exception:
        return None


def parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    candidates = [text]
    if text.endswith("Z"):
        candidates.append(text[:-1] + "+00:00")
    if text.endswith("+0000"):
        candidates.append(text[:-5] + "+00:00")
    for item in candidates:
        try:
            dt = datetime.fromisoformat(item)
            # الحل هنا: إذا كان التاريخ بدون منطقة زمنية، نُجبره على استخدام UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None


def ts_to_text(value: Optional[datetime]) -> str:
    if not value:
        return ""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def ensure_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def ensure_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def canonical_parameters(data: Dict[str, Any]) -> Dict[str, str]:
    params = ensure_dict(data)
    return {
        "ip": str(params.get("ip", "") or "").strip(),
        "path": str(params.get("path", "") or "").strip(),
        "user": str(params.get("user", "") or "").strip(),
        "tty": str(params.get("tty", "") or "").strip(),
        "service_name": str(params.get("service_name", "") or "").strip(),
    }


def parameters_equivalent(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    pa = canonical_parameters(a)
    pb = canonical_parameters(b)
    for key in ("ip", "path", "user", "tty", "service_name"):
        av = pa.get(key, "")
        bv = pb.get(key, "")
        if av and bv and av != bv:
            return False
    return True


def resolved_command_for_target(action: str, target_agent_id: str, current_command: str = "") -> str:
    current_command = str(current_command or "").strip()
    if current_command:
        return current_command

    action = str(action or "").strip()
    target_agent_id = str(target_agent_id or "").strip()

    if target_agent_id == "000":
        return str(ACTION_TO_LOCAL_COMMAND.get(action, "")).strip()
    return str(ACTION_TO_REMOTE_COMMAND.get(action, "")).strip()


def compute_dedup_key(response_id: str, target_agent_id: str, recommended_action: str, response_command: str, parameters: Dict[str, str]) -> str:
    return "|".join([
        response_id,
        target_agent_id,
        recommended_action,
        response_command,
        parameters.get("ip", ""),
        parameters.get("path", ""),
        parameters.get("user", ""),
        parameters.get("tty", ""),
        parameters.get("service_name", ""),
    ])


def classify_event(event_name: str) -> Tuple[str, str]:
    event_name = str(event_name or "").strip()
    if event_name.startswith("dispatch_"):
        return ("dispatch", "success" if event_name == "dispatch_success" else "failed")
    if event_name in ("unblock_ip_success", "enable_user_success", "unisolate_host_success", "restore_success"):
        return ("rollback", "success")
    if event_name in ("unblock_ip_failed", "enable_user_failed", "unisolate_host_failed", "restore_failed"):
        return ("rollback", "failed")
    if event_name == "quarantine_delete_ignored":
        return ("rollback", "ignored")
    if event_name.endswith("_success"):
        return ("execution", "success")
    if event_name.endswith("_failed"):
        return ("execution", "failed")
    return ("other", "unknown")


class CentralizedActionLedger:
    def __init__(self, alerts_file: str = DEFAULT_ALERTS_FILE, response_id: str = RESPONSE_ID) -> None:
        self.alerts_file = Path(alerts_file)
        self.response_id = response_id

    def _iter_alert_objects(self) -> Iterator[Dict[str, Any]]:
        if not self.alerts_file.exists():
            return
        with self.alerts_file.open("r", encoding="utf-8", errors="ignore") as file_obj:
            for line in file_obj:
                line = line.strip()
                if not line:
                    continue
                obj = json_loads_safe(line)
                if obj:
                    yield obj

    def _is_recommendation_alert(self, alert: Dict[str, Any]) -> bool:
        data = ensure_dict(alert.get("data"))
        if str(data.get("response_id", "")).strip() != self.response_id:
            return False
        if data.get("event"):
            return False
        if not isinstance(data.get("ai_response"), dict):
            return False
        rid = str(ensure_dict(alert.get("rule")).get("id", "")).strip()
        if rid:
            return rid in RECOMMENDATION_RULE_IDS
        return True

    def _build_recommendation_entry(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        data = ensure_dict(alert.get("data"))
        ai_response = ensure_dict(data.get("ai_response"))
        source_ai_alert = ensure_dict(data.get("source_ai_alert"))
        target_endpoint = ensure_dict(data.get("target_endpoint"))
        ai_agent_info = ensure_dict(data.get("ai_agent_info"))
        params = canonical_parameters(ai_response.get("action_parameters", {}) or ai_response.get("parameters", {}))

        target_agent_id = first_non_empty(ai_response.get("target_agent_id"), target_endpoint.get("agent_id"), ai_agent_info.get("id"))
        target_agent_name = first_non_empty(ai_response.get("target_agent_name"), target_endpoint.get("agent_name"), ai_agent_info.get("name"))
        target_platform = first_non_empty(ai_response.get("target_platform"), target_endpoint.get("platform"), ai_agent_info.get("platform")).lower()

        recommended_action = str(ai_response.get("recommended_action", "")).strip()
        response_command = resolved_command_for_target(
            action=recommended_action,
            target_agent_id=target_agent_id,
            current_command=ai_response.get("response_command", ""),
        )
        recommendation_alert_id = str(alert.get("id", "")).strip()
        recommendation_timestamp = first_non_empty(alert.get("timestamp"))

        return {
            "recommendation_alert_id": recommendation_alert_id,
            "recommendation_rule_id": str(ensure_dict(alert.get("rule")).get("id", "")).strip(),
            "recommendation_timestamp": recommendation_timestamp,
            "response_id": str(data.get("response_id", self.response_id)).strip(),
            "target_agent_id": target_agent_id,
            "target_agent_name": target_agent_name,
            "target_platform": target_platform,
            "recommended_action": recommended_action,
            "response_command": response_command,
            "parameters": params,
            "dedup_key": compute_dedup_key(
                str(data.get("response_id", self.response_id)).strip(),
                target_agent_id,
                recommended_action,
                response_command,
                params,
            ),
            "auto_execute": str(ai_response.get("auto_execute", "False")).strip().lower() == "true",
            "execution_mode": str(ai_response.get("execution_mode", "")).strip(),
            "summary": str(ai_response.get("summary", "")).strip(),
            "confidence": str(ai_response.get("confidence", "")).strip(),
            "reasoning": str(ai_response.get("reasoning", "")).strip(),
            "policy_name": str(ai_response.get("policy_name", "")).strip(),
            "policy_reason": str(ai_response.get("policy_reason", "")).strip(),
            "response_rule_level": int(ensure_dict(data.get("response_rule")).get("level", 0) or 0),
            "source_level": int(source_ai_alert.get("level", 0) or 0),
            "source_description": str(source_ai_alert.get("description", "")).strip(),
            "source_ai_analysis": str(source_ai_alert.get("ai_analysis", "")).strip(),
            "manual_steps": [str(x).strip() for x in (ai_response.get("manual_steps", []) or []) if str(x).strip()],
            "evidence_to_collect": [str(x).strip() for x in (ai_response.get("evidence_to_collect", []) or []) if str(x).strip()],
            "delivery_status": "not_sent",
            "delivery_timestamp": "",
            "delivery_alert_id": "",
            "execution_status": "not_executed",
            "execution_timestamp": "",
            "execution_alert_id": "",
            "rollback_status": "not_requested",
            "rollback_timestamp": "",
            "rollback_alert_id": "",
            "latest_status": "planned",
            "latest_status_timestamp": recommendation_timestamp,
            "related_dispatch_events": [],
            "related_execution_events": [],
            "related_rollback_events": [],
        }

    def _is_action_event(self, alert: Dict[str, Any]) -> bool:
        data = ensure_dict(alert.get("data"))
        return str(data.get("response_id", "")).strip() == self.response_id and bool(str(data.get("event", "")).strip())

    def _extract_event_record(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        data = ensure_dict(alert.get("data"))
        extra_payload = ensure_dict(data.get("extra_payload"))
        params = canonical_parameters(data.get("parameters") or extra_payload.get("parameters") or {})
        event_name = str(data.get("event", "")).strip()
        kind, status = classify_event(event_name)

        target_agent_id = first_non_empty(data.get("target_agent_id"), extra_payload.get("target_agent_id"))
        target_agent_name = first_non_empty(data.get("target_agent_name"), extra_payload.get("target_agent_name"))
        target_platform = first_non_empty(data.get("target_platform"), extra_payload.get("target_platform")).lower()
        recommended_action = first_non_empty(data.get("recommended_action"), extra_payload.get("recommended_action"))
        response_command = resolved_command_for_target(
            action=recommended_action,
            target_agent_id=target_agent_id,
            current_command=first_non_empty(data.get("response_command"), extra_payload.get("response_command")),
        )
        response_id = first_non_empty(data.get("response_id"), extra_payload.get("response_id"), self.response_id)

        return {
            "kind": kind,
            "status": status,
            "wazuh_alert_id": str(alert.get("id", "")).strip(),
            "timestamp": first_non_empty(alert.get("timestamp")),
            "response_id": response_id,
            "target_agent_id": target_agent_id,
            "target_agent_name": target_agent_name,
            "target_platform": target_platform,
            "recommended_action": recommended_action,
            "response_command": response_command,
            "parameters": params,
            "rule_id": str(ensure_dict(alert.get("rule")).get("id", "")).strip(),
            "event_name": event_name,
            "summary": str(data.get("summary", "") or extra_payload.get("summary", "")).strip(),
            "confidence": str(data.get("confidence", "") or extra_payload.get("confidence", "")).strip(),
            "raw": alert,
            "dedup_key": compute_dedup_key(response_id, target_agent_id, recommended_action, response_command, params),
            "original_alert_id": first_non_empty(
                extra_payload.get("original_alert_id"),
                extra_payload.get("recommendation_alert_id"),
                data.get("recommendation_alert_id"),
                data.get("original_alert_id"),
            ),
        }

    def _build_orphan_entry_from_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "recommendation_alert_id": f"orphan:{event['wazuh_alert_id']}",
            "recommendation_rule_id": "",
            "recommendation_timestamp": event["timestamp"],
            "response_id": event["response_id"],
            "target_agent_id": event["target_agent_id"],
            "target_agent_name": event["target_agent_name"],
            "target_platform": event["target_platform"],
            "recommended_action": event["recommended_action"],
            "response_command": event["response_command"],
            "parameters": event["parameters"],
            "dedup_key": event["dedup_key"],
            "auto_execute": False,
            "execution_mode": "manual",
            "summary": event["summary"],
            "confidence": event["confidence"],
            "reasoning": "",
            "policy_name": "",
            "policy_reason": "",
            "response_rule_level": 0,
            "source_level": 0,
            "source_description": "",
            "source_ai_analysis": "",
            "manual_steps": [],
            "evidence_to_collect": [],
            "delivery_status": "not_sent",
            "delivery_timestamp": "",
            "delivery_alert_id": "",
            "execution_status": "not_executed",
            "execution_timestamp": "",
            "execution_alert_id": "",
            "rollback_status": "not_requested",
            "rollback_timestamp": "",
            "rollback_alert_id": "",
            "latest_status": "unknown",
            "latest_status_timestamp": event["timestamp"],
            "related_dispatch_events": [],
            "related_execution_events": [],
            "related_rollback_events": [],
        }

    def _is_open_entry(self, entry: Dict[str, Any]) -> bool:
        return str(entry.get("latest_status", "")).strip() in {
            "planned",
            "sent",
            "dispatch_failed",
            "execution_failed",
            "rollback_failed",
            "manual_restore_required",
            "unknown",
        }

    def _match_event_to_entry(self, event: Dict[str, Any], entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if event["original_alert_id"]:
            for entry in reversed(entries):
                if entry["recommendation_alert_id"] == event["original_alert_id"]:
                    return entry

        event_ts = parse_ts(event["timestamp"])

        exact_candidates = []
        for entry in entries:
            if entry["dedup_key"] != event["dedup_key"]:
                continue
            rec_ts = parse_ts(entry["recommendation_timestamp"])
            if event_ts and rec_ts and rec_ts > event_ts:
                continue
            exact_candidates.append(entry)

        if exact_candidates:
            exact_candidates.sort(
                key=lambda x: (
                    1 if self._is_open_entry(x) else 0,
                    parse_ts(x["recommendation_timestamp"]) or datetime.min.replace(tzinfo=timezone.utc),
                ),
                reverse=True,
            )
            return exact_candidates[0]

        relaxed_candidates = []
        for entry in entries:
            if entry["response_id"] != event["response_id"]:
                continue
            if entry["target_agent_id"] != event["target_agent_id"]:
                continue
            if entry["recommended_action"] != event["recommended_action"]:
                continue
            if not parameters_equivalent(entry.get("parameters", {}), event.get("parameters", {})):
                continue

            rec_ts = parse_ts(entry["recommendation_timestamp"])
            if event_ts and rec_ts and rec_ts > event_ts:
                continue

            relaxed_candidates.append(entry)

        if not relaxed_candidates:
            return None

        relaxed_candidates.sort(
            key=lambda x: (
                1 if self._is_open_entry(x) else 0,
                parse_ts(x["recommendation_timestamp"]) or datetime.min.replace(tzinfo=timezone.utc),
            ),
            reverse=True,
        )
        return relaxed_candidates[0]

    def _apply_event_to_entry(self, entry: Dict[str, Any], event: Dict[str, Any]) -> None:
        kind = event["kind"]
        status = event["status"]
        ts = event["timestamp"]

        if event.get("confidence") and not entry.get("confidence"):
            entry["confidence"] = event["confidence"]
        if event.get("summary") and not entry.get("summary"):
            entry["summary"] = event["summary"]

        if event.get("parameters"):
            merged = dict(entry.get("parameters", {}))
            for k, v in canonical_parameters(event.get("parameters", {})).items():
                if v:
                    merged[k] = v
            entry["parameters"] = merged

        if kind == "dispatch":
            entry["related_dispatch_events"].append(event)
            if status == "success":
                entry["delivery_status"] = "dispatch_success"
                entry["delivery_alert_id"] = event["wazuh_alert_id"]
                entry["delivery_timestamp"] = ts
                entry["latest_status"] = "sent"
                entry["latest_status_timestamp"] = ts
            else:
                entry["delivery_status"] = "dispatch_failed"
                entry["delivery_alert_id"] = event["wazuh_alert_id"]
                entry["delivery_timestamp"] = ts
                entry["latest_status"] = "dispatch_failed"
                entry["latest_status_timestamp"] = ts
            return

        if kind == "execution":
            entry["related_execution_events"].append(event)
            if status == "success":
                entry["execution_status"] = "executed"
                entry["execution_alert_id"] = event["wazuh_alert_id"]
                entry["execution_timestamp"] = ts
                entry["latest_status"] = "executed"
                entry["latest_status_timestamp"] = ts
            else:
                entry["execution_status"] = "execution_failed"
                entry["execution_alert_id"] = event["wazuh_alert_id"]
                entry["execution_timestamp"] = ts
                entry["latest_status"] = "execution_failed"
                entry["latest_status_timestamp"] = ts
            return

        if kind == "rollback":
            entry["related_rollback_events"].append(event)
            if status == "success":
                entry["rollback_status"] = "rolled_back"
                entry["rollback_alert_id"] = event["wazuh_alert_id"]
                entry["rollback_timestamp"] = ts
                entry["latest_status"] = "rolled_back"
                entry["latest_status_timestamp"] = ts
            elif status == "failed":
                entry["rollback_status"] = "rollback_failed"
                entry["rollback_alert_id"] = event["wazuh_alert_id"]
                entry["rollback_timestamp"] = ts
                entry["latest_status"] = "rollback_failed"
                entry["latest_status_timestamp"] = ts
            else:
                entry["rollback_status"] = "manual_restore_required"
                entry["rollback_alert_id"] = event["wazuh_alert_id"]
                entry["rollback_timestamp"] = ts
                entry["latest_status"] = "manual_restore_required"
                entry["latest_status_timestamp"] = ts

    def _decorate_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        action = str(entry.get("recommended_action", "")).strip()
        latest_status = str(entry.get("latest_status", "")).strip()

        is_actionable = action in ACTIONABLE_ACTIONS
        supports_rollback = action in ROLLBACK_SUPPORTED

        executable_statuses = {
            "planned",
            "dispatch_failed",
            "execution_failed",
            "rollback_failed",
            "manual_restore_required",
            "unknown",
        }

        visible_statuses = {
            "planned",
            "sent",
            "executed",
            "dispatch_failed",
            "execution_failed",
            "rollback_failed",
            "manual_restore_required",
            "unknown",
        }

        can_execute = is_actionable and latest_status in executable_statuses
        can_rollback = supports_rollback and latest_status == "executed"

        # Show all response recommendations in Control.
        # Only executable actions get Execute/Rollback buttons.
        control_visible = latest_status in visible_statuses

        entry["is_actionable"] = is_actionable
        entry["supports_rollback"] = supports_rollback
        entry["can_execute"] = can_execute
        entry["can_rollback"] = can_rollback
        entry["control_visible"] = control_visible
        return entry

    def _build_snapshot_from_alerts(self, alerts: List[Dict[str, Any]], source: str) -> Dict[str, Any]:
        normalized_alerts: List[Dict[str, Any]] = []

        for item in alerts:
            if isinstance(item, dict):
                normalized_alerts.append(_unwrap_alert_object(item))

        alerts = normalized_alerts
        alerts.sort(key=lambda a: parse_ts(a.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))

        recommendations_seen = 0
        action_events_seen = 0
        entries: List[Dict[str, Any]] = []

        for alert in alerts:
            if self._is_recommendation_alert(alert):
                recommendations_seen += 1
                entries.append(self._build_recommendation_entry(alert))

        entries.sort(key=lambda x: parse_ts(x["recommendation_timestamp"]) or datetime.min.replace(tzinfo=timezone.utc))

        for alert in alerts:
            if not self._is_action_event(alert):
                continue

            action_events_seen += 1
            event = self._extract_event_record(alert)
            entry = self._match_event_to_entry(event, entries)

            if not entry:
                entry = self._build_orphan_entry_from_event(event)
                entries.append(entry)

            self._apply_event_to_entry(entry, event)

        entries = [self._decorate_entry(item) for item in entries]
        entries.sort(
            key=lambda x: parse_ts(x["latest_status_timestamp"]) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True
        )

        counts = Counter()
        for item in entries:
            counts[item["latest_status"]] += 1

        control_visible_count = sum(1 for item in entries if item.get("control_visible"))

        return {
            "generated_at": ts_to_text(datetime.now(timezone.utc)),
            "source": source,
            "response_id": self.response_id,
            "counts": {
                "recommendations_seen": recommendations_seen,
                "action_events_seen": action_events_seen,
                "ledger_entries": len(entries),
                "control_visible_entries": control_visible_count,
                "by_latest_status": dict(counts),
            },
            "items": entries,
        }

    def load_from_alerts(self, alerts: List[Dict[str, Any]], source: str = "wazuh_indexer") -> Dict[str, Any]:
        return self._build_snapshot_from_alerts(alerts, source=source)

    def load(self) -> Dict[str, Any]:
        alerts = list(self._iter_alert_objects())
        return self._build_snapshot_from_alerts(alerts, source=str(self.alerts_file))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build centralized AI action ledger from Wazuh archive alerts.")
    parser.add_argument("--alerts-file", default=DEFAULT_ALERTS_FILE)
    parser.add_argument("--response-id", default=RESPONSE_ID)
    parser.add_argument("--output-json", default="")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    ledger = CentralizedActionLedger(alerts_file=args.alerts_file, response_id=args.response_id)
    snapshot = ledger.load()

    if args.output_json:
        path = Path(args.output_json)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.pretty:
        print(json.dumps(snapshot, indent=2, ensure_ascii=False))
        return

    print(f"[LEDGER] generated_at={snapshot['generated_at']}")
    print(f"[LEDGER] source={snapshot['source']}")
    print(f"[LEDGER] recommendations_seen={snapshot['counts']['recommendations_seen']}")
    print(f"[LEDGER] action_events_seen={snapshot['counts']['action_events_seen']}")
    print(f"[LEDGER] ledger_entries={snapshot['counts']['ledger_entries']}")
    print(f"[LEDGER] control_visible_entries={snapshot['counts']['control_visible_entries']}")
    print(f"[LEDGER] by_latest_status={snapshot['counts']['by_latest_status']}")
    for item in snapshot["items"][:args.limit]:
        print(
            f"- recommendation_alert_id={item['recommendation_alert_id']} | "
            f"agent={item['target_agent_id']}:{item['target_agent_name']} | "
            f"action={item['recommended_action']} | "
            f"latest_status={item['latest_status']} | "
            f"control_visible={item['control_visible']} | "
            f"latest_ts={item['latest_status_timestamp']}"
        )


if __name__ == "__main__":
    main()