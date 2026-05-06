#!/usr/bin/env python3
import os
import sys
import json
import datetime
import subprocess
from typing import Any, Dict, Optional

import requests

# =========================
# PATHS / CONFIG
# =========================
if os.name == "nt":
    LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ENV_FILE = "/var/ossec/etc/ai-response-dispatcher.env"
JOURNAL_FILE = "/var/ossec/logs/ai-response-dispatcher.jsonl"
AR_BIN_DIR = "/var/ossec/active-response/bin"

RESPONSE_ID = "000_response_ai"

DEFAULT_API_URL = "https://127.0.0.1:55000"
DEFAULT_API_TIMEOUT = 20
DEFAULT_VERIFY_TLS = False

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

MANAGER_LOCAL_AGENT_IDS = {"000"}

LOCAL_COMMAND_EXECUTABLE = {
    "ai-quarantine-file-linux0": "ai-quarantine-file.py",
    "ai-block-ip-linux0": "ai-block-ip.py",
    "ai-kill-process-linux0": "ai-kill-process.py",
    "ai-disable-user-linux0": "ai-disable-user.py",
    "ai-isolate-host-linux0": "ai-isolate-host.py",

    "ai-quarantine-file-windows0": "ai-quarantine-file.py",
    "ai-block-ip-windows0": "ai-block-ip.py",
    "ai-kill-process-windows0": "ai-kill-process.py",
    "ai-disable-user-windows0": "ai-disable-user.py",
    "ai-isolate-host-windows0": "ai-isolate-host.py",
}

LOCAL_COMMAND_EXECUTABLE.update({
    "ai-quarantine-file-linux": "ai-quarantine-file.py",
    "ai-block-ip-linux": "ai-block-ip.py",
    "ai-kill-process-linux": "ai-kill-process.py",
    "ai-disable-user-linux": "ai-disable-user.py",
    "ai-isolate-host-linux": "ai-isolate-host.py",

    "ai-quarantine-file-windows": "ai-quarantine-file.py",
    "ai-block-ip-windows": "ai-block-ip.py",
    "ai-kill-process-windows": "ai-kill-process.py",
    "ai-disable-user-windows": "ai-disable-user.py",
    "ai-isolate-host-windows": "ai-isolate-host.py",
})


# =========================
# JSON HELPERS
# =========================
def json_loads(value: str) -> Any:
    return json.loads(value)


def json_dumps_text(value: Any) -> str:
    dumped = json.dumps(value, ensure_ascii=False)
    return dumped.decode("utf-8") if isinstance(dumped, bytes) else dumped


# =========================
# LOGGING / JOURNAL
# =========================
def write_debug_file(ar_name: str, msg: str) -> None:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
        log_file.write(f"{timestamp} {ar_name}: {msg}\n")


def write_journal(entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(JOURNAL_FILE), exist_ok=True)
    item = dict(entry)
    item["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(JOURNAL_FILE, mode="a", encoding="utf-8") as file_obj:
        file_obj.write(json_dumps_text(item) + "\n")


# =========================
# ENV / SETTINGS
# =========================
def load_env_file(path: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not os.path.exists(path):
        return values

    with open(path, "r", encoding="utf-8") as file_obj:
        for raw_line in file_obj:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


ENV = load_env_file(ENV_FILE)

API_URL = os.getenv("WAZUH_API_URL", ENV.get("WAZUH_API_URL", DEFAULT_API_URL)).rstrip("/")
API_USER = os.getenv("WAZUH_API_USER", ENV.get("WAZUH_API_USER", ""))
API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", ENV.get("WAZUH_API_PASSWORD", ""))
API_TIMEOUT = int(os.getenv("WAZUH_API_TIMEOUT", ENV.get("WAZUH_API_TIMEOUT", str(DEFAULT_API_TIMEOUT))))
VERIFY_TLS = str(
    os.getenv("WAZUH_API_VERIFY_TLS", ENV.get("WAZUH_API_VERIFY_TLS", str(DEFAULT_VERIFY_TLS)))
).strip().lower() in ("1", "true", "yes", "on")


# =========================
# ACTIVE RESPONSE MESSAGE
# =========================
class Message:
    def __init__(self) -> None:
        self.alert: Dict[str, Any] = {}
        self.command: int = OS_INVALID


def setup_and_check_message(argv) -> Message:
    msg = Message()

    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    if not input_str:
        write_debug_file(argv[0], "No input received on STDIN")
        msg.command = OS_INVALID
        return msg

    try:
        data = json_loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Decoding JSON failed, invalid input format")
        msg.command = OS_INVALID
        return msg

    msg.alert = data

    command = data.get("command")
    if command == "add":
        msg.command = ADD_COMMAND
    elif command == "delete":
        msg.command = DELETE_COMMAND
    else:
        msg.command = OS_INVALID
        write_debug_file(argv[0], f"Invalid command: {command}")

    return msg


def send_keys_and_check_message(argv, keys):
    keys_msg = json_dumps_text({
        "version": 1,
        "origin": {
            "name": argv[0],
            "module": "active-response",
        },
        "command": "check_keys",
        "parameters": {
            "keys": keys
        }
    })

    write_debug_file(argv[0], f"check_keys => {keys_msg}")

    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json_loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Decoding JSON failed on check_keys response")
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    if action == "abort":
        return ABORT_COMMAND

    write_debug_file(argv[0], f"Invalid check_keys response command: {action}")
    return OS_INVALID


# =========================
# PAYLOAD HELPERS
# =========================
def get_nested(data: Dict[str, Any], *path: str, default=None):
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def normalize_bool_str(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_parameters(parameters: Dict[str, Any]) -> Dict[str, str]:
    parameters = parameters if isinstance(parameters, dict) else {}
    return {
        "ip": normalize_text(parameters.get("ip", "")),
        "path": normalize_text(parameters.get("path", "")),
        "user": normalize_text(parameters.get("user", "")),
        "tty": normalize_text(parameters.get("tty", "")),
        "service_name": normalize_text(parameters.get("service_name", "")),
    }


def build_action_key(alert: Dict[str, Any]) -> str:
    data = alert.get("data", {}) or {}
    ai_response = data.get("ai_response", {}) or {}

    parts = [
        str(data.get("response_id", "")),
        str(ai_response.get("target_agent_id", "")),
        str(ai_response.get("response_command", "")),
        str(ai_response.get("recommended_action", "")),
        str(get_nested(ai_response, "action_parameters", "ip", default="")),
        str(get_nested(ai_response, "action_parameters", "path", default="")),
        str(get_nested(ai_response, "action_parameters", "user", default="")),
        str(get_nested(ai_response, "action_parameters", "tty", default="")),
        str(get_nested(ai_response, "action_parameters", "service_name", default="")),
        str(alert.get("id", "")),
        str(alert.get("timestamp", "")),
    ]
    return "|".join(parts)


def extract_response_context(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    data = alert.get("data", {}) or {}

    if data.get("response_id") != RESPONSE_ID:
        return None

    ai_response = data.get("ai_response", {}) or {}
    ai_agent_info = data.get("ai_agent_info", {}) or {}
    source_ai_alert = data.get("source_ai_alert", {}) or {}

    return {
        "mode": "auto",
        "response_id": data.get("response_id", ""),
        "response_origin": str(data.get("response_origin", "")).strip(),
        "target_agent_id": str(ai_response.get("target_agent_id", ai_agent_info.get("id", "000"))),
        "target_agent_name": str(ai_response.get("target_agent_name", ai_agent_info.get("name", "unknown"))),
        "target_platform": str(ai_response.get("target_platform", ai_agent_info.get("platform", "unknown"))).lower(),
        "recommended_action": str(ai_response.get("recommended_action", "")).strip(),
        "response_command": str(ai_response.get("response_command", "")).strip(),
        "auto_execute": normalize_bool_str(ai_response.get("auto_execute", "False")),
        "policy_name": str(ai_response.get("policy_name", "")),
        "policy_reason": str(ai_response.get("policy_reason", "")),
        "summary": str(ai_response.get("summary", "")),
        "confidence": str(ai_response.get("confidence", "")),
        "source_level": int(source_ai_alert.get("level", 0) or 0),
        "parameters": normalize_parameters(ai_response.get("action_parameters", {}) or {}),
        "manual_steps": ai_response.get("manual_steps", []) or [],
        "evidence_to_collect": ai_response.get("evidence_to_collect", []) or [],
        "full_log": str(data.get("full_log", "")),
        "original_alert_id": str(alert.get("id", "")),
        "original_alert_timestamp": str(alert.get("timestamp", "")),
        "requested_command": "add",
        "control_operation": "",
        "recommendation_alert_id": "",
    }


def extract_manual_request(wrapper: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    params = wrapper.get("parameters", {}) or {}
    if not params.get("control_direct"):
        return None

    extra_args = params.get("extra_args", []) or []
    if not extra_args:
        return None

    raw = extra_args[0]
    payload = None

    if isinstance(raw, dict):
        payload = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            payload = json_loads(raw)
        except Exception:
            payload = None

    if not isinstance(payload, dict):
        return None

    if normalize_text(payload.get("response_id")) != RESPONSE_ID:
        return None

    response_command = normalize_text(payload.get("response_command"))
    recommended_action = normalize_text(payload.get("recommended_action"))
    target_agent_id = normalize_text(payload.get("target_agent_id"))
    requested_command = normalize_text(payload.get("requested_command")) or (
        "delete" if normalize_text(wrapper.get("command")) == "delete" else "add"
    )

    if not response_command or not recommended_action or not target_agent_id:
        return None

    return {
        "mode": "manual",
        "response_id": normalize_text(payload.get("response_id")),
        "response_origin": normalize_text(payload.get("response_origin")) or "ai_control_api_manual",
        "target_agent_id": target_agent_id,
        "target_agent_name": normalize_text(payload.get("target_agent_name")) or "unknown",
        "target_platform": normalize_text(payload.get("target_platform")).lower() or "unknown",
        "recommended_action": recommended_action,
        "response_command": response_command,
        "auto_execute": False,
        "policy_name": normalize_text(payload.get("policy_name")),
        "policy_reason": normalize_text(payload.get("policy_reason")),
        "summary": normalize_text(payload.get("summary")),
        "confidence": normalize_text(payload.get("confidence")) or "high",
        "source_level": int(payload.get("source_level", 0) or 0),
        "parameters": normalize_parameters(payload.get("parameters", {})),
        "manual_steps": payload.get("manual_steps", []) or [],
        "evidence_to_collect": payload.get("evidence_to_collect", []) or [],
        "full_log": normalize_text(payload.get("summary")),
        "original_alert_id": normalize_text(payload.get("original_alert_id")),
        "original_alert_timestamp": normalize_text(payload.get("original_alert_timestamp")),
        "requested_command": requested_command,
        "control_operation": normalize_text(payload.get("control_operation")),
        "recommendation_alert_id": normalize_text(payload.get("recommendation_alert_id")),
        "raw_payload": payload,
    }


def build_extra_payload_from_auto(ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "response_id": ctx["response_id"],
        "target_agent_id": ctx["target_agent_id"],
        "target_agent_name": ctx["target_agent_name"],
        "target_platform": ctx["target_platform"],
        "recommended_action": ctx["recommended_action"],
        "response_command": ctx["response_command"],
        "policy_name": ctx["policy_name"],
        "policy_reason": ctx["policy_reason"],
        "source_level": ctx["source_level"],
        "summary": ctx["summary"],
        "confidence": ctx["confidence"],
        "parameters": ctx["parameters"],
        "original_alert_id": ctx["original_alert_id"],
        "original_alert_timestamp": ctx["original_alert_timestamp"],
    }


def build_extra_payload_from_manual(ctx: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "response_id": ctx["response_id"],
        "target_agent_id": ctx["target_agent_id"],
        "target_agent_name": ctx["target_agent_name"],
        "target_platform": ctx["target_platform"],
        "recommended_action": ctx["recommended_action"],
        "response_command": ctx["response_command"],
        "policy_name": ctx["policy_name"],
        "policy_reason": ctx["policy_reason"],
        "source_level": ctx["source_level"],
        "summary": ctx["summary"],
        "confidence": ctx["confidence"],
        "parameters": ctx["parameters"],
        "original_alert_id": ctx.get("original_alert_id", ""),
        "original_alert_timestamp": ctx.get("original_alert_timestamp", ""),
        "recommendation_alert_id": ctx.get("recommendation_alert_id", ""),
        "control_operation": ctx.get("control_operation", ""),
        "requested_command": ctx.get("requested_command", "add"),
    }


# =========================
# COMMAND RESOLUTION
# =========================
def resolve_local_executable_name(command_name: str) -> str:
    return LOCAL_COMMAND_EXECUTABLE.get(command_name, command_name)


def resolve_dispatch_command(base_command: str, target_platform: str) -> str:
    base_command = normalize_text(base_command)
    target_platform = normalize_text(target_platform).lower()

    if not base_command.startswith("ai-"):
        return base_command

    has_zero_index = False
    if base_command.endswith("0"):
        base_command = base_command[:-1]
        has_zero_index = True

    if "windows" in target_platform:
        command_to_send = f"{base_command}-windows"
    else:
        command_to_send = f"{base_command}-linux"

    if has_zero_index:
        command_to_send = f"{command_to_send}0"

    return command_to_send


# =========================
# WAZUH API
# =========================
def get_api_token() -> str:
    if not API_USER or not API_PASSWORD:
        raise RuntimeError("Missing WAZUH_API_USER or WAZUH_API_PASSWORD")

    url = f"{API_URL}/security/user/authenticate?raw=true"
    response = requests.post(
        url,
        auth=(API_USER, API_PASSWORD),
        verify=VERIFY_TLS,
        timeout=API_TIMEOUT,
    )
    response.raise_for_status()
    return response.text.strip()


def _validate_remote_active_response_result(response_json: Dict[str, Any]) -> None:
    if not isinstance(response_json, dict):
        raise RuntimeError(f"Invalid Wazuh API response type: {type(response_json).__name__}")

    api_error = response_json.get("error", 0)
    data = response_json.get("data", {}) or {}
    total_failed_items = int(data.get("total_failed_items", 0) or 0)
    failed_items = data.get("failed_items", []) or []

    if api_error != 0 or total_failed_items > 0:
        raise RuntimeError(
            "Wazuh API active-response logical failure: "
            f"error={api_error}, total_failed_items={total_failed_items}, "
            f"failed_items={json_dumps_text(failed_items)}"
        )


def run_remote_active_response(target_agent_id: str, command_name: str, extra_payload: Dict[str, Any]) -> Dict[str, Any]:
    token = get_api_token()
    url = f"{API_URL}/active-response"

    body = {
        "command": command_name,
        "arguments": [json_dumps_text(extra_payload)],
    }

    response = requests.put(
        url,
        params={"agents_list": target_agent_id},
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=body,
        verify=VERIFY_TLS,
        timeout=API_TIMEOUT,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"Wazuh API active-response failed: status={response.status_code} body={response.text}"
        )

    response_json = response.json()
    _validate_remote_active_response_result(response_json)
    return response_json


# =========================
# LOCAL EXECUTION FOR AGENT 000
# =========================
def run_local_active_response(command_name: str, extra_payload: Dict[str, Any], ar_command: str = "add") -> None:
    executable_name = resolve_local_executable_name(command_name)
    executable_path = os.path.join(AR_BIN_DIR, executable_name)

    if not os.path.exists(executable_path):
        raise RuntimeError(
            f"Local active response executable not found: {executable_path} "
            f"(command_name={command_name}, resolved_executable={executable_name})"
        )

    wrapper = {
        "version": 1,
        "origin": {
            "name": "ai_response_dispatcher.py",
            "module": "active-response"
        },
        "command": ar_command,
        "parameters": {
            "extra_args": [json_dumps_text(extra_payload)],
            "alert": {},
            "program": command_name,
        }
    }

    proc = subprocess.run(
        [executable_path],
        input=(json_dumps_text(wrapper) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )

    stdout_text = proc.stdout.decode("utf-8", errors="ignore").strip()
    stderr_text = proc.stderr.decode("utf-8", errors="ignore").strip()

    if proc.returncode != 0:
        raise RuntimeError(
            f"Local AR failed rc={proc.returncode} stdout={stdout_text} stderr={stderr_text}"
        )


# =========================
# DISPATCH CORE
# =========================
def dispatch_context(argv, ctx: Dict[str, Any]) -> int:
    requested_command = normalize_text(ctx.get("requested_command")) or "add"
    resolved_command = resolve_dispatch_command(ctx["response_command"], ctx["target_platform"])

    if ctx["mode"] == "manual":
        extra_payload = build_extra_payload_from_manual(ctx)
    else:
        extra_payload = build_extra_payload_from_auto(ctx)

    write_debug_file(
        argv[0],
        f"Dispatching | mode={ctx['mode']} | target_agent={ctx['target_agent_id']} | "
        f"platform={ctx['target_platform']} | base_command={ctx['response_command']} | "
        f"resolved_command={resolved_command} | requested_command={requested_command} | "
        f"action={ctx['recommended_action']}"
    )

    try:
        if ctx["target_agent_id"] in MANAGER_LOCAL_AGENT_IDS:
            run_local_active_response(
                command_name=resolved_command,
                extra_payload=extra_payload,
                ar_command=requested_command,
            )
            result = {
                "mode": "local_manager_execution",
                "status": "sent",
                "resolved_local_executable": resolve_local_executable_name(resolved_command),
            }
        else:
            api_result = run_remote_active_response(
                target_agent_id=ctx["target_agent_id"],
                command_name=resolved_command,
                extra_payload=extra_payload,
            )
            result = {"mode": "remote_agent_execution", "api_result": api_result}

        write_journal({
            "event": "dispatch_success",
            "response_id": ctx["response_id"],
            "target_agent_id": ctx["target_agent_id"],
            "target_agent_name": ctx["target_agent_name"],
            "target_platform": ctx["target_platform"],
            "recommended_action": ctx["recommended_action"],
            "response_command": ctx["response_command"],
            "resolved_command": resolved_command,
            "requested_command": requested_command,
            "control_operation": ctx.get("control_operation", ""),
            "recommendation_alert_id": ctx.get("recommendation_alert_id", ""),
            "original_alert_id": ctx.get("original_alert_id", ""),
            "auto_execute": bool(ctx.get("auto_execute", False)),
            "result": result,
            "extra_payload": extra_payload,
        })

        write_debug_file(
            argv[0],
            f"Dispatched successfully | mode={ctx['mode']} | target_agent={ctx['target_agent_id']} "
            f"| requested_command={requested_command} | command={ctx['response_command']}"
        )
        return OS_SUCCESS

    except Exception as exc:
        write_journal({
            "event": "dispatch_failed",
            "response_id": ctx["response_id"],
            "target_agent_id": ctx["target_agent_id"],
            "target_agent_name": ctx["target_agent_name"],
            "target_platform": ctx["target_platform"],
            "recommended_action": ctx["recommended_action"],
            "response_command": ctx["response_command"],
            "resolved_command": resolved_command,
            "requested_command": requested_command,
            "control_operation": ctx.get("control_operation", ""),
            "recommendation_alert_id": ctx.get("recommendation_alert_id", ""),
            "original_alert_id": ctx.get("original_alert_id", ""),
            "auto_execute": bool(ctx.get("auto_execute", False)),
            "error": str(exc),
            "extra_payload": extra_payload,
        })
        write_debug_file(argv[0], f"Dispatch failed: {exc}")
        return OS_INVALID


# =========================
# MAIN DISPATCH LOGIC
# =========================
def handle_add(argv, wrapper: Dict[str, Any]) -> int:
    manual_ctx = extract_manual_request(wrapper)
    if manual_ctx:
        write_debug_file(
            argv[0],
            f"Direct manual execute request received | target_agent={manual_ctx['target_agent_id']} "
            f"| action={manual_ctx['recommended_action']}"
        )
        return dispatch_context(argv, manual_ctx)

    alert = get_nested(wrapper, "parameters", "alert", default={}) or {}
    ctx = extract_response_context(alert)

    if not ctx:
        write_debug_file(argv[0], "Ignored non-response alert")
        return OS_SUCCESS

    if not ctx["auto_execute"]:
        write_debug_file(
            argv[0],
            f"Manual-only response ignored | target_agent={ctx['target_agent_id']} "
            f"| action={ctx['recommended_action']} | reason={ctx['policy_reason']}"
        )
        return OS_SUCCESS

    if not ctx["response_command"]:
        write_debug_file(argv[0], "auto_execute=True but response_command is empty")
        return OS_INVALID

    action_key = build_action_key(alert)
    decision = send_keys_and_check_message(argv, [action_key])

    if decision == ABORT_COMMAND:
        write_debug_file(argv[0], f"Aborted duplicated action | key={action_key}")
        return OS_SUCCESS

    if decision != CONTINUE_COMMAND:
        write_debug_file(argv[0], f"Invalid check_keys decision | key={action_key}")
        return OS_INVALID

    return dispatch_context(argv, ctx)


def handle_delete(argv, wrapper: Dict[str, Any]) -> int:
    manual_ctx = extract_manual_request(wrapper)
    if manual_ctx:
        write_debug_file(
            argv[0],
            f"Direct manual rollback request received | target_agent={manual_ctx['target_agent_id']} "
            f"| action={manual_ctx['recommended_action']}"
        )
        return dispatch_context(argv, manual_ctx)

    alert = get_nested(wrapper, "parameters", "alert", default={}) or {}
    ctx = extract_response_context(alert)

    if ctx:
        write_debug_file(
            argv[0],
            f"Delete command received from Wazuh path and ignored by design | "
            f"target_agent={ctx['target_agent_id']} | command={ctx['response_command']}"
        )
    else:
        write_debug_file(argv[0], "Delete command received for unrelated alert, ignored")

    return OS_SUCCESS


def main(argv) -> int:
    write_debug_file(argv[0], "Started")

    msg = setup_and_check_message(argv)
    if msg.command < 0:
        write_debug_file(argv[0], "Invalid incoming message")
        return OS_INVALID

    if msg.command == ADD_COMMAND:
        rc = handle_add(argv, msg.alert)
    elif msg.command == DELETE_COMMAND:
        rc = handle_delete(argv, msg.alert)
    else:
        rc = OS_INVALID

    write_debug_file(argv[0], f"Ended with rc={rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))