#!/usr/bin/env python3
import os
import sys
import json
import time
import shutil
import hashlib
import datetime
from typing import Any, Dict, Optional, List

if os.name == "nt":
    LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
    QUARANTINE_ROOT = r"C:\Program Files (x86)\ossec-agent\quarantine"
    JOURNAL_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\ai-quarantine-file.jsonl"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    QUARANTINE_ROOT = "/var/ossec/quarantine/files"
    JOURNAL_FILE = "/var/ossec/logs/ai-quarantine-file.jsonl"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1


class Message:
    def __init__(self):
        self.alert: Dict[str, Any] = {}
        self.command = OS_INVALID


def json_loads(value: str) -> Any:
    return json.loads(value)


def json_dumps_text(value: Any) -> str:
    dumped = json.dumps(value, ensure_ascii=False)
    return dumped.decode("utf-8") if isinstance(dumped, bytes) else dumped


def write_debug_file(ar_name: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
        log_file.write(f"{ts} {ar_name}: {msg}\n")


def write_journal(entry: Dict[str, Any]) -> None:
    entry = dict(entry)
    entry["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    os.makedirs(os.path.dirname(JOURNAL_FILE), exist_ok=True)
    with open(JOURNAL_FILE, mode="a", encoding="utf-8") as file_obj:
        file_obj.write(json_dumps_text(entry) + "\n")


def read_journal_entries() -> List[Dict[str, Any]]:
    if not os.path.exists(JOURNAL_FILE):
        return []

    entries: List[Dict[str, Any]] = []
    with open(JOURNAL_FILE, mode="r", encoding="utf-8") as file_obj:
        for line in file_obj:
            line = line.strip()
            if not line:
                continue
            try:
                item = json_loads(line)
                if isinstance(item, dict):
                    entries.append(item)
            except Exception:
                continue
    return entries


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        write_debug_file(argv[0], "Decoding JSON has failed, invalid input format")
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
        write_debug_file(argv[0], f"Not valid command: {command}")

    return msg


def send_keys_and_check_message(argv, keys):
    keys_msg = json_dumps_text({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
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
        write_debug_file(argv[0], "Decoding JSON has failed on check_keys response")
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    if action == "abort":
        return ABORT_COMMAND

    write_debug_file(argv[0], f"Invalid value of 'command': {action}")
    return OS_INVALID


def get_nested(data: Dict[str, Any], *path: str, default=None):
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def extract_extra_payload(wrapper: Dict[str, Any]) -> Dict[str, Any]:
    params = wrapper.get("parameters", {}) or {}

    extra_args = params.get("extra_args", [])
    if isinstance(extra_args, list):
        for item in extra_args:
            if isinstance(item, dict):
                return item
            if isinstance(item, str) and item.strip():
                try:
                    parsed = json_loads(item)
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    continue

    alert = params.get("alert", {}) or {}
    data = alert.get("data", {}) or {}
    ai_response = data.get("ai_response", {}) or {}

    if ai_response:
        action_parameters = ai_response.get("action_parameters", {}) or {}
        return {
            "response_id": data.get("response_id", ""),
            "target_agent_id": ai_response.get("target_agent_id", ""),
            "target_agent_name": ai_response.get("target_agent_name", ""),
            "target_platform": ai_response.get("target_platform", ""),
            "recommended_action": ai_response.get("recommended_action", ""),
            "response_command": ai_response.get("response_command", ""),
            "policy_name": ai_response.get("policy_name", ""),
            "policy_reason": ai_response.get("policy_reason", ""),
            "source_level": data.get("source_ai_alert", {}).get("level", 0),
            "summary": ai_response.get("summary", ""),
            "confidence": ai_response.get("confidence", ""),
            "parameters": {
                "ip": str(action_parameters.get("ip", "")),
                "path": str(action_parameters.get("path", "")),
                "user": str(action_parameters.get("user", "")),
                "tty": str(action_parameters.get("tty", "")),
                "service_name": str(action_parameters.get("service_name", "")),
                
            }
        }

    return {}


def parse_boolish(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def resolve_effective_command(incoming_command: int, payload: Dict[str, Any]) -> int:
    if incoming_command == DELETE_COMMAND:
        return DELETE_COMMAND

    if not isinstance(payload, dict):
        return incoming_command

    requested_command = str(payload.get("requested_command", "")).strip().lower()
    control_operation = str(payload.get("control_operation", "")).strip().lower()

    if requested_command == "delete":
        return DELETE_COMMAND

    if control_operation in ("delete", "rollback", "undo", "restore"):
        return DELETE_COMMAND

    if parse_boolish(payload.get("rollback", False)):
        return DELETE_COMMAND

    return incoming_command


def normalize_path(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


def build_action_key(extra_payload: Dict[str, Any], original_path: str) -> str:
    return "|".join([
        str(extra_payload.get("response_id", "")),
        str(extra_payload.get("target_agent_id", "")),
        str(extra_payload.get("recommended_action", "")),
        original_path,
    ])


def build_quarantine_destination(original_path: str) -> str:
    os.makedirs(QUARANTINE_ROOT, exist_ok=True)

    day_dir = datetime.datetime.utcnow().strftime("%Y%m%d")
    target_dir = os.path.join(QUARANTINE_ROOT, day_dir)
    os.makedirs(target_dir, exist_ok=True)

    basename = os.path.basename(original_path) or "unknown_file"
    ts = datetime.datetime.utcnow().strftime("%H%M%S")
    suffix = hashlib.md5(f"{original_path}|{time.time()}".encode("utf-8")).hexdigest()[:10]

    new_name = f"{basename}.{ts}.{suffix}.quarantine"
    return os.path.join(target_dir, new_name)


def resolve_restore_entry(extra_payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    response_id = str(extra_payload.get("response_id", "")).strip()
    target_path = normalize_path(str(get_nested(extra_payload, "parameters", "path", default="")).strip())
    journal = read_journal_entries()

    for entry in reversed(journal):
        if entry.get("event") != "quarantine_success":
            continue

        entry_response_id = str(entry.get("response_id", "")).strip()
        entry_original_path = normalize_path(str(entry.get("original_path", "")).strip())

        if response_id and entry_response_id == response_id:
            return entry

        if target_path and entry_original_path == target_path:
            return entry

    return None


def quarantine_file(argv, wrapper: Dict[str, Any], incoming_command: int, effective_command: int) -> int:
    extra_payload = extract_extra_payload(wrapper)
    if not extra_payload:
        write_debug_file(argv[0], "No extra payload found")
        return OS_INVALID

    raw_path = str(get_nested(extra_payload, "parameters", "path", default="")).strip()
    if not raw_path:
        write_debug_file(argv[0], "No path provided for quarantine_file")
        return OS_INVALID

    original_path = normalize_path(raw_path)

    if original_path.startswith(normalize_path(QUARANTINE_ROOT) + os.sep):
        write_debug_file(argv[0], f"Path already under quarantine root: {original_path}")
        return OS_SUCCESS

    if not os.path.exists(original_path):
        write_debug_file(argv[0], f"Target file does not exist: {original_path}")
        return OS_INVALID

    if not os.path.isfile(original_path):
        write_debug_file(argv[0], f"Target path is not a regular file: {original_path}")
        return OS_INVALID

    action_key = build_action_key(extra_payload, original_path)
    decision = send_keys_and_check_message(argv, [action_key])

    if decision == ABORT_COMMAND:
        write_debug_file(argv[0], f"Aborted duplicated quarantine action for: {original_path}")
        return OS_SUCCESS
    if decision != CONTINUE_COMMAND:
        write_debug_file(argv[0], f"Invalid check_keys response for: {original_path}")
        return OS_INVALID

    try:
        file_hash = sha256_file(original_path)
        file_size = os.path.getsize(original_path)
        destination = build_quarantine_destination(original_path)

        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.move(original_path, destination)

        try:
            os.chmod(destination, 0o600)
        except Exception:
            pass

        write_journal({
            "event": "quarantine_success",
            "response_id": extra_payload.get("response_id", ""),
            "target_agent_id": extra_payload.get("target_agent_id", ""),
            "target_agent_name": extra_payload.get("target_agent_name", ""),
            "target_platform": extra_payload.get("target_platform", ""),
            "recommended_action": extra_payload.get("recommended_action", ""),
            "response_command": extra_payload.get("response_command", ""),
            "policy_name": extra_payload.get("policy_name", ""),
            "policy_reason": extra_payload.get("policy_reason", ""),
            "source_level": extra_payload.get("source_level", 0),
            "summary": extra_payload.get("summary", ""),
            "confidence": extra_payload.get("confidence", ""),
            "original_path": original_path,
            "quarantine_path": destination,
            "sha256": file_hash,
            "size": file_size,
            "parameters": extra_payload.get("parameters", {}),
            "incoming_command": incoming_command,
            "effective_command": effective_command,
            "requested_command": extra_payload.get("requested_command", ""),
            "control_operation": extra_payload.get("control_operation", ""),
            "recommendation_alert_id": extra_payload.get("recommendation_alert_id", ""),
            "original_alert_id": extra_payload.get("original_alert_id", ""),
        })

        write_debug_file(
            argv[0],
            f"Quarantined file successfully | original={original_path} | quarantine={destination} | sha256={file_hash} | incoming_command={incoming_command} | effective_command={effective_command}"
        )
        return OS_SUCCESS

    except Exception as exc:
        write_journal({
            "event": "quarantine_failed",
            "response_id": extra_payload.get("response_id", ""),
            "target_agent_id": extra_payload.get("target_agent_id", ""),
            "target_agent_name": extra_payload.get("target_agent_name", ""),
            "target_platform": extra_payload.get("target_platform", ""),
            "recommended_action": extra_payload.get("recommended_action", ""),
            "response_command": extra_payload.get("response_command", ""),
            "original_path": original_path,
            "error": str(exc),
            "parameters": extra_payload.get("parameters", {}),
            "incoming_command": incoming_command,
            "effective_command": effective_command,
            "requested_command": extra_payload.get("requested_command", ""),
            "control_operation": extra_payload.get("control_operation", ""),
            "recommendation_alert_id": extra_payload.get("recommendation_alert_id", ""),
            "original_alert_id": extra_payload.get("original_alert_id", ""),
        })
        write_debug_file(argv[0], f"Error quarantining file {original_path}: {exc}")
        return OS_INVALID


def restore_file(argv, wrapper: Dict[str, Any], incoming_command: int, effective_command: int) -> int:
    extra_payload = extract_extra_payload(wrapper)
    if not extra_payload:
        write_debug_file(argv[0], "No extra payload found for restore")
        return OS_INVALID

    entry = resolve_restore_entry(extra_payload)
    if not entry:
        write_debug_file(argv[0], "No matching quarantine journal entry found for restore")
        return OS_INVALID

    original_path = normalize_path(str(entry.get("original_path", "")).strip())
    quarantine_path = normalize_path(str(entry.get("quarantine_path", "")).strip())

    if not quarantine_path or not os.path.exists(quarantine_path):
        write_debug_file(argv[0], f"Quarantine path not found: {quarantine_path}")
        return OS_INVALID

    if os.path.exists(original_path):
        write_debug_file(argv[0], f"Original path already exists, restore skipped: {original_path}")
        return OS_INVALID

    try:
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.move(quarantine_path, original_path)

        write_journal({
            "event": "restore_success",
            "response_id": extra_payload.get("response_id", ""),
            "target_agent_id": extra_payload.get("target_agent_id", ""),
            "target_agent_name": extra_payload.get("target_agent_name", ""),
            "target_platform": extra_payload.get("target_platform", ""),
            "recommended_action": extra_payload.get("recommended_action", ""),
            "response_command": extra_payload.get("response_command", ""),
            "policy_name": extra_payload.get("policy_name", ""),
            "policy_reason": extra_payload.get("policy_reason", ""),
            "source_level": extra_payload.get("source_level", 0),
            "summary": extra_payload.get("summary", ""),
            "confidence": extra_payload.get("confidence", ""),
            "original_path": original_path,
            "quarantine_path": quarantine_path,
            "parameters": extra_payload.get("parameters", {}),
            "incoming_command": incoming_command,
            "effective_command": effective_command,
            "requested_command": extra_payload.get("requested_command", ""),
            "control_operation": extra_payload.get("control_operation", ""),
            "recommendation_alert_id": extra_payload.get("recommendation_alert_id", ""),
            "original_alert_id": extra_payload.get("original_alert_id", ""),
        })

        write_debug_file(
            argv[0],
            f"Restored file successfully | original={original_path} | quarantine={quarantine_path} | incoming_command={incoming_command} | effective_command={effective_command}"
        )
        return OS_SUCCESS

    except Exception as exc:
        write_journal({
            "event": "restore_failed",
            "response_id": extra_payload.get("response_id", ""),
            "target_agent_id": extra_payload.get("target_agent_id", ""),
            "target_agent_name": extra_payload.get("target_agent_name", ""),
            "target_platform": extra_payload.get("target_platform", ""),
            "recommended_action": extra_payload.get("recommended_action", ""),
            "response_command": extra_payload.get("response_command", ""),
            "original_path": original_path,
            "quarantine_path": quarantine_path,
            "error": str(exc),
            "parameters": extra_payload.get("parameters", {}),
            "incoming_command": incoming_command,
            "effective_command": effective_command,
            "requested_command": extra_payload.get("requested_command", ""),
            "control_operation": extra_payload.get("control_operation", ""),
            "recommendation_alert_id": extra_payload.get("recommendation_alert_id", ""),
            "original_alert_id": extra_payload.get("original_alert_id", ""),
        })
        write_debug_file(argv[0], f"Error restoring file {original_path}: {exc}")
        return OS_INVALID


def main(argv) -> int:
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        write_debug_file(argv[0], "Invalid incoming message")
        return OS_INVALID

    payload = extract_extra_payload(msg.alert)
    if not payload:
        write_debug_file(argv[0], "No extra payload found")
        return OS_INVALID

    effective_command = resolve_effective_command(msg.command, payload)

    if effective_command == ADD_COMMAND:
        rc = quarantine_file(argv, msg.alert, msg.command, effective_command)
    elif effective_command == DELETE_COMMAND:
        rc = restore_file(argv, msg.alert, msg.command, effective_command)
    else:
        rc = OS_INVALID

    write_debug_file(argv[0], f"Ended with rc={rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))