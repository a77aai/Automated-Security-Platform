#!/usr/bin/env python3
import os
import sys
import json
import time
import hashlib
import shutil
import datetime

def get_ossec_base():
    candidates = [
        os.environ.get("OSSEC_HOME", ""),
        r"C:\Program Files\ossec-agent",
        r"C:\Program Files (x86)\ossec-agent",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return r"C:\Program Files\ossec-agent"

OSSEC_BASE = get_ossec_base()
LOG_FILE = os.path.join(OSSEC_BASE, "active-response", "active-responses.log")
JOURNAL_FILE = os.path.join(OSSEC_BASE, "active-response", "ai-quarantine-file.jsonl")
QUARANTINE_ROOT = os.path.join(OSSEC_BASE, "quarantine", "files")

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3
OS_SUCCESS = 0
OS_INVALID = -1


class Message:
    def __init__(self):
        self.alert = {}
        self.command = OS_INVALID


def json_loads(value):
    return json.loads(value)


def json_dumps_text(value):
    dumped = json.dumps(value, ensure_ascii=False)
    return dumped.decode("utf-8") if isinstance(dumped, bytes) else dumped


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)


def write_debug_file(ar_name, msg):
    ensure_parent(LOG_FILE)
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
        log_file.write("%s %s: %s\n" % (timestamp, ar_name, msg))


def write_journal(entry):
    ensure_parent(JOURNAL_FILE)
    item = dict(entry)
    item["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(JOURNAL_FILE, mode="a", encoding="utf-8") as file_obj:
        file_obj.write(json_dumps_text(item) + "\n")


def read_journal_entries():
    if not os.path.exists(JOURNAL_FILE):
        return []

    entries = []
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


def setup_and_check_message(argv):
    msg = Message()
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break
    if not input_str:
        write_debug_file(argv[0], "No input received on STDIN")
        return msg
    try:
        data = json_loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Decoding JSON failed, invalid input format")
        return msg
    msg.alert = data
    command = data.get("command")
    if command == "add":
        msg.command = ADD_COMMAND
    elif command == "delete":
        msg.command = DELETE_COMMAND
    else:
        write_debug_file(argv[0], "Invalid command: %s" % command)
    return msg


def send_keys_and_check_message(argv, keys):
    keys_msg = json_dumps_text({
        "version": 1,
        "origin": {"name": argv[0], "module": "active-response"},
        "command": "check_keys",
        "parameters": {"keys": keys}
    })
    write_debug_file(argv[0], "check_keys => %s" % keys_msg)
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
    return OS_INVALID


def get_extra_payload(wrapper):
    params = wrapper.get("parameters", {}) or {}
    extra_args = params.get("extra_args", []) or []
    if not extra_args:
        return None
    try:
        return json_loads(extra_args[0])
    except Exception:
        return None


def parse_boolish(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def resolve_effective_command(incoming_command, payload):
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


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def build_action_key(payload, path):
    return "|".join([
        str(payload.get("response_id", "")),
        str(payload.get("target_agent_id", "")),
        str(payload.get("recommended_action", "")),
        path,
    ])


def normalize_path(path):
    value = str(path or "").strip().strip('"')
    if not value:
        return ""
    return os.path.normcase(os.path.realpath(os.path.abspath(value)))


def sanitize_path(path):
    normalized = normalize_path(path)
    if not normalized:
        raise ValueError("Missing path parameter")
    return normalized


def build_quarantine_path(original_path):
    date_dir = datetime.datetime.utcnow().strftime("%Y%m%d")
    destination_root = os.path.join(QUARANTINE_ROOT, date_dir)
    if not os.path.exists(destination_root):
        os.makedirs(destination_root)

    base_name = os.path.basename(original_path.rstrip("\\/"))
    stamp = datetime.datetime.utcnow().strftime("%H%M%S")
    suffix = hashlib.md5(("%s|%s" % (original_path, time.time())).encode("utf-8")).hexdigest()[:10]
    file_name = "%s.%s.%s.quarantine" % (base_name, stamp, suffix)
    return os.path.join(destination_root, file_name)


def resolve_restore_entry(payload):
    params = payload.get("parameters", {}) or {}
    target_path = normalize_path(params.get("path", ""))
    response_id = str(payload.get("response_id", "")).strip()
    journal = read_journal_entries()

    for entry in reversed(journal):
        if entry.get("event") != "quarantine_success":
            continue

        entry_original_path = normalize_path(entry.get("original_path", ""))
        entry_response_id = str(entry.get("response_id", "")).strip()

        if target_path and entry_original_path == target_path:
            return entry

        if not target_path and response_id and entry_response_id == response_id:
            return entry

    return None


def handle_add(payload, argv, incoming_command, effective_command):
    params = payload.get("parameters", {}) or {}
    original_path = sanitize_path(params.get("path", ""))
    action_key = build_action_key(payload, original_path)

    decision = send_keys_and_check_message(argv, [action_key])
    if decision == ABORT_COMMAND:
        write_debug_file(argv[0], "Aborted duplicated action | key=%s" % action_key)
        return OS_SUCCESS
    if decision != CONTINUE_COMMAND:
        write_debug_file(argv[0], "Invalid check_keys decision | key=%s" % action_key)
        return OS_INVALID

    if not os.path.exists(original_path):
        raise RuntimeError("Target file does not exist: %s" % original_path)

    quarantine_path = build_quarantine_path(original_path)
    file_hash = sha256_file(original_path)
    file_size = os.path.getsize(original_path)

    ensure_parent(quarantine_path)
    shutil.move(original_path, quarantine_path)

    write_debug_file(
        argv[0],
        "Quarantined file successfully | original=%s | quarantine=%s | sha256=%s | incoming_command=%s | effective_command=%s" % (
            original_path, quarantine_path, file_hash, incoming_command, effective_command
        )
    )
    write_journal({
        "event": "quarantine_success",
        "response_id": payload.get("response_id", ""),
        "target_agent_id": payload.get("target_agent_id", ""),
        "target_agent_name": payload.get("target_agent_name", ""),
        "target_platform": payload.get("target_platform", ""),
        "recommended_action": payload.get("recommended_action", ""),
        "response_command": payload.get("response_command", ""),
        "policy_name": payload.get("policy_name", ""),
        "policy_reason": payload.get("policy_reason", ""),
        "source_level": payload.get("source_level", 0),
        "summary": payload.get("summary", ""),
        "confidence": payload.get("confidence", ""),
        "original_path": original_path,
        "quarantine_path": quarantine_path,
        "sha256": file_hash,
        "size": file_size,
        "parameters": params,
        "incoming_command": incoming_command,
        "effective_command": effective_command,
        "requested_command": payload.get("requested_command", ""),
        "control_operation": payload.get("control_operation", ""),
        "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
        "original_alert_id": payload.get("original_alert_id", ""),
    })
    return OS_SUCCESS


def handle_delete(payload, argv, incoming_command, effective_command):
    entry = resolve_restore_entry(payload)
    if not entry:
        raise RuntimeError("No matching quarantine journal entry found for restore")

    original_path = normalize_path(entry.get("original_path", ""))
    quarantine_path = normalize_path(entry.get("quarantine_path", ""))

    if not quarantine_path or not os.path.exists(quarantine_path):
        raise RuntimeError("Quarantine path not found: %s" % quarantine_path)

    if os.path.exists(original_path):
        raise RuntimeError("Original path already exists, restore skipped: %s" % original_path)

    ensure_parent(original_path)
    shutil.move(quarantine_path, original_path)

    write_debug_file(
        argv[0],
        "Restored file successfully | original=%s | quarantine=%s | incoming_command=%s | effective_command=%s" % (
            original_path, quarantine_path, incoming_command, effective_command
        )
    )
    write_journal({
        "event": "restore_success",
        "response_id": payload.get("response_id", ""),
        "target_agent_id": payload.get("target_agent_id", ""),
        "target_agent_name": payload.get("target_agent_name", ""),
        "target_platform": payload.get("target_platform", ""),
        "recommended_action": payload.get("recommended_action", ""),
        "response_command": payload.get("response_command", ""),
        "policy_name": payload.get("policy_name", ""),
        "policy_reason": payload.get("policy_reason", ""),
        "source_level": payload.get("source_level", 0),
        "summary": payload.get("summary", ""),
        "confidence": payload.get("confidence", ""),
        "original_path": original_path,
        "quarantine_path": quarantine_path,
        "parameters": payload.get("parameters", {}),
        "incoming_command": incoming_command,
        "effective_command": effective_command,
        "requested_command": payload.get("requested_command", ""),
        "control_operation": payload.get("control_operation", ""),
        "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
        "original_alert_id": payload.get("original_alert_id", ""),
    })
    return OS_SUCCESS


def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)
    if msg.command < 0:
        write_debug_file(argv[0], "Invalid message")
        return OS_INVALID

    payload = get_extra_payload(msg.alert)
    if not payload:
        write_debug_file(argv[0], "No extra payload found")
        return OS_INVALID

    effective_command = resolve_effective_command(msg.command, payload)

    try:
        rc = handle_add(payload, argv, msg.command, effective_command) if effective_command == ADD_COMMAND else handle_delete(payload, argv, msg.command, effective_command)
        write_debug_file(argv[0], "Ended with rc=%s" % rc)
        return rc
    except Exception as exc:
        write_debug_file(argv[0], "Execution failed: %s" % exc)
        write_journal({
            "event": "quarantine_failed" if effective_command == ADD_COMMAND else "restore_failed",
            "response_id": payload.get("response_id", ""),
            "target_agent_id": payload.get("target_agent_id", ""),
            "target_agent_name": payload.get("target_agent_name", ""),
            "target_platform": payload.get("target_platform", ""),
            "recommended_action": payload.get("recommended_action", ""),
            "response_command": payload.get("response_command", ""),
            "error": str(exc),
            "parameters": payload.get("parameters", {}),
            "incoming_command": msg.command,
            "effective_command": effective_command,
            "requested_command": payload.get("requested_command", ""),
            "control_operation": payload.get("control_operation", ""),
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })
        return OS_INVALID


if __name__ == "__main__":
    sys.exit(main(sys.argv))
