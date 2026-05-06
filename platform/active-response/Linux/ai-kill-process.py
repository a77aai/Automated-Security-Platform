#!/usr/bin/env python3
import os
import sys
import json
import shutil
import datetime
import subprocess

if os.name == "nt":
    LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
    JOURNAL_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\ai-kill-process.jsonl"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    JOURNAL_FILE = "/var/ossec/logs/ai-kill-process.jsonl"

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


def write_debug_file(ar_name, msg):
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
        log_file.write(f"{timestamp} {ar_name}: {msg}\n")


def write_journal(entry):
    item = dict(entry)
    item["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(JOURNAL_FILE, mode="a", encoding="utf-8") as file_obj:
        file_obj.write(json_dumps_text(item) + "\n")


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
        write_debug_file(argv[0], f"Invalid command: {command}")

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


def build_action_key(payload, process_selector):
    return "|".join([
        str(payload.get("response_id", "")),
        str(payload.get("target_agent_id", "")),
        str(payload.get("recommended_action", "")),
        str(process_selector),
    ])


def run_command(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def resolve_process_selector(payload):
    params = payload.get("parameters", {}) or {}
    service_name = str(params.get("service_name", "")).strip()
    path_value = str(params.get("path", "")).strip()

    if service_name:
        return service_name, "service_name"

    if path_value:
        return os.path.basename(path_value), "path_basename"

    raise ValueError("Missing service_name and path for process termination")


def kill_linux_process(selector, selector_type):
    if selector_type == "service_name":
        result = run_command(["pkill", "-f", selector])
    else:
        result = run_command(["pkill", "-f", selector])

    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def kill_windows_process(selector):
    result = run_command(["taskkill", "/F", "/IM", selector])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())


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

    if msg.command == DELETE_COMMAND:
        write_debug_file(argv[0], "Delete command ignored by design for kill_process")
        return OS_SUCCESS

    try:
        selector, selector_type = resolve_process_selector(payload)
    except Exception as exc:
        write_debug_file(argv[0], f"Invalid process selector: {exc}")
        return OS_INVALID

    action_key = build_action_key(payload, selector)
    decision = send_keys_and_check_message(argv, [action_key])
    if decision == ABORT_COMMAND:
        write_debug_file(argv[0], f"Aborted duplicated action | key={action_key}")
        return OS_SUCCESS
    if decision != CONTINUE_COMMAND:
        write_debug_file(argv[0], f"Invalid check_keys decision | key={action_key}")
        return OS_INVALID

    try:
        if os.name == "nt":
            kill_windows_process(selector)
        else:
            kill_linux_process(selector, selector_type)

        write_debug_file(argv[0], f"Killed process successfully | selector={selector}")

        write_journal({
            "event": "kill_process_success",
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
            "process_selector": selector,
            "selector_type": selector_type,
            "parameters": payload.get("parameters", {}),
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })

        write_debug_file(argv[0], f"Ended with rc={OS_SUCCESS}")
        return OS_SUCCESS

    except Exception as exc:
        write_debug_file(argv[0], f"Execution failed: {exc}")
        write_journal({
            "event": "kill_process_failed",
            "response_id": payload.get("response_id", ""),
            "target_agent_id": payload.get("target_agent_id", ""),
            "target_agent_name": payload.get("target_agent_name", ""),
            "target_platform": payload.get("target_platform", ""),
            "recommended_action": payload.get("recommended_action", ""),
            "response_command": payload.get("response_command", ""),
            "process_selector": selector,
            "selector_type": selector_type,
            "error": str(exc),
            "parameters": payload.get("parameters", {}),
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })
        return OS_INVALID


if __name__ == "__main__":
    sys.exit(main(sys.argv))