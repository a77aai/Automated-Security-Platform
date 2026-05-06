#!/usr/bin/env python3
import os
import sys
import json
import subprocess
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
JOURNAL_FILE = os.path.join(OSSEC_BASE, "active-response", "ai-block-ip.jsonl")

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


def sanitize_ip(value):
    ip = str(value or "").strip()
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError("Invalid IPv4 address")

    for part in parts:
        if not part.isdigit():
            raise ValueError("Invalid IPv4 address")
        n = int(part)
        if n < 0 or n > 255:
            raise ValueError("Invalid IPv4 address")

    return ip


def build_action_key(payload, ip):
    return "|".join([
        str(payload.get("response_id", "")),
        str(payload.get("target_agent_id", "")),
        str(payload.get("recommended_action", "")),
        ip,
    ])


def rule_names(ip):
    return (
        "WAZUH_AI_BLOCK_IN_%s" % ip,
        "WAZUH_AI_BLOCK_OUT_%s" % ip,
    )


def run_netsh(argv, command):
    write_debug_file(argv[0], "RUN => %s" % command)
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=True,
        check=False,
    )
    write_debug_file(
        argv[0],
        "RC=%s | STDOUT=%s | STDERR=%s" % (
            result.returncode,
            (result.stdout or "").strip(),
            (result.stderr or "").strip(),
        )
    )
    return result


def show_rule(argv, rule_name):
    cmd = 'netsh advfirewall firewall show rule name="%s"' % rule_name
    return run_netsh(argv, cmd)


def delete_rules(argv, ip):
    in_name, out_name = rule_names(ip)
    run_netsh(argv, 'netsh advfirewall firewall delete rule name="%s"' % in_name)
    run_netsh(argv, 'netsh advfirewall firewall delete rule name="%s"' % out_name)


def add_rules(argv, ip):
    in_name, out_name = rule_names(ip)

    delete_rules(argv, ip)

    add_in = (
        'netsh advfirewall firewall add rule '
        'name="%s" dir=in action=block remoteip=%s enable=yes profile=domain,private,public'
        % (in_name, ip)
    )
    add_out = (
        'netsh advfirewall firewall add rule '
        'name="%s" dir=out action=block remoteip=%s enable=yes profile=domain,private,public'
        % (out_name, ip)
    )

    result_in = run_netsh(argv, add_in)
    result_out = run_netsh(argv, add_out)

    if result_in.returncode != 0 or result_out.returncode != 0:
        raise RuntimeError(
            "Failed adding firewall rules | in_rc=%s out_rc=%s" % (
                result_in.returncode, result_out.returncode
            )
        )

    verify_in = show_rule(argv, in_name)
    verify_out = show_rule(argv, out_name)

    if "No rules match" in (verify_in.stdout or "") or "No rules match" in (verify_out.stdout or ""):
        raise RuntimeError("Rules were not created successfully")


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
        params = payload.get("parameters", {}) or {}
        ip = sanitize_ip(params.get("ip", ""))

        if effective_command == ADD_COMMAND:
            action_key = build_action_key(payload, ip)
            decision = send_keys_and_check_message(argv, [action_key])

            if decision == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted duplicated action | key=%s" % action_key)
                return OS_SUCCESS

            if decision != CONTINUE_COMMAND:
                write_debug_file(argv[0], "Invalid check_keys decision | key=%s" % action_key)
                return OS_INVALID

            add_rules(argv, ip)
            event_name = "block_ip_success"
        else:
            delete_rules(argv, ip)
            event_name = "unblock_ip_success"

        write_debug_file(argv[0], "Completed successfully | action=%s | ip=%s | incoming_command=%s | effective_command=%s" % (
            payload.get("recommended_action", ""), ip, msg.command, effective_command
        ))

        write_journal({
            "event": event_name,
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
            "ip": ip,
            "parameters": params,
            "incoming_command": msg.command,
            "effective_command": effective_command,
            "requested_command": payload.get("requested_command", ""),
            "control_operation": payload.get("control_operation", ""),
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),

        })

        write_debug_file(argv[0], "Ended with rc=%s" % OS_SUCCESS)
        return OS_SUCCESS

    except Exception as exc:
        write_debug_file(argv[0], "Execution failed: %s" % exc)
        write_journal({
            "event": "block_ip_failed" if effective_command == ADD_COMMAND else "unblock_ip_failed",
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
