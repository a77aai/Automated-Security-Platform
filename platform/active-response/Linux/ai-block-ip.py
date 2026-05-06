#!/usr/bin/env python3
import os
import sys
import json
import shutil
import ipaddress
import datetime
import subprocess

if os.name == "nt":
    LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
    JOURNAL_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\ai-block-ip.jsonl"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    JOURNAL_FILE = "/var/ossec/logs/ai-block-ip.jsonl"

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

    write_debug_file(argv[0], f"Invalid check_keys response: {action}")
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


def build_action_key(payload):
    params = payload.get("parameters", {}) or {}
    return "|".join([
        str(payload.get("response_id", "")),
        str(payload.get("target_agent_id", "")),
        str(payload.get("recommended_action", "")),
        str(params.get("ip", "")),
    ])


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


def validate_ip(ip_value):
    if not ip_value:
        raise ValueError("Missing IP parameter")
    ip_obj = ipaddress.ip_address(ip_value.strip())
    return str(ip_obj), ip_obj.version


def run_command(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def build_rule_name(payload, ip_value):
    target_id = str(payload.get("target_agent_id", "unknown"))
    return f"WAZUH-AI-{target_id}-{ip_value}"


def linux_rule_exists(cmd_bin, chain, ip_value):
    result = run_command([cmd_bin, "-C", chain, "-s", ip_value, "-j", "DROP"])
    return result.returncode == 0


def linux_add_rule(cmd_bin, chain, ip_value):
    if linux_rule_exists(cmd_bin, chain, ip_value):
        return
    result = run_command([cmd_bin, "-I", chain, "-s", ip_value, "-j", "DROP"])
    if result.returncode != 0:
        raise RuntimeError(f"Failed to add {chain} rule: {result.stderr.strip()}")


def linux_delete_rule(cmd_bin, chain, ip_value):
    if not linux_rule_exists(cmd_bin, chain, ip_value):
        return
    result = run_command([cmd_bin, "-D", chain, "-s", ip_value, "-j", "DROP"])
    if result.returncode != 0:
        raise RuntimeError(f"Failed to delete {chain} rule: {result.stderr.strip()}")


def handle_linux(ip_value, ip_version, add_mode):
    if ip_version == 4:
        cmd_bin = shutil.which("iptables")
    else:
        cmd_bin = shutil.which("ip6tables")

    if not cmd_bin:
        raise RuntimeError("iptables/ip6tables not found")

    chains = ["INPUT", "OUTPUT"]

    for chain in chains:
        if add_mode:
            linux_add_rule(cmd_bin, chain, ip_value)
        else:
            linux_delete_rule(cmd_bin, chain, ip_value)


def windows_add_rule(rule_name, ip_value):
    inbound = run_command([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}-IN",
        "dir=in",
        "action=block",
        f"remoteip={ip_value}",
    ])
    if inbound.returncode != 0:
        raise RuntimeError(f"Failed to add Windows inbound rule: {inbound.stderr.strip() or inbound.stdout.strip()}")

    outbound = run_command([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}-OUT",
        "dir=out",
        "action=block",
        f"remoteip={ip_value}",
    ])
    if outbound.returncode != 0:
        raise RuntimeError(f"Failed to add Windows outbound rule: {outbound.stderr.strip() or outbound.stdout.strip()}")


def windows_delete_rule(rule_name):
    run_command([
        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}-IN"
    ])
    run_command([
        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}-OUT"
    ])


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

    params = payload.get("parameters", {}) or {}
    ip_value = params.get("ip", "")

    try:
        ip_value, ip_version = validate_ip(ip_value)
    except Exception as exc:
        write_debug_file(argv[0], f"Invalid IP: {exc}")
        return OS_INVALID

    action_key = build_action_key(payload)

    if effective_command == ADD_COMMAND:
        decision = send_keys_and_check_message(argv, [action_key])
        if decision == ABORT_COMMAND:
            write_debug_file(argv[0], f"Aborted duplicated action | key={action_key}")
            return OS_SUCCESS
        if decision != CONTINUE_COMMAND:
            write_debug_file(argv[0], f"Invalid check_keys decision | key={action_key}")
            return OS_INVALID

    try:
        if os.name == "nt":
            rule_name = build_rule_name(payload, ip_value)
            if effective_command == ADD_COMMAND:
                windows_add_rule(rule_name, ip_value)
                event_name = "block_ip_success"
            else:
                windows_delete_rule(rule_name)
                event_name = "unblock_ip_success"
        else:
            if effective_command == ADD_COMMAND:
                handle_linux(ip_value, ip_version, add_mode=True)
                event_name = "block_ip_success"
            else:
                handle_linux(ip_value, ip_version, add_mode=False)
                event_name = "unblock_ip_success"

        write_debug_file(
            argv[0],
            f"Completed successfully | action={payload.get('recommended_action')} | ip={ip_value} | incoming_command={msg.command} | effective_command={effective_command}"
        )

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
            "ip": ip_value,
            "parameters": params,
            "incoming_command": msg.command,
            "effective_command": effective_command,
            "requested_command": payload.get("requested_command", ""),
            "control_operation": payload.get("control_operation", ""),
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })

        write_debug_file(argv[0], f"Ended with rc={OS_SUCCESS}")
        return OS_SUCCESS

    except Exception as exc:
        write_debug_file(argv[0], f"Execution failed: {exc}")
        write_journal({
            "event": "block_ip_failed" if effective_command == ADD_COMMAND else "unblock_ip_failed",
            "response_id": payload.get("response_id", ""),
            "target_agent_id": payload.get("target_agent_id", ""),
            "target_agent_name": payload.get("target_agent_name", ""),
            "target_platform": payload.get("target_platform", ""),
            "recommended_action": payload.get("recommended_action", ""),
            "response_command": payload.get("response_command", ""),
            "ip": ip_value,
            "error": str(exc),
            "parameters": params,
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