#!/usr/bin/env python3
import os
import sys
import json
import shutil
import datetime
import subprocess

if os.name == "nt":
    LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
    JOURNAL_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\ai-isolate-host.jsonl"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"
    JOURNAL_FILE = "/var/ossec/logs/ai-isolate-host.jsonl"

ENV_FILE = "/var/ossec/etc/ai-isolate-host.env"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

CHAIN_IN = "WAZUH_AI_ISO_IN"
CHAIN_OUT = "WAZUH_AI_ISO_OUT"


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


def load_env_file(path):
    values = {}
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
MANAGER_IP = ENV.get("WAZUH_MANAGER_IP", "").strip()
ALLOW_TCP_PORTS = [p.strip() for p in ENV.get("ALLOW_TCP_PORTS", "1514,1515,1516").split(",") if p.strip()]


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


def build_action_key(payload):
    return "|".join([
        str(payload.get("response_id", "")),
        str(payload.get("target_agent_id", "")),
        str(payload.get("recommended_action", "")),
        "host_isolation",
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


def run_command(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def require_linux_tools():
    if os.name == "nt":
        raise RuntimeError("Windows version not enabled in this script")
    if not shutil.which("iptables"):
        raise RuntimeError("iptables not found")


def rule_exists(cmd):
    result = run_command(cmd)
    return result.returncode == 0


def ensure_chain(chain_name):
    if not rule_exists(["iptables", "-L", chain_name]):
        result = run_command(["iptables", "-N", chain_name])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    flush = run_command(["iptables", "-F", chain_name])
    if flush.returncode != 0:
        raise RuntimeError(flush.stderr.strip() or flush.stdout.strip())


def append_rule(cmd):
    result = run_command(cmd)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def insert_jump_if_missing(parent_chain, child_chain):
    check_cmd = ["iptables", "-C", parent_chain, "-j", child_chain]
    if not rule_exists(check_cmd):
        add_cmd = ["iptables", "-I", parent_chain, "1", "-j", child_chain]
        result = run_command(add_cmd)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def delete_jump_if_exists(parent_chain, child_chain):
    check_cmd = ["iptables", "-C", parent_chain, "-j", child_chain]
    if rule_exists(check_cmd):
        del_cmd = ["iptables", "-D", parent_chain, "-j", child_chain]
        result = run_command(del_cmd)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def build_linux_isolation():
    if not MANAGER_IP:
        raise RuntimeError("WAZUH_MANAGER_IP is missing in /var/ossec/etc/ai-isolate-host.env")

    ensure_chain(CHAIN_IN)
    ensure_chain(CHAIN_OUT)

    append_rule(["iptables", "-A", CHAIN_IN, "-i", "lo", "-j", "ACCEPT"])
    append_rule(["iptables", "-A", CHAIN_IN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    append_rule(["iptables", "-A", CHAIN_IN, "-s", MANAGER_IP, "-j", "ACCEPT"])
    append_rule(["iptables", "-A", CHAIN_IN, "-j", "DROP"])

    append_rule(["iptables", "-A", CHAIN_OUT, "-o", "lo", "-j", "ACCEPT"])
    append_rule(["iptables", "-A", CHAIN_OUT, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    for port in ALLOW_TCP_PORTS:
        append_rule(["iptables", "-A", CHAIN_OUT, "-d", MANAGER_IP, "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
        append_rule(["iptables", "-A", CHAIN_OUT, "-d", MANAGER_IP, "-p", "udp", "--dport", port, "-j", "ACCEPT"])

    append_rule(["iptables", "-A", CHAIN_OUT, "-j", "DROP"])

    insert_jump_if_missing("INPUT", CHAIN_IN)
    insert_jump_if_missing("OUTPUT", CHAIN_OUT)


def remove_linux_isolation():
    delete_jump_if_exists("INPUT", CHAIN_IN)
    delete_jump_if_exists("OUTPUT", CHAIN_OUT)

    if rule_exists(["iptables", "-L", CHAIN_IN]):
        run_command(["iptables", "-F", CHAIN_IN])
        run_command(["iptables", "-X", CHAIN_IN])

    if rule_exists(["iptables", "-L", CHAIN_OUT]):
        run_command(["iptables", "-F", CHAIN_OUT])
        run_command(["iptables", "-X", CHAIN_OUT])


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

    require_linux_tools()

    if effective_command == ADD_COMMAND:
        action_key = build_action_key(payload)
        decision = send_keys_and_check_message(argv, [action_key])
        if decision == ABORT_COMMAND:
            write_debug_file(argv[0], f"Aborted duplicated action | key={action_key}")
            return OS_SUCCESS
        if decision != CONTINUE_COMMAND:
            write_debug_file(argv[0], f"Invalid check_keys decision | key={action_key}")
            return OS_INVALID

    try:
        if effective_command == ADD_COMMAND:
            build_linux_isolation()
            event_name = "isolate_host_success"
        else:
            remove_linux_isolation()
            event_name = "unisolate_host_success"

        write_debug_file(
            argv[0],
            f"Completed successfully | incoming_command={msg.command} | effective_command={effective_command} | manager_ip={MANAGER_IP}"
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
            "manager_ip": MANAGER_IP,
            "allow_tcp_ports": ALLOW_TCP_PORTS,
            "parameters": payload.get("parameters", {}),
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
            "event": "isolate_host_failed" if effective_command == ADD_COMMAND else "unisolate_host_failed",
            "response_id": payload.get("response_id", ""),
            "target_agent_id": payload.get("target_agent_id", ""),
            "target_agent_name": payload.get("target_agent_name", ""),
            "target_platform": payload.get("target_platform", ""),
            "recommended_action": payload.get("recommended_action", ""),
            "response_command": payload.get("response_command", ""),
            "manager_ip": MANAGER_IP,
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