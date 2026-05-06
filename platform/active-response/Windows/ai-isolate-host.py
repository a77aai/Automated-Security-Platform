#!/usr/bin/env python3
import os
import sys
import json
import shutil
import datetime
import subprocess

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
JOURNAL_FILE = os.path.join(OSSEC_BASE, "active-response", "ai-isolate-host.jsonl")
STATE_DIR = os.path.join(OSSEC_BASE, "active-response", "state")
ENV_FILE = os.path.join(OSSEC_BASE, "ai-isolate-host.env")

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3
OS_SUCCESS = 0
OS_INVALID = -1


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
PROFILE_TARGET = ENV.get("PROFILE_TARGET", "allprofiles").strip() or "allprofiles"


class Message:
    def __init__(self):
        self.alert = {}
        self.command = OS_INVALID


def json_loads(value):
    return json.loads(value)


def json_dumps_text(value):
    dumped = json.dumps(value, ensure_ascii=False)
    return dumped.decode("utf-8") if isinstance(dumped, bytes) else dumped


def ensure_dir(path):
    if path and not os.path.exists(path):
        os.makedirs(path)


def write_debug_file(ar_name, msg):
    ensure_dir(os.path.dirname(LOG_FILE))
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG_FILE, mode="a", encoding="utf-8") as log_file:
        log_file.write("%s %s: %s\n" % (timestamp, ar_name, msg))


def write_journal(entry):
    ensure_dir(os.path.dirname(JOURNAL_FILE))
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


def state_path(target_agent_id):
    ensure_dir(STATE_DIR)
    return os.path.join(STATE_DIR, "ai-isolate-host-%s.wfw" % target_agent_id)


def run_command(cmd_str):
    return subprocess.run(
        cmd_str,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False
    )


def run_command_checked(cmd_str):
    result = run_command(cmd_str)
    if result.returncode != 0:
        raise RuntimeError(
            "cmd=%s | rc=%s | stdout=%s | stderr=%s" % (
                cmd_str,
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip()
            )
        )
    return result


def require_netsh():
    if not shutil.which("netsh"):
        raise RuntimeError("netsh not found")


def build_action_key(payload):
    return "|".join([
        str(payload.get("response_id", "")),
        str(payload.get("target_agent_id", "")),
        str(payload.get("recommended_action", "")),
        "host_isolation",
    ])


def add_allow_rules(manager_ip):
    for port in ALLOW_TCP_PORTS:
        cmds = [
            f'netsh advfirewall firewall add rule name="WAZUH_AI_ISO_ALLOW_OUT_TCP_{port}" dir=out action=allow remoteip={manager_ip} protocol=TCP remoteport={port} profile=any',
            f'netsh advfirewall firewall add rule name="WAZUH_AI_ISO_ALLOW_IN_TCP_{port}" dir=in action=allow remoteip={manager_ip} protocol=TCP localport={port} profile=any',
            f'netsh advfirewall firewall add rule name="WAZUH_AI_ISO_ALLOW_OUT_UDP_{port}" dir=out action=allow remoteip={manager_ip} protocol=UDP remoteport={port} profile=any',
            f'netsh advfirewall firewall add rule name="WAZUH_AI_ISO_ALLOW_IN_UDP_{port}" dir=in action=allow remoteip={manager_ip} protocol=UDP localport={port} profile=any'
        ]
        for cmd_str in cmds:
            run_command_checked(cmd_str)


def delete_allow_rules():
    prefixes = [
        "WAZUH_AI_ISO_ALLOW_OUT_TCP_",
        "WAZUH_AI_ISO_ALLOW_IN_TCP_",
        "WAZUH_AI_ISO_ALLOW_OUT_UDP_",
        "WAZUH_AI_ISO_ALLOW_IN_UDP_"
    ]
    for prefix in prefixes:
        for port in ALLOW_TCP_PORTS:
            cmd_str = f'netsh advfirewall firewall delete rule name="{prefix}{port}"'
            run_command(cmd_str)


def export_firewall(path):
    quoted_path = f'"{path}"'
    cmd_str = f'netsh advfirewall export {quoted_path}'
    run_command_checked(cmd_str)


def import_firewall(path):
    quoted_path = f'"{path}"'
    cmd_str = f'netsh advfirewall import {quoted_path}'
    run_command_checked(cmd_str)


def set_block_policy():
    cmd_str = f'netsh advfirewall set {PROFILE_TARGET} firewallpolicy blockinbound,blockoutbound'
    run_command_checked(cmd_str)


def validate_manager_ip(ip):
    value = str(ip or "").strip()
    parts = value.split(".")
    if len(parts) != 4:
        raise ValueError("Invalid manager IPv4 address")
    for part in parts:
        if not part.isdigit():
            raise ValueError("Invalid manager IPv4 address")
        n = int(part)
        if n < 0 or n > 255:
            raise ValueError("Invalid manager IPv4 address")
    return value


def handle_add(payload, argv, incoming_command, effective_command):
    require_netsh()

    if not MANAGER_IP:
        write_debug_file(argv[0], "CRITICAL ERROR: WAZUH_MANAGER_IP is empty or not found in env file.")
        return OS_INVALID

    manager_ip = validate_manager_ip(MANAGER_IP)
    target_id = str(payload.get("target_agent_id", "unknown"))
    action_key = build_action_key(payload)

    decision = send_keys_and_check_message(argv, [action_key])
    if decision == ABORT_COMMAND:
        write_debug_file(argv[0], "Aborted duplicated action | key=%s" % action_key)
        return OS_SUCCESS
    if decision != CONTINUE_COMMAND:
        write_debug_file(argv[0], "Invalid check_keys decision | key=%s" % action_key)
        return OS_INVALID

    state_file = state_path(target_id)

    if os.path.exists(state_file):
        try:
            os.remove(state_file)
        except Exception:
            pass

    export_firewall(state_file)
    add_allow_rules(manager_ip)
    set_block_policy()

    write_debug_file(
        argv[0],
        "Host isolated successfully | manager_ip=%s | ports=%s | incoming_command=%s | effective_command=%s" % (
            manager_ip, ",".join(ALLOW_TCP_PORTS), incoming_command, effective_command
        )
    )
    write_journal({
        "event": "isolate_host_success",
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
        "manager_ip": manager_ip,
        "allow_tcp_ports": ALLOW_TCP_PORTS,
        "state_file": state_file,
        "parameters": payload.get("parameters", {}),
        "incoming_command": incoming_command,
        "effective_command": effective_command,
        "requested_command": payload.get("requested_command", ""),
        "control_operation": payload.get("control_operation", ""),
        "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
        "original_alert_id": payload.get("original_alert_id", ""),
    })
    return OS_SUCCESS


def handle_delete(payload, argv, incoming_command, effective_command):
    require_netsh()
    target_id = str(payload.get("target_agent_id", "unknown"))
    state_file = state_path(target_id)
    if not os.path.exists(state_file):
        raise RuntimeError("Isolation state file not found: %s" % state_file)

    import_firewall(state_file)

    try:
        os.remove(state_file)
    except Exception:
        pass

    delete_allow_rules()

    write_debug_file(
        argv[0],
        "Host isolation reverted successfully | incoming_command=%s | effective_command=%s" % (
            incoming_command, effective_command
        )
    )
    write_journal({
        "event": "unisolate_host_success",
        "response_id": payload.get("response_id", ""),
        "target_agent_id": payload.get("target_agent_id", ""),
        "target_agent_name": payload.get("target_agent_name", ""),
        "target_platform": payload.get("target_platform", ""),
        "recommended_action": payload.get("recommended_action", ""),
        "response_command": payload.get("response_command", ""),
        "policy_name": payload.get("policy_name", ""),
        "policy_reason": payload.get("policy_reason", ""),
        "state_file": state_file,
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
            "event": "isolate_host_failed" if effective_command == ADD_COMMAND else "unisolate_host_failed",
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
