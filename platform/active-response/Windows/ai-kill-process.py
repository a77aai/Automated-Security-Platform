#!/usr/bin/env python3
import os
import sys
import json
import re
import datetime
import subprocess


def resolve_ossec_base() -> str:
    candidates = []
    if os.name == 'nt':
        candidates.extend([
            r"C:\Program Files\ossec-agent",
            r"C:\Program Files (x86)\ossec-agent",
        ])
    script_base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    candidates.append(script_base)
    for path in candidates:
        if os.path.isdir(path):
            return path
    return script_base


OSSEC_BASE = resolve_ossec_base()
AR_DIR = os.path.join(OSSEC_BASE, 'active-response')
LOG_FILE = os.path.join(AR_DIR, 'active-responses.log')
JOURNAL_FILE = os.path.join(AR_DIR, 'ai-kill-process.jsonl')

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
    return dumped.decode('utf-8') if isinstance(dumped, bytes) else dumped


def write_debug_file(ar_name, msg):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
    with open(LOG_FILE, mode='a', encoding='utf-8') as log_file:
        log_file.write(f"{timestamp} {ar_name}: {msg}\n")


def write_journal(entry):
    os.makedirs(os.path.dirname(JOURNAL_FILE), exist_ok=True)
    item = dict(entry)
    item['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    with open(JOURNAL_FILE, mode='a', encoding='utf-8') as file_obj:
        file_obj.write(json_dumps_text(item) + '\n')


def setup_and_check_message(argv):
    msg = Message()
    input_str = ''
    for line in sys.stdin:
        input_str = line
        break

    if not input_str:
        write_debug_file(argv[0], 'No input received on STDIN')
        return msg

    try:
        data = json_loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON failed, invalid input format')
        return msg

    msg.alert = data
    command = data.get('command')
    if command == 'add':
        msg.command = ADD_COMMAND
    elif command == 'delete':
        msg.command = DELETE_COMMAND
    else:
        write_debug_file(argv[0], f'Invalid command: {command}')
    return msg


def send_keys_and_check_message(argv, keys):
    keys_msg = json_dumps_text({
        'version': 1,
        'origin': {'name': argv[0], 'module': 'active-response'},
        'command': 'check_keys',
        'parameters': {'keys': keys},
    })
    write_debug_file(argv[0], f'check_keys => {keys_msg}')
    print(keys_msg)
    sys.stdout.flush()

    input_str = ''
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json_loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON failed on check_keys response')
        return OS_INVALID

    action = data.get('command')
    if action == 'continue':
        return CONTINUE_COMMAND
    if action == 'abort':
        return ABORT_COMMAND
    return OS_INVALID


def get_extra_payload(wrapper):
    params = wrapper.get('parameters', {}) or {}
    extra_args = params.get('extra_args', []) or []
    if not extra_args:
        return None
    try:
        return json_loads(extra_args[0])
    except Exception:
        return None


def choose_selector(params):
    service_name = str(params.get('service_name', '') or '').strip()
    path_value = str(params.get('path', '') or '').strip()
    selector = service_name
    selector_type = 'service_name'
    if not selector and path_value:
        selector = os.path.basename(path_value)
        selector_type = 'path_basename'
    if not selector:
        raise ValueError('Missing service_name or path selector')
    return selector, selector_type


def validate_selector(selector):
    if selector.isdigit():
        return selector
    if not re.fullmatch(r'[A-Za-z0-9_.() -]{1,128}', selector):
        raise ValueError('Invalid process selector format')
    return selector


def build_action_key(payload, selector):
    return '|'.join([
        str(payload.get('response_id', '')),
        str(payload.get('target_agent_id', '')),
        str(payload.get('recommended_action', '')),
        selector,
    ])


def run_command(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        shell=False,
    )


def kill_selector(selector):
    if selector.isdigit():
        result = run_command(['taskkill', '/F', '/T', '/PID', selector])
    else:
        result = run_command(['taskkill', '/F', '/T', '/IM', selector])
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip() or 'taskkill failed')


def main(argv):
    write_debug_file(argv[0], 'Started')
    msg = setup_and_check_message(argv)
    if msg.command < 0:
        write_debug_file(argv[0], 'Invalid message')
        return OS_INVALID

    payload = get_extra_payload(msg.alert)
    if not payload:
        write_debug_file(argv[0], 'No extra payload found')
        return OS_INVALID

    params = payload.get('parameters', {}) or {}
    try:
        selector, selector_type = choose_selector(params)
        selector = validate_selector(selector)
    except Exception as exc:
        write_debug_file(argv[0], f'Invalid selector: {exc}')
        return OS_INVALID

    if msg.command == ADD_COMMAND:
        action_key = build_action_key(payload, selector)
        decision = send_keys_and_check_message(argv, [action_key])
        if decision == ABORT_COMMAND:
            write_debug_file(argv[0], f'Aborted duplicated action | key={action_key}')
            return OS_SUCCESS
        if decision != CONTINUE_COMMAND:
            write_debug_file(argv[0], f'Invalid check_keys decision | key={action_key}')
            return OS_INVALID

    if msg.command == DELETE_COMMAND:
        write_debug_file(argv[0], f'Delete received and ignored by design | selector={selector}')
        write_journal({
            'event': 'kill_process_delete_ignored',
            'response_id': payload.get('response_id', ''),
            'target_agent_id': payload.get('target_agent_id', ''),
            'target_agent_name': payload.get('target_agent_name', ''),
            'target_platform': payload.get('target_platform', ''),
            'recommended_action': payload.get('recommended_action', ''),
            'response_command': payload.get('response_command', ''),
            'process_selector': selector,
            'selector_type': selector_type,
            'parameters': params,
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })
        return OS_SUCCESS

    try:
        kill_selector(selector)
        write_debug_file(argv[0], f'Killed process successfully | selector={selector}')
        write_journal({
            'event': 'kill_process_success',
            'response_id': payload.get('response_id', ''),
            'target_agent_id': payload.get('target_agent_id', ''),
            'target_agent_name': payload.get('target_agent_name', ''),
            'target_platform': payload.get('target_platform', ''),
            'recommended_action': payload.get('recommended_action', ''),
            'response_command': payload.get('response_command', ''),
            'policy_name': payload.get('policy_name', ''),
            'policy_reason': payload.get('policy_reason', ''),
            'source_level': payload.get('source_level', 0),
            'summary': payload.get('summary', ''),
            'confidence': payload.get('confidence', ''),
            'process_selector': selector,
            'selector_type': selector_type,
            'parameters': params,
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })
        write_debug_file(argv[0], f'Ended with rc={OS_SUCCESS}')
        return OS_SUCCESS
    except Exception as exc:
        write_debug_file(argv[0], f'Execution failed: {exc}')
        write_journal({
            'event': 'kill_process_failed',
            'response_id': payload.get('response_id', ''),
            'target_agent_id': payload.get('target_agent_id', ''),
            'target_agent_name': payload.get('target_agent_name', ''),
            'target_platform': payload.get('target_platform', ''),
            'recommended_action': payload.get('recommended_action', ''),
            'response_command': payload.get('response_command', ''),
            'process_selector': selector,
            'selector_type': selector_type,
            'error': str(exc),
            'parameters': params,
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })
        return OS_INVALID


if __name__ == '__main__':
    sys.exit(main(sys.argv))
