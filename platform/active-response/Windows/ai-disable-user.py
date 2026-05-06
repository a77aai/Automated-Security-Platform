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
JOURNAL_FILE = os.path.join(AR_DIR, 'ai-disable-user.jsonl')

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


def parse_boolish(value):
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


def resolve_effective_command(incoming_command, payload):
    if incoming_command == DELETE_COMMAND:
        return DELETE_COMMAND

    if not isinstance(payload, dict):
        return incoming_command

    requested_command = str(payload.get('requested_command', '')).strip().lower()
    control_operation = str(payload.get('control_operation', '')).strip().lower()

    if requested_command == 'delete':
        return DELETE_COMMAND

    if control_operation in ('delete', 'rollback', 'undo', 'restore'):
        return DELETE_COMMAND

    if parse_boolish(payload.get('rollback', False)):
        return DELETE_COMMAND

    return incoming_command


def validate_username(username):
    username = str(username or '').strip()
    if not username:
        raise ValueError('Missing user parameter')
    if not re.fullmatch(r'[A-Za-z0-9_. -]{1,64}', username):
        raise ValueError('Invalid Windows username format')
    forbidden = {'administrator', 'guest'}
    if username.lower() in forbidden:
        raise ValueError(f'Refusing to modify protected account: {username}')
    return username


def build_action_key(payload, username):
    return '|'.join([
        str(payload.get('response_id', '')),
        str(payload.get('target_agent_id', '')),
        str(payload.get('recommended_action', '')),
        username,
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


def disable_user(username):
    result = run_command(['net', 'user', username, '/active:no'])
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip() or 'net user disable failed')


def enable_user(username):
    result = run_command(['net', 'user', username, '/active:yes'])
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip() or 'net user enable failed')


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

    effective_command = resolve_effective_command(msg.command, payload)
    params = payload.get('parameters', {}) or {}

    try:
        username = validate_username(params.get('user', ''))
    except Exception as exc:
        write_debug_file(argv[0], f'Invalid username: {exc}')
        return OS_INVALID

    if effective_command == ADD_COMMAND:
        action_key = build_action_key(payload, username)
        decision = send_keys_and_check_message(argv, [action_key])
        if decision == ABORT_COMMAND:
            write_debug_file(argv[0], f'Aborted duplicated action | key={action_key}')
            return OS_SUCCESS
        if decision != CONTINUE_COMMAND:
            write_debug_file(argv[0], f'Invalid check_keys decision | key={action_key}')
            return OS_INVALID

    try:
        if effective_command == ADD_COMMAND:
            disable_user(username)
            event_name = 'disable_user_success'
        else:
            enable_user(username)
            event_name = 'enable_user_success'

        write_debug_file(argv[0], f'Completed successfully | user={username} | incoming_command={msg.command} | effective_command={effective_command}')
        write_journal({
            'event': event_name,
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
            'user': username,
            'parameters': params,
            'incoming_command': msg.command,
            'effective_command': effective_command,
            'requested_command': payload.get('requested_command', ''),
            'control_operation': payload.get('control_operation', ''),
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })
        write_debug_file(argv[0], f'Ended with rc={OS_SUCCESS}')
        return OS_SUCCESS
    except Exception as exc:
        write_debug_file(argv[0], f'Execution failed: {exc}')
        write_journal({
            'event': 'disable_user_failed' if effective_command == ADD_COMMAND else 'enable_user_failed',
            'response_id': payload.get('response_id', ''),
            'target_agent_id': payload.get('target_agent_id', ''),
            'target_agent_name': payload.get('target_agent_name', ''),
            'target_platform': payload.get('target_platform', ''),
            'recommended_action': payload.get('recommended_action', ''),
            'response_command': payload.get('response_command', ''),
            'user': username,
            'error': str(exc),
            'parameters': params,
            'incoming_command': msg.command,
            'effective_command': effective_command,
            'requested_command': payload.get('requested_command', ''),
            'control_operation': payload.get('control_operation', ''),
            "recommendation_alert_id": payload.get("recommendation_alert_id", ""),
            "original_alert_id": payload.get("original_alert_id", ""),
        })
        return OS_INVALID


if __name__ == '__main__':
    sys.exit(main(sys.argv))
