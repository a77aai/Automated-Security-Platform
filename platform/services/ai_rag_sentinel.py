#!/usr/bin/env python3
import os
import re
import time
import socket
import hashlib
import requests
import concurrent.futures

from datetime import datetime
from collections import deque, defaultdict
from sentence_transformers import SentenceTransformer

try:
    import orjson as json
except ImportError:
    import json


# =========================
# CONFIGURATION
# =========================
WAZUH_ARCHIVES = "/var/ossec/logs/archives/archives.json"
AI_ALERTS_OUTPUT = "/var/ossec/logs/alerts/ai_alerts.json"

EMBED_MODEL_PATH = "/home/i77/AS-Platform/models/bge-small-en-v1.5"
QDRANT_URL = "http://localhost:6333"
COLLECTION = "RAG_detection_knowledge"

def _env_int(primary_name, default, *fallback_names):
    for name in (primary_name,) + fallback_names:
        raw = os.getenv(name)
        if raw is None or str(raw).strip() == "":
            continue
        try:
            return int(raw)
        except Exception:
            continue
    return default


def _env_text(primary_name, default, *fallback_names):
    for name in (primary_name,) + fallback_names:
        raw = os.getenv(name)
        if raw is not None and str(raw).strip():
            return str(raw).strip()
    return default


def _clamp_int(value, minimum, maximum):
    try:
        value = int(value)
    except Exception:
        value = minimum
    return max(minimum, min(maximum, value))


OLLAMA_URL = _env_text("OLLAMA_URL", "http://192.168.56.1:11434/api/generate")
MODEL_NAME = _env_text(
    "AI_RAG_DETECTION_MODEL",
    "llama3.2",
    "OLLAMA_MODEL",
    "AI_MODEL",
)

NETWORK_BURST_THRESHOLD = _env_int("AI_NETWORK_BURST_THRESHOLD", 30)
NETWORK_BURST_COOLDOWN = _env_int("AI_NETWORK_BURST_COOLDOWN", 60)
CACHE_TTL = _env_int("AI_RAG_DETECTION_CACHE_TTL", 300, "CACHE_TTL")
MAX_THREADS = _clamp_int(
    _env_int("AI_RAG_DETECTION_MAX_THREADS", 2, "AI_MAX_THREADS", "MAX_THREADS"),
    1,
    64,
)
LLM_TIMEOUT = _env_int("AI_RAG_DETECTION_LLM_TIMEOUT", 120, "LLM_TIMEOUT")

OLLAMA_OPTIONS = {
    "temperature": 0.0,
    "top_p": 0.8,
    "num_ctx": 1536,
    "repeat_penalty": 1.05,
}

QDRANT_PLATFORM_FILTER = ["Linux", "Unknown"]
QDRANT_DOC_TYPES = ["technique", "data_component", "detection_strategy"]

SUSPICIOUS_KEYWORDS = [
    "failed", "error", "denied", "sudo", "root", "attack",
    "malware", "critical", "shell", "php", "cmd", "execution",
]
INFRASTRUCTURE_NOISE = [
    "wazuh", "ossec", "ollama", "opensearch", "indexer",
    "filebeat", "elasticsearch", "kibana",
]

USERNAME_PATTERNS = [
    r'for invalid user ([a-zA-Z0-9._-]+)',
    r'for user ([a-zA-Z0-9._-]+)',
    r'user[=: ]+([a-zA-Z0-9._-]+)',
    r'username[=: ]+([a-zA-Z0-9._-]+)',
    r'account[=: ]+([a-zA-Z0-9._-]+)',
    r'\bUSER=([A-Za-z0-9._-]+)',
    r'\buser=([A-Za-z0-9._-]+)',
]

AUTH_ACTOR_PATTERNS = [
    r'\bruser=([A-Za-z0-9._-]+)',
    r'\blogname=([A-Za-z0-9._-]+)',
    r'sudo:\s+([A-Za-z0-9._-]+)\s*:',
    r'by\s+([A-Za-z0-9._-]+)\(uid=',
]

AUTH_ACTOR_UID_PATTERNS = [
    r'by\s+\(uid=(\d+)\)',
    r'logname=\s*uid=(\d+)\s+euid=\d+',
    r'\buid=(\d+)\s+euid=\d+\b',
]

TTY_PATTERNS = [
    r'tty=(/dev/pts/\d+)',
    r'tty=(pts/\d+)',
    r'\bon (pts/\d+)\b',
    r'\b(/dev/pts/\d+)\b',
    r'\b(pts/\d+)\b',
]

PATH_PATTERNS = [
    r'(?:name|path|pwd|command)=["\']?((?:/[A-Za-z0-9._-]+){1,}(?:/[A-Za-z0-9._-]+)*)',
    r'((?:/[A-Za-z0-9._-]+){2,})',
]


def json_loads(value):
    return json.loads(value)


def json_dumps_text(value):
    dumped = json.dumps(value)
    return dumped.decode("utf-8") if isinstance(dumped, bytes) else dumped


# =========================
# UTILS & STATE
# =========================
class AlertCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.default_ttl = ttl

    def is_cached(self, signature, ttl=None):
        now = time.time()
        effective_ttl = ttl if ttl is not None else self.default_ttl

        self.cache = {k: v for k, v in self.cache.items() if now < v}

        if signature in self.cache:
            return True

        self.cache[signature] = now + effective_ttl
        return False

class NetworkBurstGate:

    FLOOD_FAMILIES = {
        "network_flood",
        "network_dos",
        "network_ddos",
    }

    def __init__(self, threshold=30, cooldown=60):
        self.threshold = threshold
        self.cooldown = cooldown
        self.last_alert_time = {}

    def _extract_dstip(self, log_entry, full_log_str):
        data = log_entry.get("data", {}) or {}

        candidates = [
            data.get("dstip"),
            data.get("dst_ip"),
            data.get("destination_ip"),
            data.get("destinationIp"),
            data.get("win", {}).get("eventdata", {}).get("destinationAddress"),
            log_entry.get("win", {}).get("eventdata", {}).get("destinationAddress"),
        ]

        for value in candidates:
            if value:
                return str(value)

        match = re.search(
            r'\b(?:dst|destinationAddress|destination_ip|dstip)[=:"\s]+((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b',
            full_log_str,
            re.IGNORECASE
        )
        return match.group(1) if match else "No_DST"

    def _extract_dstport(self, log_entry, full_log_str):
        data = log_entry.get("data", {}) or {}

        candidates = [
            data.get("dstport"),
            data.get("dst_port"),
            data.get("destination_port"),
            data.get("destinationPort"),
            data.get("win", {}).get("eventdata", {}).get("destinationPort"),
            log_entry.get("win", {}).get("eventdata", {}).get("destinationPort"),
        ]

        for value in candidates:
            if value:
                return str(value)

        patterns = [
            r'\bdpt=(\d+)\b',
            r'\bdstport["\']?\s*:\s*["\']?(\d+)',
            r'\bdestinationPort["\']?\s*:\s*["\']?(\d+)',
            r'\bdestination_port["\']?\s*:\s*["\']?(\d+)',
            r'\bdst_port["\']?\s*:\s*["\']?(\d+)',
            r'\bport\s+(\d+)\b',
        ]

        for pattern in patterns:
            match = re.search(pattern, full_log_str, re.IGNORECASE)
            if match:
                return match.group(1)

        return "No_DPT"

    def should_emit(self, log_entry, full_log_str, local_context):
        family = local_context.get("event_family", "other")

        if family not in self.FLOOD_FAMILIES:
            return True, f"Not flood-gated event family: {family}"

        burst_count = int(local_context.get("burst_count_60s", 0) or 0)

        if burst_count < self.threshold:
            return False, f"Network flood below threshold ({burst_count}/{self.threshold})"

        agent_id = log_entry.get("agent", {}).get("id", "000")
        srcip = local_context.get("source_ip", "No_IP")
        dstip = self._extract_dstip(log_entry, full_log_str)
        dstport = self._extract_dstport(log_entry, full_log_str)

        key = f"{agent_id}:{srcip}:{dstip}:{dstport}"

        now = time.time()
        last_time = self.last_alert_time.get(key, 0)

        if now - last_time < self.cooldown:
            remaining = round(self.cooldown - (now - last_time), 1)
            return False, f"Network flood cooldown active for {remaining}s"

        self.last_alert_time[key] = now
        return True, f"Network flood threshold reached ({burst_count} events)"


class BurstContextTracker:
  
    def __init__(self, time_window=60, threshold=20):
        self.time_window = time_window
        self.threshold = threshold
        self.events = defaultdict(list)
        self.auth_events = defaultdict(list)
        self.actor_alias = defaultdict(lambda: {"uid_to_user": {}, "user_to_uid": {}})

    @staticmethod
    def _find_first(patterns, text, flags=re.IGNORECASE):
        for pattern in patterns:
            match = re.search(pattern, text, flags)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _normalize_tty(tty_value):
        if not tty_value:
            return "No_TTY"
        tty_value = tty_value.strip().lower().replace("/dev/", "")
        return tty_value or "No_TTY"

    @staticmethod
    def _normalize_scope(value, fallback):
        if value in (None, "", "No_User", "No_Actor", "No_Principal", "No_TTY", "No_UID"):
            return fallback
        value = str(value).strip().lower()
        value = value.replace("/", "_").replace("\\", "_").replace(" ", "_")
        value = re.sub(r'[^a-z0-9._:-]+', '_', value)
        return value or fallback

    def extract_ip(self, log_entry):
        data = log_entry.get("data", {})
        candidates = [
            data.get("srcip"),
            data.get("src_ip"),
            data.get("srcIp"),
            data.get("ip"),
            log_entry.get("srcip"),
            log_entry.get("src_ip"),
            log_entry.get("win", {}).get("eventdata", {}).get("ipAddress"),
        ]
        for value in candidates:
            if value:
                return str(value)

        text = log_entry.get("full_log", "")
        match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
        return match.group(0) if match else "No_IP"

    def extract_username(self, text):
        return self._find_first(USERNAME_PATTERNS, text) or "No_User"

    def extract_auth_actor(self, text):
        return self._find_first(AUTH_ACTOR_PATTERNS, text) or "No_Actor"

    def extract_auth_actor_uid(self, text):
        return self._find_first(AUTH_ACTOR_UID_PATTERNS, text) or "No_UID"

    def extract_tty(self, text):
        value = self._find_first(TTY_PATTERNS, text)
        return self._normalize_tty(value) if value else "No_TTY"

    def extract_path(self, text):
        return self._find_first(PATH_PATTERNS, text) or "No_Path"

    @staticmethod
    def detect_event_family(text):
        # Confidentiality / sensitive file access canary
        if re.search(
            r'ai_confidential_canary|customer_secrets|/opt/confidential_lab|'
            r'key="?ai_confidential_canary"?|'
            r'success=no.*exit=-13|exit=-13.*success=no|'
            r'syscall=openat|type=syscall',
            text,
            re.IGNORECASE
        ):
            return "confidentiality"

        # Network vulnerability probes / exploit validation
        if re.search(
            r'ms17-010|cve-2017-0143|cve-2017-0144|cve-2017-0145|'
            r'eternalblue|smb-vuln|smb_vuln|vulnerable|vulnerability|'
            r'exploit check|exploit validation|vuln scan|vulnerability scan|'
            r'remote code execution vulnerability',
            text,
            re.IGNORECASE
        ):
            return "network_vuln_probe"

        # DoS / DDoS / flood 
        if re.search(
            r'http_port80_test|dos attack|ddos attack|flood|syn flood|'
            r'ack flood|rst flood|udp flood|icmp flood|packet flood|'
            r'http flood|request flood|high-rate|high rate|high_frequency|'
            r'high-frequency|service exhaustion|availability test|'
            r'burst threshold|burst_count',
            text,
            re.IGNORECASE
        ):
            return "network_flood"

        # Recon / scan
        if re.search(
            r'\bnmap\b|\bmasscan\b|\bzmap\b|port scan|scan detected|'
            r'portsweep|port sweep|reconnaissance|service scan|'
            r'version detection|os detection|smb scan|rdp scan|ssh scan',
            text,
            re.IGNORECASE
        ):
            return "network_scan"

        # Sensitive services: SMB/RDP/SSH/WinRM/VNC/DB
        if re.search(
            r'\bdpt=(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bdstport["\']?\s*[:=]\s*["\']?(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bdst_port["\']?\s*[:=]\s*["\']?(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bspt=(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bsourceport["\']?\s*[:=]\s*["\']?(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bsource_port["\']?\s*[:=]\s*["\']?(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'source port\s*[:=]\s*(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bdestinationport["\']?\s*[:=]\s*["\']?(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bdestination_port["\']?\s*[:=]\s*["\']?(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'destination port\s*[:=]\s*(22|445|3389|5985|5986|5900|3306|5432|1433|6379)\b|'
            r'\bssh\b|\bsmb\b|\bmicrosoft-ds\b|\brdp\b|\bwinrm\b|\bvnc\b|'
            r'\bmysql\b|\bpostgres\b|\bmssql\b|\bredis\b',
            text,
            re.IGNORECASE
        ):
            return "network_sensitive_service"

        # Auth
        if re.search(
            r'failed password|invalid user|authentication failure|login failed|pam_unix',
            text,
            re.IGNORECASE
        ):
            return "auth"

        if re.search(
            r'accepted password|session opened|login successful|authentication succeeded|sudo|su:',
            text,
            re.IGNORECASE
        ):
            return "auth"

        # Web activity
        if re.search(
            r'wp-login|xmlrpc|/phpmyadmin|/\.env|http/1\.|http/2|get /|post /|head /|user-agent:',
            text,
            re.IGNORECASE
        ):
            return "web"

        # Process / execution
        if re.search(
            r'powershell -enc|bash -i|nc -e|curl\|sh|wget\|sh|cmd\.exe|'
            r'/bin/sh|python -c|perl -e|reverse shell|meterpreter',
            text,
            re.IGNORECASE
        ):
            return "process"

        # File integrity / webshell style file changes
        if re.search(
            r'/var/www/|\.php\b|\.py\b|\.sh\b|\.pl\b|chmod|chown|'
            r'created file|modified file|renamed file|file added|file modified',
            text,
            re.IGNORECASE
        ):
            return "file"

        # Denied / policy / blocked
        if re.search(
            r'denied|blocked|forbidden|reject|drop\b|permission denied|access denied',
            text,
            re.IGNORECASE
        ):
            return "policy_denied"

        # Inventory noise
        if re.search(
            r'syscollector|dbsync_processes|dbsync_packages|dbsync_ports|dbsync_hw',
            text,
            re.IGNORECASE
        ):
            return "inventory"

        # Generic network connection, not automatically suspicious
        if re.search(
            r'connection|firewall|netflow|network|proto=tcp|proto=udp|'
            r'\bsyn\b|\bicmp\b|\bdpt=\d+\b|destinationport|dstport',
            text,
            re.IGNORECASE
        ):
            return "network_connection"

        # System errors
        if re.search(
            r'error|exception|traceback|timeout|segfault|out of memory|connection refused',
            text,
            re.IGNORECASE
        ):
            return "system_error"

        return "other"

    @staticmethod
    def detect_auth_outcome(text, event_family):
        if event_family != "auth":
            return "other"
        if re.search(r'incorrect password attempts|authentication failure|failed password|login failed|invalid user', text, re.IGNORECASE):
            return "failure"
        if re.search(r'session closed', text, re.IGNORECASE):
            return "closed"
        if re.search(r'session opened|accepted password|authentication succeeded', text, re.IGNORECASE):
            return "success"
        if re.search(r'sudo:\s+[A-Za-z0-9._-]+\s*:.*\bCOMMAND=', text, re.IGNORECASE):
            return "success"
        if re.search(r'su:\s+\(to root\)\s+root on pts/\d+', text, re.IGNORECASE):
            return "success"
        return "other"

    @staticmethod
    def extract_failure_weight(text, auth_outcome):
        if auth_outcome != "failure":
            return 0
        match = re.search(r'(\d+)\s+incorrect password attempts', text, re.IGNORECASE)
        if not match:
            return 1
        try:
            return int(match.group(1))
        except Exception:
            return 1

    @staticmethod
    def normalize_template(text):
        text = text.lower()
        substitutions = [
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '<ip>'),
            (r'\b\d{4}-\d{2}-\d{2}[t\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?z?\b', '<timestamp>'),
            (r'\b[a-f0-9]{32,64}\b', '<hash>'),
            (r'\bport\s+\d+\b', 'port <num>'),
            (r'\bpid[=: ]\d+\b', 'pid=<num>'),
            (r'\b\d+\b', '<num>'),
        ]
        for pattern, replacement in substitutions:
            text = re.sub(pattern, replacement, text)
        return re.sub(r'\s+', ' ', text).strip()[:300]

    @staticmethod
    def detect_local_interactive_auth(text, source_ip, event_family):
        if event_family != "auth" or source_ip != "No_IP":
            return "False"
        if re.search(r'(tty=/dev/pts/\d+|tty=pts/\d+|\bon pts/\d+\b|\bpts/\d+\b)', text, re.IGNORECASE):
            return "True"
        return "False"

    @staticmethod
    def detect_known_benign_policy_noise(text, event_family):
        desktop_portal_noise = (
            re.search(
                r'xdg-desktop-portal|org\.freedesktop\.impl\.portal\.desktop\.gtk|dbus-daemon',
                text,
                re.IGNORECASE
            )
            and re.search(
                r'timed out|failed to activate service|failed with result|service_start_timeout',
                text,
                re.IGNORECASE
            )
        )
        if desktop_portal_noise:
            return "True"

        snap_noise = (
            re.search(r'snap\.', text, re.IGNORECASE)
            and re.search(r'apparmor="denied"|permission denied|denied', text, re.IGNORECASE)
        )
        if snap_noise:
            return "True"

        if event_family != "policy_denied":
            return "False"

        snap_pressure = (
            re.search(r'apparmor="denied"', text, re.IGNORECASE)
            and re.search(r'profile="snap\.[^"]+"', text, re.IGNORECASE)
            and re.search(r'/proc/pressure/(memory|cpu|io)', text, re.IGNORECASE)
        )
        if snap_pressure:
            return "True"

        memorypoller = (
            re.search(r'apparmor="denied"', text, re.IGNORECASE)
            and re.search(r'comm="memorypoller"', text, re.IGNORECASE)
        )
        return "True" if memorypoller else "False"

    def _remember_actor_alias(self, agent_id, auth_actor, auth_actor_uid, username, auth_principal):
        alias_store = self.actor_alias[agent_id]

        candidate_user = None
        for value in (auth_actor, auth_principal, username):
            if value not in (None, "", "No_User", "No_Actor", "No_Principal") and not str(value).startswith("uid:"):
                candidate_user = str(value).strip()
                break

        candidate_uid = None
        if auth_actor_uid not in (None, "", "No_UID"):
            candidate_uid = str(auth_actor_uid).strip()

        if candidate_user and candidate_uid:
            alias_store["uid_to_user"][candidate_uid] = candidate_user
            alias_store["user_to_uid"][candidate_user] = candidate_uid

    def _resolve_auth_principal(self, agent_id, auth_actor, auth_actor_uid, username):
        alias_store = self.actor_alias[agent_id]

        if auth_actor not in (None, "", "No_Actor"):
            return str(auth_actor).strip()

        if auth_actor_uid not in (None, "", "No_UID"):
            actor_uid = str(auth_actor_uid).strip()
            mapped_user = alias_store["uid_to_user"].get(actor_uid)
            return mapped_user if mapped_user else f"uid:{actor_uid}"

        if username not in (None, "", "No_User"):
            return str(username).strip()

        return "No_Principal"

    def _update_general_event_bucket(self, agent_id, event_family, source_ip, program_name, rule_id,
                                     normalized_template, username, path, now):
        secondary_key = source_ip if source_ip != "No_IP" else f"{program_name}_{rule_id}"
        bucket_key = f"{agent_id}_{event_family}_{secondary_key}"

        self.events[bucket_key] = [
            event for event in self.events[bucket_key]
            if now - event["ts"] < self.time_window
        ]
        self.events[bucket_key].append({
            "ts": now,
            "template": normalized_template,
            "ip": source_ip,
            "username": username,
            "path": path,
        })
        bucket = self.events[bucket_key]

        template_counts = defaultdict(int)
        for event in bucket:
            template_counts[event["template"]] += 1

        total = len(bucket)
        most_common = max(template_counts.values()) if template_counts else 0

        return {
            "burst_count_60s": total,
            "unique_templates_60s": len(set(e["template"] for e in bucket)),
            "unique_source_ips_60s": len(set(e["ip"] for e in bucket if e["ip"] != "No_IP")),
            "unique_usernames_60s": len(set(e["username"] for e in bucket if e["username"] != "No_User")),
            "unique_paths_60s": len(set(e["path"] for e in bucket if e["path"] != "No_Path")),
            "same_template_ratio": round((most_common / total), 2) if total > 0 else 0.0,
            "high_frequency_context": "True" if total >= self.threshold else "False",
            "moderate_repetition_context": "True" if total >= 5 else "False",
        }

    def _build_auth_keys(self, agent_id, source_ip, auth_principal, auth_actor_uid, tty):
        scope = "remote" if source_ip != "No_IP" else "local"
        prefix = f"{agent_id}_{scope}_auth"
        if source_ip != "No_IP":
            prefix = f"{prefix}_{source_ip}"
        return {
            "user": f"{prefix}_user_{self._normalize_scope(auth_principal, 'noprincipal')}",
            "uid": f"{prefix}_uid_{self._normalize_scope(auth_actor_uid, 'nouid')}",
            "tty": f"{prefix}_tty_{self._normalize_scope(tty, 'notty')}",
        }

    def _prune_auth_keys(self, keys, auth_principal, auth_actor_uid, tty, now):
        if auth_principal != "No_Principal":
            self.auth_events[keys["user"]] = [
                event for event in self.auth_events[keys["user"]]
                if now - event["ts"] < self.time_window
            ]
        if auth_actor_uid != "No_UID":
            self.auth_events[keys["uid"]] = [
                event for event in self.auth_events[keys["uid"]]
                if now - event["ts"] < self.time_window
            ]
        if tty != "No_TTY":
            self.auth_events[keys["tty"]] = [
                event for event in self.auth_events[keys["tty"]]
                if now - event["ts"] < self.time_window
            ]

    def analyze(self, log_entry):
        now = time.time()
        full_log = log_entry.get("full_log", "")
        text = full_log.lower()

        agent_id = log_entry.get("agent", {}).get("id", "000")
        rule_id = log_entry.get("rule", {}).get("id", "unknown_rule")
        program_name = (
            log_entry.get("program_name")
            or log_entry.get("decoder", {}).get("name")
            or "unknown_program"
        )

        source_ip = self.extract_ip(log_entry)
        username = self.extract_username(text)
        auth_actor = self.extract_auth_actor(text)
        auth_actor_uid = self.extract_auth_actor_uid(text)
        tty = self.extract_tty(text)
        path = self.extract_path(text)
        event_family = self.detect_event_family(text)
        auth_outcome = self.detect_auth_outcome(text, event_family)
        failure_weight = self.extract_failure_weight(text, auth_outcome)
        normalized_template = self.normalize_template(text)
        local_interactive_auth = self.detect_local_interactive_auth(text, source_ip, event_family)
        known_benign_policy_noise = self.detect_known_benign_policy_noise(text, event_family)

        auth_principal = self._resolve_auth_principal(
            agent_id=agent_id,
            auth_actor=auth_actor,
            auth_actor_uid=auth_actor_uid,
            username=username,
        )
        self._remember_actor_alias(
            agent_id=agent_id,
            auth_actor=auth_actor,
            auth_actor_uid=auth_actor_uid,
            username=username,
            auth_principal=auth_principal,
        )

        general_context = self._update_general_event_bucket(
            agent_id=agent_id,
            event_family=event_family,
            source_ip=source_ip,
            program_name=program_name,
            rule_id=rule_id,
            normalized_template=normalized_template,
            username=username,
            path=path,
            now=now,
        )

        auth_context = {
            "auth_failures_60s": 0,
            "failed_then_success_same_user": "False",
            "failed_then_success_same_tty": "False",
        }

        if event_family == "auth":
            keys = self._build_auth_keys(agent_id, source_ip, auth_principal, auth_actor_uid, tty)
            self._prune_auth_keys(keys, auth_principal, auth_actor_uid, tty, now)

            prior_user_bucket = list(self.auth_events[keys["user"]]) if auth_principal != "No_Principal" else []
            prior_uid_bucket = list(self.auth_events[keys["uid"]]) if auth_actor_uid != "No_UID" else []
            prior_tty_bucket = list(self.auth_events[keys["tty"]]) if tty != "No_TTY" else []

            prior_fail_same_user = False
            if auth_principal != "No_Principal":
                prior_fail_same_user = prior_fail_same_user or any(
                    event["outcome"] == "failure" for event in prior_user_bucket
                )
            if auth_actor_uid != "No_UID":
                prior_fail_same_user = prior_fail_same_user or any(
                    event["outcome"] == "failure" for event in prior_uid_bucket
                )

            prior_fail_same_tty = (
                tty != "No_TTY"
                and any(event["outcome"] == "failure" for event in prior_tty_bucket)
            )

            current_event = {
                "ts": now,
                "outcome": auth_outcome,
                "principal": auth_principal,
                "actor_uid": auth_actor_uid,
                "tty": tty,
                "failure_weight": failure_weight,
            }

            if auth_principal != "No_Principal":
                self.auth_events[keys["user"]].append(current_event)
            if auth_actor_uid != "No_UID":
                self.auth_events[keys["uid"]].append(current_event)
            if tty != "No_TTY":
                self.auth_events[keys["tty"]].append(current_event)

            user_failures = 0
            uid_failures = 0
            tty_failures = 0

            if auth_principal != "No_Principal":
                user_failures = sum(
                    event.get("failure_weight", 0)
                    for event in self.auth_events[keys["user"]]
                    if event.get("outcome") == "failure"
                )
            if auth_actor_uid != "No_UID":
                uid_failures = sum(
                    event.get("failure_weight", 0)
                    for event in self.auth_events[keys["uid"]]
                    if event.get("outcome") == "failure"
                )
            if tty != "No_TTY":
                tty_failures = sum(
                    event.get("failure_weight", 0)
                    for event in self.auth_events[keys["tty"]]
                    if event.get("outcome") == "failure"
                )

            auth_context["auth_failures_60s"] = max(user_failures, uid_failures, tty_failures)

            if auth_outcome == "success" and prior_fail_same_user:
                auth_context["failed_then_success_same_user"] = "True"
            if auth_outcome == "success" and prior_fail_same_tty:
                auth_context["failed_then_success_same_tty"] = "True"

        return {
            "event_family": event_family,
            "source_ip": source_ip,
            "username": username,
            "auth_actor": auth_actor,
            "auth_actor_uid": auth_actor_uid,
            "auth_principal": auth_principal,
            "tty": tty,
            "auth_outcome": auth_outcome,
            "path": path,
            "rule_id": rule_id,
            "program_name": program_name,
            "normalized_template": normalized_template,
            "local_interactive_auth": local_interactive_auth,
            "known_benign_policy_noise": known_benign_policy_noise,
            **general_context,
            **auth_context,
        }


# =========================
# POLICY HELPERS
# =========================
def get_cache_ttl(local_context):
    family = local_context.get("event_family", "other")
    if family in ("policy_denied", "system_error"):
        return 300
    if family == "auth":
        return 15
    if family == "network":
        return 60
    if family in ("web", "process", "file"):
        return 30
    return 60


def should_bypass_cache(local_context):
    family = local_context.get("event_family", "other")

    if family == "network":
        return False

    if family != "auth":
        return False

    auth_failures = int(local_context.get("auth_failures_60s", 0) or 0)
    return any([
        auth_failures >= 5,
        local_context.get("moderate_repetition_context") == "True",
        local_context.get("high_frequency_context") == "True",
        local_context.get("failed_then_success_same_user") == "True",
        local_context.get("failed_then_success_same_tty") == "True",
    ])


def build_history_key(log_entry, local_context=None):
    agent = log_entry.get("agent", {}) or {}
    agent_id = str(agent.get("id", "000")).strip() or "000"
    agent_name = str(agent.get("name", "unknown")).strip().lower() or "unknown"

    base_key = f"{agent_id}:{agent_name}"
    if not local_context:
        return base_key

    family = str(local_context.get("event_family", "other")).strip().lower() or "other"
    if family != "auth":
        return f"{base_key}:{family}"

    principal = local_context.get("auth_principal", "No_Principal")
    actor_uid = local_context.get("auth_actor_uid", "No_UID")
    tty = local_context.get("tty", "No_TTY")

    if principal not in (None, "", "No_Principal"):
        principal_scope = re.sub(r'[^a-z0-9._:-]+', '_', str(principal).strip().lower())
        return f"{base_key}:auth:user:{principal_scope}"

    if actor_uid not in (None, "", "No_UID"):
        return f"{base_key}:auth:uid:{actor_uid}"

    if tty not in (None, "", "No_TTY"):
        tty_scope = re.sub(r'[^a-z0-9._:-]+', '_', str(tty).strip().lower().replace("/", "_"))
        return f"{base_key}:auth:tty:{tty_scope}"

    return f"{base_key}:auth:generic"


# =========================
# CORE HELPERS
# =========================
def get_embedding(text, embedder):
    try:
        return embedder.encode(text).tolist()
    except Exception:
        return []


def _safe_prompt_text(text):
    if not text:
        return ""
    import json as standard_json
    
    escaped_string = standard_json.dumps(str(text))
    
    return escaped_string[1:-1]


def _extract_json_candidate(text):
    if not text:
        return None
    start_idx = text.find('{')
    end_idx = text.rfind('}') + 1
    if start_idx != -1 and end_idx > start_idx:
        return text[start_idx:end_idx]
    return None


def _qdrant_parse_results(response_obj):
    if isinstance(response_obj, dict):
        return response_obj.get("result", [])
    return []


def _build_qdrant_context(results, max_items=2, max_chars_per_item=320):
    snippets = []
    for item in results[:max_items]:
        payload = item.get("payload", {})
        doc_type = payload.get("doc_type", "unknown")
        name = payload.get("name", "unknown")
        attack_id = payload.get("attack_id", "")
        text = payload.get("text", "")

        title = f"[{doc_type}]"
        if attack_id:
            title += f" {attack_id}"
        if name:
            title += f" - {name}"

        snippets.append(f"- {title}: {text[:max_chars_per_item]}")
    return "\n".join(snippets)


def qdrant_search(vector, local_context=None):
    if local_context and local_context.get("known_benign_policy_noise") == "True":
        return (
            "Known benign local AppArmor/Snap policy-noise pattern detected. "
            "Use LOCAL CONTEXT and RECENT AGENT HISTORY primarily; external ATT&CK context is likely low-value for this event."
        )

    if local_context:
        auth_failures = int(local_context.get("auth_failures_60s", 0) or 0)
        low_value_local_auth = (
            local_context.get("event_family") == "auth"
            and local_context.get("local_interactive_auth") == "True"
            and local_context.get("source_ip") == "No_IP"
            and local_context.get("moderate_repetition_context") == "False"
            and auth_failures <= 2
            and local_context.get("failed_then_success_same_user") == "False"
            and local_context.get("failed_then_success_same_tty") == "False"
        )
        if low_value_local_auth:
            return (
                "Local interactive sudo/su authentication flow detected. "
                "Prefer LOCAL CONTEXT and RECENT AGENT HISTORY; ATT&CK context is low-value unless extra malicious evidence exists."
            )

    url = f"{QDRANT_URL}/collections/{COLLECTION}/points/search"
    must_conditions = [{
        "key": "doc_type",
        "match": {"any": QDRANT_DOC_TYPES},
    }]

    if local_context:
        event_family = local_context.get("event_family", "other")
        if event_family and event_family != "other":
            must_conditions.append({
                "key": "event_families",
                "match": {"any": [event_family]},
            })
        must_conditions.append({
            "key": "platforms",
            "match": {"any": QDRANT_PLATFORM_FILTER},
        })

    primary_payload = {
        "vector": vector,
        "limit": 4,
        "with_payload": True,
        "filter": {"must": must_conditions},
    }
    fallback_payload = {
        "vector": vector,
        "limit": 4,
        "with_payload": True,
    }

    try:
        response = requests.post(url, json=primary_payload, timeout=2)
        if response.status_code == 200:
            results = _qdrant_parse_results(response.json())
            if results:
                return _build_qdrant_context(results, max_items=2, max_chars_per_item=320)

        response = requests.post(url, json=fallback_payload, timeout=2)
        if response.status_code == 200:
            results = _qdrant_parse_results(response.json())
            if results:
                return _build_qdrant_context(results, max_items=2, max_chars_per_item=260)

    except Exception as exc:
        print(f"[ERROR] Qdrant search failed: {exc}")

    return "No specific playbook found."


def build_prompt(mode, full_log, local_context_text, history_text, context, original_agent_id, agent_name):
    escaped_full_log = _safe_prompt_text(full_log)
    escaped_agent_name = _safe_prompt_text(agent_name)
    escaped_agent_id = _safe_prompt_text(original_agent_id)

    return f"""
You are a strict SOC analyst.
Return valid JSON only.
Do not use markdown.
Do not explain outside JSON.
Keep ai_analysis under 220 characters.
Keep description under 110 characters.

MODE:
{mode}

CURRENT_LOG:
{full_log}

LOCAL_CONTEXT:
{local_context_text}

RECENT_HISTORY:
{history_text}

KB_CONTEXT:
{context}

RULES:
- Use CURRENT_LOG first, then LOCAL_CONTEXT, then RECENT_HISTORY, then KB_CONTEXT.
- If KB_CONTEXT is not directly relevant, set rag_context_used="False".
- If source_ip=No_IP, do not invent a remote attacker.
- If burst_count_60s=1, treat as isolated unless history clearly proves repetition.
- auth_failures_60s is the count of password failures within 60s.
- failed_then_success_same_user=True means the same local principal had failures then success in 60s.
- failed_then_success_same_tty=True means the same local tty had failures then success in 60s.
- auth_actor_uid is the local numeric uid of the actor when username is missing, for example "by (uid=1000)".
- If auth_actor_uid matches earlier local auth failures, treat that as same-user auth correlation even when actor username is missing.
- Local sudo/su on tty/pts with no remote source IP is usually benign or low severity.
- Local auth_failures_60s 1-2 usually means level 2-3 unless extra evidence exists.
- Local auth_failures_60s 3-4 usually means level 3-4 unless extra evidence exists.
- Local auth_failures_60s >=5 without success usually means level 4-6.
- Password mistakes followed by local sudo/su success are usually level 4-6 unless extra malicious evidence exists.
- Do not rate local sudo/su authentication-only activity above 7 without extra malicious evidence.
- known_benign_policy_noise=True usually means level 1-2.
- Explicit web shell or RCE wording in /var/www/ is usually level 9-12.
- For local tty auth repetition, prefer wording like repeated local password failures or possible local password guessing, not remote brute force.
- If auth_failures_60s >= 3, auth_correlation_used should usually be "True".
- If failed_then_success_same_user=True or failed_then_success_same_tty=True, auth_correlation_used must be "True".
- Set recent_history_used="True" only if RECENT_HISTORY changed severity or changed the conclusion.
- If we Have burst_count_60s > 500 , this mean we had DOS Attack : usually means level 15.
- If we Have burst_count_60s and unique_source_ips_60s > 500 , this mean we had DDOS Attack : usually means level 15.
- Confidentiality canary access with success=no and exit=-13 means unauthorized sensitive file access attempt; usually level 6-8.
- Confidentiality canary access with success=yes means sensitive file access succeeded; usually level 9-12 unless clearly authorized.
- If key=ai_confidential_canary or path contains /opt/confidential_lab/customer_secrets.csv, classify as confidentiality-relevant.
- Do not treat all network events as DoS.
- event_family=network_flood means possible DoS/DDoS/high-rate traffic.
- event_family=network_scan means reconnaissance or port/service scanning.
- event_family=network_vuln_probe means vulnerability probing or exploit validation.
- event_family=network_sensitive_service means access/probing to sensitive service ports such as SMB, RDP, SSH, WinRM, VNC, databases.
- Only network_flood should depend on burst_count_60s for DoS/DDoS judgement.
- SMB/445, RDP/3389, SSH/22, and WinRM/5985 single events may still be security-relevant even without high burst count.
- If event_family=network_vuln_probe, analyze as vulnerability validation, not availability attack.
- If event_family=network_scan, analyze as reconnaissance unless exploit evidence exists.
WINDOWS POWERSHELL / C2 POLICY:
- If a Windows PowerShell process creates an outbound TCP connection to a non-standard port such as 4444, 1337, 4443, 8081, 9001, or 31337, classify as level 10-12.
- If PowerShell connects outbound to a remote IP shortly after cmd.exe or service creation, classify as likely reverse shell or C2 activity.
- If destination port is 4444 and process is powershell.exe, do not classify below level 10.
- If the event shows Service Control Manager Event ID 7045 with powershell.exe, -nop, -w hidden, -noni, encoded command, or logging bypass, classify as level 12-14.
- If PowerShell binds to 0.0.0.0 without inbound session evidence, classify lower, level 3-5, unless command line or parent process is suspicious.

SEVERITY GUIDE:
1-2 benign routine activity
3-4 weak suspicion / isolated anomaly
5-6 denied or blocked security-relevant action
7-8 repeated suspicious activity without success
9 strong attack attempt / partial compromise indicator
10 likely compromise attempt
11-13 strong evidence of compromise
14-15 confirmed major compromise

Return exactly this JSON:
{{
  "ai_id": "000_ai",
  "ai_rule": {{
    "level": <int 1-15>,
    "description": "<short summary>",
    "groups": ["ai_analyzed", "rag_detection", "correlated_event"]
  }},
  "ai_agent_info": {{
    "id": "{escaped_agent_id}",
    "name": "{escaped_agent_name}",
    "platform": "linux/windows/MacOS/ios/android/(try to guess what is the platform , if not then type other)"
  }},
  "manager": {{ "name": "wazuh-manager" }},
  "full_log": "__FULL_LOG_PLACEHOLDER__",
  "ai_evaluation": {{
    "ai_analysis": "<very short evidence-based reasoning>",
    "local_context_used": "True/False",
    "recent_history_used": "True/False",
    "auth_correlation_used": "True/False",
    "rag_context_used": "True/False"
  }}
}}
""".strip()


def llama_analysis(prompt):
    print(f"  [STEP 3] Sending Request to OLLAMA ({MODEL_NAME})...")

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": OLLAMA_OPTIONS,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=LLM_TIMEOUT)
        print("  [STEP 4] Response Received from LLM.")
        response_text = response.json().get("response", "")

        candidate = _extract_json_candidate(response_text)
        if candidate and candidate.strip().endswith("}"):
            return response_text

        print("  [RETRY] Incomplete JSON detected. Requesting compact repair...")

        repair_prompt = f"""
Repair this truncated JSON and return valid JSON only.
Do not add explanations.
Keep ai_analysis under 180 characters.
Keep description under 100 characters.

TRUNCATED_JSON:
{response_text}
""".strip()

        repair_payload = {
            "model": MODEL_NAME,
            "prompt": repair_prompt,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.0,
                "top_p": 0.8,
                "num_ctx": 1024,
                "num_predict": 220,
                "repeat_penalty": 1.05,
            },
        }

        repaired_response = requests.post(OLLAMA_URL, json=repair_payload, timeout=LLM_TIMEOUT)
        repaired = repaired_response.json().get("response", "")
        return repaired if repaired else response_text

    except Exception as exc:
        print(f"[ERROR] LLM Failed: {exc}")
        return ""


def write_to_wazuh(alert_data):
    try:
        message = json_dumps_text(alert_data) + "\n"

        print("  [STEP 6] Opening TCP Socket to Wazuh (127.0.0.1:5555)...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("127.0.0.1", 5555))
        sock.sendall(message.encode("utf-8"))
        sock.close()

        level = alert_data.get("ai_rule", {}).get("level", "N/A")
        print(f"[SUCCESS] Alert injected into Wazuh Dashboard via TCP (Level {level})")
        return True

    except ConnectionRefusedError:
        print("[ERROR] Wazuh is NOT listening on port 5555. Check ossec.conf!")
        return False
    except Exception as exc:
        print(f"[ERROR] TCP Injection Failed: {exc}")
        return False


# =========================
# MAIN LOGIC
# =========================
def process_event(log_entry, embedder, past_logs_snapshot, local_context):
    success = True

    full_log = log_entry.get("full_log", "")
    original_agent_id = log_entry.get("agent", {}).get("id", "000")
    agent_name = log_entry.get("agent", {}).get("name", "unknown")
    wazuh_rule = log_entry.get("rule", {})
    mode = "VALIDATION" if wazuh_rule.get("level", 0) >= 10 else "HUNTING"

    try:
        print(f"\n[AI ANALYZING] Mode: {mode} | Agent: {agent_name} | Event: Enriched Log Analysis")
        print(f"  [RAW LOG] {full_log}")

        print("  [LOCAL CONTEXT]")
        for key, value in local_context.items():
            print(f"    - {key}: {value}")

        print("  [STEP 1] Generating Embedding...")
        vector = get_embedding(full_log, embedder)

        print("  [STEP 2] Querying Vector DB (RAG)...")
        context = qdrant_search(vector, local_context)

        print(f"  [RAG RESULT] Found Context:\n{context}")

        history_text = "\n".join(past_logs_snapshot) if past_logs_snapshot else "No recent prior events for this agent."
        local_context_text = "\n".join(f"{key}: {value}" for key, value in local_context.items())

        prompt = build_prompt(
            mode=mode,
            full_log=full_log,
            local_context_text=local_context_text,
            history_text=history_text,
            context=context,
            original_agent_id=original_agent_id,
            agent_name=agent_name,
        )

        response = llama_analysis(prompt)

        print(f"  [LLM RESPONSE] \n{response}\n")
        print("  [STEP 5] Parsing JSON Output...")

        clean_json_str = _extract_json_candidate(response)
        if not clean_json_str:
            raise ValueError("No complete JSON object found in LLM response")

        final_json = json_loads(clean_json_str)
        final_json["ai_id"] = "000_ai"
        final_json["full_log"] = full_log
        level = final_json.get("ai_rule", {}).get("level", 0)

        if level >= 1:
            inject_ok = write_to_wazuh(final_json)
            if not inject_ok:
                success = False
        else:
            print(f"  [INFO] AI dismissed event (Level {level}) - Not Sending to Wazuh.")

    except Exception as exc:
        success = False
        if "No complete JSON object found" in str(exc) or isinstance(exc, ValueError):
            print(f"[ERROR] JSON Parsing failed: {exc}")
        else:
            print(f"[ERROR] process_event crashed: {exc}")

    return success


# =========================
# FILE FOLLOWER
# =========================
def follow(file_path):
    if not os.path.exists(file_path):
        print(f"[FATAL] File not found: {file_path}")
        raise SystemExit(1)

    with open(file_path, "r") as file_obj:
        file_obj.seek(0, os.SEEK_END)
        while True:
            line = file_obj.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line


def should_skip_log(log_entry, full_log_str):
    data = log_entry.get("data", {}) or {}
    rule = log_entry.get("rule", {}) or {}
    groups = rule.get("groups", []) or []
    decoder_name = str(log_entry.get("decoder", {}).get("name", "")).lower()
    location = str(log_entry.get("location", "")).lower()

    active_response_noise = any(x in full_log_str for x in [
        "active-response/bin/",
        "ai-kill-process",
        "ai-block-ip",
        "ai-quarantine-file",
        "ai-disable-user",
        "ai-isolate-host",
        "killed process successfully",
        "rollback",
    ])

    if active_response_noise:
        return True

    if (
        "ai_id" in log_entry
        or data.get("ai_id") == "000_ai"
        or data.get("response_id") == "000_response_ai"
        or "000_ai" in full_log_str
        or "000_response_ai" in full_log_str
        or "ai_response" in data
        or "ai_response" in groups
        or "rag_response" in groups
        or decoder_name == "json" and "127.0.0.1" in location
        or any(noise in full_log_str for noise in INFRASTRUCTURE_NOISE)
    ):
        return True

    return False


def should_skip_ai_analysis(full_log_str, local_context):
    family = local_context.get("event_family", "other")
    program_name = local_context.get("program_name", "")

    if local_context.get("known_benign_policy_noise") == "True":
        return True, "Known benign local noise"

    php_sessionclean_noise = (
        "phpsessionclean" in full_log_str
        or "clean php session files" in full_log_str
        or "/usr/lib/php/sessionclean" in full_log_str
        or "php session cleanup" in full_log_str
    )
    if php_sessionclean_noise:
        return True, "Benign PHP session cleanup noise"

    cron_pam_noise = (
        "pam_unix(cron:session)" in full_log_str
        and (
            "session opened for user root" in full_log_str
            or "session closed for user root" in full_log_str
        )
    )
    if cron_pam_noise:
        return True, "Benign cron PAM session noise"

    auditd_cron_success_noise = (
        program_name == "auditd"
        and "/usr/sbin/cron" in full_log_str
        and "res=success" in full_log_str
        and (
            "type=user_start" in full_log_str
            or "type=user_end" in full_log_str
            or "type=cred_acq" in full_log_str
            or "type=cred_disp" in full_log_str
        )
    )
    if auditd_cron_success_noise:
        return True, "Benign auditd cron success noise"

    systemd_routine_noise = (
        program_name == "systemd"
        and (
            "deactivated successfully" in full_log_str
            or "finished " in full_log_str
            or "starting clean php session files" in full_log_str
        )
    )
    if systemd_routine_noise:
        return True, "Benign systemd routine service noise"

    if family == "system_error":
        if (
            local_context.get("high_frequency_context") != "True"
            and local_context.get("moderate_repetition_context") != "True"
        ):
            return True, "Low-value isolated system error"

    return False, ""

def get_trigger_reason(full_log_str, wazuh_level, local_context):
    if wazuh_level >= 10:
        return f"High Level Rule ({wazuh_level})"

    family = local_context.get("event_family", "other")
    burst_count = int(local_context.get("burst_count_60s", 0) or 0)

    if family == "confidentiality":
        return "Unauthorized Sensitive File Access Attempt"

    if (
        "ai_confidential_canary" in full_log_str
        or "customer_secrets" in full_log_str
        or "/opt/confidential_lab" in full_log_str
        or ("success=no" in full_log_str and "exit=-13" in full_log_str)
    ):
        return "Confidentiality Canary File Access"

    if family == "network":
        is_http_port80_test = (
            "http_port80_test" in full_log_str
            or "dpt=80" in full_log_str
            or '"dstport":"80"' in full_log_str
        )

        if is_http_port80_test and burst_count >= 10:
            return "HTTP Port 80 Burst - Availability Test"

        return None

    strong_keywords = [
        "attack", "malware", "critical", "webshell",
        "cmd.exe", "powershell", "amsi", "base64",
        "frombase64string", "gzipstream", "execution",
        "exploit", "rce", "mimikatz", "meterpreter",
        "reverse shell"
    ]

    if any(keyword in full_log_str for keyword in strong_keywords):
        return "Strong Suspicious Keyword Match"

    suspicious_php = (
        ".php" in full_log_str
        and (
            "/var/www/" in full_log_str
            or "upload" in full_log_str
            or "shell" in full_log_str
            or "eval(" in full_log_str
            or "base64_decode" in full_log_str
            or "system(" in full_log_str
            or "passthru(" in full_log_str
            or "cmd=" in full_log_str
        )
    )
    if suspicious_php:
        return "Suspicious PHP Web Activity"

    if family in ("auth", "web", "process", "file", "policy_denied"):
        weak_keywords = ["denied", "blocked", "forbidden", "failed"]
        if any(keyword in full_log_str for keyword in weak_keywords):
            return "Security-Relevant Event"

    return None


def build_dedupe_hash(agent_id, local_context):
    dedupe_key = (
        f"{agent_id}|"
        f"{local_context['event_family']}|"
        f"{local_context['program_name']}|"
        f"{local_context['rule_id']}|"
        f"{local_context['normalized_template']}"
    )
    return hashlib.md5(dedupe_key.encode()).hexdigest()


def print_debug_summary(trigger_reason, local_context, family_ttl, bypass_cache):
    print(f"[DEBUG] Log Picked for Analysis! Reason: {trigger_reason}")
    print(
        f"[DEBUG] Local Context Summary: "
        f"family={local_context['event_family']} | "
        f"burst={local_context['burst_count_60s']} | "
        f"same_template_ratio={local_context['same_template_ratio']} | "
        f"auth_failures_60s={local_context.get('auth_failures_60s', 0)} | "
        f"failed_then_success_same_user={local_context.get('failed_then_success_same_user', 'False')} | "
        f"failed_then_success_same_tty={local_context.get('failed_then_success_same_tty', 'False')} | "
        f"ip={local_context['source_ip']} | "
        f"cache_ttl={family_ttl}s | "
        f"cache_bypass={bypass_cache}"
    )


def print_queue_state():
    print("[QUEUE] Event submitted for analysis.")


# =========================
# MAIN EXECUTION
# =========================
def main():
    print("[INIT] Loading AI Models (This may take a moment)...")
    embedder = SentenceTransformer(EMBED_MODEL_PATH)
    cache = AlertCache(ttl=CACHE_TTL)
    burst_tracker = BurstContextTracker(threshold=20)
    network_gate = NetworkBurstGate(
    threshold=NETWORK_BURST_THRESHOLD,
    cooldown=NETWORK_BURST_COOLDOWN
    )
    history_memory = defaultdict(lambda: deque(maxlen=4))
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS)

    print(f"[RUNNING] Monitoring {WAZUH_ARCHIVES}...")
    print(f"[RUNNING] MAX_THREADS={MAX_THREADS} | MODEL={MODEL_NAME}")

    try:
        for line in follow(WAZUH_ARCHIVES):
            try:
                log_entry = json_loads(line)
                full_log_str = log_entry.get("full_log", "").lower()

                if should_skip_log(log_entry, full_log_str):
                    continue

                agent_id = log_entry.get("agent", {}).get("id", "000")
                wazuh_level = log_entry.get("rule", {}).get("level", 0)

                local_context = burst_tracker.analyze(log_entry)

                skip_ai, skip_reason = should_skip_ai_analysis(full_log_str, local_context)
                if skip_ai:
                    print(
                        f"[SKIP] Noise filtered before AI: {skip_reason} | "
                        f"family={local_context['event_family']} | "
                        f"{full_log_str[:100]}..."
                    )
                    continue

                trigger_reason = get_trigger_reason(full_log_str, wazuh_level, local_context)
                if not trigger_reason:
                    continue
                
                network_emit, network_reason = network_gate.should_emit(
                    log_entry,
                    full_log_str,
                    local_context
                )

                if not network_emit:
                    print(
                        f"[SKIP] Network aggregation gate: {network_reason} | "
                        f"family={local_context['event_family']} | "
                        f"burst={local_context['burst_count_60s']} | "
                        f"src={local_context['source_ip']} | "
                        f"{full_log_str[:100]}..."
                    )
                    continue


                log_hash = build_dedupe_hash(agent_id, local_context)
                family_ttl = get_cache_ttl(local_context)
                bypass_cache = should_bypass_cache(local_context)

                if bypass_cache or not cache.is_cached(log_hash, ttl=family_ttl):
                    print_debug_summary(trigger_reason, local_context, family_ttl, bypass_cache)

                    history_key = build_history_key(log_entry, local_context)
                    past_logs_snapshot = list(history_memory[history_key])

                    current_time_str = datetime.now().strftime("%H:%M:%S")
                    history_memory[history_key].append(f"[{current_time_str}] {full_log_str[:150]}")

                    print_queue_state()
                    executor.submit(process_event, log_entry, embedder, past_logs_snapshot, local_context)
                else:
                    print(
                        f"[SKIP] Duplicate Log (Cached): family={local_context['event_family']} | "
                        f"ttl={family_ttl}s | {full_log_str[:80]}..."
                    )

            except Exception as exc:
                if not isinstance(exc, ValueError):
                    print(f"[ERROR] Main Loop: {exc}")

    except KeyboardInterrupt:
        print("\n[STOP] Keyboard interrupt received. Shutting down gracefully...")

    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        print("[STOP] Sentinel stopped.")


if __name__ == "__main__":
    main()