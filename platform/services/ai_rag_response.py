#!/usr/bin/env python3
import os
import re
import time
import socket
import hashlib
import requests
import concurrent.futures

from sentence_transformers import SentenceTransformer

try:
    import orjson as json
except ImportError:
    import json


# =========================
# CONFIGURATION
# =========================
WAZUH_ALERTS = "/var/ossec/logs/alerts/alerts.json"
WAZUH_SOCKET_HOST = "127.0.0.1"
WAZUH_SOCKET_PORT = 5555

EMBED_MODEL_PATH = "/home/i77/AS-Platform/models/bge-small-en-v1.5"
QDRANT_URL = "http://localhost:6333"
COLLECTION = "RAG_response_knowledge"

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
    "AI_RAG_RESPONSE_MODEL",
    "llama3.2",
    "OLLAMA_MODEL",
    "AI_MODEL",
)

MAX_THREADS = _clamp_int(
    _env_int("AI_RAG_RESPONSE_MAX_THREADS", 2, "AI_MAX_THREADS", "MAX_THREADS"),
    1,
    64,
)
CACHE_TTL = _env_int("AI_RAG_RESPONSE_CACHE_TTL", 120, "CACHE_TTL")
LLM_TIMEOUT = _env_int("AI_RAG_RESPONSE_LLM_TIMEOUT", 120, "LLM_TIMEOUT")

RESPONSE_ID = _env_text("AI_RESPONSE_ID", "000_response_ai")
RESPONSE_ORIGIN = "ai_response_engine"
RESPONSE_VERSION = 1

DETECTION_AI_ID = "000_ai"

AUTO_EXECUTE_MIN_LEVEL = _clamp_int(
    _env_int("AI_AUTO_RESPONSE_MIN_LEVEL", 15, "AUTO_EXECUTE_MIN_LEVEL"),
    0,
    15,
)

OLLAMA_OPTIONS = {
    "temperature": 0.0,
    "top_p": 0.8,
    "num_ctx": 2048,
    "repeat_penalty": 1.05,
}

RESPONSE_DOC_TYPES = [
    "response_playbook",
    "detection_response_map",
    "evidence_collection_guide",
    "mitigation_mapping",
]

PLATFORM_MAP = {
    "linux": "linux",
    "kali": "linux",
    "parrot": "linux",
    "ubuntu": "linux",
    "debian": "linux",
    "windows": "windows",
    "windows7": "windows",
    "windows 7": "windows",
    "windows 8": "windows",
    "windows 10": "windows",
    "windows 11": "windows",
}

ALLOWED_ACTIONS_BY_PLATFORM = {
    "linux": {
        "monitor_only",
        "collect_triage",
        "block_ip",
        "kill_process",
        "quarantine_file",
        "disable_user",
        "isolate_host",
    },
    "windows": {
        "monitor_only",
        "collect_triage",
        "block_ip",
        "kill_process",
        "quarantine_file",
        "disable_user",
        "isolate_host",
    },
    "unknown": {
        "monitor_only",
        "collect_triage",
    },
}

AUTO_EXECUTE_ALLOWED = {
    "linux": {
        "block_ip",
        "kill_process",
        "quarantine_file",
        "disable_user",
        "isolate_host",
    },
    "windows": {
        "block_ip",
        "kill_process",
        "quarantine_file",
        "disable_user",
        "isolate_host",
    },
    "unknown": set(),
}

ACTION_TO_COMMAND = {
    "monitor_only": "",
    "collect_triage": "",
    "block_ip": "ai-block-ip0",
    "kill_process": "ai-kill-process0",
    "quarantine_file": "ai-quarantine-file0",
    "disable_user": "ai-disable-user0",
    "isolate_host": "ai-isolate-host0",
}


# =========================
# JSON HELPERS
# =========================
def json_loads(value):
    return json.loads(value)


def json_dumps_text(value):
    dumped = json.dumps(value)
    return dumped.decode("utf-8") if isinstance(dumped, bytes) else dumped


# =========================
# SIMPLE CACHE
# =========================
class TTLCache:
    def __init__(self, ttl=120):
        self.cache = {}
        self.ttl = ttl

    def seen(self, signature):
        now = time.time()
        self.cache = {k: v for k, v in self.cache.items() if now < v}

        if signature in self.cache:
            return True

        self.cache[signature] = now + self.ttl
        return False


# =========================
# FILE FOLLOWER
# =========================
def follow(file_path):
    file_obj = None
    inode = None
    pending = ""
    max_pending_bytes = 1024 * 1024

    while True:
        try:
            if file_obj is None:
                if not os.path.exists(file_path):
                    print(f"[FATAL] File not found: {file_path}")
                    time.sleep(1)
                    continue

                file_obj = open(file_path, "r", encoding="utf-8", errors="ignore")
                inode = os.fstat(file_obj.fileno()).st_ino
                file_obj.seek(0, os.SEEK_END)
                pending = ""

            chunk = file_obj.readline()

            if chunk:
                pending += chunk

                if pending.endswith("\n"):
                    line = pending
                    pending = ""
                    yield line
                    continue

                if len(pending.encode("utf-8", errors="ignore")) > max_pending_bytes:
                    print(
                        f"[SKIP] Dropping oversized incomplete alert buffer | "
                        f"len={len(pending)} | head={pending[:160]}"
                    )
                    pending = ""

                continue

            time.sleep(0.1)

            try:
                stat = os.stat(file_path)

                if stat.st_ino != inode:
                    if pending.strip():
                        print(
                            f"[SKIP] Dropping incomplete alert before rotation | "
                            f"len={len(pending)} | head={pending[:160]}"
                        )

                    print("[INFO] alerts.json rotated. Reopening file.")
                    file_obj.close()
                    file_obj = open(file_path, "r", encoding="utf-8", errors="ignore")
                    inode = os.fstat(file_obj.fileno()).st_ino
                    file_obj.seek(0, os.SEEK_SET)
                    pending = ""
                    continue

                if stat.st_size < file_obj.tell():
                    if pending.strip():
                        print(
                            f"[SKIP] Dropping incomplete alert before truncate | "
                            f"len={len(pending)} | head={pending[:160]}"
                        )

                    print("[INFO] alerts.json truncated. Resetting reader to beginning.")
                    file_obj.seek(0, os.SEEK_SET)
                    pending = ""
                    continue

            except FileNotFoundError:
                print("[WARN] alerts.json temporarily missing. Waiting...")
                try:
                    file_obj.close()
                except Exception:
                    pass

                file_obj = None
                inode = None
                pending = ""
                time.sleep(1)

        except Exception as exc:
            print(f"[ERROR] follow failed: {exc}")

            try:
                if file_obj:
                    file_obj.close()
            except Exception:
                pass

            file_obj = None
            inode = None
            pending = ""
            time.sleep(1)


# =========================
# GENERIC HELPERS
# =========================
def normalize_platform(platform_value):
    if not platform_value:
        return "unknown"

    value = str(platform_value).strip().lower()
    return PLATFORM_MAP.get(value, value if value in ("linux", "windows") else "unknown")


def md5_text(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _safe_prompt_text(text):
    text = str(text)
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    text = text.replace("\n", " ")
    return text


def _extract_json_candidate(text):
    if not text:
        return None

    start_idx = text.find("{")
    end_idx = text.rfind("}") + 1

    if start_idx != -1 and end_idx > start_idx:
        return text[start_idx:end_idx]

    return None


def get_embedding(text, embedder):
    try:
        return embedder.encode(text).tolist()
    except Exception:
        return []


# =========================
# IOC EXTRACTION
# =========================
def extract_ip(text):
    match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    return match.group(0) if match else ""


def extract_linux_path(text):
    match = re.search(r"((?:/[A-Za-z0-9._-]+){2,})", text)
    return match.group(1) if match else ""


def extract_windows_path(text):
    match = re.search(r"([A-Za-z]:\\[^\s\"']+)", text)
    return match.group(1) if match else ""


def extract_user(text):
    patterns = [
        r"\bruser=([A-Za-z0-9._-]+)",
        r"\blogname=([A-Za-z0-9._-]+)",
        r"sudo:\s+([A-Za-z0-9._-]+)\s*:",
        r"for invalid user ([A-Za-z0-9._-]+)",
        r"for user ([A-Za-z0-9._-]+)",
        r"\bUSER=([A-Za-z0-9._-]+)",
        r"\buser=([A-Za-z0-9._-]+)",
        r"by\s+([A-Za-z0-9._-]+)\(uid=",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def extract_tty(text):
    patterns = [
        r"tty=(/dev/pts/\d+)",
        r"tty=(pts/\d+)",
        r"\bon (pts/\d+)\b",
        r"\b(/dev/pts/\d+)\b",
        r"\b(pts/\d+)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).replace("/dev/", "")
    return ""


def extract_service_name(text):
    match = re.search(r"Service Name:\s*([^\s]+)", text, re.IGNORECASE)
    return match.group(1) if match else ""


def extract_iocs(full_log):
    return {
        "ip": extract_ip(full_log),
        "linux_path": extract_linux_path(full_log),
        "windows_path": extract_windows_path(full_log),
        "user": extract_user(full_log),
        "tty": extract_tty(full_log),
        "service_name": extract_service_name(full_log),
    }


# =========================
# QDRANT RESPONSE KB
# =========================
def _qdrant_parse_results(response_obj):
    if isinstance(response_obj, dict):
        return response_obj.get("result", [])
    return []


def _build_qdrant_context(results, max_items=4, max_chars_per_item=420):
    snippets = []
    for item in results[:max_items]:
        payload = item.get("payload", {})
        doc_type = payload.get("doc_type", "unknown")
        title = payload.get("title") or payload.get("name") or "unknown"
        attack_id = payload.get("attack_id", "")
        description = payload.get("description", "")
        text = payload.get("text", "")

        header = f"[{doc_type}]"
        if attack_id:
            header += f" {attack_id}"
        header += f" - {title}"

        body = description if description else text
        snippets.append(f"- {header}: {body[:max_chars_per_item]}")
    return "\n".join(snippets) if snippets else "No response guidance found."


def qdrant_response_search(vector, platform):
    if not vector:
        return "No response guidance found."

    url = f"{QDRANT_URL}/collections/{COLLECTION}/points/search"

    must_conditions = [{
        "key": "doc_type",
        "match": {"any": RESPONSE_DOC_TYPES},
    }]

    qdrant_platform = PLATFORM_MAP.get(platform, platform).lower()

    if qdrant_platform in ("linux", "windows"):
        must_conditions.append({
            "key": "platforms",
            "match": {"any": [qdrant_platform, qdrant_platform.capitalize()]},
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
        response = requests.post(url, json=primary_payload, timeout=3)
        if response.status_code == 200:
            results = _qdrant_parse_results(response.json())
            if results:
                return _build_qdrant_context(results)

        response = requests.post(url, json=fallback_payload, timeout=3)
        if response.status_code == 200:
            results = _qdrant_parse_results(response.json())
            if results:
                return _build_qdrant_context(results)

    except Exception as exc:
        print(f"[ERROR] Qdrant response search failed: {exc}")

    return "No response guidance found."


# =========================
# LLM RESPONSE PLANNING
# =========================
def default_response_plan(platform, iocs):
    return {
        "recommended_action": "collect_triage" if platform in ("linux", "windows") else "monitor_only",
        "summary": "Generate investigation guidance and manual response recommendation.",
        "confidence": "low",
        "reasoning": "Fallback plan used because the response model output was unavailable or invalid.",
        "manual_steps": [
            "Review the original AI detection alert in Wazuh.",
            "Collect endpoint triage artifacts before taking destructive action.",
            "Validate the IOC on the target endpoint.",
        ],
        "evidence_to_collect": [
            "process_list",
            "network_connections",
            "recent_logon_events",
            "file_metadata",
        ],
        "action_parameters": {
            "ip": iocs.get("ip", ""),
            "path": iocs.get("linux_path") or iocs.get("windows_path") or "",
            "user": iocs.get("user", ""),
            "tty": iocs.get("tty", ""),
            "service_name": iocs.get("service_name", ""),
        },
        "rag_context_used": "False",
        "safe_for_auto_execute": "False",
    }


def sanitize_plan(plan, platform, iocs):
    allowed = ALLOWED_ACTIONS_BY_PLATFORM.get(platform, ALLOWED_ACTIONS_BY_PLATFORM["unknown"])
    action = str(plan.get("recommended_action", "monitor_only")).strip()

    if action not in allowed:
        action = "monitor_only"

    summary = str(plan.get("summary", "")).strip()[:180]
    reasoning = str(plan.get("reasoning", "")).strip()[:240]

    confidence = str(plan.get("confidence", "low")).strip().lower()
    if confidence not in ("low", "medium", "high"):
        confidence = "low"

    manual_steps = plan.get("manual_steps", [])
    if not isinstance(manual_steps, list):
        manual_steps = []
    manual_steps = [str(x).strip()[:160] for x in manual_steps if str(x).strip()][:5]

    evidence = plan.get("evidence_to_collect", [])
    if not isinstance(evidence, list):
        evidence = []
    evidence = [str(x).strip()[:120] for x in evidence if str(x).strip()][:5]

    action_parameters = plan.get("action_parameters", {})
    if not isinstance(action_parameters, dict):
        action_parameters = {}

    merged_parameters = {
        "ip": str(action_parameters.get("ip", "") or iocs.get("ip", "")).strip(),
        "path": str(
            action_parameters.get("path", "")
            or iocs.get("linux_path", "")
            or iocs.get("windows_path", "")
        ).strip(),
        "user": str(action_parameters.get("user", "") or iocs.get("user", "")).strip(),
        "tty": str(action_parameters.get("tty", "") or iocs.get("tty", "")).strip(),
        "service_name": str(action_parameters.get("service_name", "") or iocs.get("service_name", "")).strip(),
    }

    rag_context_used = "True" if str(plan.get("rag_context_used", "False")) == "True" else "False"
    safe_for_auto_execute = "True" if str(plan.get("safe_for_auto_execute", "False")) == "True" else "False"

    return {
        "recommended_action": action,
        "summary": summary or "AI response recommendation generated.",
        "confidence": confidence,
        "reasoning": reasoning or "Response plan generated from alert context and response knowledge.",
        "manual_steps": manual_steps,
        "evidence_to_collect": evidence,
        "action_parameters": merged_parameters,
        "rag_context_used": rag_context_used,
        "safe_for_auto_execute": safe_for_auto_execute,
    }


def build_response_prompt(alert, kb_context, platform, iocs):
    ai_rule = alert.get("ai_rule", {})
    ai_eval = alert.get("ai_evaluation", {})
    ai_agent = alert.get("ai_agent_info", {})

    full_log = alert.get("full_log", "")
    level = ai_rule.get("level", 0)
    description = ai_rule.get("description", "")
    ai_analysis = ai_eval.get("ai_analysis", "")
    target_id = ai_agent.get("id", "000")
    target_name = ai_agent.get("name", "unknown")
    target_platform = ai_agent.get("platform", platform)

    allowed_actions = sorted(ALLOWED_ACTIONS_BY_PLATFORM.get(platform, {"monitor_only", "collect_triage"}))
    allowed_actions_text = ", ".join(allowed_actions)

    return f"""
You are a strict SOC response planner.
Return valid JSON only.
Do not use markdown.
Do not explain outside JSON.
Keep summary under 160 characters.
Keep reasoning under 220 characters.

ALLOWED_ACTIONS:
{allowed_actions_text}

TARGET_ENDPOINT:
- agent_id: {_safe_prompt_text(target_id)}
- agent_name: {_safe_prompt_text(target_name)}
- platform: {_safe_prompt_text(target_platform)}

SOURCE_AI_ALERT:
- level: {level}
- description: {_safe_prompt_text(description)}
- ai_analysis: {_safe_prompt_text(ai_analysis)}

CURRENT_LOG:
{full_log}

IOC_HINTS:
- ip: {_safe_prompt_text(iocs.get("ip", ""))}
- path: {_safe_prompt_text(iocs.get("linux_path") or iocs.get("windows_path") or "")}
- user: {_safe_prompt_text(iocs.get("user", ""))}
- tty: {_safe_prompt_text(iocs.get("tty", ""))}
- service_name: {_safe_prompt_text(iocs.get("service_name", ""))}

KB_CONTEXT:
{kb_context}

RULES:
- Choose exactly one value from ALLOWED_ACTIONS as recommended_action.
- Do not invent remote attackers when no IP exists.
- Do not choose actions that are not listed in ALLOWED_ACTIONS.
- Use monitor_only only for benign, low-confidence, or routine activity.
- Use collect_triage only when evidence is incomplete AND no immediate containment condition is met.
- Use block_ip only when a source IP is relevant and the activity is network-based.
- Use quarantine_file only when a file path is relevant.
- Use disable_user only when a specific user account is relevant.
- Use kill_process only when process/service-style containment is appropriate.
- Use isolate_host only for severe host compromise, lateral movement, ransomware, or broad containment scenarios.
- Prefer conservative recommendations for routine local sudo/su activity.

NETWORK DOS / FLOOD DECISION POLICY:
- If SOURCE_AI_ALERT level is 15 AND a source IP exists AND the source IP is different from the target IP, then high-volume network flood evidence is enough to recommend block_ip.
- This rule overrides the generic collect_triage preference.
- For confirmed DoS, DDoS, flood, high-frequency TCP, SYN, ACK, RST, HTTP request flood, or service-exhaustion traffic, choose block_ip when the source IP is present.
- If the alert says burst, high-frequency, high-rate, flood, DoS, DDoS, service exhaustion, or packet/request count exceeds a threshold, treat it as confirmed enough when SOURCE_AI_ALERT level is 15.
- Do not downgrade level-15 high-volume network flood activity to collect_triage just because service outage is not explicitly confirmed.
- If service impact is confirmed by availability DOWN, DEGRADED, timeout, consecutive_failures, or unavailable service, block_ip is strongly preferred.
- If source IP equals target IP, do not block_ip; use collect_triage.
- If no source IP exists, do not block_ip; use collect_triage.

AUTO EXECUTION SAFETY:
- safe_for_auto_execute must be "True" when all are true:
  1) SOURCE_AI_ALERT level is 15
  2) recommended_action is block_ip
  3) a source IP exists
  4) the source IP is different from the target IP
  5) the evidence indicates DoS, flood, high-frequency traffic, or service exhaustion
- safe_for_auto_execute must be "False" for collect_triage, monitor_only, or any action without a precise target.
- For level-15 confirmed network flood with a clear source IP, block_ip is targeted and operationally safe.

RAG USAGE:
- Use KB_CONTEXT to improve the response recommendation.
- Set rag_context_used="True" only if KB_CONTEXT directly supports the selected action.
- If KB_CONTEXT is generic or unrelated, set rag_context_used="False".



Return exactly this JSON:
{{
  "recommended_action": "<one enum from ALLOWED_ACTIONS>",
  "summary": "<short response summary>",
  "confidence": "low/medium/high",
  "reasoning": "<brief evidence-based justification>",
  "manual_steps": ["<step1>", "<step2>"],
  "evidence_to_collect": ["<artifact1>", "<artifact2>"],
  "action_parameters": {{
    "ip": "<ip or empty>",
    "path": "<path or empty>",
    "user": "<user or empty>",
    "tty": "<tty or empty>",
    "service_name": "<service_name or empty>"
  }},
  "rag_context_used": "True/False",
  "safe_for_auto_execute": "True/False"
}}
""".strip()


def llama_response_plan(prompt):
    print(f"  [STEP 3] Sending Response Request to OLLAMA ({MODEL_NAME})...")

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": OLLAMA_OPTIONS,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=LLM_TIMEOUT)
        print("  [STEP 4] Response Received from Response LLM.")
        response_text = response.json().get("response", "")

        candidate = _extract_json_candidate(response_text)
        if candidate and candidate.strip().endswith("}"):
            return response_text

        print("  [RETRY] Incomplete JSON detected. Requesting compact repair...")

        repair_prompt = f"""
Repair this truncated JSON and return valid JSON only.
Do not add explanations.
Keep summary under 120 characters.
Keep reasoning under 180 characters.

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
        print(f"[ERROR] Response LLM Failed: {exc}")
        return ""


# =========================
# POLICY GATE
# =========================
def compute_policy(alert, plan, platform):
    source_level = int(alert.get("ai_rule", {}).get("level", 0) or 0)
    action = plan.get("recommended_action", "monitor_only")
    safe_for_auto = plan.get("safe_for_auto_execute", "False") == "True"

    auto_execute = False
    policy_reason = "Manual recommendation only."
    response_command = ""
    execution_mode = "manual"

    if (
        source_level >= AUTO_EXECUTE_MIN_LEVEL
        and action in AUTO_EXECUTE_ALLOWED.get(platform, set())
        and safe_for_auto
    ):
        auto_execute = True
        execution_mode = "auto"
        response_command = ACTION_TO_COMMAND.get(action, "")
        policy_reason = (
            f"Auto execution allowed: level>={AUTO_EXECUTE_MIN_LEVEL}, "
            f"platform={platform}, action={action}, safe_for_auto_execute=True."
        )
    else:
        reasons = []
        if source_level < AUTO_EXECUTE_MIN_LEVEL:
            reasons.append(f"level<{AUTO_EXECUTE_MIN_LEVEL}")
        if action not in AUTO_EXECUTE_ALLOWED.get(platform, set()):
            reasons.append("action_not_auto_allowed")
        if not safe_for_auto:
            reasons.append("safe_for_auto_execute=False")

        policy_reason = "Manual recommendation only: " + ", ".join(reasons)

    return {
        "auto_execute": auto_execute,
        "execution_mode": execution_mode,
        "policy_name": "level15_safe_action_gate",
        "policy_reason": policy_reason,
        "response_command": response_command,
    }


# =========================
# WAZUH OUTPUT
# =========================
def build_response_alert(source_alert, plan, policy):
    ai_agent = source_alert.get("ai_agent_info", {}) or {}
    ai_rule = source_alert.get("ai_rule", {}) or {}
    ai_eval = source_alert.get("ai_evaluation", {}) or {}

    source_level = int(ai_rule.get("level", 0) or 0)
    response_level = max(1, source_level)

    groups = ["ai_response", "rag_response", "recommended_action"]
    if policy["auto_execute"]:
        groups.append("auto_execute")

    target_agent_id = str(ai_agent.get("id", "000"))
    target_agent_name = str(ai_agent.get("name", "unknown"))
    target_platform = str(ai_agent.get("platform", "Unknown"))

    return {
        "response_id": RESPONSE_ID,
        "response_origin": RESPONSE_ORIGIN,
        "response_version": RESPONSE_VERSION,
        "response_rule": {
            "level": response_level,
            "description": (
                "AI response requires immediate execution"
                if policy["auto_execute"]
                else "AI response recommendation generated"
            ),
            "groups": groups,
        },
        "ai_agent_info": {
            "id": target_agent_id,
            "name": target_agent_name,
            "platform": target_platform,
        },
        "manager": {"name": "wazuh-manager"},
        "full_log": source_alert.get("full_log", ""),
        "source_ai_alert": {
            "level": source_level,
            "description": ai_rule.get("description", ""),
            "ai_analysis": ai_eval.get("ai_analysis", ""),
        },
        "target_endpoint": {
            "agent_id": target_agent_id,
            "agent_name": target_agent_name,
            "platform": target_platform,
        },
        "ai_response": {
            "recommended_action": plan["recommended_action"],
            "response_command": policy["response_command"],
            "auto_execute": "True" if policy["auto_execute"] else "False",
            "execution_mode": policy["execution_mode"],
            "policy_name": policy["policy_name"],
            "policy_reason": policy["policy_reason"],
            "summary": plan["summary"],
            "confidence": plan["confidence"],
            "reasoning": plan["reasoning"],
            "manual_steps": plan["manual_steps"],
            "evidence_to_collect": plan["evidence_to_collect"],
            "action_parameters": plan["action_parameters"],
            "rag_context_used": plan["rag_context_used"],
            "target_agent_id": target_agent_id,
            "target_agent_name": target_agent_name,
            "target_platform": target_platform,
        },
    }


def write_to_wazuh(alert_data):
    try:
        message = json_dumps_text(alert_data) + "\n"

        print(f"  [STEP 6] Opening TCP Socket to Wazuh ({WAZUH_SOCKET_HOST}:{WAZUH_SOCKET_PORT})...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((WAZUH_SOCKET_HOST, WAZUH_SOCKET_PORT))
        sock.sendall(message.encode("utf-8"))
        sock.close()

        level = alert_data.get("response_rule", {}).get("level", "N/A")
        target_id = alert_data.get("ai_response", {}).get("target_agent_id", "N/A")
        auto_execute = alert_data.get("ai_response", {}).get("auto_execute", "False")
        response_command = alert_data.get("ai_response", {}).get("response_command", "")

        print(
            f"[SUCCESS] Response alert injected into Wazuh "
            f"(Level {level}) | target_agent={target_id} | "
            f"auto_execute={auto_execute} | command={response_command or 'manual_only'}"
        )
        return True

    except ConnectionRefusedError:
        print("[ERROR] Wazuh is NOT listening on the socket. Check ossec.conf!")
        return False
    except Exception as exc:
        print(f"[ERROR] TCP Injection Failed: {exc}")
        return False


# =========================
# ALERT FILTERING
# =========================
def extract_detection_payload(alert):
    if not isinstance(alert, dict):
        return None

    candidates = []

    direct_data = alert.get("data", {})
    if isinstance(direct_data, dict):
        candidates.append(direct_data)

    source = alert.get("_source", {})
    if isinstance(source, dict):
        source_data = source.get("data", {})
        if isinstance(source_data, dict):
            candidates.append(source_data)

    candidates.append(alert)

    for item in candidates:
        if not isinstance(item, dict):
            continue

        if (
            item.get("ai_id") == DETECTION_AI_ID
            and isinstance(item.get("ai_rule"), dict)
            and isinstance(item.get("ai_agent_info"), dict)
            and item.get("response_id") != RESPONSE_ID
            and "ai_response" not in item
        ):
            return item

    return None


def build_alert_signature(alert):
    ai_agent = alert.get("ai_agent_info", {}) or {}
    ai_rule = alert.get("ai_rule", {}) or {}

    base = (
        f"{ai_agent.get('id', '000')}|"
        f"{ai_agent.get('platform', 'unknown')}|"
        f"{ai_rule.get('level', 0)}|"
        f"{ai_rule.get('description', '')}|"
        f"{alert.get('full_log', '')}"
    )
    return md5_text(base)


# =========================
# MAIN PROCESSING
# =========================
def process_response_alert(source_alert, embedder):
    ai_agent = source_alert.get("ai_agent_info", {}) or {}
    ai_rule = source_alert.get("ai_rule", {}) or {}
    full_log = source_alert.get("full_log", "")

    platform = normalize_platform(ai_agent.get("platform", "Unknown"))

    event_context = source_alert.get("ai_event_context", {}) or {}
    iocs = extract_iocs(full_log)

    if event_context.get("source_ip") and event_context.get("source_ip") != "No_IP":
        iocs["ip"] = event_context.get("source_ip")

    if event_context.get("username") and event_context.get("username") != "No_User":
        iocs["user"] = event_context.get("username")

    if event_context.get("path") and event_context.get("path") != "No_Path":
        iocs["linux_path"] = event_context.get("path")

    print(
        f"\n[AI RESPONSE] Agent={ai_agent.get('name', 'unknown')} "
        f"| TargetID={ai_agent.get('id', '000')} "
        f"| Platform={ai_agent.get('platform', 'Unknown')} "
        f"| SourceLevel={ai_rule.get('level', 0)}"
    )
    print(f"  [SOURCE LOG] {full_log}")

    try:
        query_text = "\n".join([
            str(ai_rule.get("description", "")),
            str(source_alert.get("ai_evaluation", {}).get("ai_analysis", "")),
            full_log,
            f"platform: {platform}",
        ]).strip()

        print("  [STEP 1] Generating Embedding...")
        vector = get_embedding(query_text, embedder)

        print("  [STEP 2] Querying Response Vector DB (RAG)...")
        kb_context = qdrant_response_search(vector, platform)
        print(f"  [RAG RESULT] Found Response Context:\n{kb_context}")

        prompt = build_response_prompt(
            alert=source_alert,
            kb_context=kb_context,
            platform=platform,
            iocs=iocs,
        )

        raw_response = llama_response_plan(prompt)
        print(f"  [LLM RESPONSE PLAN]\n{raw_response}\n")

        plan = None
        candidate = _extract_json_candidate(raw_response)
        if candidate:
            try:
                plan = sanitize_plan(json_loads(candidate), platform, iocs)
            except Exception as exc:
                print(f"  [WARN] Invalid response JSON after extraction: {exc}")
                plan = sanitize_plan(default_response_plan(platform, iocs), platform, iocs)
        else:
            print("  [WARN] Invalid response JSON. Using fallback response plan.")
            plan = sanitize_plan(default_response_plan(platform, iocs), platform, iocs)

        policy = compute_policy(source_alert, plan, platform)
        response_alert = build_response_alert(source_alert, plan, policy)

        print(
            f"  [DECISION] action={plan['recommended_action']} | "
            f"auto_execute={response_alert['ai_response']['auto_execute']} | "
            f"command={response_alert['ai_response']['response_command'] or 'manual_only'}"
        )

        write_to_wazuh(response_alert)

    except Exception as exc:
        print(f"[ERROR] Response processing failed: {exc}")

def raw_line_has_detection_ai_id(raw):
    if DETECTION_AI_ID not in raw:
        return False

    patterns = [
        # Normal decoded Wazuh alert:
        # "data":{"ai_id":"000_ai", ...}
        r'"data"\s*:\s*\{\s*"ai_id"\s*:\s*"' + re.escape(DETECTION_AI_ID) + r'"',

        # AI detection JSON stored inside full_log:
        # "full_log":"{\"ai_id\":\"000_ai\", ...}"
        r'"full_log"\s*:\s*"\{\\"ai_id\\"\s*:\s*\\"' + re.escape(DETECTION_AI_ID) + r'\\"',
    ]

    return any(re.search(pattern, raw) for pattern in patterns)


def parse_ai_detection_line(line):
    raw = (line or "").strip()

    if not raw:
        return None

  
    if not raw_line_has_detection_ai_id(raw):
        return None

    if not raw.startswith("{"):
        print(f"[SKIP] AI marker found but line is not JSON | len={len(raw)} | head={raw[:160]}")
        return None

    try:
        alert = json_loads(raw)
    except Exception as exc:
        print(
            f"[SKIP] AI detection candidate but JSON parse failed | "
            f"len={len(raw)} | error={exc} | head={raw[:200]}"
        )
        return None

    payload = extract_detection_payload(alert)
    if not payload:
        print(
            f"[SKIP] ai_id={DETECTION_AI_ID} marker found, "
            f"but this is not a valid detection payload | "
            f"alert_id={alert.get('id', 'N/A')}"
        )
        return None

    return payload
    
# =========================
# MAIN
# =========================
def main():
    print("[INIT] Loading Response Models...")
    embedder = SentenceTransformer(EMBED_MODEL_PATH)
    cache = TTLCache(ttl=CACHE_TTL)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS)

    print(f"[RUNNING] Monitoring {WAZUH_ALERTS}...")
    print(f"[RUNNING] MAX_THREADS={MAX_THREADS} | MODEL={MODEL_NAME}")
    print(f"[RUNNING] RESPONSE_COLLECTION={COLLECTION}")

    try:
        for line in follow(WAZUH_ALERTS):
            try:
                payload = parse_ai_detection_line(line)
                if not payload:
                    continue

                signature = build_alert_signature(payload)
                if cache.seen(signature):
                    print("[SKIP] Duplicate AI detection alert already handled by response stage.")
                    continue

                print(
                    "[DEBUG] AI detection alert accepted for response planning | "
                    f"target_agent={payload.get('ai_agent_info', {}).get('id', 'N/A')} | "
                    f"target_name={payload.get('ai_agent_info', {}).get('name', 'N/A')} | "
                    f"platform={payload.get('ai_agent_info', {}).get('platform', 'N/A')}"
                )

                executor.submit(process_response_alert, payload, embedder)

            except Exception as exc:
                print(f"[ERROR] Main Loop: {exc}")

    except KeyboardInterrupt:
        print("\n[STOP] Keyboard interrupt received. Shutting down gracefully...")

    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        print("[STOP] AI Response Sentinel stopped.")


if __name__ == "__main__":
    main()
