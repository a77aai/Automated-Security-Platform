#!/usr/bin/env python3
import os
import json
import time
import hashlib
import requests
import socket
from sentence_transformers import SentenceTransformer

# =========================
# CONFIGURATION
# =========================
WAZUH_ARCHIVES = "/var/ossec/logs/archives/archives.json"
AI_ALERTS_OUTPUT = "/var/ossec/logs/alerts/ai_alerts.json"

# Settings
EMBED_MODEL_PATH = "/home/i77/AS-Platform/models/bge-small-en-v1.5"
QDRANT_URL = "http://localhost:6333"
COLLECTION = "RAG_knowledge"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:latest"

CACHE_TTL = 300

# =========================
# UTILS & CLASSES
# =========================

class AlertCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl

    def is_cached(self, signature):
        current_time = time.time()
        self.cache = {k: v for k, v in self.cache.items() if current_time - v < self.ttl}
        if signature in self.cache:
            return True
        self.cache[signature] = current_time
        return False


# =========================
# CORE FUNCTIONS
# =========================

def get_embedding(text, embedder):
    try:
        return embedder.encode(text).tolist()
    except Exception:
        return []

def qdrant_search(vector):
    url = f"{QDRANT_URL}/collections/{COLLECTION}/points/search"
    payload = {"vector": vector, "limit": 4, "with_payload": True}
    try:
        r = requests.post(url, json=payload, timeout=2)
        if r.status_code == 200:
            results = r.json().get("result", [])
            context = "\n".join([f"- {item['payload'].get('text', '')}" for item in results])
            return context
    except:
        pass
    return "No specific playbook found."

def llama_analysis(prompt):
    print(f"  [STEP 3] Sending Request to OLLAMA ({MODEL_NAME})...")
    payload = {"model": MODEL_NAME, "prompt": prompt, "format": "json", "stream": False}
    try:
        res = requests.post(OLLAMA_URL, json=payload, timeout=1000)
        print("  [STEP 4] Response Received from LLM.")
        return res.json().get("response", "")
    except Exception as e:
        print(f"[ERROR] LLM Failed: {e}")
        return ""

def write_to_wazuh(alert_data):
    try:
        message = json.dumps(alert_data) + "\n"
        
        print("  [STEP 6] Opening TCP Socket to Wazuh (127.0.0.1:5555)...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2) 
        
        sock.connect(("127.0.0.1", 5555))
        
        sock.sendall(message.encode('utf-8'))
        
        sock.close()
        
        level = alert_data.get('ai_rule', {}).get('level', 'N/A')
        print(f"[SUCCESS] Alert injected into Wazuh Dashboard via TCP (Level {level})")
        
    except ConnectionRefusedError:
        print("[ERROR] Wazuh is NOT listening on port 5555. Check ossec.conf!")
    except Exception as e:
        print(f"[ERROR] TCP Injection Failed: {e}")

# =========================
# MAIN LOGIC
# =========================

def process_event(log_entry, embedder):
    full_log = log_entry.get("full_log", "")

    original_agent_id = log_entry.get("agent", {}).get("id", "000")
    agent_name = log_entry.get("agent", {}).get("name", "unknown")
    
    wazuh_rule = log_entry.get("rule", {})
    mode = "VALIDATION" if wazuh_rule.get("level", 0) >= 10 else "HUNTING"
    
    print(f"\n[AI ANALYZING] Mode: {mode} | Agent: {agent_name} | Event: Single Log Analysis")
    print(f"  [RAW LOG] {full_log}") 

    # 1. RAG Search
    print("  [STEP 1] Generating Embedding...")
    vector = get_embedding(full_log, embedder)
    print("  [STEP 2] Querying Vector DB (RAG)...")
    context = qdrant_search(vector)
    
    print(f"  [RAG RESULT] Found Context:\n{context}") 
    # ---------------------------------------

    # 2. Prompt Engineering
    prompt = f"""
    You are a Tier-3 SOC Analyst.
    Task: Analyze this log entry.
    
    MODE: {mode} (If VALIDATION: Check for False Positive. If HUNTING: Check for missed attacks).
    ANALYSIS TYPE: Single Log Inspection
    
    LOG: {full_log}
    CONTEXT from KNOWLEDGE BASE: {context}
    
   ABSOLUTE RULES (NO EXCEPTIONS):
   1) No hallucination: If the LOG lacks direct evidence of compromise/attack, do NOT invent malware/actors/tools.
   2) Context validation: If CONTEXT is unrelated (e.g., LOG=AppArmor deny, CONTEXT=APT malware), set rag_context_used="False" and ignore CONTEXT.
   3) Use conservative severity: When uncertain, choose the LOWER reasonable level and mark confidence < 0.6 with "needs_more_data".
   4) Always include ai_evaluation field in output JSON. Output must be COMPLETE valid JSON (no truncation, no markdown, no extra text).

    SEVERITY LEVEL GUIDE (1–15) — Choose ONE final level:
   - Level 1–2 (Informational/Benign):
    * Normal service start/stop, routine cron, successful logins, expected configuration messages, harmless scans blocked with no impact.
   - Level 3–4 (Suspicious but low risk):
    * Single suspicious event with weak evidence: odd user-agent, one failed login, one blocked request, minor anomaly.
   - Level 5–6 (Policy Violation / Low-confidence security event):
    * AppArmor/SELinux DENIED, permission denied, blocked action, single firewall drop.
    * Non-malicious by itself unless repeated + targeting sensitive assets.
   - Level 7–8 (Confirmed suspicious activity / Recon / Brute attempts without success):
    * Multiple failed logins from same src, password spraying signs, enumeration attempts, port scans with persistence,
    repeated probing of admin panels, directory traversal attempts blocked.
   - Level 9 (Strong attack attempt or partial compromise indicators):
    * Exploit attempt patterns (SQLi/XSS/RFI/LFI) with clear payloads, repeated across endpoints,
    suspicious file writes to temp, suspicious process spawn, persistence attempts blocked.
   - Level 10 (High risk — likely compromise attempt / successful foothold indicators):
    * Webshell indicators, command injection strings, suspicious file upload execution attempts,
    reverse shell patterns, suspicious parent-child process relations (e.g., webserver -> shell),
    privilege escalation attempts observed.
   - Level 11–12-13 (Very high — strong evidence of compromise / lateral movement / credential theft):
    * Successful brute force (login success after many fails),
    new admin user created, ssh key added, suspicious scheduled task/service created,
    credential dumping indicators, lateral movement tools/commands,
    data staging/compression for exfil (tar/zip + unusual outbound).
   - Level 14-15 (Critical — confirmed breach / destructive or large-impact event):
   * Confirmed RCE with execution, ransomware behavior, mass file encryption,
    critical service disruption, DDoS causing outage, confirmed data exfiltration,
    root/admin compromise with persistence + active attacker control.
 
   MAPPING HINTS (choose based on evidence in LOG):
   - If LOG clearly contains "RCE", "web shell", "cmd=", "bash -i", "powershell -enc", "nc -e", "curl|sh", "wget|sh"
     OR shows webserver spawning shell => Level MUST be 11–14.
   - If LOG is only "DENIED" permission (AppArmor) with no exploit/payload indicators => Level 5–7.
   - If repeated failed authentication attempts (>= 10 in short window) => Level 7–9.
   - If there is success after fails (or account lockouts, new session from same src) => Level 10–13.
   - If repeated high-volume network requests suggesting DDoS and service impact => Level 12–15 depending on impact evidence.

    
    Output strictly VALID JSON matching the structure below.
    IMPORTANT: Use keys "ai_rule" and "ai_agent_info" exactly as shown.
    
    Required JSON Structure:
    {{
      "ai_id": "000_ai",
      
      "ai_rule": {{
        "level": <int 1-15>,
        "description": "<Concise Summary of AI Finding>",
        "groups": ["ai_analyzed", "rag_detection"]
      }},
      
      "ai_agent_info": {{
        "id": "{original_agent_id}",
        "name": "{agent_name}"
      }},
      
      "manager": {{ "name": "wazuh-manager" }},
      "full_log": "{full_log}",
      
      "ai_evaluation": {{
        "ai_analysis": "<Your detailed reasoning here>",
        "rag_context_used": "True/False"
      }}
    }}
    """

    # 3. Get Analysis
    response = llama_analysis(prompt)
    
    print(f"  [LLM RESPONSE] \n{response}\n")
    # ------------------------------------------
    
    try:
        print("  [STEP 5] Parsing JSON Output...")

        start_idx = response.find('{')
        end_idx = response.rfind('}') + 1 

        if start_idx != -1 and end_idx != -1:
            clean_json_str = response[start_idx:end_idx]
            final_json = json.loads(clean_json_str)
        else:
            raise ValueError("No JSON braces found in LLM response")
        
        final_json["ai_id"] = "000_ai"
        
        level = final_json.get('ai_rule', {}).get('level', 0)
        
        if level >= 5:
            write_to_wazuh(final_json)
        else:
            print(f"  [INFO] AI dismissed event (Level {level}) - Not Sending to Wazuh.")
            
    except Exception as e:
        print(f"[ERROR] JSON Parsing failed: {e}")

# =========================
# FILE FOLLOWER
# =========================
def follow(file_path):
    if os.path.exists(file_path):
        f = open(file_path, "r")
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line
    else:
        print(f"[FATAL] File not found: {file_path}")
        exit(1)

# =========================
# MAIN EXECUTION
# =========================
def main():
    print("[INIT] Loading AI Models (This may take a moment)...")
    embedder = SentenceTransformer(EMBED_MODEL_PATH)
    cache = AlertCache(ttl=CACHE_TTL)
    
    print(f"[RUNNING] Monitoring {WAZUH_ARCHIVES}...")
    
    suspicious_keywords = ["failed", "error", "denied", "sudo", "root", "attack", "malware", "critical", "shell", "php", "cmd", "execution"]
    
    infrastructure_noise = ["wazuh", "ossec", "ollama", "opensearch", "indexer", "filebeat", "elasticsearch", "kibana"]

    for line in follow(WAZUH_ARCHIVES):
        try:
            log_entry = json.loads(line)
            full_log_str = log_entry.get("full_log", "").lower()

            if "ai_id" in log_entry or \
               log_entry.get("data", {}).get("ai_id") == "000_ai" or \
               "000_ai" in full_log_str:
                continue

            if any(noise in full_log_str for noise in infrastructure_noise):
                continue
            
            agent_id = log_entry.get("agent", {}).get("id", "000")
            wazuh_level = log_entry.get("rule", {}).get("level", 0)
            
            should_analyze = False
            trigger_reason = ""
            
            if wazuh_level >= 10:
                should_analyze = True
                trigger_reason = f"High Level Rule ({wazuh_level})"
                
            elif any(k in full_log_str for k in suspicious_keywords):
                should_analyze = True
                trigger_reason = "Suspicious Keyword Match"
            else :
                should_analyze = True
                trigger_reason = "Suspicious Log"

            # 4. Execution
            if should_analyze:
                log_hash = hashlib.md5((agent_id + full_log_str[:50]).encode()).hexdigest()
                
                if not cache.is_cached(log_hash):
                    print(f"[DEBUG] Log Picked for Analysis! Reason: {trigger_reason}")
                    process_event(log_entry, embedder)
                else:
                    print(f"[SKIP] Duplicate Log (Cached): {full_log_str[:50]}...")
            
           

        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"[ERROR] Main Loop: {e}")

if __name__ == "__main__":
    main()