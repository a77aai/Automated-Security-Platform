#!/usr/bin/env python3
import os
import re
import json
import pandas as pd
from collections import defaultdict

SRC_DIR = "/home/i77/AS-Platform/attack_xlsx"
OUT_JSONL = "/home/i77/AS-Platform/attack_cards.jsonl"

TECHNIQUES_XLSX = os.path.join(SRC_DIR, "enterprise-attack-v18.1-techniques.xlsx")
DATACOMPONENTS_XLSX = os.path.join(SRC_DIR, "enterprise-attack-v18.1-datacomponents.xlsx")
DETECTIONSTRATEGIES_XLSX = os.path.join(SRC_DIR, "enterprise-attack-v18.1-detectionstrategies.xlsx")
ANALYTIC_LOGSOURCES_XLSX = os.path.join(SRC_DIR, "enterprise-attack-v18.1-detectionstrategy-analytic-logsources.xlsx")


def norm(s):
    return re.sub(r"\s+", " ", str(s).strip().lower())


def clean_text(s):
    try:
        if pd.isna(s):
            return ""
    except Exception:
        pass
    s = str(s).strip()
    s = re.sub(r"\s+", " ", s)
    return s


def split_listish(s):
    s = clean_text(s)
    if not s:
        return []
    parts = re.split(r"[;\n,|]+", s)
    return [p.strip() for p in parts if p.strip()]


def infer_event_families(text):
    t = text.lower()
    fam = set()

    if re.search(r'auth|login|logon|credential|password|pam|sudo|sshd|kerberos|mfa|su\b', t):
        fam.add("auth")
    if re.search(r'http|web|browser|uri|url|apache|nginx|iis|php|tomcat|public-facing|upload\.php|web shell', t):
        fam.add("web")
    if re.search(r'process|command|shell|powershell|bash|cmd|execution|script|execve', t):
        fam.add("process")
    if re.search(r'file|registry|plist|document|write|modify|rename|create|path|/var/www/', t):
        fam.add("file")
    if re.search(r'network|dns|port|connection|packet|firewall|proxy|c2|beacon|socket', t):
        fam.add("network")
    if re.search(r'denied|blocked|forbidden|reject|drop|policy|apparmor', t):
        fam.add("policy_denied")
    if re.search(r'error|exception|crash|timeout|segfault', t):
        fam.add("system_error")

    return sorted(fam) if fam else ["other"]


def infer_platforms_from_text(text):
    t = text.lower()
    plats = set()

    if re.search(r'linux|auditd|linux:syslog|linux:auth|sudo|pam_unix|sshd|syscall|apparmor|snap', t):
        plats.add("Linux")
    if re.search(r'windows|wineventlog|sysmon|eventcode', t):
        plats.add("Windows")
    if re.search(r'macos|unifiedlog', t):
        plats.add("macOS")
    if re.search(r'kubernetes|container|containerd', t):
        plats.add("Containers")
    if re.search(r'aws|azure|gcp|cloud', t):
        plats.add("Cloud")
    if re.search(r'networkdevice|nsm|firewall|zeek|suricata', t):
        plats.add("Network")

    return sorted(plats) if plats else ["Unknown"]


def infer_tags(text, attack_id="", name="", doc_type=""):
    t = f"{attack_id} {name} {text}".lower()
    tags = set()

    if "linux" in t or "auditd" in t or "pam_unix" in t or "sudo" in t or "sshd" in t or "apparmor" in t:
        tags.add("linux")

    if re.search(r'auth|authentication|login|logon|password|credential|pam|sshd|sudo|su\b', t):
        tags.add("auth")
        tags.add("linux_auth" if "linux" in t or "pam_unix" in t or "sudo" in t or "sshd" in t else "general_auth")

    if re.search(r'sudo|su\b|privilege escalation|elevate|root', t):
        tags.add("sudo_su")
        tags.add("privilege_escalation")

    if re.search(r'local interactive|tty|pts/|sudo:auth|su:session', t):
        tags.add("local_auth")

    if re.search(r'web shell|upload\.php|public-facing|web server|server software component', t):
        tags.add("webshell")

    if re.search(r'apparmor|snap\.', t):
        tags.add("apparmor_policy")

    if re.search(r'file creation|file modification|open, write|/var/www/|php|shell script', t):
        tags.add("file_activity")

    if re.search(r'process creation|command execution|execve|powershell|bash|cmd', t):
        tags.add("process_activity")

    if re.search(r'network connection|c2|beacon|socket|dns|proxy', t):
        tags.add("network_activity")

    if doc_type == "technique":
        tags.add("attack_technique")
    elif doc_type == "data_component":
        tags.add("telemetry")
    elif doc_type == "detection_strategy":
        tags.add("detection_logic")

    return sorted(tags)


def load_sheet(path, sheet_name):
    df = pd.read_excel(path, sheet_name=sheet_name)
    df.columns = [norm(c) for c in df.columns]
    return df


def finalize_card(doc_type, attack_id, name, platforms, tactics, source_file, sheet_name, text):
    event_families = infer_event_families(text)
    inferred_platforms = platforms if platforms else infer_platforms_from_text(text)
    tags = infer_tags(text, attack_id=attack_id, name=name, doc_type=doc_type)

    tag_text = ""
    if tags:
        tag_text = " Tags: " + ", ".join(tags) + "."

    return {
        "doc_type": doc_type,
        "attack_id": attack_id,
        "name": name,
        "platforms": inferred_platforms if inferred_platforms else ["Unknown"],
        "tactics": tactics if tactics else [],
        "event_families": event_families,
        "tags": tags,
        "source_file": source_file,
        "sheet_name": sheet_name,
        "text": f"{text}{tag_text}"
    }


def build_technique_cards():
    cards = []

    main_df = load_sheet(TECHNIQUES_XLSX, "techniques")
    proc_df = load_sheet(TECHNIQUES_XLSX, "procedure examples")
    assoc_det_df = load_sheet(TECHNIQUES_XLSX, "associated detection strategies")

    procedure_map = defaultdict(list)
    for _, row in proc_df.iterrows():
        row = row.to_dict()
        technique_id = clean_text(row.get("target id"))
        desc = clean_text(row.get("mapping description"))
        if technique_id and desc and desc not in procedure_map[technique_id]:
            if len(procedure_map[technique_id]) < 3:
                procedure_map[technique_id].append(desc)

    assoc_detection_map = defaultdict(list)
    for _, row in assoc_det_df.iterrows():
        row = row.to_dict()
        technique_id = clean_text(row.get("target id"))
        det_id = clean_text(row.get("source id"))
        det_name = clean_text(row.get("source name"))
        if technique_id and det_name:
            val = f"{det_id} {det_name}".strip()
            if val not in assoc_detection_map[technique_id]:
                if len(assoc_detection_map[technique_id]) < 5:
                    assoc_detection_map[technique_id].append(val)

    for _, row in main_df.iterrows():
        row = row.to_dict()

        attack_id = clean_text(row.get("id"))
        name = clean_text(row.get("name"))
        desc = clean_text(row.get("description"))
        platforms = split_listish(row.get("platforms"))
        tactics = split_listish(row.get("tactics"))
        detection = clean_text(row.get("detection"))

        if not attack_id or not name or not desc:
            continue

        text = (
            f"Technique {attack_id} - {name}. "
            f"Platforms: {', '.join(platforms) if platforms else 'Unknown'}. "
            f"Tactics: {', '.join(tactics) if tactics else 'Unknown'}. "
            f"Description: {desc}. "
        )

        if detection:
            text += f"Detection notes: {detection}. "

        if assoc_detection_map.get(attack_id):
            text += (
                "Associated detection strategies: "
                + "; ".join(assoc_detection_map[attack_id])
                + ". "
            )

        if procedure_map.get(attack_id):
            text += (
                "Procedure examples: "
                + " ".join(procedure_map[attack_id])
                + ". "
            )

        cards.append(
            finalize_card(
                doc_type="technique",
                attack_id=attack_id,
                name=name,
                platforms=platforms if platforms else ["Unknown"],
                tactics=tactics if tactics else ["Unknown"],
                source_file=os.path.basename(TECHNIQUES_XLSX),
                sheet_name="techniques",
                text=text
            )
        )

    return cards


def build_data_component_cards():
    cards = []

    df = load_sheet(DATACOMPONENTS_XLSX, "datacomponents")

    for _, row in df.iterrows():
        row = row.to_dict()

        dc_id = clean_text(row.get("id"))
        name = clean_text(row.get("name"))
        desc = clean_text(row.get("description"))
        domain = clean_text(row.get("domain"))

        if not dc_id or not name or not desc:
            continue

        text = (
            f"Data Component {dc_id} - {name}. "
            f"Domain: {domain or 'enterprise-attack'}. "
            f"Description: {desc}."
        )

        cards.append(
            finalize_card(
                doc_type="data_component",
                attack_id=dc_id,
                name=name,
                platforms=infer_platforms_from_text(text),
                tactics=[],
                source_file=os.path.basename(DATACOMPONENTS_XLSX),
                sheet_name="datacomponents",
                text=text
            )
        )

    return cards


def build_detection_strategy_cards():
    cards = []

    ds_main = load_sheet(DETECTIONSTRATEGIES_XLSX, "detectionstrategies")
    ds_analytic = load_sheet(DETECTIONSTRATEGIES_XLSX, "detectionstrategies-analytic")

    det_to_analytics = defaultdict(list)

    for _, row in ds_analytic.iterrows():
        row = row.to_dict()
        det_stix_id = clean_text(row.get("detection_strategy_id"))
        analytic_id = clean_text(row.get("analytic_id"))
        analytic_name = clean_text(row.get("analytic_name"))

        if det_stix_id and analytic_id:
            pair = (analytic_id, analytic_name)
            if pair not in det_to_analytics[det_stix_id]:
                det_to_analytics[det_stix_id].append(pair)

    d2a_df = load_sheet(ANALYTIC_LOGSOURCES_XLSX, "detectionstrategy_to_analytics")
    a2l_df = load_sheet(ANALYTIC_LOGSOURCES_XLSX, "analytics_to_logsources")

    for _, row in d2a_df.iterrows():
        row = row.to_dict()
        det_stix_id = clean_text(row.get("detection_strategy_id"))
        analytic_id = clean_text(row.get("analytic_id"))
        analytic_name = clean_text(row.get("analytic_name"))

        if det_stix_id and analytic_id:
            pair = (analytic_id, analytic_name)
            if pair not in det_to_analytics[det_stix_id]:
                det_to_analytics[det_stix_id].append(pair)

    analytic_to_logsources = defaultdict(list)
    for _, row in a2l_df.iterrows():
        row = row.to_dict()
        analytic_id = clean_text(row.get("analytic_id"))
        data_component_name = clean_text(row.get("data_component_name"))
        log_source_name = clean_text(row.get("log_source_name"))
        channel = clean_text(row.get("channel"))

        if analytic_id:
            val = (data_component_name, log_source_name, channel)
            if val not in analytic_to_logsources[analytic_id]:
                analytic_to_logsources[analytic_id].append(val)

    for _, row in ds_main.iterrows():
        row = row.to_dict()

        det_id = clean_text(row.get("id"))
        det_stix_id = clean_text(row.get("stix id"))
        name = clean_text(row.get("name"))
        domain = clean_text(row.get("domain"))

        if not det_id or not name:
            continue

        analytics = []
        for key in [det_stix_id, det_id]:
            if key in det_to_analytics:
                analytics.extend(det_to_analytics[key])

        unique_analytics = []
        seen_analytics = set()
        for analytic_id, analytic_name in analytics:
            if analytic_id not in seen_analytics:
                seen_analytics.add(analytic_id)
                unique_analytics.append((analytic_id, analytic_name))

        logsource_items = []
        seen_logs = set()
        for analytic_id, analytic_name in unique_analytics[:8]:
            for item in analytic_to_logsources.get(analytic_id, [])[:4]:
                if item not in seen_logs:
                    seen_logs.add(item)
                    logsource_items.append(item)

        text = (
            f"Detection Strategy {det_id} - {name}. "
            f"Domain: {domain or 'enterprise-attack'}. "
        )

        if unique_analytics:
            text += (
                "Related analytics: "
                + ", ".join([an_name if an_name else an_id for an_id, an_name in unique_analytics[:8]])
                + ". "
            )

        if logsource_items:
            formatted = []
            for dc_name, log_source_name, channel in logsource_items[:12]:
                part = dc_name if dc_name else "Unknown Data Component"
                if log_source_name:
                    part += f" via {log_source_name}"
                if channel:
                    part += f" channel {channel}"
                formatted.append(part)

            text += "Relevant log sources: " + "; ".join(formatted) + "."

        cards.append(
            finalize_card(
                doc_type="detection_strategy",
                attack_id=det_id,
                name=name,
                platforms=infer_platforms_from_text(text),
                tactics=[],
                source_file=os.path.basename(DETECTIONSTRATEGIES_XLSX),
                sheet_name="detectionstrategies",
                text=text
            )
        )

    return cards


def main():
    cards = []

    if os.path.exists(TECHNIQUES_XLSX):
        cards.extend(build_technique_cards())

    if os.path.exists(DATACOMPONENTS_XLSX):
        cards.extend(build_data_component_cards())

    if os.path.exists(DETECTIONSTRATEGIES_XLSX) and os.path.exists(ANALYTIC_LOGSOURCES_XLSX):
        cards.extend(build_detection_strategy_cards())

    clean_cards = []
    seen = set()

    for c in cards:
        key = (
            c["doc_type"],
            c["attack_id"],
            c["name"],
            c["text"]
        )
        if key in seen:
            continue
        seen.add(key)
        clean_cards.append(c)

    with open(OUT_JSONL, "w", encoding="utf-8") as f:
        for c in clean_cards:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"[+] Wrote {len(clean_cards)} cards to {OUT_JSONL}")

    counts = defaultdict(int)
    for c in clean_cards:
        counts[c["doc_type"]] += 1

    print("[+] Breakdown:")
    for k, v in counts.items():
        print(f"    - {k}: {v}")


if __name__ == "__main__":
    main()