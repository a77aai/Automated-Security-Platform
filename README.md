# Automated Security Platform (Wazuh + AI RAG + Active Response)

![Project](https://img.shields.io/badge/Project-Automated%20Security%20Platform-blue)
![Wazuh](https://img.shields.io/badge/Wazuh-4.14.0-005571)
![Python](https://img.shields.io/badge/Python-3.10%2B-yellow)
![Qdrant](https://img.shields.io/badge/Vector%20DB-Qdrant-green)
![LLM](https://img.shields.io/badge/LLM-Llama%203.2-purple)

## 📌 Overview

This project is an **Automated Security Platform** that extends the capabilities of **Wazuh SIEM/XDR** by integrating **Retrieval-Augmented Generation (RAG)**, **Large Language Models (LLMs)**, **Qdrant Vector Database**, and **Wazuh Active Response**.

The platform is designed to support Security Operations Center (SOC) workflows by improving alert analysis, reducing false positives, generating contextual security explanations, recommending response actions, and executing selected actions under controlled safety conditions.

Unlike cloud-based AI security solutions, this platform is designed to operate locally using **Ollama**, **Llama 3.2**, and **Qdrant**, which helps preserve log privacy and keeps security data inside the local environment.

---

## 🚀 Key Features

- **Wazuh SIEM/XDR Integration**  
  Monitors Wazuh raw logs and alerts, then enriches selected events with AI-based contextual analysis.

- **Two-Stage RAG Pipeline**  
  Separates the AI workflow into:
  - **RAG Detection**: analyzes raw logs and high-severity alerts.
  - **RAG Response**: generates response plans based on AI detection output.

- **Vector-Based Knowledge Retrieval**  
  Uses **Qdrant** to retrieve relevant cybersecurity knowledge for both detection and response.

- **Local LLM Processing**  
  Uses **Llama 3.2 via Ollama** for private, local, and contextual incident analysis.

- **AI Alert Injection into Wazuh**  
  AI-generated detection alerts are injected back into Wazuh using TCP port `5555` and identified by:

  ```text
  ai_id = 000_ai
  ```

- **AI Response Planning**  
  Response alerts are generated and injected back into Wazuh using:

  ```text
  response_id = 000_response_ai
  ```

- **Controlled Active Response**  
  Supports automatic or manual response execution through a policy gate.

- **Supported Response Actions**
  - Block IP
  - Kill Process
  - Quarantine File
  - Disable User
  - Isolate Host

- **Rollback Support**  
  Provides rollback capability for supported response actions such as IP blocking, file quarantine, user disabling, and host isolation.

- **Floating AI Assistant for Wazuh Dashboard**  
  Includes a custom OpenSearch Dashboards plugin named `wazuh_ai_assistant` that adds an interactive floating AI assistant to the Wazuh Dashboard.

---

## 🧠 System Architecture

The platform follows this workflow:

```text
Attacker Machine
      ↓
Windows / Ubuntu Endpoint with Wazuh Agent
      ↓
Wazuh Manager
      ↓
RAG Detection
      ↓
AI Detection Alert injected into Wazuh
      ↓
RAG Response
      ↓
Policy Gate
      ↓
Manual Recommendation OR Active Response Execution
      ↓
Action Ledger + Rollback Tracking
```

### Main Components

| Component | Role |
| :--- | :--- |
| **Wazuh Manager** | Collects logs, applies rules, receives AI-generated alerts, and triggers Active Response. |
| **Wazuh Agents** | Installed on Windows and Ubuntu endpoints to collect endpoint security events. |
| **Qdrant** | Stores vectorized detection and response knowledge collections. |
| **BAAI-bge-small-en-v1.5** | Converts logs and knowledge documents into vector embeddings. |
| **Ollama / Llama 3.2** | Performs contextual reasoning for detection and response planning. |
| **RAG Detection** | Validates high-severity alerts and analyzes suspicious raw logs. |
| **RAG Response** | Generates response recommendations and controlled remediation plans. |
| **Active Response Dispatcher** | Translates AI response decisions into platform-specific actions. |
| **Action Ledger** | Tracks planned, executed, failed, and rollback actions. |
| **Floating AI Assistant** | Provides analyst interaction inside the Wazuh Dashboard. |

---

## 📁 Project Structure

```text
platform/
├── active-response/
│   ├── Linux/
│   │   ├── ai-block-ip.py
│   │   ├── ai-disable-user.py
│   │   ├── ai-isolate-host.py
│   │   ├── ai-kill-process.py
│   │   └── ai-quarantine-file.py
│   └── Windows/
│       ├── ai-block-ip.py
│       ├── ai-disable-user.py
│       ├── ai-isolate-host.py
│       ├── ai-kill-process.py
│       └── ai-quarantine-file.py
│
├── services/
│   ├── ai_rag_sentinel.py
│   ├── ai_rag_response.py
│   ├── ai_response_dispatcher.py
│   ├── ai_action_ledger.py
│   ├── ai_control_api.py
│   ├── chunk_and_prepare.py
│   ├── build_response_knowledge.py
│   └── embed_and_upsert.py
│
├── wazuh_ai_assistant/
│   ├── public/
│   ├── server/
│   ├── package.json
│   └── opensearch_dashboards.json
│
├── linux-ar/
│   └── agent.conf
│
├── windows-ar/
│   └── agent.conf
│
├── custom-rules.xml
├── ossec.conf
├── ai-rag-detection.service
├── ai-rag-response.service
├── ai-control-api.service
└── ai-response-dispatcher.env
```

---

## 📄 Main Files

| File | Description |
| :--- | :--- |
| `services/ai_rag_sentinel.py` | RAG Detection engine. Monitors Wazuh `archives.json`, selects suspicious logs, retrieves detection context from Qdrant, queries the LLM, and injects AI detection alerts back into Wazuh. |
| `services/ai_rag_response.py` | RAG Response engine. Monitors AI detection alerts, retrieves response knowledge, generates response plans, applies policy checks, and injects response alerts into Wazuh. |
| `services/ai_response_dispatcher.py` | Executes approved response actions through Wazuh Active Response and writes execution results to the action journal. |
| `services/ai_action_ledger.py` | Tracks response lifecycle states such as planned, executed, failed, rolled back, and rollback failed. |
| `services/ai_control_api.py` | Flask API used by the floating assistant to display actions, execute manual responses, perform rollback, and control AI services. |
| `services/chunk_and_prepare.py` | Builds the detection knowledge base from cybersecurity source files. |
| `services/build_response_knowledge.py` | Builds the response knowledge base and response playbook-style documents. |
| `services/embed_and_upsert.py` | Embeds detection knowledge using `BAAI-bge-small-en-v1.5` and uploads it to Qdrant. |
| `custom-rules.xml` | Custom Wazuh rules for AI detection alerts, AI response alerts, and Active Response lifecycle events. |
| `ossec.conf` | Wazuh Manager configuration including TCP input on port `5555`, log collection, and Active Response commands. |
| `wazuh_ai_assistant/` | Custom OpenSearch Dashboards plugin that adds the floating AI assistant button to Wazuh Dashboard. |

---

## 🛠️ Prerequisites

Before running the platform, ensure the following components are installed and configured:

- Ubuntu Server 2024 for Wazuh Manager
- Wazuh Manager 4.14.0
- Wazuh Agent on Windows endpoint
- Wazuh Agent on Ubuntu endpoint
- Parrot Security machine for testing
- Python 3.10+
- Qdrant running on port `6333`
- Ollama running with `llama3.2`
- BAAI-bge-small-en-v1.5 model available locally
- Node.js 18 and Yarn for the Wazuh AI Assistant plugin

---

## 📦 Python Dependencies

Install the required Python packages:

```bash
pip install sentence-transformers qdrant-client requests flask flask-cors pandas openpyxl orjson
```

Additional Python modules used by the platform include:

```text
argparse
collections
concurrent.futures
datetime
hashlib
ipaddress
json
os
pathlib
re
shutil
socket
subprocess
sys
time
typing
```

---

## ⚙️ Installation & Setup

### 1. Prepare the Project Directory

Example project path:

```bash
mkdir -p /home/i77/AS-Platform
cd /home/i77/AS-Platform
```

Place the project files inside this directory.

---

### 2. Start Qdrant

Run Qdrant locally on port `6333`.

Example using Docker:

```bash
docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

---

### 3. Start Ollama and Pull the LLM

On the host machine running Ollama:

```bash
ollama pull llama3.2
ollama run llama3.2
```

The platform uses Ollama through:

```text
http://192.168.56.1:11434/api/generate
```

Update this address in the service scripts if your Ollama server uses a different IP.

---

## 🧩 Knowledge Base Setup

The project uses two Qdrant collections:

| Collection | Purpose |
| :--- | :--- |
| `RAG_detection_knowledge` | Used by RAG Detection to analyze and classify suspicious logs. |
| `RAG_response_knowledge` | Used by RAG Response to generate response recommendations and remediation actions. |

### 1. Build Detection Knowledge

```bash
cd /home/i77/AS-Platform/services
python3 chunk_and_prepare.py
python3 embed_and_upsert.py
```

### 2. Build Response Knowledge

```bash
cd /home/i77/AS-Platform/services
python3 build_response_knowledge.py
```

---

## 🛡️ Wazuh Configuration

### 1. Enable AI Alert Injection Port

Add the following block to `/var/ossec/etc/ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>5555</port>
  <protocol>tcp</protocol>
  <allowed-ips>127.0.0.1</allowed-ips>
  <local_ip>127.0.0.1</local_ip>
</remote>
```

This allows AI-generated alerts to be injected locally into Wazuh using TCP port `5555`.

---

### 2. Enable JSON Logging

Make sure the following options are enabled in `/var/ossec/etc/ossec.conf`:

```xml
<jsonout_output>yes</jsonout_output>
<alerts_log>yes</alerts_log>
<logall_json>yes</logall_json>
```

`logall_json` is required because `ai_rag_sentinel.py` monitors:

```text
/var/ossec/logs/archives/archives.json
```

---

### 3. Add Custom Wazuh Rules

Copy the contents of `custom-rules.xml` into your local Wazuh rules file:

```bash
sudo cp custom-rules.xml /var/ossec/etc/rules/local_rules.xml
```

Or manually merge the rules into:

```text
/var/ossec/etc/rules/local_rules.xml
```

The custom rules detect:

- AI detection alerts with `ai_id = 000_ai`
- AI response alerts with `response_id = 000_response_ai`
- Active Response execution results
- Rollback results

---

## ⚡ Active Response Setup

### 1. Create Agent Groups

```bash
sudo mkdir -p /var/ossec/etc/shared/linux-ar
sudo mkdir -p /var/ossec/etc/shared/windows-ar

sudo /var/ossec/bin/agent_groups -a -g linux-ar -q
sudo /var/ossec/bin/agent_groups -a -g windows-ar -q
```

### 2. Assign Agents to Groups

Example:

```bash
sudo /var/ossec/bin/agent_groups -a -i 001 -g linux-ar -q
sudo /var/ossec/bin/agent_groups -a -i 005 -g windows-ar -q
```

### 3. Copy Agent Configuration Files

```bash
sudo cp linux-ar/agent.conf /var/ossec/etc/shared/linux-ar/agent.conf
sudo cp windows-ar/agent.conf /var/ossec/etc/shared/windows-ar/agent.conf
```

### 4. Verify and Restart Wazuh

```bash
sudo /var/ossec/bin/verify-agent-conf
sudo systemctl restart wazuh-manager
```

### 5. Install Active Response Scripts on Endpoints

Copy the correct scripts to the target endpoint:

```text
/var/ossec/active-response/bin/
```

For Linux endpoints:

```bash
sudo cp active-response/Linux/ai-*.py /var/ossec/active-response/bin/
sudo chown root:wazuh /var/ossec/active-response/bin/ai-*.py
sudo chmod 750 /var/ossec/active-response/bin/ai-*.py
```

For Windows endpoints, copy the scripts from:

```text
active-response/Windows/
```

to the Wazuh Agent active response directory.

---

## 🔁 Systemd Services

Copy the service files:

```bash
sudo cp ai-rag-detection.service /etc/systemd/system/
sudo cp ai-rag-response.service /etc/systemd/system/
sudo cp ai-control-api.service /etc/systemd/system/
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

Enable and start services:

```bash
sudo systemctl enable ai-rag-detection.service
sudo systemctl enable ai-rag-response.service
sudo systemctl enable ai-control-api.service

sudo systemctl start ai-rag-detection.service
sudo systemctl start ai-rag-response.service
sudo systemctl start ai-control-api.service
```

Check status:

```bash
sudo systemctl status ai-rag-detection.service
sudo systemctl status ai-rag-response.service
sudo systemctl status ai-control-api.service
```

---

## ▶️ Manual Run

For testing, services can also be started manually:

```bash
cd /home/i77/AS-Platform/services
sudo python3 ai_rag_sentinel.py
sudo python3 ai_rag_response.py
sudo python3 ai_control_api.py
```

---

## 🌐 Flask Control API

The Flask API provides control functions for the floating assistant.

Default port:

```text
8777
```

Example health check:

```bash
curl http://127.0.0.1:8777/health
```

Main functions:

- Retrieve AI response actions
- Execute manual response actions
- Perform rollback
- Ask AI questions about alerts
- Enable or disable RAG Detection
- Enable or disable RAG Response

---

## 🧠 Wazuh AI Assistant Plugin

The folder `wazuh_ai_assistant/` contains the OpenSearch Dashboards plugin used to add the floating assistant button to the Wazuh Dashboard.

### Install Build Requirements

```bash
sudo apt-get update
sudo apt-get install -y git curl unzip build-essential
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm install -g yarn
```

### Plugin Structure

```text
wazuh_ai_assistant/
├── public/
│   └── plugin.tsx
├── server/
│   ├── routes.ts
│   └── plugin.ts
├── package.json
└── opensearch_dashboards.json
```

The plugin provides:

- Ask AI panel
- Response control panel
- Manual execute button
- Rollback button
- RAG Detection / RAG Response service controls

---

## 🧪 Tested Attack Scenarios

The platform was tested using four main scenarios:

| Scenario | Security Impact | AI Response |
| :--- | :--- | :--- |
| Unauthorized access to a sensitive file | Confidentiality | Disable user / manual investigation |
| DoS flood using `hping3` | Availability | Block attacker IP automatically |
| Meterpreter-like process creation | Endpoint compromise | Kill process / isolate host |
| Web Shell upload | Integrity | Quarantine malicious file |

---

## 🧠 How It Works

### 1. Log Collection

Wazuh Agents collect logs from Windows and Linux endpoints and send them to Wazuh Manager.

### 2. RAG Detection

`ai_rag_sentinel.py` monitors Wazuh raw logs from:

```text
/var/ossec/logs/archives/archives.json
```

It selects logs for analysis when:

- Wazuh rule level is high
- suspicious keywords are detected
- raw logs appear security-relevant

The selected event is embedded and searched against the Qdrant detection knowledge collection.

### 3. LLM Detection Analysis

The log, local context, recent history, and retrieved knowledge are sent to Llama 3.2 through Ollama.

The model generates a JSON detection alert with:

```text
ai_id = 000_ai
```

### 4. Alert Injection

The AI alert is sent to Wazuh through:

```text
127.0.0.1:5555
```

Wazuh custom rules classify and display the AI alert in the dashboard.

### 5. RAG Response

`ai_rag_response.py` monitors Wazuh alerts and processes AI detection alerts.

It generates a response plan containing:

- recommended action
- confidence
- reasoning
- evidence to collect
- action parameters
- safe execution decision

### 6. Policy Gate

Automatic execution is allowed only when:

```text
severity level = 15
safe_for_auto_execute = true
action is allowed for the target platform
```

### 7. Active Response Execution

If approved, the Active Response Dispatcher executes the correct endpoint action.

If not approved, the action remains a manual recommendation in the floating assistant.

### 8. Ledger and Rollback

All actions are tracked by the Action Ledger. Supported actions can be rolled back through the Wazuh AI Assistant interface.

---

## 📊 Dashboard Filtering

### RAG Detection Alerts

Filter AI detection alerts in Wazuh Dashboard using:

```text
data.ai_id = 000_ai
```

### RAG Response Alerts

Filter AI response alerts using:

```text
data.response_id = 000_response_ai
```

These filters can be saved and used to build custom dashboards for AI detection and AI response monitoring.

---

## 🔐 Security Notes

- The AI injection port `5555` should remain restricted to `127.0.0.1`.
- Do not expose Ollama, Qdrant, or Flask Control API directly to untrusted networks.
- Automatic response should only be enabled for high-confidence cases.
- Always test Active Response scripts in a lab environment before production use.
- Keep Wazuh API and Indexer credentials outside public repositories.

---

## 📌 Current Limitations

- The prototype was tested in a controlled virtual lab.
- LLM inference time depends on hardware and model size.
- Automated execution is intentionally restricted to reduce operational risk.
- More attack scenarios are required for large-scale statistical evaluation.

---

## 🔮 Future Work

- Integrate live threat intelligence feeds.
- Improve LLM inference latency.
- Add more Active Response actions.
- Expand rollback support.
- Use larger or cybersecurity-specialized LLMs.
- Deploy the system in a larger SOC-like environment.
- Add performance dashboards for AI analysis time and response success rate.

---

## 📜 License & Acknowledgments

This project was developed as a graduation project for a Bachelor's degree in **Informatics Engineering - System and Network Security**.

### Models Used

- Llama 3.2
- BAAI-bge-small-en-v1.5

### Core Tools

- Wazuh
- Qdrant
- Ollama
- Python
- Flask
- OpenSearch Dashboards

---

## 👤 Author

```text
Eng. Abdulmalek Salameh
```

```text
All Rights Reserved © 2026
```
