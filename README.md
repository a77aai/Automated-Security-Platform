# Automated AI-Powered Security Platform  
## Wazuh + RAG Detection + RAG Response + Active Response

---

## 📌 Overview

This project is an **Automated AI-Powered Security Platform** that extends the capabilities of **Wazuh SIEM/XDR** by integrating **Retrieval-Augmented Generation (RAG)**, **Large Language Models (LLMs)**, a **Qdrant vector database**, and **Wazuh Active Response**.

The platform is designed to enhance Security Operations Center (SOC) workflows by providing contextual alert analysis, reducing false positives, generating response recommendations, and executing selected remediation actions under controlled safety policies.

Unlike cloud-based AI solutions, this platform is designed to run locally and on-premise. The LLM is executed locally using **Ollama** with **Llama 3.2**, while cybersecurity knowledge is stored inside **Qdrant** as vector embeddings. This design improves privacy, keeps security logs inside the local environment, and reduces dependency on external APIs.

---

## 🚀 Key Features

### 🔍 RAG-Based Detection
Monitors selected Wazuh raw logs and alerts, enriches them with cybersecurity knowledge, and generates AI-enhanced detection alerts.

### 🧠 Context-Aware LLM Analysis
Uses **Llama 3.2 via Ollama** to analyze logs, understand the security context, and produce structured JSON-based security alerts.

### 🗃️ Vector Knowledge Base
Uses **Qdrant** as a vector database to store embedded cybersecurity knowledge, mainly based on **MITRE ATT&CK** techniques and detection/response context.

### ⚡ RAG Response Planning
Analyzes AI-generated detection alerts and recommends suitable response actions such as:

- Block IP
- Kill Process
- Quarantine File
- Disable User
- Isolate Host
- Collect Triage Evidence
- Monitor Only

### 🛡️ Policy-Controlled Active Response
The system does not blindly execute LLM decisions. Every AI response passes through a **Policy Gate** before execution. Automated execution is allowed only under strict conditions, such as high severity and safe action classification.

### 🔁 Rollback Support
Selected response actions support rollback, allowing the analyst to reverse actions such as IP blocking, user disabling, host isolation, or file quarantine when needed.

### 📊 Wazuh Dashboard Integration
AI-generated detection and response alerts are injected back into Wazuh and displayed in the Wazuh Dashboard using custom rules.

### 🤖 Floating AI Assistant Button
Includes a custom **OpenSearch Dashboards / Wazuh Dashboard plugin** that adds a floating AI assistant button. This interface allows the analyst to:

- Ask questions about alerts
- View AI recommendations
- Execute manual actions
- Roll back executed actions
- Enable or disable AI Detection and AI Response services

---

## 🧩 System Architecture

The platform consists of the following main components:

1. **Wazuh Agents**  
   Installed on monitored endpoints such as Ubuntu and Windows.

2. **Wazuh Manager**  
   Collects logs, applies rule-based detection, and receives AI-generated alerts.

3. **RAG Detection Engine**  
   Implemented in `ai_rag_sentinel.py`.  
   It analyzes selected logs and generates enriched AI detection alerts.

4. **RAG Response Engine**  
   Implemented in `ai_rag_response.py`.  
   It analyzes AI detection alerts and generates response recommendations.

5. **Qdrant Vector Database**  
   Stores vectorized cybersecurity knowledge for detection and response.

6. **Ollama + Llama 3.2**  
   Performs local LLM-based reasoning and response generation.

7. **Active Response Dispatcher**  
   Implemented in `ai_response_dispatcher.py`.  
   It translates AI response decisions into Wazuh Active Response commands.

8. **Action Ledger**  
   Implemented in `ai_action_ledger.py`.  
   It tracks recommendations, execution results, rollback status, and audit records.

9. **Flask Control API**  
   Implemented in `ai_control_api.py`.  
   It connects the backend services with the floating dashboard assistant.

10. **Wazuh AI Assistant Plugin**  
   A custom OpenSearch Dashboards plugin that provides an interactive UI inside Wazuh.

---

## 📁 Project Structure

| Path / File | Description |
|---|---|
| `services/ai_rag_sentinel.py` | RAG Detection engine. Monitors Wazuh raw logs, retrieves context from Qdrant, queries the LLM, and injects AI detection alerts into Wazuh. |
| `services/ai_rag_response.py` | RAG Response engine. Reads AI detection alerts, retrieves response context, generates response plans, and injects response alerts into Wazuh. |
| `services/ai_response_dispatcher.py` | Active Response dispatcher. Executes approved response actions on Linux or Windows agents. |
| `services/ai_action_ledger.py` | Tracks AI response recommendations, execution status, rollback status, and audit records. |
| `services/ai_control_api.py` | Flask API used by the floating assistant plugin to control AI services and response actions. |
| `services/chunk_and_prepare.py` | Builds detection knowledge chunks from cybersecurity data sources. |
| `services/build_response_knowledge.py` | Builds response-oriented knowledge chunks and optionally uploads them to Qdrant. |
| `services/embed_and_upsert.py` | Converts detection knowledge chunks into embeddings and uploads them to Qdrant. |
| `custom-rules.xml` | Custom Wazuh rules for AI detection alerts, AI response alerts, and Active Response lifecycle events. |
| `ossec.conf` | Wazuh configuration file with additional TCP input, Active Response commands, and logging settings. |
| `active-response/Linux/` | Linux Active Response scripts. |
| `active-response/Windows/` | Windows Active Response scripts. |
| `linux-ar/agent.conf` | Wazuh shared agent configuration for Linux Active Response logging. |
| `windows-ar/agent.conf` | Wazuh shared agent configuration for Windows Active Response logging. |
| `wazuh_ai_assistant/` | OpenSearch Dashboards plugin for the floating AI assistant button. |
| `*.service` | Systemd service files for running AI Detection, AI Response, and Control API services. |

---

## 🛠️ Prerequisites

Before running the platform, ensure the following components are installed and configured.

### Core Requirements

| Component | Recommended Version |
|---|---|
| Wazuh Manager | 4.14.0 |
| Wazuh Agents | Compatible with Wazuh 4.x |
| Python | 3.10+ |
| Qdrant | Running on port `6333` |
| Ollama | Installed and running |
| LLM | `llama3.2:latest` |
| Embedding Model | `BAAI/bge-small-en-v1.5` |
| Node.js | 18.x |
| Yarn | Required for building the dashboard plugin |

---

## 🧪 Test Environment

The project was tested in a virtualized lab environment using **VirtualBox** and NAT networking.

| Machine | Role |
|---|---|
| Ubuntu Server 2024 | Wazuh Manager 4.14.0 |
| Ubuntu Desktop 2024 | Linux endpoint with Wazuh Agent |
| Windows 7 Ultimate 32-bit | Windows endpoint with Wazuh Agent |
| Parrot Security 2024 | Attacker machine |
| Windows 11 Host | Runs Ollama and Llama 3.2 using GPU resources |

---

## 📦 Python Dependencies

Install the required Python libraries:

```bash
pip install sentence-transformers qdrant-client requests pandas openpyxl orjson flask flask-cors
