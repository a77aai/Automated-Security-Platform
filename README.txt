Automated Security Platform (Wazuh + AI RAG)
📌 Overview
This project represents a next-generation Automated Security Platform that integrates the Wazuh SIEM/XDR capabilities with Generative AI (GenAI) using Retrieval-Augmented Generation (RAG) technology. The platform is designed to enhance Security Operations Centers (SOCs) by automating threat analysis, reducing false positives, and performing proactive threat hunting.
+1

Unlike cloud-based solutions, this platform runs entirely on-premise using local LLMs (Llama 3.2) and vector databases (Qdrant), ensuring data privacy and operational security.

🚀 Key Features

Intelligent SIEM Integration: Seamlessly monitors Wazuh logs and enhances them with AI analysis.


RAG-Driven Context: Retrieves relevant security knowledge (e.g., MITRE ATT&CK techniques, Incident Response Playbooks) from a vector database to ground the AI's reasoning.


Local AI Processing: Utilizes Llama 3.2 via Ollama for high-performance, private, and offline log analysis.
+2


Automated Alert Injection: Feeds AI-generated alerts and severity assessments back into the Wazuh Dashboard as new security events.


Multi-Format Knowledge Ingestion: Includes tools to process and ingest security documents from PDF, JSON, Excel, and TXT formats.


File,			Description
RAG.py,			"The core engine. It monitors Wazuh archives, performs vector searches, queries the LLM, and injects alerts back into Wazuh.+1"
chunk_and_prepare.py,	"A utility script to process raw documents (PDF, Excel, JSON) and split them into semantic chunks."
embed_and_upsert.py,	 Converts text chunks into vector embeddings using BAAI/bge-small-en-v1.5 and uploads them to Qdrant.+1
rules.xml,		"Custom Wazuh rules defined to detect, classify, and display the AI-generated alerts in the dashboard."


🛠️ Prerequisites
Before running the platform, ensure the following components are installed and running:


Operating System: Ubuntu Server 22.04 LTS (recommended).


Python: Version 3.10+.


Wazuh Manager: Version 4.x.


Qdrant: Vector Database running on port 6333.


Ollama: Running locally with the llama3.2 model pulled.
+1

Python Dependencies
Install the required libraries:
pip install sentence-transformers qdrant-client nltk requests pypdf openpyxl pandas pdfminer.six

⚙️ Installation & Setup
1. Build the Knowledge Base
First, you need to populate the vector database with security context (e.g., playbooks, threat intelligence).

1   Chunk your documents:
python3 chunk_and_prepare.py /path/to/raw_docs /path/to/chunked_output



2.  Embed and Upsert to Qdrant: (Edit embed_and_upsert.py to point to your chunked_output directory)
python3 embed_and_upsert.py

2. Configure Wazuh

Add Custom Rules: Copy the content of rules.xml into your Wazuh Manager's local rules file (usually /var/ossec/etc/rules/local_rules.xml).

Enable TCP Input: Modify /var/ossec/etc/ossec.conf to accept logs via TCP on port 5555:

XML

<remote>
  <connection>syslog</connection>
  <port>5555</port>
  <protocol>tcp</protocol>
  <allowed-ips>127.0.0.1</allowed-ips>
</remote>

Restart Wazuh:

Bash

systemctl restart wazuh-manager
3. Run the AI Engine
Start the main script to begin monitoring and analyzing logs:

Bash

python3 RAG.py
.

🧠 How It Works

Log Ingestion: RAG.py tails the archives.json file to catch real-time events.


Filtering: It filters logs based on specific criteria (e.g., high severity or suspicious keywords like "failed", "sudo").


Context Retrieval (RAG): It converts the log into a vector and queries Qdrant for the most relevant security playbooks or MITRE techniques.

LLM Analysis: The log + retrieved context are sent to Llama 3.2. The model analyzes the incident for false positives or missed attacks.


Alert Injection: The AI's findings are formatted as JSON and sent back to Wazuh via TCP port 5555, triggering the custom rules.

📜 License & Acknowledgments
This project was developed as a graduation project for a Bachelor's degree in Informatics Engineering (System and Network Security).

Models used: Llama 3.2, BAAI/bge-small-en-v1.5.

Core Tools: Wazuh, Qdrant, Ollama.
