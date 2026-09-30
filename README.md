# 🛡️ AI-Powered SOC Investigation Agent

An end-to-end **AI-assisted Security Operations Center (SOC) investigation platform** that automates evidence collection, IOC enrichment, MITRE ATT&CK / ATLAS mapping, deterministic risk analysis, and AI-assisted investigation reporting.

The project demonstrates how **AI agents can support SOC analysts while keeping security decisions grounded in collected evidence**.

---

## 🚀 Live Demo

### Application

https://ai-soc-investigation-agent-frontend.onrender.com

### Backend API / Swagger

https://ai-soc-investigation-agent.onrender.com/docs

> **Note:** The application is hosted on Render. Initial loading may take a little longer if a service needs to start.

---

## 📸 Application Screenshots

### SOC Dashboard

![SOC Dashboard](docs/screenshots/dashboard.png)

### AI-Powered Investigation

![AI Investigation](docs/screenshots/ai-investigation.png)

### Investigation Report

![Investigation Report](docs/screenshots/investigation-report.png)

### MITRE ATT&CK / ATLAS Mapping

![MITRE Mapping](docs/screenshots/mitre-mapping.png)

---

## 🔎 Investigation Workflow

```text
Security / AI Alert
        ↓
SOC Investigation Agent
        ↓
Evidence Collection
 ├── Alert Context
 ├── Log Correlation
 ├── IOC Extraction
 └── Threat Intelligence Enrichment
        ↓
MITRE ATT&CK + MITRE ATLAS Mapping
        ↓
Deterministic Risk Analysis
        ↓
Groq LLM
        ↓
AI Investigation Summary
        ↓
Analyst Investigation Report
        ↓
Recommended Response
        ↓
Human Review / Approval
```

The LLM is used to analyze and summarize collected evidence.

IOC reputation, MITRE mappings, risk analysis, and other security evidence are collected or calculated outside the LLM so that the model does not become the source of truth for security decisions.

---

# ✨ Key Features

## 🤖 AI-Assisted SOC Investigation

The investigation agent can:

- Process security alerts
- Collect investigation evidence
- Correlate relevant logs
- Extract indicators of compromise
- Enrich IOCs using threat intelligence
- Map activity to MITRE ATT&CK
- Map AI-related threats to MITRE ATLAS
- Perform deterministic risk analysis
- Generate AI-assisted investigation summaries
- Produce recommended response actions

Groq is used as the LLM provider for AI-assisted investigation.

Structured LLM output is validated before it is used by the application.

If AI generation fails, the investigation workflow can fall back to deterministic analysis instead of failing the entire investigation.

---

## 🔍 IOC Extraction & Threat Intelligence

The agent can extract indicators including:

- IPv4 / IPv6 addresses
- SHA256 hashes
- SHA1 hashes
- MD5 hashes
- Domains
- URLs
- Email indicators

External threat-intelligence enrichment supports providers such as:

- VirusTotal
- AbuseIPDB

When enrichment data is unavailable, the application reports only the available evidence rather than inventing missing information.

---

## 🧠 MITRE ATT&CK & MITRE ATLAS

The investigation workflow supports:

### MITRE ATT&CK

Used for mapping traditional cybersecurity activity and attacker techniques.

### MITRE ATLAS

Used for mapping threats involving AI and machine-learning systems.

This allows the project to demonstrate investigation of both **traditional SOC incidents** and **AI-security incidents**.

---

## 🧪 AI Security Incident Scenarios

The sample alert dataset includes AI-security scenarios such as:

### Prompt Injection

Attempts to manipulate an AI assistant through malicious instructions.

### Sensitive Data Exfiltration Through LLM

Potential attempts to expose confidential information using an LLM.

### RAG Knowledge Base Poisoning

Suspicious modifications that could influence information retrieved by an AI system.

### Unauthorized AI Agent Tool Execution

Attempts to make an AI agent execute unauthorized tools or actions.

### LLM API Credential Exposure

Potential exposure of credentials associated with an LLM service.

---

## 📊 Deterministic Risk Analysis

The project does not rely solely on an LLM to determine security risk.

The deterministic analysis layer evaluates collected evidence such as:

- Alert context
- IOC reputation
- Log evidence
- MITRE mappings
- Investigation findings

The AI layer then helps explain the collected evidence in an analyst-friendly format.

---

## 📄 Investigation Reports

The platform generates analyst-oriented reports containing:

- Incident summary
- Entity details
- Key findings
- IOC / threat-intelligence findings
- MITRE ATT&CK mappings
- MITRE ATLAS mappings
- Risk assessment
- AI-assisted investigation summary
- Recommended response actions
- Additional investigation details

---

# 🔐 Authentication & Account Security

The application includes a complete authentication workflow.

Features include:

- Email-based registration
- Email + password login
- Secure password hashing
- JWT authentication
- Protected SOC API endpoints
- Forgot-password workflow
- Email OTP verification
- OTP expiration
- Password reset

Password-reset OTP emails in the hosted application are delivered using **Resend**.

Sensitive credentials remain in backend environment variables and are not exposed to the React frontend.

---

## 👨‍💻 Human-in-the-Loop Response

The platform intentionally avoids automatically executing destructive remediation actions.

Instead, the investigation agent produces recommended response actions that can be reviewed by an analyst.

```text
AI Investigation
       ↓
Recommended Action
       ↓
Human Review
    ↙       ↘
Approve    Reject
```

This keeps the analyst involved in security-response decisions.

---

# 🏗️ System Architecture

```text
┌─────────────────────────────┐
│       React Frontend        │
│   TypeScript + Tailwind     │
└──────────────┬──────────────┘
               │
               │ REST API
               ▼
┌─────────────────────────────┐
│       FastAPI Backend       │
│                             │
│  Authentication / JWT       │
│  Alert Management           │
│  Investigation APIs         │
│  IOC Services               │
│  Reporting                  │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│    Investigation Agent      │
│         LangGraph           │
│                             │
│  Evidence Collection        │
│  IOC Extraction             │
│  Threat Enrichment          │
│  Log Correlation            │
│  ATT&CK / ATLAS Mapping     │
│  Deterministic Risk Engine  │
│  Groq LLM Analysis          │
└──────────────┬──────────────┘
               │
       ┌───────┴─────────┐
       ▼                 ▼
┌─────────────┐    ┌──────────────┐
│ PostgreSQL  │    │ Threat Intel │
│             │    │              │
│ Users       │    │ VirusTotal   │
│ Alerts      │    │ AbuseIPDB    │
│ IOCs        │    │              │
│ Incidents   │    └──────────────┘
└─────────────┘
```

---

# 🛠️ Technology Stack

## Backend

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Pydantic
- JWT Authentication

## AI / Agent

- LangGraph
- Groq API
- Structured LLM output validation
- Retrieval-Augmented Generation (RAG)

## Cybersecurity

- IOC Extraction
- VirusTotal
- AbuseIPDB
- MITRE ATT&CK
- MITRE ATLAS
- Deterministic Risk Scoring

## Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Nginx

## Infrastructure

- Docker
- Docker Compose
- GitHub
- Render
- PostgreSQL
- Resend

---

# 📁 Project Structure

```text
ai-soc-investigation-agent/
│
├── backend/
│   └── app/
│       ├── agents/
│       ├── api/
│       ├── config/
│       ├── database/
│       ├── models/
│       ├── schemas/
│       └── services/
│           ├── enrichment/
│           ├── llm/
│           ├── logs/
│           └── reporting/
│
├── frontend/
│   └── src/
│
├── data/
│   ├── alerts/
│   ├── knowledge_base/
│   └── MITRE datasets
│
├── docs/
│   ├── screenshots/
│   ├── ARCHITECTURE.md
│   ├── DATABASE_SCHEMA.md
│   ├── API_DESIGN.md
│   ├── MILESTONES.md
│   └── SENTINEL_INTEGRATION.md
│
├── docker-compose.yml
├── .env.example
└── README.md
```

---

# ⚙️ Running Locally

## 1. Clone the repository

```bash
git clone https://github.com/Divya2842/ai-soc-investigation-agent.git

cd ai-soc-investigation-agent
```

---

## 2. Configure Environment Variables

Create a local `.env` file based on:

```text
.env.example
```

Configure the services you want to use.

Example:

```env
DATABASE_URL=your_database_url

JWT_SECRET_KEY=your_jwt_secret

GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=openai/gpt-oss-20b

VT_API_KEY=your_virustotal_api_key

ABUSEIPDB_API_KEY=your_abuseipdb_api_key

RESEND_API_KEY=your_resend_api_key
```

> Never commit real passwords, API keys, JWT secrets, database credentials, or other sensitive values to GitHub.

---

## 3. Run with Docker Compose

```bash
docker compose up --build
```

Local services:

```text
Frontend
http://localhost:5173

Backend
http://localhost:8000

Swagger
http://localhost:8000/docs
```

---

# 🗄️ PostgreSQL Database

PostgreSQL provides persistent storage for application data including:

- Users
- Alerts
- IOC records
- IOC enrichment
- Investigations
- Response actions
- Password-reset OTP records

The database seeding process is incremental.

Existing alerts are preserved, and only previously unseen alert IDs are inserted.

---

# 🔐 Security Design

Several security-focused design decisions are implemented:

- Secrets are supplied using environment variables
- `.env` files are excluded from Git
- Passwords are never stored as plaintext
- Authentication uses JWTs
- Password-reset OTPs expire
- API credentials remain backend-only
- LLM output is validated
- Missing threat intelligence is not fabricated
- Security evidence is collected outside the LLM
- Response actions require human review

---

# 📚 Documentation

Additional project documentation is available in the `docs/` directory.

### Architecture

`docs/ARCHITECTURE.md`

System architecture, investigation workflow, agent design, and service structure.

### Database Schema

`docs/DATABASE_SCHEMA.md`

Application database design.

### API Design

`docs/API_DESIGN.md`

REST API architecture and endpoints.

### Milestones

`docs/MILESTONES.md`

Development milestones and implemented functionality.

### Sentinel Integration

`docs/SENTINEL_INTEGRATION.md`

Design for adding Microsoft Sentinel as a future log source.

---

# ⚠️ Current Limitations

- Microsoft Sentinel is not connected to the current live deployment.
- The project currently uses simulated SOC alerts/log data for demonstration.
- External threat-intelligence results depend on provider availability and configured API credentials.
- LLM investigation depends on Groq availability.
- A deterministic investigation path is available when AI generation fails.
- Response actions are recommendations/simulations and are not automatically executed against production infrastructure.
- The project is intended for learning, portfolio demonstration, and AI/SOC security experimentation rather than production SOC deployment.

---

# 🔮 Future Improvements

Potential future enhancements include:

- Microsoft Sentinel integration
- Microsoft Defender integration
- Additional SIEM connectors
- Additional log-source connectors
- Expanded MITRE ATT&CK coverage
- Expanded MITRE ATLAS coverage
- Additional AI-security incident scenarios
- Improved RAG knowledge retrieval
- Investigation timeline visualization
- Analyst feedback loops
- Additional threat-intelligence providers
- Production monitoring and observability

---

# 🎯 Project Goal

The goal of this project is to explore how **AI agents and deterministic cybersecurity engineering can work together in SOC investigation workflows**.

Instead of asking an LLM to independently make security decisions, the platform first collects and analyzes evidence using deterministic security logic.

AI is then used to help analysts interpret that evidence, summarize the investigation, and accelerate the investigation workflow.

---

# 👩‍💻 Author

**Divya K**

Cybersecurity / SOC professional exploring the intersection of:

**SOC Engineering • Security Automation • AI Agents • Generative AI • AI Security**

GitHub:

https://github.com/Divya2842