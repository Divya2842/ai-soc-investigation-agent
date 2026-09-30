# Architecture

## 1. High-level data flow

```
Security Alert
   |
   v
Alert Ingestion (POST /api/alerts)
   |
   v
IOC Extraction (deterministic regex, app/services/ioc)
   |
   v
IOC Enrichment (provider adapters, app/services/ioc/enrichment)
   |
   v
Security Log Investigation (LogSource abstraction, app/services/logs)
   |
   v
MITRE ATT&CK + MITRE ATLAS Mapping (app/services/mitre)
   |
   v
AI SOC Investigation Agent (LangGraph, app/agents)
   |
   v
Evidence Correlation (app/services/rag + agent state)
   |
   v
Risk / Severity Assessment (deterministic, app/services/risk)
   |
   v
Investigation Summary (LLM explanation over deterministic evidence)
   |
   v
Recommended Response (app/services/risk -> playbook lookup)
   |
   v
Human Approval (POST /api/response/{id}/approve|reject)
```

Everything left of the "AI SOC Investigation Agent" box is deterministic
Python. The agent orchestrates calls into that deterministic layer as tools;
it does not replace it. The LLM is only ever asked to (a) decide which tool
to call next, within an explicit allow-list, or (b) turn already-computed
evidence into an explanation. It is never asked to invent a verdict,
severity, IOC reputation, or ATT&CK/ATLAS ID from nothing.

## 2. Component responsibilities

| Layer | Responsibility | Determinism |
|---|---|---|
| `LogSource` (`services/logs`) | Read alerts/logs from a source. `LocalLogSource` today, `SentinelLogSource` later. | Deterministic |
| IOC extraction (`services/ioc/extract.py`) | Regex/parsing over alert + raw_event to find IPs, domains, URLs, hashes, emails. Normalize + dedupe. | Deterministic |
| IOC enrichment (`services/ioc/enrichment/`) | Provider adapter pattern: `LocalMockProvider` always available; external providers optional via env vars. | Deterministic (LLM never touches reputation data) |
| MITRE ATT&CK mapper (`services/mitre/attack.py`) | Rule-based matching of evidence patterns (e.g. encoded PowerShell, LSASS access) against a local ATT&CK technique dataset. | Deterministic |
| MITRE ATLAS mapper (`services/mitre/atlas.py`) | Same pattern, but only fires on AI/ML/LLM-related evidence (prompt injection markers, model extraction attempts, etc). Returns "no relevant technique" explicitly when nothing matches. | Deterministic |
| Risk engine (`services/risk/score.py`) | Weighted scoring function over IOC reputation, technique count, privilege, asset criticality, TI confidence → Low/Medium/High/Critical. | Deterministic |
| RAG (`services/rag/`) | Chroma/FAISS local vector store over SOC playbooks + MITRE reference docs. Retrieves supporting docs before the LLM writes its summary. | Deterministic retrieval, LLM only consumes results |
| LLM client (`services/llm/groq_client.py`) | Single choke point for all Groq calls. Structured (Pydantic) output only. | N/A — explicitly the only non-deterministic layer |
| Agent (`agents/investigation_graph.py`) | LangGraph state machine wiring the above into a controlled tool-calling loop. | Orchestration is deterministic; tool *selection* by the LLM is bounded to an explicit allow-list |
| Audit log (`services/audit.py`) | Every tool call, LLM decision, and human approval/rejection is recorded. | Deterministic |

## 3. Agent graph (LangGraph, Milestone 4)

```
START
  -> alert_triage
  -> extract_iocs
  -> enrich_iocs
  -> investigate_logs        (search_logs, get_user_activity, get_host_activity)
  -> map_attack
  -> map_atlas
  -> correlate_evidence
  -> assess_risk             (deterministic risk score computed here)
  -> summarize_investigation  (LLM explains the evidence + score)
  -> recommend_response       (playbook lookup keyed by risk + technique)
  -> END (awaiting human approval)
```

Tool allow-list per node is defined explicitly in
`agents/tool_permissions.py` — the LLM cannot call a tool that isn't listed
for the current node, and every tool call + result is written to the audit
log before the graph proceeds.

## 4. IOC enrichment design

```
IOC value + declared/detected type
        |
        v
 IOCTypeDetector (services/ioc/detect.py)
        |
        v
 EnrichmentRouter (services/ioc/enrichment/router.py)
        |
        +--> LocalMockProvider   (always available, deterministic lookup table)
        +--> VirusTotalProvider  (optional, only if VT_API_KEY set)
        +--> AbuseIPDBProvider   (optional, only if ABUSEIPDB_API_KEY set)
        |
        v
 EnrichmentResult (Pydantic model, tagged with `source`: "local_mock" | "<provider name>")
        |
        v
 Persisted to `ioc_enrichments` table, surfaced in UI with a clear source badge
```

Adding a new provider means writing one adapter class implementing
`EnrichmentProvider` (`enrich_ip`, `enrich_domain`, `enrich_url`,
`enrich_hash`) and registering it in the router — nothing else in the agent
or API changes.

## 5. MITRE ATT&CK / ATLAS separation

ATT&CK and ATLAS are deliberately two independent mappers with two
independent local datasets (`data/mitre/attack_techniques.json`,
`data/atlas/atlas_techniques.json`). ATLAS mapping only runs when the
evidence contains AI/ML/LLM-related signals (prompt-injection markers, model
endpoint access patterns, embedding/vector-store access, etc — see
`services/mitre/atlas.py::AI_SIGNAL_PATTERNS`). If no AI-related evidence
exists, the API returns an explicit
`"No relevant MITRE ATLAS technique identified."` rather than omitting the
field or letting the LLM guess.

## 6. Sentinel-ready abstraction

```
LogSource (ABC)
 ├── LocalLogSource     — reads data/logs/*.jsonl into SQLite, fully functional today
 └── SentinelLogSource  — placeholder only (Milestone 8+), documents:
                             - AAD app registration / auth
                             - KQL query execution against Log Analytics
                             - Sentinel incident/alert retrieval via REST API
                           No fake responses are implemented for this class;
                           calling it today raises NotImplementedError with
                           a clear message.
```

Swapping sources is a config change (`LOG_SOURCE=local|sentinel` in `.env`)
— the agent, API, and DB schema are source-agnostic (`services/logs/base.py`
defines the common `AlertRecord` / `LogEvent` shape both sources must
return).

## 7. Security controls baked into the architecture

- **Tool permission control** — `agents/tool_permissions.py` is an explicit
  allow-list per graph node; the LangGraph runtime enforces it, it isn't a
  suggestion to the LLM.
- **Input validation** — all API bodies are Pydantic models with strict
  field types (`schemas/`).
- **Output validation** — every LLM response is parsed into a Pydantic
  `InvestigationResult` (or rejected) before it's stored or returned.
- **Data leakage prevention** — `services/llm/groq_client.py` strips
  `.env` values and system-prompt content from anything that could echo
  into a user-facing field; API keys are never included in any model
  request body.
- **Prompt injection defense** — `services/llm/prompt_guard.py` screens
  alert/log text for instruction-like content before it's interpolated into
  a prompt, and flags it in the audit log rather than silently stripping it.
- **Audit logging** — `services/audit.py` records every tool call, LLM
  decision, and human approval/rejection with timestamps.
