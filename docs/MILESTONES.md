# Development Milestones

- [x] **Milestone 1 — Foundation**
  Local SOC sample data (8 scenarios across 8 log types), SQLite +
  SQLAlchemy models, FastAPI app, `POST/GET /api/alerts`, `GET /api/iocs`,
  `GET /api/logs`, deterministic regex-based IOC extraction with
  normalization/deduplication, seed script, unit tests, `.env.example`.

- [x] **Milestone 2 — IOC Enrichment**
  `EnrichmentProvider` interface, `LocalMockProvider` with a curated
  lookup table matching the sample scenarios, optional external adapters
  (`VirusTotalProvider`, `AbuseIPDBProvider`) gated by env vars and
  degrading gracefully on failure, `ioc_enrichments` table,
  `GET /api/iocs/{id}/enrichment`.

- [x] **Milestone 3 — MITRE ATT&CK + ATLAS Mapping**
  Local curated ATT&CK and ATLAS technique datasets, rule-based matchers
  (substring evidence matching, no LLM involved), ATLAS mapper is
  independent and only fires on AI/ML signals — returns the explicit
  "No relevant MITRE ATLAS technique identified" otherwise —
  `GET /api/mitre/attack/{id}`, `GET /api/mitre/atlas/{id}`.

- [x] **Milestone 4 — LangGraph Agent + Groq LLM**
  `services/llm/groq_client.py` (single choke point for all Groq calls,
  structured-JSON `InvestigationResult` output, graceful failure without a
  key), `services/llm/prompt_guard.py` (prompt-injection screening),
  `agents/investigation_graph.py` (LangGraph `StateGraph` wiring triage →
  extraction → enrichment → log investigation → ATT&CK/ATLAS →
  correlation → risk → summary → response recommendation), explicit
  per-node tool allow-list in `agents/tool_permissions.py`, full audit
  logging of every step.

- [x] **Milestone 5 — Deterministic Risk Scoring + RAG**
  `services/risk/score.py` weighted scoring engine (source of truth for
  severity, LLM never overrides it), local dependency-free TF-IDF
  retriever (`services/rag/retriever.py`) over `data/knowledge_base/`
  (SOC procedures, incident response, detection engineering, MITRE
  ATT&CK/ATLAS reference, security playbooks).

- [x] **Milestone 6 — Human-in-the-Loop Response**
  `response_actions` table, `POST /api/response/{id}/approve|reject`,
  simulated-only execution (`[SIMULATED] ... No real system was
  modified.`), full audit trail of approvals/rejections.

- [x] **Milestone 7 — Frontend**
  React + TypeScript + Tailwind dashboard (Vite): Overview (alert counts by
  severity, recent alerts), Alerts list with severity filter, Alert detail
  page (IOC list → enrichment on demand → run investigation → ATT&CK/ATLAS
  side-by-side → RAG sources → recommended response with approve/reject),
  IOC lookup page. Type-checks and builds cleanly (`npm run build`).

- [x] **Milestone 8 — Testing, Docker Compose, Docs**
  47 backend tests (unit + integration, including a full alert → IOC
  extraction → enrichment → investigation → MITRE mapping → AI/deterministic
  result → response-approval integration test), `docker-compose.yml`
  (backend + nginx-served frontend build, SQLite on a named volume), this
  documentation set.

- [x] **Milestone 9 — Sentinel readiness (documentation only)**
  `SentinelLogSource` placeholder class (raises `NotImplementedError` with
  a clear message) + `docs/SENTINEL_INTEGRATION.md` describing AAD auth,
  KQL execution, and incident retrieval — no fake Sentinel responses, per
  the project's engineering requirements.

## Possible next steps (beyond original scope)

- Swap the local TF-IDF RAG retriever for Chroma/FAISS if embedding-based
  retrieval quality becomes a priority.
- Add a real Sentinel integration behind `SentinelLogSource` once a
  subscription is available.
- Add authentication/authorization to the API (currently unauthenticated,
  appropriate for a local portfolio demo but not for production).
- Expand the frontend investigation timeline view described in the
  original spec (alert received → IOC extracted → ... → response
  recommended) as an explicit visual timeline component.

## Milestone 10 — Production-readiness pass (this round)

Prompted by a gap-analysis against a stricter SOC-platform spec. Extended
(not rebuilt) the existing app:

- **Fixed a live bug**: default Groq model `llama-3.3-70b-versatile` was
  confirmed deprecated/enterprise-only as of 08/16/2026 (verified against
  Groq's docs) -- every LLM call was silently falling back to the
  deterministic summary. Replaced with `openai/gpt-oss-120b`.
- **Automatic IOC enrichment**: moved from on-demand/lazy to a
  `BackgroundTasks`-triggered flow right after alert ingestion. No manual
  "Enrich" click anywhere in the UI anymore. Added `status`
  (pending/completed/failed/not_available) and
  malicious/suspicious/harmless counts to `IOCEnrichment`, and fixed a
  fallback inconsistency where failed IP lookups didn't fall back to the
  local mock provider (domain/URL/hash already did).
- **Dashboard**: added `GET /api/alerts/stats` so counts are always
  computed live from the DB (previously computed client-side from a
  capped 50-row page). Added an "Informational" severity bucket.
- **Alerts list**: added backend-side global search (`?search=`) across
  alert ID/name/source/user/hostname/IPs/domain/URL/hash, plus
  `X-Total-Count`-header-based pagination on the frontend.
- **Structured investigation report**: new `services/reporting/report_builder.py`
  -- a deterministic (non-LLM) disposition classifier
  (TP/FP/BP/Suspicious/Inconclusive, explicitly not derived from risk
  score alone) and report builder matching the required section structure
  (Entity Details, Key Findings, IOC/TI Findings, MITRE mapping,
  Conclusion, Recommended Actions, Other Details), plus a separate
  customer-escalation format, both available via
  `GET /api/investigations/{id}/report?format=analyst|customer`.
- **RAG sources are no longer exposed** via the API or the frontend --
  removed from `InvestigationOut` and the old "Retrieved Playbook /
  Reference Sources" UI panel. RAG retrieval still runs internally to
  ground the LLM's summary.
- **Investigation/alert status lifecycle**: `Alert.status` now correctly
  transitions `new -> investigating -> investigated` (previously it got
  stuck on `"investigating"` even after success) or
  `investigation_failed` if the pipeline throws, with the whole
  investigation flow now wrapped so a failure can never crash the API.
