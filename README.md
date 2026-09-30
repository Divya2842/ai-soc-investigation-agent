# AI-Powered SOC Investigation & IOC Enrichment Agent

A portfolio-grade backend application that simulates an AI-assisted Security
Operations Center (SOC) workflow: alert ingestion → IOC extraction → IOC
enrichment → log correlation → MITRE ATT&CK / ATLAS mapping → LLM-assisted
investigation → deterministic risk scoring → human-approved response.

No Microsoft Sentinel subscription is required. The app runs entirely against
a local simulated SOC environment (JSONL sample data loaded into SQLite), and
is architected so a `SentinelLogSource` adapter can be dropped in later
without touching the agent or API layer.

> **Status: feature-complete per the original spec.** Local SOC data,
> deterministic IOC extraction/enrichment, MITRE ATT&CK + ATLAS mapping, a
> LangGraph agent backed by Groq (with a validated deterministic fallback
> when no API key is set), risk scoring, RAG over a local SOC knowledge
> base, human-approved response actions, a React/TypeScript/Tailwind
> dashboard, tests (47 passing), and Docker Compose are all implemented.
> See `docs/MILESTONES.md` for what shipped in each milestone.

## Why it's built this way

- **Evidence-driven, not vibes-driven.** The LLM never invents IOC
  reputations, MITRE technique IDs, or severities. Deterministic Python code
  extracts IOCs, enriches them, maps them to MITRE, and scores risk. The LLM
  only explains/summarizes what the deterministic layer already found — and
  if it's unavailable or its output fails validation, a deterministic-only
  summary is used instead so an investigation never fails outright.
- **Provider-agnostic LLM.** Groq is the only wired-up provider, but the
  client lives behind one module (`services/llm/`) and is swapped via
  `.env`, never hardcoded.
- **No paid dependencies required to run.** IOC enrichment defaults to a
  local/mock provider; external TI providers are optional and configured via
  environment variables. RAG uses a small dependency-free local retriever
  instead of a heavyweight vector DB (see `docs/ARCHITECTURE.md` §4 for why).
- **No destructive automation, ever.** Response actions are recommendations
  that a human must explicitly approve before they're (simulated and)
  logged — nothing is ever actually executed.

## Quick start

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
python -m app.database.seed        # loads sample SOC data + sample alerts
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs for the interactive API docs.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173 — the Vite dev server proxies `/api` and
`/health` to the backend on port 8000 (see `vite.config.ts`).

### Everything via Docker Compose

```bash
cp .env.example .env   # optionally set GROQ_API_KEY
docker compose up --build
```

Backend: http://127.0.0.1:8000 · Frontend: http://127.0.0.1:5173

### Run tests

```bash
cd backend
pytest -v
```

## Project layout

See `docs/ARCHITECTURE.md` for the full breakdown. Top level:

```
backend/     FastAPI app, LangGraph agent, services, models, schemas, tests
data/        Simulated SOC data, MITRE/ATLAS datasets, RAG knowledge base
docs/        Architecture, schema, API design, milestone plan
frontend/    React + TypeScript + Tailwind SOC analyst dashboard
docker-compose.yml
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full system architecture, data flow, agent graph, IOC enrichment design, ATT&CK/ATLAS design
- [`docs/DATABASE_SCHEMA.md`](docs/DATABASE_SCHEMA.md) — database schema
- [`docs/API_DESIGN.md`](docs/API_DESIGN.md) — REST API design
- [`docs/MILESTONES.md`](docs/MILESTONES.md) — development milestone plan and current status
- [`docs/SENTINEL_INTEGRATION.md`](docs/SENTINEL_INTEGRATION.md) — how Microsoft Sentinel would be plugged in later

## Limitations

- The LLM summary requires a Groq API key (`GROQ_API_KEY` in `.env`); without
  one, investigations still run to completion using the deterministic
  fallback summary — nothing about extraction, enrichment, MITRE mapping,
  risk scoring, or response recommendation depends on the LLM.
- RAG retrieval is a small local TF-IDF/cosine index over
  `data/knowledge_base/`, not Chroma/FAISS — see `docs/ARCHITECTURE.md` §4
  for the reasoning and how to swap it later.
- `SentinelLogSource` is a documented placeholder, not a working
  integration (see `docs/SENTINEL_INTEGRATION.md`) — this project doesn't
  require or fake a Sentinel subscription.
- Sample data is fictional and safe (no real malware, no real victim data).
- The frontend has been built and type-checks/builds cleanly, but hasn't
  been exercised against a running backend inside a browser in this
  environment — if something looks off, the backend's `/docs` (Swagger UI)
  is the ground truth for API behavior.

## Authentication and PostgreSQL
The application now has separate username/password authentication. Users register at `/register`; user profile data is stored in PostgreSQL and passwords are stored as PBKDF2-SHA256 salted hashes. Login returns an HS256 JWT, and all SOC API routes require `Authorization: Bearer <token>`.

Set `JWT_SECRET_KEY` and `POSTGRES_PASSWORD` in production. Threat reputation has no local/mock fallback: configure `VT_API_KEY` and/or `ABUSEIPDB_API_KEY`. If an enrichment field is unavailable, reports omit that field rather than inventing a value.
