# app/tools

Reserved for future standalone tool-call wrappers if the agent graph in
`agents/investigation_graph.py` is refactored into an LLM-driven
tool-calling loop (see `docs/MILESTONES.md` → "Possible next steps").

Currently, the deterministic capabilities the spec calls "tools"
(`search_logs`, `enrich_ip`, `map_mitre_attack`, `calculate_risk`, etc.)
are called directly from each LangGraph node in `agents/investigation_graph.py`,
with access restricted per-node by `agents/tool_permissions.py`. That
keeps the orchestration simple and fully auditable for this project's
scope; this directory is where they'd move if/when the LLM is given a
genuine tool-selection loop instead of the current fixed pipeline.
