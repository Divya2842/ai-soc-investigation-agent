# data/threat_intelligence

Reserved for future flat-file threat-intel feeds (e.g. a bulk IOC
blocklist to bulk-load into the local mock provider). Currently, the
local/mock threat-intel lookup tables live directly in
`backend/app/services/ioc/enrichment/local_mock.py` since the curated set
is small enough to be self-documenting as code. If the lookup table grows
significantly, move it to a JSON/CSV file here and have
`local_mock.py` load it, the same pattern used for
`data/mitre/attack_techniques.json` and `data/atlas/atlas_techniques.json`.
