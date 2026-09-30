# MITRE ATLAS Reference Notes

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence
Systems) catalogs adversary techniques specifically targeting AI/ML
systems -- it is a distinct framework from ATT&CK, not a subset of it.

## When ATLAS applies
Only when there is direct evidence of AI/ML/LLM-related activity, such
as:
- Prompt injection attempts against an LLM application (e.g. text
  instructing the model to ignore its system prompt).
- Attempts to extract a model's system prompt or configuration.
- Abuse of an LLM agent's tool/plugin-calling capability outside its
  intended scope.
- Data poisoning or adversarial-example crafting against a trained
  model.
- Sensitive data exposure through an AI application's outputs.

## When ATLAS does NOT apply
Traditional SOC alerts -- PowerShell abuse, credential dumping, phishing,
brute force, C2 beaconing -- have no AI/ML component and should receive
no ATLAS mapping. The correct output in that case is the explicit
statement "No relevant MITRE ATLAS technique identified," not a forced
or approximate mapping.
