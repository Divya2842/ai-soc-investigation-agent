"""
Single choke point for all Groq API calls in the application.

No other module should import the Groq SDK directly. This keeps the
LLM provider swappable and gives us one place to enforce structured
output validation and graceful failure.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from app.config.settings import settings
from app.schemas.investigation import InvestigationResult


SYSTEM_PROMPT = """
You are a SOC investigation assistant.

You receive a JSON object named EVIDENCE. The evidence was collected by
deterministic security tools, including:

- IOC extraction
- IOC enrichment
- log analysis
- MITRE ATT&CK mapping
- MITRE ATLAS mapping
- deterministic risk scoring

Your job is to create an analyst-readable investigation narrative using
ONLY the supplied evidence.

IMPORTANT RULES

1. Never invent security facts.

2. Never invent:
   - users
   - hosts
   - processes
   - commands
   - IP addresses
   - hashes
   - domains
   - threat actors
   - IOC reputations
   - MITRE ATT&CK techniques
   - MITRE ATLAS techniques

3. Follow:

   EVIDENCE -> ANALYSIS -> CONCLUSION

   Never:

   ALERT TYPE -> ASSUMPTION -> CONCLUSION

4. If important information is unavailable, use:

   "Not available in the collected evidence."

5. Every finding must be supported by evidence.

6. MITRE ATT&CK techniques must come only from:
   EVIDENCE["mitre_attack_matches"]

7. MITRE ATLAS techniques must come only from:
   EVIDENCE["mitre_atlas_matches"]

8. If no ATLAS techniques exist, return:

   "atlas_techniques": []

9. Do not change technique IDs supplied in EVIDENCE.

10. Do not use Markdown.

11. Do not wrap the response in ```json fences.

12. Return ONE JSON object only.

The JSON object MUST contain exactly these top-level fields:

{
  "verdict": "string",
  "severity": "low",
  "confidence": 0.0,
  "summary": "string",
  "findings": [],
  "evidence": [],
  "attack_techniques": [],
  "atlas_techniques": [],
  "recommended_actions": []
}

Allowed severity values:

"low"
"medium"
"high"
"critical"

confidence must be a number from 0.0 to 1.0.

findings must use this structure:

[
  {
    "statement": "string",
    "evidence": ["string"]
  }
]

attack_techniques must use this structure:

[
  {
    "technique_id": "string",
    "name": "string",
    "tactic": "string",
    "rationale": "string",
    "supporting_evidence": ["string"]
  }
]

atlas_techniques must use the same structure.

recommended_actions must be an array of strings.

SUMMARY REQUIREMENTS

Write the summary as a concise SOC analyst narrative.

Explain:

- what was observed
- what evidence was collected
- IOC enrichment results
- relevant ATT&CK/ATLAS mappings
- why the evidence matters
- what should be reviewed next

Do not exaggerate the evidence.

If an IOC reputation is clean, do not describe that IOC as malicious.

If evidence is insufficient to prove malicious intent, clearly say so.

Return JSON only.
""".strip()


class GroqNotConfiguredError(RuntimeError):
    """Raised when Groq is requested without an API key."""


class LLMOutputValidationError(RuntimeError):
    """Raised when the LLM response cannot be validated."""


def is_configured() -> bool:
    return settings.groq_configured


def _get_client():
    if not settings.groq_configured:
        raise GroqNotConfiguredError(
            "GROQ_API_KEY is not set. "
            "Deterministic investigation can still run, "
            "but AI-authored summaries require Groq."
        )

    # Lazy import so the application does not require Groq
    # unless AI generation is actually used.
    from groq import Groq

    return Groq(
        api_key=settings.groq_api_key
    )


def _extract_json(raw_text: str) -> dict[str, Any]:
    """
    Extract a JSON object from the model response.

    Normally the model should return pure JSON. This function also
    tolerates accidental ```json fences or small amounts of surrounding
    text.
    """

    if not raw_text:
        raise LLMOutputValidationError(
            "Groq returned an empty response."
        )

    text = raw_text.strip()

    # Remove accidental Markdown code fences.
    text = re.sub(
        r"^```(?:json)?\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"\s*```$",
        "",
        text,
    )

    text = text.strip()

    # First try normal JSON parsing.
    try:
        parsed = json.loads(text)

        if not isinstance(parsed, dict):
            raise LLMOutputValidationError(
                "Groq response was valid JSON but was not a JSON object."
            )

        return parsed

    except json.JSONDecodeError:
        pass

    # If the model accidentally included surrounding text,
    # extract the outer JSON object.
    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise LLMOutputValidationError(
            "Could not find a JSON object in the Groq response."
        )

    candidate = text[start:end + 1]

    try:
        parsed = json.loads(candidate)

    except json.JSONDecodeError as exc:
        raise LLMOutputValidationError(
            f"Model did not return valid JSON: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        raise LLMOutputValidationError(
            "Groq response was not a JSON object."
        )

    return parsed


def _validate_result(
    parsed: dict[str, Any],
) -> InvestigationResult:
    """
    Validate Groq JSON against the application's
    InvestigationResult Pydantic schema.
    """

    try:
        return InvestigationResult.model_validate(
            parsed
        )

    except ValidationError as exc:
        raise LLMOutputValidationError(
            "Model JSON did not match "
            f"InvestigationResult schema: {exc}"
        ) from exc


def _call_groq(
    client,
    evidence: dict[str, Any],
    retry_instruction: str | None = None,
) -> str:
    """
    Make one Groq request.

    JSON parsing/validation is intentionally handled locally instead
    of using response_format=json_object. This avoids provider-side
    json_validate_failed errors while still enforcing our Pydantic
    schema after generation.
    """

    evidence_json = json.dumps(
        evidence,
        default=str,
        ensure_ascii=False,
    )

    user_content = (
        "Generate the SOC investigation result using the "
        "following evidence.\n\n"
        "EVIDENCE:\n"
        f"{evidence_json}\n\n"
        "Return exactly one valid JSON object and nothing else."
    )

    if retry_instruction:
        user_content += (
            "\n\nIMPORTANT CORRECTION:\n"
            f"{retry_instruction}"
        )

    response = client.chat.completions.create(
        model=settings.groq_model,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_content,
            },
        ],
        temperature=0.0,
    )

    raw_text = (
        response.choices[0].message.content
        if response.choices
        else None
    )

    if not raw_text:
        raise LLMOutputValidationError(
            "Groq returned no response content."
        )

    return raw_text


def generate_investigation_summary(
    evidence: dict[str, Any],
) -> InvestigationResult:
    """
    Generate an AI-authored investigation result.

    Flow:

        Evidence
            ↓
        Groq
            ↓
        JSON extraction
            ↓
        Pydantic validation
            ↓
        InvestigationResult

    If the first generation is malformed, one additional generation
    is attempted with stricter JSON instructions.

    If both attempts fail, an LLMOutputValidationError is raised and
    the investigation graph can use its deterministic fallback.
    """

    client = _get_client()

    first_error: Exception | None = None

    # ---------------------------------------------------------
    # ATTEMPT 1
    # ---------------------------------------------------------

    try:

        raw_text = _call_groq(
            client=client,
            evidence=evidence,
        )

        parsed = _extract_json(
            raw_text
        )

        return _validate_result(
            parsed
        )

    except (
        LLMOutputValidationError,
        ValidationError,
        json.JSONDecodeError,
    ) as exc:

        first_error = exc

        print(
            f"GROQ OUTPUT VALIDATION WARNING: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

    # ---------------------------------------------------------
    # ATTEMPT 2
    # ---------------------------------------------------------

    try:

        raw_text = _call_groq(
            client=client,
            evidence=evidence,
            retry_instruction=(
                "The previous generation could not be validated. "
                "Return ONLY syntactically valid JSON. "
                "Do not use Markdown. "
                "Do not include comments. "
                "Do not include text before or after the JSON. "
                "Make sure every required field exists and all "
                "arrays and objects are properly closed."
            ),
        )

        parsed = _extract_json(
            raw_text
        )

        return _validate_result(
            parsed
        )

    except Exception as exc:

        print(
            f"GROQ RETRY ERROR: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

        raise LLMOutputValidationError(
            "Groq failed to produce a valid "
            "InvestigationResult after two attempts. "
            f"First error: {first_error}. "
            f"Second error: {exc}"
        ) from exc