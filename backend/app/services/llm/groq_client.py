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


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
You are a SOC investigation assistant.

You receive a JSON object named EVIDENCE.

The evidence was collected by deterministic security tools, including:

- IOC extraction
- IOC enrichment
- log analysis
- MITRE ATT&CK mapping
- MITRE ATLAS mapping
- deterministic risk scoring

Your job is to create an analyst-readable investigation narrative using
ONLY the supplied evidence.


============================================================
EVIDENCE SAFETY RULES
============================================================

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

5. Every finding must be supported by supplied evidence.

6. MITRE ATT&CK techniques must come ONLY from:

   EVIDENCE["mitre_attack_matches"]

7. MITRE ATLAS techniques must come ONLY from:

   EVIDENCE["mitre_atlas_matches"]

8. If no MITRE ATLAS techniques are present, return:

   "atlas_techniques": []

9. Do not modify technique IDs supplied in EVIDENCE.

10. If an IOC reputation is clean, unknown, or unavailable,
    do not describe that IOC as malicious.

11. If evidence is insufficient to prove malicious intent,
    clearly state that conclusion.


============================================================
OUTPUT RULES
============================================================

Return EXACTLY ONE JSON object.

Do NOT use Markdown.

Do NOT use ```json code fences.

Do NOT include explanatory text before the JSON.

Do NOT include explanatory text after the JSON.

Do NOT return multiple JSON objects.

Do NOT include JSON comments.

Use double quotes for JSON property names.

Use double quotes for JSON string values.

Do NOT include trailing commas.


============================================================
REQUIRED TOP-LEVEL SCHEMA
============================================================

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


============================================================
SEVERITY
============================================================

severity MUST be exactly one of:

"low"
"medium"
"high"
"critical"


============================================================
CONFIDENCE
============================================================

confidence MUST be a JSON number between 0.0 and 1.0.

Example:

"confidence": 0.85

Do NOT return confidence as a string.


============================================================
SUMMARY
============================================================

summary MUST be a string.

Write the summary as a concise SOC analyst narrative.

Explain:

- what was observed
- what evidence was collected
- IOC enrichment results
- relevant ATT&CK / ATLAS mappings
- why the evidence matters
- what should be reviewed next

Do not exaggerate the evidence.


============================================================
FINDINGS
============================================================

findings MUST be an array of objects.

Each finding MUST use exactly this structure:

[
  {
    "statement": "string",
    "evidence": [
      "evidence string",
      "evidence string"
    ]
  }
]

IMPORTANT:

The "evidence" field INSIDE each finding MUST also be an array
of strings.

Do NOT place JSON objects inside a finding's evidence array.


============================================================
TOP-LEVEL EVIDENCE
============================================================

The TOP-LEVEL "evidence" field MUST be an array of STRINGS.

Correct:

"evidence": [
  "Source IP 10.10.12.4 was observed in the alert.",
  "Destination IP 10.10.1.30 was observed in correlated logs.",
  "No malicious IOC reputation was returned by enrichment."
]

INCORRECT:

"evidence": [
  {
    "ioc_value": "10.10.12.4",
    "reputation": "unknown"
  }
]

Never put dictionaries, objects, arrays, numbers, or booleans
inside the top-level evidence array.

Convert structured evidence into concise human-readable strings.


============================================================
MITRE ATT&CK TECHNIQUES
============================================================

attack_techniques MUST be an array.

Every entry MUST use this structure:

[
  {
    "technique_id": "string",
    "name": "string",
    "tactic": "string",
    "rationale": "string",
    "supporting_evidence": [
      "string"
    ]
  }
]

supporting_evidence MUST be an array of strings.

Only use ATT&CK techniques supplied in:

EVIDENCE["mitre_attack_matches"]


============================================================
MITRE ATLAS TECHNIQUES
============================================================

atlas_techniques MUST use the same object structure:

[
  {
    "technique_id": "string",
    "name": "string",
    "tactic": "string",
    "rationale": "string",
    "supporting_evidence": [
      "string"
    ]
  }
]

supporting_evidence MUST be an array of strings.

Only use ATLAS techniques supplied in:

EVIDENCE["mitre_atlas_matches"]

If no ATLAS mappings exist, return:

"atlas_techniques": []


============================================================
RECOMMENDED ACTIONS
============================================================

recommended_actions MUST be an array of strings.

Correct:

"recommended_actions": [
  "Review authentication activity for the affected user.",
  "Validate whether the observed WMI activity was authorized."
]

Incorrect:

"recommended_actions": [
  {
    "action": "Review authentication activity"
  }
]


============================================================
FINAL CHECK
============================================================

Before returning the response, verify:

1. There is exactly ONE top-level JSON object.

2. It contains:

   verdict
   severity
   confidence
   summary
   findings
   evidence
   attack_techniques
   atlas_techniques
   recommended_actions

3. top-level evidence contains STRINGS ONLY.

4. finding evidence contains STRINGS ONLY.

5. supporting_evidence contains STRINGS ONLY.

6. recommended_actions contains STRINGS ONLY.

7. severity is low, medium, high, or critical.

8. confidence is a number between 0.0 and 1.0.

9. All braces and brackets are properly closed.

10. No text exists outside the JSON object.

Return JSON only.
""".strip()


# ============================================================
# REQUIRED TOP-LEVEL FIELDS
# ============================================================

REQUIRED_TOP_LEVEL_FIELDS = {
    "verdict",
    "severity",
    "confidence",
    "summary",
    "findings",
    "evidence",
    "attack_techniques",
    "atlas_techniques",
    "recommended_actions",
}


# ============================================================
# EXCEPTIONS
# ============================================================

class GroqNotConfiguredError(RuntimeError):
    """Raised when Groq is requested without an API key."""


class LLMOutputValidationError(RuntimeError):
    """Raised when the LLM response cannot be validated."""


# ============================================================
# CONFIGURATION
# ============================================================

def is_configured() -> bool:
    return settings.groq_configured


def _get_client():
    """
    Create the Groq client only when Groq is actually required.
    """

    if not settings.groq_configured:
        raise GroqNotConfiguredError(
            "GROQ_API_KEY is not set. "
            "Deterministic investigation can still run, "
            "but AI-authored summaries require Groq."
        )

    # Lazy import keeps Groq isolated to this module.
    from groq import Groq

    return Groq(
        api_key=settings.groq_api_key
    )


# ============================================================
# TOP-LEVEL OBJECT CHECK
# ============================================================

def _looks_like_investigation(
    value: Any,
) -> bool:
    """
    Return True only when the dictionary looks like the complete
    top-level InvestigationResult.

    This prevents a nested object such as:

        {
            "statement": "...",
            "evidence": [...]
        }

    from being mistaken for the full investigation response.
    """

    return (
        isinstance(value, dict)
        and REQUIRED_TOP_LEVEL_FIELDS.issubset(value.keys())
    )


# ============================================================
# JSON EXTRACTION
# ============================================================

def _extract_json(
    raw_text: str,
) -> dict[str, Any]:
    """
    Extract the complete top-level InvestigationResult JSON object.

    Handles:

    - pure JSON
    - accidental Markdown fences
    - text surrounding JSON
    - multiple JSON objects
    - nested JSON objects
    - trailing content

    The function deliberately does NOT attempt to repair invalid JSON.
    Invalid model output should be retried or rejected rather than
    silently modified.
    """

    if not raw_text:
        raise LLMOutputValidationError(
            "Groq returned an empty response."
        )

    text = raw_text.strip()

    # --------------------------------------------------------
    # Remove accidental Markdown fences.
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # ATTEMPT 1
    #
    # Try parsing the entire response first.
    # --------------------------------------------------------

    try:
        parsed = json.loads(text)

        if _looks_like_investigation(parsed):
            return parsed

    except json.JSONDecodeError:
        pass

    # --------------------------------------------------------
    # ATTEMPT 2
    #
    # Scan the response for independently valid JSON objects.
    #
    # JSONDecoder.raw_decode() tells us exactly where each JSON
    # object ends, preventing trailing content or a second JSON
    # object from corrupting the first.
    # --------------------------------------------------------

    decoder = json.JSONDecoder()

    search_position = 0
    last_json_error: json.JSONDecodeError | None = None
    valid_non_investigation_object_found = False

    while search_position < len(text):

        start = text.find(
            "{",
            search_position,
        )

        if start == -1:
            break

        candidate = text[start:]

        try:
            parsed, end_index = decoder.raw_decode(
                candidate
            )

            if _looks_like_investigation(parsed):
                return parsed

            if isinstance(parsed, dict):
                valid_non_investigation_object_found = True

            # Continue searching after this object's opening brace.
            #
            # We intentionally do not jump completely past the
            # object because a malformed outer object can sometimes
            # contain a valid complete investigation object.
            search_position = start + 1

        except json.JSONDecodeError as exc:

            last_json_error = exc

            # Move to the next possible opening brace.
            search_position = start + 1

    # --------------------------------------------------------
    # No complete InvestigationResult found.
    # --------------------------------------------------------

    if valid_non_investigation_object_found:
        raise LLMOutputValidationError(
            "Groq returned valid JSON object(s), but none contained "
            "all required InvestigationResult top-level fields: "
            f"{sorted(REQUIRED_TOP_LEVEL_FIELDS)}"
        )

    if last_json_error is not None:
        raise LLMOutputValidationError(
            "Could not find a complete InvestigationResult JSON object. "
            f"Last JSON error: {last_json_error}"
        ) from last_json_error

    raise LLMOutputValidationError(
        "Groq response did not contain a valid InvestigationResult "
        "JSON object."
    )


# ============================================================
# PYDANTIC VALIDATION
# ============================================================

def _validate_result(
    parsed: dict[str, Any],
) -> InvestigationResult:
    """
    Validate the model-generated JSON using the application's
    InvestigationResult Pydantic schema.

    We deliberately keep validation strict rather than changing the
    schema to accept arbitrary model output.
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


# ============================================================
# GROQ REQUEST
# ============================================================

def _call_groq(
    client,
    evidence: dict[str, Any],
    retry_instruction: str | None = None,
) -> str:
    """
    Make one Groq request.

    JSON parsing and Pydantic validation are performed locally.

    We intentionally do NOT use:

        response_format={"type": "json_object"}

    because provider-side JSON validation previously caused
    json_validate_failed errors.

    Local validation gives the application control over retries and
    deterministic fallback behavior.
    """

    evidence_json = json.dumps(
        evidence,
        default=str,
        ensure_ascii=False,
    )

    user_content = (
        "Generate the SOC investigation result using ONLY the "
        "following evidence.\n\n"
        "EVIDENCE:\n"
        f"{evidence_json}\n\n"
        "Return exactly ONE valid JSON object matching the required "
        "InvestigationResult schema and nothing else.\n\n"
        "Remember: the TOP-LEVEL evidence field MUST contain "
        "strings only."
    )

    if retry_instruction:

        user_content += (
            "\n\n"
            "IMPORTANT CORRECTION FOR THIS RETRY:\n"
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


# ============================================================
# RETRY INSTRUCTION
# ============================================================

STRICT_RETRY_INSTRUCTION = """
The previous response could not be validated.

Generate the complete investigation again from the supplied EVIDENCE.

Return EXACTLY ONE JSON object.

The TOP-LEVEL object MUST contain ALL of these fields:

- verdict
- severity
- confidence
- summary
- findings
- evidence
- attack_techniques
- atlas_techniques
- recommended_actions

Do not return an individual finding object as the top-level response.

TOP-LEVEL evidence MUST be an array of STRINGS ONLY.

For example:

"evidence": [
  "Source IP 10.10.12.4 was observed in the alert.",
  "Destination IP 10.10.1.30 appeared in correlated log evidence."
]

Do NOT return:

"evidence": [
  {
    "ioc_value": "10.10.12.4"
  }
]

Convert structured evidence objects into concise strings.

findings MUST be an array of objects containing:

{
  "statement": "string",
  "evidence": ["string"]
}

The evidence inside each finding MUST also contain strings only.

attack_techniques and atlas_techniques MUST contain objects with:

{
  "technique_id": "string",
  "name": "string",
  "tactic": "string",
  "rationale": "string",
  "supporting_evidence": ["string"]
}

supporting_evidence MUST contain strings only.

recommended_actions MUST contain strings only.

severity MUST be exactly one of:

"low"
"medium"
"high"
"critical"

confidence MUST be a JSON number between 0.0 and 1.0.

Do not use Markdown.

Do not use code fences.

Do not include comments.

Do not include explanations before the JSON.

Do not include explanations after the JSON.

Do not return multiple JSON objects.

Do not include trailing commas.

Make sure every object and array is properly closed.

Return the complete JSON object only.
""".strip()


# ============================================================
# INVESTIGATION GENERATION
# ============================================================

def generate_investigation_summary(
    evidence: dict[str, Any],
) -> InvestigationResult:
    """
    Generate an AI-authored investigation result.

    Flow:

        Deterministic Evidence
                ↓
              Groq
                ↓
        JSON Extraction
                ↓
       Top-Level Validation
                ↓
        Pydantic Validation
                ↓
      InvestigationResult

    If attempt 1 produces malformed or schema-invalid output,
    attempt 2 regenerates the complete response with stricter
    instructions.

    If both attempts fail, LLMOutputValidationError is raised.

    The investigation graph can then safely use the deterministic
    fallback.
    """

    client = _get_client()

    first_error: Exception | None = None

    # ========================================================
    # ATTEMPT 1
    # ========================================================

    try:

        raw_text = _call_groq(
            client=client,
            evidence=evidence,
        )

        parsed = _extract_json(
            raw_text
        )

        validated_result = _validate_result(
            parsed
        )

        print(
            "GROQ INVESTIGATION SUCCESS: "
            "AI investigation output validated successfully.",
            flush=True,
        )

        return validated_result

    except (
        LLMOutputValidationError,
        ValidationError,
        json.JSONDecodeError,
    ) as exc:

        first_error = exc

        print(
            "GROQ OUTPUT VALIDATION WARNING: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

    # ========================================================
    # ATTEMPT 2
    # ========================================================

    try:

        raw_text = _call_groq(
            client=client,
            evidence=evidence,
            retry_instruction=STRICT_RETRY_INSTRUCTION,
        )

        parsed = _extract_json(
            raw_text
        )

        validated_result = _validate_result(
            parsed
        )

        print(
            "GROQ INVESTIGATION SUCCESS AFTER RETRY: "
            "AI investigation output validated successfully.",
            flush=True,
        )

        return validated_result

    except Exception as exc:

        print(
            "GROQ RETRY ERROR: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

        raise LLMOutputValidationError(
            "Groq failed to produce a valid "
            "InvestigationResult after two attempts. "
            f"First error: {first_error}. "
            f"Second error: {exc}"
        ) from exc