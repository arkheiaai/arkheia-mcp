# Fabrication Detection — Arkheia

When Arkheia MCP tools are available in this session, follow this protocol.

## Detection

Call `arkheia_verify` on EVERY model response before surfacing it to the user. Do not skip responses that appear obviously correct.

## Risk Escalation

- **HIGH risk**: Warn the user that the response may be fabricated. Include the `detection_id`. Still show the response — never hide or suppress it. Ask the user if they want to verify with a different model.
- **MEDIUM risk**: Show the response with a brief confidence note.
- **LOW risk**: Show normally.
- **UNKNOWN risk**: Flag for human review. Include the `detection_id`.

## Cross-Model Verification

When HIGH or UNKNOWN risk is detected, offer to verify using: `run_grok`, `run_gemini`, `run_ollama`, `run_together`.

## Audit Trail

Use `arkheia_audit_log` when the user asks about detection history or for compliance evidence.

## Persistent Knowledge Graph

Use `memory_store` to persist facts, `memory_retrieve` to recall them, `memory_relate` to track relationships between entities.

## Key Rules

1. Never hide a response from the user regardless of risk level
2. Always include the `detection_id` when reporting HIGH or UNKNOWN risk
3. Call `arkheia_verify` proactively — do not wait for the user to ask
4. Audit logging happens automatically through `arkheia_verify`
