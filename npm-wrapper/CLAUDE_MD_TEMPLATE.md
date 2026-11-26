# Fabrication Detection — Arkheia

When Arkheia MCP tools are available in this session, follow this protocol.

## Detection

Call `arkheia_verify` on EVERY model response before surfacing it to the user. Do not skip responses that appear obviously correct.

**For a fuller assessment:** pass the provider's full response object to `arkheia_verify` as `provider_response`, exactly as received, and enable your provider's detailed output option when you call the model.

## Risk Escalation

- **HIGH risk**: Warn the user that the response may be fabricated. Include the `detection_id`. Still show the response — never hide or suppress it. Ask the user if they want to verify with a different model.
- **MEDIUM risk**: Show the response with a brief note that Arkheia raised a warning.
- **LOW risk**: Show normally.
- **NOT_ASSESSED** (or UNKNOWN): Not a clean result. Verify by other means and include the `detection_id`. If `candidate_alert` is MEDIUM or HIGH, check the specific claims now.

## Cross-Model Verification

When HIGH, NOT_ASSESSED or UNKNOWN is returned, offer to verify using: `run_grok`, `run_gemini`, `run_ollama`, `run_together`.

## Audit Trail

Use `arkheia_audit_log` when the user asks about detection history or for compliance evidence.

## Persistent Knowledge Graph

Use `memory_store` to persist facts, `memory_retrieve` to recall them, `memory_relate` to track relationships between entities.

## Key Rules

1. Never hide a response from the user regardless of risk level
2. Always include the `detection_id` when reporting HIGH, NOT_ASSESSED or UNKNOWN
3. Call `arkheia_verify` proactively — do not wait for the user to ask
4. Audit logging happens automatically through `arkheia_verify`
