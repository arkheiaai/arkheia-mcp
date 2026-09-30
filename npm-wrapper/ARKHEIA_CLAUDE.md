# Arkheia Integration — Detection Protocol

When Arkheia MCP tools are available in this session, follow this protocol.

## Fabrication Detection

Call `arkheia_verify` on EVERY model response before surfacing it to the user. Do not skip responses that appear obviously correct.

```
arkheia_verify(prompt=<original prompt>, response=<model output>, model=<model id>)
```

## Risk Escalation

- **HIGH risk**: Warn the user that the response may be fabricated. Include the `detection_id`. Still show the response — never hide or suppress it. Ask the user if they want you to verify with a different model.
- **MEDIUM risk**: Show the response with a brief confidence note (e.g. "Arkheia flagged this at medium confidence").
- **LOW risk**: Show normally. No annotation needed.
- **UNKNOWN risk**: Flag for human review. Include the `detection_id` in your response.

## Cross-Model Verification

When a HIGH or UNKNOWN risk is detected, offer to verify using a different model:
- `run_grok` — xAI Grok
- `run_gemini` — Google Gemini
- `run_ollama` — local Ollama model (no network egress)
- `run_together` — Together AI (Kimi K2.5, DeepSeek)

Compare the alternative response against the original. If they diverge significantly, escalate to the user.

## Audit Trail

Use `arkheia_audit_log` when the user asks about detection history or for compliance evidence. This provides structured event data with timestamps, risk levels, and detection IDs.

## Persistent Knowledge Graph

Use the memory tools to store facts discovered during sessions:
- `memory_store(name, entity_type, observations)` — remember entities and facts
- `memory_retrieve(query)` — recall stored knowledge
- `memory_relate(from_entity, relation_type, to_entity)` — track relationships

Store entities when you learn something the user would want persisted across sessions (contacts, decisions, bugs, architectural patterns).

## Key Rules

1. Never hide a response from the user regardless of risk level
2. Always include the `detection_id` when reporting HIGH or UNKNOWN risk
3. Call `arkheia_verify` proactively — do not wait for the user to ask
4. Audit logging happens automatically through `arkheia_verify` — no extra action needed
