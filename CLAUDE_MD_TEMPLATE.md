# Fabrication Detection — Arkheia

This project uses Arkheia for runtime fabrication detection.
The `arkheia_verify` MCP tool is available in every conversation.

## Verification Protocol

Before presenting any substantive response to the user:
1. Call `arkheia_verify` with the model name, prompt, and response
2. Check the `risk_level` field in the result

**For a fuller assessment:** pass the provider's full response object to `arkheia_verify` as `provider_response`, exactly as received, and enable your provider's detailed output option when you call the model.

### Risk Handling
- **LOW**: Present normally
- **MEDIUM**: Present with caveat — "Arkheia raised a warning on this response. Key claims should be verified."
- **HIGH**: Do not present as-is. Investigate the specific claims against known sources. If claims cannot be verified, regenerate or escalate to the user with the detection result.
- **NOT_ASSESSED** (or UNKNOWN): Not a clean result. Verify by other means and include the `detection_id`. If `candidate_alert` is MEDIUM or HIGH, check the specific claims now.

### Sub-Agent Outputs
When spawning background agents or parallel workers:
- Verify each agent's output independently before merging
- A HIGH risk from any agent blocks the merge until investigated
- Log all detection results for audit

### What NOT to Do
- Do not skip verification because the response "looks correct"
- Do not suppress HIGH findings — the user needs to know
- Do not retry the same prompt hoping for a different result
