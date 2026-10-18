# Fabrication Detection — Arkheia

This project uses Arkheia for runtime fabrication detection.
The `arkheia_verify` MCP tool is available in every conversation. Treat Arkheia findings as an intervention signal, not passive telemetry.

## Detection Intervention Protocol

If a live Arkheia hook, proxy header, or MCP-runner result surfaces a detection alert, act on it before relying on the flagged output.

If no live hook is installed and only the MCP tool is available, use `arkheia_verify` for high-stakes answers, external actions, code changes that will be committed/deployed, and factual claims the user is likely to rely on. Do not run a blanket end-of-answer check when live detection has already scored the response.

### Risk Handling
- **LOW**: Continue normally.
- **MEDIUM**: Pause risky action. Verify material claims against code, docs, sources, or user-provided context before editing, committing, deploying, or presenting the claim as settled. Tell the user what was checked if the alert affected the answer.
- **HIGH**: Stop autonomous action. Do not merge, deploy, send externally, or present the flagged output as reliable. Identify the suspicious claim(s), verify against primary context, then either correct/regenerate or escalate to the user with the detection result and recommended next step.
- **UNKNOWN / evidence-limited / detection-off**: Treat as unscored, not safe. Do not upgrade autonomy based on silence. Increase verification depth or ask the user before taking irreversible action.

### Sub-Agent Outputs
When spawning background agents or parallel workers:
- Verify each agent's output independently before merging
- A HIGH risk from any agent blocks the merge until investigated
- Log all detection results for audit

### User-Facing Language
When an alert changes your behaviour, narrate the intervention lifecycle explicitly and briefly:
- Investigating: "Investigating HIGH alert before I rely on that output."
- Reworking: "The alert showed a critical finding, so I am reworking the original answer with stronger grounding."
- Confirmed issue: "HIGH alert looks genuine: I appear to have invented or mislocated `<claim/artifact>`. Please point me to the correct repo/doc/source if you have it, otherwise I will proceed without relying on that claim."
- False positive: "False positive after investigation: `<claim>` is supported by `<source/context>`, so I am carrying on."
- Medium risk: "Arkheia flagged this as MEDIUM, so I verified the material claims before proceeding."
- Detection unavailable: "Detection is off or evidence-limited here, so this is not an all-clear."

Do not just say "HIGH detected" and continue. The user should be able to see whether the agent is investigating, correcting, asking for missing grounding, or closing the alert as false positive.

### What NOT to Do
- Do not skip verification because the response "looks correct"
- Do not suppress HIGH findings — the user needs to know
- Do not retry the same prompt expecting a different risk score — the fingerprint is consistent
- Do not treat missing detection as LOW risk
