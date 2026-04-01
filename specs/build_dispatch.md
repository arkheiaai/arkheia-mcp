# MCP Commercial Protection — Build Dispatch Plan

## Agent Assignments

| # | Task | Agent | Repo | Est. |
|---|------|-------|------|------|
| 1 | Mount `/v1/detect` on Railway | **Gemini** | arkheia-proxy | 1h |
| 2 | Build `/v1/profile-key` endpoint | **Grok** | arkheia-proxy | 1.5h |
| 3 | Wire MCP install to provision `ak_live_` key | **Kimi** | arkheia-mcp | 1h |
| 4 | Wire DynamicKeyLoader into MCP server startup | **Codex** | arkheia-mcp | 1h |
| 5 | Cython build config + setup_cython.py | **Claude agent** | arkheia-mcp | 1.5h |
| 6 | Build release pipeline (compile+encrypt+sign) | **Claude agent** | arkheia-mcp | 1h |
| 7 | End-to-end install test on clean machine | **Manual** | cross-repo | after 1-6 |

## Dependencies
- Task 2 depends on Task 1 (profile-key endpoint needs detect infrastructure)
- Task 4 depends on Task 2 (DynamicKeyLoader calls profile-key endpoint)
- Task 3 is independent (install provisioning uses existing /v1/provision)
- Tasks 5-6 are independent (build tooling, no runtime deps)
- Task 7 depends on ALL of 1-6

## Parallel execution
- Wave 1 (NOW): Tasks 1, 3, 5, 6 — all independent
- Wave 2 (after Task 1): Task 2
- Wave 3 (after Task 2): Task 4
- Wave 4 (after all): Task 7
