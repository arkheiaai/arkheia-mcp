# Agent 1: Fix Hosted URL + Build /v1/profile-key Endpoint

## Repo: C:\arkheia-proxy

## Context
The MCP server's proxy_client.py points to `https://app.arkheia.ai` (marketing site) instead of
`https://arkheia-proxy-production.up.railway.app` (actual API). Also, a new `/v1/profile-key`
endpoint is needed so MCP servers can fetch their profile decryption key at startup.

## Task 1: Fix hosted URL in MCP proxy_client.py

**File:** `C:\arkheia-mcp\mcp_server\proxy_client.py`
**Change:** Update `HOSTED_API_URL` from `https://app.arkheia.ai` to `https://arkheia-proxy-production.up.railway.app`

## Task 2: Build POST /v1/profile-key endpoint

**File to create:** `C:\arkheia-proxy\app\routers\profile_key.py`

**Spec:**
- Route: `POST /v1/profile-key`
- Auth: `verify_api_key` dependency (same as /v1/detect)
- Rate limit: 10 requests/hour per API key (custom, not the standard per-minute limiter)
- Request body: empty (key determined by API key tier)
- Response: `{ "profile_key": "<base64-encoded-32-byte-key>", "expires_at": "<ISO timestamp>" }`

**Logic:**
1. Validate API key via existing `verify_api_key`
2. Look up the profile master key from `ARKHEIA_PROFILE_MASTER_KEY` env var
3. If not set, return 503 with `{"error": "Profile encryption not configured"}`
4. Return the key base64-encoded with 24h expiry timestamp
5. Log the key fetch to usage tracking (provider="profile-key")

**Mount:** Add `app.include_router(profile_key.router)` in `app/main.py`

## Task 3: Test Plan

### Unit tests (file: `tests/test_profile_key.py`)

1. **test_profile_key_returns_key** — POST /v1/profile-key with valid API key returns 200, base64-decodable key, expires_at in future
2. **test_profile_key_no_auth** — POST without API key returns 401
3. **test_profile_key_no_master_key** — POST when ARKHEIA_PROFILE_MASTER_KEY unset returns 503
4. **test_profile_key_rate_limited** — 11 requests in a row, 11th returns 429
5. **test_profile_key_key_is_32_bytes** — decoded key is exactly 32 bytes

### Integration test
6. **test_mcp_proxy_client_hosted_url** — verify HOSTED_API_URL constant points to railway, not app.arkheia.ai

## Verification
```bash
# Unit tests
pytest tests/test_profile_key.py -v

# Manual Railway test (after deploy)
curl -X POST https://arkheia-proxy-production.up.railway.app/v1/profile-key \
  -H "X-Arkheia-Key: <YOUR_KEY_HERE>" | python -c "import sys,json,base64; d=json.load(sys.stdin); k=base64.b64decode(d['profile_key']); print(f'Key length: {len(k)} bytes')"
```
