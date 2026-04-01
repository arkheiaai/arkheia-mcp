# Agent 2: Wire Install Provisioning + DynamicKeyLoader Startup

## Repo: C:\arkheia-mcp

## Context
The MCP server installs via `npx @arkheia/mcp-server` but does not provision an API key.
Without a key, the server can't call the hosted detection endpoint or fetch profile decryption keys.
The DynamicKeyLoader class exists but isn't wired into the server startup.

## Task 1: Install-time key provisioning

**File:** `C:\arkheia-mcp\npm-wrapper\scripts\setup.js`

**Current behavior:** Checks for Python, prints instructions.
**New behavior:** After Python check, also:

1. Check if `~/.arkheia/config.json` exists and has `api_key`
2. If not, prompt: "Enter your Arkheia API key (get one free at arkheia.ai/signup), or press Enter to auto-provision:"
3. If Enter (empty), call `POST https://arkheia-proxy-production.up.railway.app/v1/provision` with a generated email placeholder
4. Save the returned `ak_live_...` key to `~/.arkheia/config.json`
5. Print: "API key provisioned and saved to ~/.arkheia/config.json"

**Config format:**
```json
{
  "api_key": "ak_live_...",
  "proxy_url": "https://arkheia-proxy-production.up.railway.app",
  "provisioned_at": "2026-04-01T12:00:00Z"
}
```

## Task 2: Load config on startup

**File:** `C:\arkheia-mcp\npm-wrapper\bin\arkheia-mcp.js`

Before spawning the Python process, read `~/.arkheia/config.json` and inject:
- `ARKHEIA_API_KEY` into child process env
- `ARKHEIA_HOSTED_URL` into child process env

## Task 3: Wire DynamicKeyLoader into proxy startup

**File:** `C:\arkheia-mcp\proxy\main.py`

In the lifespan startup, after ProfileRouter is created:

```python
# Check for encrypted profiles that need a key
enc_files = list(Path(settings.detection.profile_dir).glob("*.yaml.enc"))
if enc_files and not profile_router._decryption_key:
    api_key = os.getenv("ARKHEIA_API_KEY", "")
    if api_key:
        from proxy.crypto.profile_crypto import DynamicKeyLoader
        loader = DynamicKeyLoader(
            hosted_url=os.getenv("ARKHEIA_HOSTED_URL", "https://arkheia-proxy-production.up.railway.app"),
            api_key=api_key,
        )
        key = loader.fetch_key()
        if key:
            profile_router.set_decryption_key(key)
            logger.info("Decryption key loaded — %d encrypted profiles available", profile_router.loaded_count)
        else:
            logger.warning("Could not fetch decryption key — encrypted profiles unavailable")
    else:
        logger.warning("Encrypted profiles found but no ARKHEIA_API_KEY — set key or provide decryption_key")
```

## Task 4: Test Plan

### Unit tests (file: `tests/test_install_provisioning.py`)

1. **test_config_created_on_first_run** — run setup logic, verify ~/.arkheia/config.json created
2. **test_config_not_overwritten** — if config exists with key, setup doesn't overwrite
3. **test_config_loaded_into_env** — verify ARKHEIA_API_KEY injected into subprocess env

### Unit tests (file: `tests/test_dynamic_key_startup.py`)

4. **test_startup_fetches_key_when_enc_files_exist** — mock DynamicKeyLoader.fetch_key, verify set_decryption_key called
5. **test_startup_skips_when_no_enc_files** — no .yaml.enc files, DynamicKeyLoader not instantiated
6. **test_startup_skips_when_no_api_key** — enc files exist but no ARKHEIA_API_KEY, warning logged
7. **test_startup_degrades_when_key_fetch_fails** — fetch_key returns None, profiles unavailable, server still starts

### Integration test

8. **test_full_startup_with_encrypted_profiles** — create temp dir with .yaml.enc, set env vars, verify profiles load

## Verification
```bash
pytest tests/test_install_provisioning.py tests/test_dynamic_key_startup.py -v
```
