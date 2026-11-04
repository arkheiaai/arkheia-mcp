# Admin sign-in and registry updates

Admin access requires a Google account whose email is verified and appears in the
configured allowlist. A Google account without explicit email verification is
refused with the existing generic access-denied response.

After this upgrade, all older admin sessions and admin bearer tokens require
fresh sign-in. Refresh tools that use an admin session token through the usual
credential-management process. Billing API keys are a separate credential and
are not rotated by this change. During a rolling upgrade, an old instance still
has the old session rules; replace every instance before confirming that old
sessions have been revoked.

Registry downloads must use the registry origin configured by the proxy:
scheme, host spelling and effective port must match. Equivalent default ports
and the HTTP client's normal domain-name encoding work; different textual IP
spellings and trailing-dot hostnames should be configured identically on both
sides. A registry download URL cannot add credentials, fragments or a foreign
origin, and the proxy will not follow a download redirect.

| Pull error | What clears it |
|---|---|
| `registry profile download URL refused` | Correct the advertised download URL to match the configured registry origin and supported URL format. |
| `registry profile download redirect refused` | Serve the profile directly at that origin rather than redirecting it. |
| `registry profile download failed` | Check the registry's availability and trusted server-side diagnostics. The client error omits the URL and transport exception text. |

An unsuccessful update retains the existing profile. Successful updates still
pass the existing checksum, schema, smoke-test and active-profile checks. Inspect
the pull result and its audit receipts rather than treating a missing receipt as
proof that nothing changed.

The registry server's advertised base URL must agree with the client setting.
After correcting a previously refused URL, use a full refresh/restart through
the normal operating procedure: the existing incremental watermark limitation
can prevent an unchanged failed profile from being offered again. This change
does not repair that separate retry limitation.

Do not put keys in download URLs. No live credential, signing key, configuration
or profile-encryption master key is changed by this source repair.
