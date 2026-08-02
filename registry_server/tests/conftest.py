"""
Suite hermeticity for `registry_server/tests`.

Auth-decision receipts are ON BY DEFAULT (that is the point — a guard whose
default is off is not a guard), and the default receipt path is
package-relative, i.e. the repo root. So the moment `require_auth` began
emitting receipts, EVERY test that starts a `TestClient(app)` — including the
pre-existing `test_registry_server.py`, which knows nothing about receipts —
started appending a real audit log to the checkout.

That is a genuine defect introduced by the receipt work, not a test-authoring
oversight: the pollution comes from the production default, so the fix belongs
somewhere every test in this package inherits rather than in each test file.
Doing it here also means `registry_server/tests/test_registry_server.py` — the
file PR #13 is editing — does not need to be touched at all.

Individual modules still set `ARKHEIA_REGISTRY_AUDIT_LOG` explicitly where they
read the artifact back; this only provides the floor.
"""

import pytest


@pytest.fixture(autouse=True)
def _receipts_never_touch_the_checkout(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "ARKHEIA_REGISTRY_AUDIT_LOG", str(tmp_path / "registry_audit.jsonl")
    )
