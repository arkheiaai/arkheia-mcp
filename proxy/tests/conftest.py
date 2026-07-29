"""
Shared fixtures for the proxy test tier.

``key_server`` and ``isolated_key_cache`` were defined inside
``test_f20_profile_key_receipts.py``. The startup-ordering suite needs the same
live endpoint — a boot that actually FETCHES a key is the only boot that can show
a premature "these surfaces went dark" record — and a second copy of an HTTP
server is a second thing to drift. One definition, both suites.

The endpoint is a real ``http.server`` on a real socket, not a transport mock:
the recorded reason this flow's ``enforced`` axis failed was a required CI
context running green over a mocked integration.
"""
from __future__ import annotations

import base64
import http.server
import json
import threading

import pytest

from proxy.crypto.profile_crypto import DynamicKeyLoader


class _KeyEndpoint(http.server.BaseHTTPRequestHandler):
    #: Set per-test by ``key_server``.
    payload: bytes = b"{}"
    status: int = 200

    def do_POST(self):  # noqa: N802 — http.server's naming
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).payload)))
        self.end_headers()
        self.wfile.write(type(self).payload)

    def log_message(self, *args):  # silence the default stderr chatter
        pass


class _Server:
    def __init__(self, handler_cls):
        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def key_server():
    """A live endpoint. ``serve(key_bytes)`` / ``fail(status)`` reconfigure it."""
    server = _Server(_KeyEndpoint)

    class _Control:
        url = server.url

        @staticmethod
        def serve(key: bytes):
            _KeyEndpoint.status = 200
            _KeyEndpoint.payload = json.dumps(
                {"profile_key": base64.b64encode(key).decode()}
            ).encode()

        @staticmethod
        def fail(status: int = 503):
            _KeyEndpoint.status = status
            _KeyEndpoint.payload = b'{"error":"unavailable"}'

    try:
        yield _Control
    finally:
        server.close()


@pytest.fixture(autouse=True)
def isolated_key_cache(tmp_path, monkeypatch):
    """
    Point ``DynamicKeyLoader``'s cache at a temp dir for EVERY proxy test.

    Autouse and unconditional: ``fetch_key`` writes the cache on a successful
    hosted fetch, and a test suite that writes into the developer's real
    ``~/.arkheia`` is a test suite that has side effects on the machine it runs
    on. Also makes the cache branch drivable, which it otherwise is not.
    """
    cache_dir = tmp_path / "keycache"
    monkeypatch.setattr(DynamicKeyLoader, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(DynamicKeyLoader, "CACHE_FILE", cache_dir / "profile_key.cache")
    return cache_dir
