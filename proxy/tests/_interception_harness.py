"""
Wire harness for the /v1/* interception middleware.

WHY A REAL SERVER AND A RAW SOCKET
----------------------------------
``AIInterceptionMiddleware`` builds its destination by string concatenation::

    target_url = upstream_url.rstrip("/") + request.url.path

``request.url.path`` is ``scope["path"]``, which uvicorn fills from the raw
request-target after percent-decoding and **without removing dot segments**.
Every HTTP client library — ``TestClient`` included — removes dot segments
*before* the bytes leave the process, so an exploit written against a client
is normalised away and returns a false negative. The sibling flow (PR #31)
banked exactly that: a traversal that reached ``/admin/keys`` on the wire was
invisible to ``TestClient``.

So this harness drives a **real uvicorn process over a raw ``socket.socket``**
with a literal request line, and observes the destination at a **raw TCP sink**
that never normalises anything either. Both ends of the wire are unmediated.

WHAT THE SINK PROVES
--------------------
``RecordingSink`` is a raw asyncio TCP server running in the *test* process
(so its records are readable without IPC). It records the exact request line,
the exact header list (duplicates preserved, in order) and the body bytes.

Two sinks are used together:

* ``upstream``  — the sink named in ``ARKHEIA_UPSTREAM_URL``.
* ``attacker``  — a sink on a *different origin* that nothing should ever reach.

A cross-host claim is therefore asserted two ways at once: the ``Host:`` header
the proxy actually put on the wire (that IS the final host httpx resolved and
connected to), and ``attacker.requests == []``.
"""
from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Recorded request
# ---------------------------------------------------------------------------

@dataclass
class WireRequest:
    """One request exactly as it arrived on the socket. Nothing is normalised."""

    raw_head: bytes
    body: bytes

    @property
    def request_line(self) -> str:
        return self.raw_head.split(b"\r\n", 1)[0].decode("latin-1")

    @property
    def target(self) -> str:
        """The request-target: the middle field of the request line."""
        parts = self.request_line.split(" ")
        return parts[1] if len(parts) > 1 else ""

    @property
    def method(self) -> str:
        return self.request_line.split(" ")[0]

    @property
    def header_pairs(self) -> list[tuple[str, str]]:
        """All header pairs, lower-cased names, duplicates preserved in order."""
        out: list[tuple[str, str]] = []
        for line in self.raw_head.split(b"\r\n")[1:]:
            if not line:
                continue
            name, _, value = line.partition(b":")
            out.append((name.decode("latin-1").strip().lower(),
                        value.decode("latin-1").strip()))
        return out

    def header_values(self, name: str) -> list[str]:
        return [v for k, v in self.header_pairs if k == name.lower()]

    def header_names(self) -> list[str]:
        return [k for k, _ in self.header_pairs]

    @property
    def host(self) -> str:
        """The Host header — the final host httpx resolved and connected to."""
        vals = self.header_values("host")
        return vals[0] if vals else ""


# ---------------------------------------------------------------------------
# Raw TCP sink
# ---------------------------------------------------------------------------

@dataclass
class _Canned:
    status: int = 200
    reason: str = "OK"
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b'{"choices":[{"message":{"content":"Paris"}}]}'


class RecordingSink:
    """
    A raw TCP server that records what it receives verbatim and replies with a
    canned response. It is *not* an HTTP framework: it does no normalisation,
    no routing and no validation, so what ``requests`` holds is what left the
    proxy.
    """

    def __init__(self, host: str = "127.0.0.1", canned: Optional[_Canned] = None):
        self.host = host
        self.port: int = 0
        self.requests: list[WireRequest] = []
        self.canned = canned or _Canned()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._ready = threading.Event()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "RecordingSink":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=10):
            raise RuntimeError("RecordingSink failed to start")
        return self

    def stop(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "RecordingSink":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"

    # -- server ------------------------------------------------------------

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        coro = asyncio.start_server(self._handle, self.host, 0)
        self._server = self._loop.run_until_complete(coro)
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            self._server.close()
            self._loop.run_until_complete(self._server.wait_closed())
            self._loop.close()

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        except Exception:
            writer.close()
            return
        head = head[:-4]
        body = b""
        pairs = WireRequest(head, b"").header_pairs
        lengths = [v for k, v in pairs if k == "content-length"]
        chunked = any(k == "transfer-encoding" and "chunked" in v.lower()
                      for k, v in pairs)
        try:
            if chunked:
                # Read chunks so a CL.TE desync is observable rather than hanging.
                while True:
                    size_line = await asyncio.wait_for(reader.readline(), timeout=5)
                    size = int(size_line.strip().split(b";")[0] or b"0", 16)
                    if size == 0:
                        await asyncio.wait_for(reader.readline(), timeout=5)
                        break
                    body += await asyncio.wait_for(reader.readexactly(size), timeout=5)
                    await asyncio.wait_for(reader.readexactly(2), timeout=5)
            elif lengths:
                n = int(lengths[0])
                if n:
                    body = await asyncio.wait_for(reader.readexactly(n), timeout=5)
        except Exception:
            pass

        self.requests.append(WireRequest(head, body))

        c = self.canned
        out = [f"HTTP/1.1 {c.status} {c.reason}".encode("latin-1")]
        sent = {k.lower() for k, _ in c.headers}
        for k, v in c.headers:
            out.append(f"{k}: {v}".encode("latin-1"))
        if "content-length" not in sent:
            out.append(f"content-length: {len(c.body)}".encode("latin-1"))
        out.append(b"connection: close")
        writer.write(b"\r\n".join(out) + b"\r\n\r\n" + c.body)
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()


# ---------------------------------------------------------------------------
# The app under test, launched by uvicorn in a subprocess
# ---------------------------------------------------------------------------

def make_app():
    """
    uvicorn factory. Configured entirely through env vars so the parent process
    can shape the run without shipping objects across the process boundary.

      ARKH_T_UPSTREAM  — detection.upstream_url ("" => standalone mode)
      ARKH_T_RISK      — risk level the stub engine returns
      ARKH_T_ACTION    — detection.high_risk_action
      ARKH_T_ENGINE    — "none" to leave app.state.engine unset,
                         "raise" to make verify() blow up
      ARKH_T_AUDIT     — audit log path (enables the audit rail when set)
    """
    from datetime import datetime, timezone
    import uuid as _uuid

    from fastapi import FastAPI
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    from proxy.detection.engine import DetectionResult
    from proxy.middleware.interception import AIInterceptionMiddleware

    app = FastAPI()

    @app.post("/v1/chat/completions")
    async def chat():                                     # pragma: no cover
        return {"choices": [{"message": {"content": "local"}}]}

    @app.post("/v1/echo")
    async def echo(request: Request):                     # pragma: no cover
        # Proves whether the downstream route still receives the body after the
        # middleware consumed the stream with ``await request.body()``.
        raw = await request.body()
        return JSONResponse({"seen_body_len": len(raw), "seen_body": raw.decode("utf-8", "replace")})

    @app.get("/health")
    async def health():                                   # pragma: no cover
        return {"ok": True}

    app.add_middleware(AIInterceptionMiddleware)

    risk = os.environ.get("ARKH_T_RISK", "LOW")

    class _Engine:
        async def verify(self, prompt, response, model_id):
            if os.environ.get("ARKH_T_ENGINE") == "raise":
                raise RuntimeError("simulated engine crash")
            return DetectionResult(
                risk_level=risk,
                confidence=0.8,
                features_triggered=["unique_word_ratio"],
                model_id=model_id,
                profile_version="1.0",
                timestamp=datetime.now(timezone.utc).isoformat(),
                detection_id=str(_uuid.uuid4()),
            )

    class _Detection:
        upstream_url = os.environ.get("ARKH_T_UPSTREAM", "")
        high_risk_action = os.environ.get("ARKH_T_ACTION", "warn")
        unknown_action = "pass"

    class _Settings:
        detection = _Detection()

    app.state.settings = _Settings()
    app.state.engine = None if os.environ.get("ARKH_T_ENGINE") == "none" else _Engine()

    audit_path = os.environ.get("ARKH_T_AUDIT", "")
    if audit_path:
        from proxy.audit.writer import AuditWriter

        writer = AuditWriter(log_path=audit_path)

        @app.on_event("startup")
        async def _start_audit():                          # pragma: no cover
            await writer.start()

        @app.on_event("shutdown")
        async def _stop_audit():                           # pragma: no cover
            await writer.stop()

        app.state.audit_writer = writer

    return app


# ---------------------------------------------------------------------------
# uvicorn subprocess
# ---------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ProxyServer:
    """A real uvicorn process serving the interception app."""

    def __init__(self, **env: str):
        self.port = _free_port()
        self.env = env
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> "ProxyServer":
        env = dict(os.environ)
        env.update({k: v for k, v in self.env.items()})
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        env.setdefault("JWT_SECRET", "harness-secret-not-for-production-use-32chars!!")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn",
             "proxy.tests._interception_harness:make_app",
             "--factory", "--host", "127.0.0.1", "--port", str(self.port),
             "--log-level", "warning"],
            cwd=str(REPO_ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out = self.proc.stdout.read().decode("utf-8", "replace") if self.proc.stdout else ""
                raise RuntimeError(f"uvicorn died on startup:\n{out}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("uvicorn did not come up")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:      # pragma: no cover
                self.proc.kill()
                self.proc.wait(timeout=5)

    def __enter__(self) -> "ProxyServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Raw socket client — writes the literal request line, normalises nothing
# ---------------------------------------------------------------------------

def raw_request(
    port: int,
    target: str,
    method: str = "POST",
    body: bytes = b'{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}',
    extra_headers: Optional[list[tuple[str, str]]] = None,
    omit_content_length: bool = False,
    timeout: float = 15.0,
) -> tuple[bytes, int, list[tuple[str, str]], bytes]:
    """
    Send ``method target HTTP/1.1`` with the target byte-for-byte as given.

    Returns (raw_response, status_code, response_header_pairs, response_body).
    """
    lines = [f"{method} {target} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
    have = {n.lower() for n, _ in (extra_headers or [])}
    if "content-type" not in have:
        lines.append("Content-Type: application/json")
    if not omit_content_length and "content-length" not in have:
        lines.append(f"Content-Length: {len(body)}")
    for n, v in (extra_headers or []):
        lines.append(f"{n}: {v}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(head + body)
        chunks = []
        while True:
            try:
                buf = s.recv(65536)
            except socket.timeout:                         # pragma: no cover
                break
            if not buf:
                break
            chunks.append(buf)
    raw = b"".join(chunks)

    head_bytes, _, resp_body = raw.partition(b"\r\n\r\n")
    first, _, rest = head_bytes.partition(b"\r\n")
    try:
        status = int(first.split(b" ")[1])
    except Exception:                                      # pragma: no cover
        status = 0
    pairs: list[tuple[str, str]] = []
    for line in rest.split(b"\r\n"):
        if not line:
            continue
        n, _, v = line.partition(b":")
        pairs.append((n.decode("latin-1").strip().lower(), v.decode("latin-1").strip()))

    # Un-chunk if the server framed it that way, so callers compare payloads.
    if any(n == "transfer-encoding" and "chunked" in v.lower() for n, v in pairs):
        out = b""
        rem = resp_body
        while True:
            size_line, _, rem = rem.partition(b"\r\n")
            try:
                size = int(size_line.split(b";")[0] or b"0", 16)
            except ValueError:                             # pragma: no cover
                break
            if size == 0:
                break
            out += rem[:size]
            rem = rem[size + 2:]
        resp_body = out

    return raw, status, pairs, resp_body


def resp_header(pairs: list[tuple[str, str]], name: str) -> Optional[str]:
    for n, v in pairs:
        if n == name.lower():
            return v
    return None
