"""Exercise the image ENV / Compose mount / registry write contract offline.

These tests do not certify Docker volume copy-up or runtime UID permissions.
Those require the separate deployment preflight described in docs.
"""
import hashlib
import os
import shlex
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import yaml
from pydantic import SecretStr

from proxy.registry.client import RegistryClient
from proxy.registry.validator import ProfileValidator
from proxy.tests.test_registry import VALID_PROFILE

ROOT = Path(__file__).resolve().parents[1]


def image_environment():
    values = {}
    for line in (ROOT / "proxy/Dockerfile").read_text().splitlines():
        if line.startswith("ENV "):
            for token in shlex.split(line[4:]):
                key, value = token.split("=", 1)
                values[key] = value
    return values


def effective_profile_dir(tmp_path):
    env = {
        "PATH": os.defpath, "HOME": str(tmp_path),
        "PYTHONDONTWRITEBYTECODE": "1", **image_environment(),
    }
    service = yaml.safe_load((ROOT / "docker-compose.yaml").read_text())["services"]["proxy"]
    for item in service["environment"]:
        key, value = item.split("=", 1)
        if key == "ARKHEIA_PROFILES_DIR":
            assert "${" not in value, "profile path interpolation needs an explicit test contract"
            env[key] = value
    result = subprocess.run(
        [sys.executable, "-c", "from proxy.config import settings; print(settings.detection.profile_dir)"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=15, check=True,
    )
    return PurePosixPath(result.stdout.strip())


def mount_for(service, path):
    matches = []
    for text in service["volumes"]:
        source, target, *mode = text.split(":")
        target = PurePosixPath(target)
        if path == target or target in path.parents:
            matches.append((len(target.parts), source, target, "ro" in mode))
    assert matches, f"no declared volume contains {path}"
    return max(matches)


def test_effective_proxy_profile_destination_is_durable_and_writable(tmp_path):
    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text())
    directory = effective_profile_dir(tmp_path)
    _, source, target, readonly = mount_for(compose["services"]["proxy"], directory)
    assert source == "profile_data", (directory, source)
    assert not readonly, (directory, source, "read-only")
    assert source in compose["volumes"]
    # ENV precedence is the original bug: the YAML fallback names another path.
    assert directory == PurePosixPath(image_environment()["ARKHEIA_PROFILES_DIR"])
    assert target == directory


def test_registry_source_stays_read_only_and_image_has_bootstrap_profiles():
    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text())
    _, source, _, readonly = mount_for(compose["services"]["registry"], PurePosixPath("/app/profiles"))
    assert source == "./profiles" and readonly
    copies = [shlex.split(line)[1:] for line in (ROOT / "proxy/Dockerfile").read_text().splitlines()
              if line.startswith("COPY ")]
    directory = PurePosixPath(image_environment()["ARKHEIA_PROFILES_DIR"])
    assert any(src == "profiles/" and PurePosixPath(dst) == directory for src, dst in copies)
    assert any((ROOT / "profiles").iterdir()), "image bootstrap source must be nonempty"


@pytest.mark.asyncio
async def test_real_registry_apply_writes_effective_proxy_volume_only(tmp_path, monkeypatch):
    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text())
    directory = effective_profile_dir(tmp_path)
    _, source, _, readonly = mount_for(compose["services"]["proxy"], directory)
    host_source = tmp_path / "registry-read-only-source"
    data_volume = tmp_path / "persistent-profile-data"
    host_source.mkdir(); data_volume.mkdir()
    original = host_source / "existing.yaml"
    original.write_text("synthetic registry source must remain unchanged\n")
    before = hashlib.sha256(original.read_bytes()).hexdigest()
    destination = data_volume if source == "profile_data" else host_source
    profile = dict(VALID_PROFILE)
    content = yaml.safe_dump(profile).encode()
    router = AsyncMock()
    router.get = MagicMock(return_value=profile)
    client = RegistryClient(
        base_url="http://registry.test", api_key=SecretStr("synthetic-fixture"),
        profile_dir=str(destination), router=router, validator=ProfileValidator(),
    )

    @asynccontextmanager
    async def offline_client(**kwargs):
        transport = httpx.MockTransport(lambda request: httpx.Response(200, content=content))
        async with httpx.AsyncClient(transport=transport) as http:
            yield http

    monkeypatch.setattr("proxy.registry.client.egress_async_client", offline_client)
    if readonly:
        destination.chmod(0o500)
    try:
        assert await client._download_and_apply({
            "model_id": profile["model"], "version": profile["version"],
            "checksum": hashlib.sha256(content).hexdigest(),
            "download_url": "http://registry.test/synthetic-profile",
        })
        _, path, _, _ = client._profile_paths(profile["model"])
        assert path.read_bytes() == content
        router.reload.assert_awaited_once()
        assert path.parent == data_volume
        assert hashlib.sha256(original.read_bytes()).hexdigest() == before
        assert list(host_source.iterdir()) == [original]
    finally:
        destination.chmod(0o700)


@pytest.mark.asyncio
@pytest.mark.parametrize("require_license", [False, True])
async def test_zero_inventory_requires_preflight_even_when_default_health_is_ok(
    tmp_path, monkeypatch, require_license,
):
    """Observe the existing branches; the mount repair adds no readiness policy."""
    import proxy.main as proxy_main
    from proxy.config import settings
    from proxy.endpoints.admin import health

    profiles = tmp_path / "empty-profiles"
    profiles.mkdir()
    monkeypatch.setattr(settings.detection, "profile_dir", str(profiles))
    monkeypatch.setattr(settings.audit, "log_path", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(settings.registry, "pull_on_startup", False)
    monkeypatch.setattr(settings.registry, "pull_interval_hours", 0)
    monkeypatch.setenv("JWT_SECRET", "synthetic-startup-test-at-least-32-characters")
    monkeypatch.setenv("ARKHEIA_REQUIRE_LICENSE", str(require_license).lower())
    writers = []
    original_writer = proxy_main.AuditWriter

    def observed_writer(*args, **kwargs):
        writer = original_writer(*args, **kwargs)
        writers.append(writer)
        return writer

    monkeypatch.setattr(proxy_main, "AuditWriter", observed_writer)
    app = proxy_main.create_app()
    try:
        if require_license:
            with pytest.raises(RuntimeError, match="required directory/config missing"):
                async with app.router.lifespan_context(app):
                    pytest.fail("licensed startup accepted empty inventory")
        else:
            async with app.router.lifespan_context(app):
                result = await health(SimpleNamespace(app=app), _="synthetic-admin")
                assert result["profiles_loaded"] == 0
                assert result["status"] == "ok"
    finally:
        # The refusal happens before lifespan reaches its shutdown block.
        # Observe and stop every writer this test created, including that path.
        for writer in writers:
            await writer.stop()
