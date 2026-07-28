"""
Floor candidate: mcp.registry_download_url_authority_egress.

Floor tier installs only stdlib + pytest. Keep this file static: behavioral
coverage for RegistryClient/ProfileStorage lives in the unit suite, while this
floor pins the production source shape that prevents registry bearer-token egress
to a metadata-supplied foreign authority.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "proxy" / "registry" / "client.py"
STORAGE = ROOT / "registry_server" / "storage.py"
REGISTRY_MAIN = ROOT / "registry_server" / "main.py"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _class_method_source(path: Path, class_name: str, method_name: str) -> str:
    source = _source(path)
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, (ast.AsyncFunctionDef, ast.FunctionDef)) and item.name == method_name:
                    return ast.get_source_segment(source, item) or ""
    raise AssertionError(f"{class_name}.{method_name} not found in {path}")


def test_registry_client_resolves_download_url_through_same_origin_helper_before_auth():
    body = _class_method_source(CLIENT, "RegistryClient", "_download_and_apply")

    assert 'download_url = self._same_origin_download_url(meta["download_url"])' in body
    get_index = body.index("client.get(")
    helper_index = body.index("_same_origin_download_url")
    assert helper_index < get_index
    assert 'headers={"Authorization": f"Bearer {key_value}"}' in body
    assert 'client.get(\n                meta["download_url"]' not in body


def test_same_origin_helper_rejects_foreign_authority_and_userinfo():
    body = _class_method_source(CLIENT, "RegistryClient", "_same_origin_download_url")

    assert "urljoin" in body
    assert "urlparse(self.base_url)" in body
    assert "urlparse(candidate)" in body
    assert "authority(parsed) != authority(base)" in body
    assert "raise ValueError" in body
    assert "registry download_url authority does not match configured registry base" in body
    assert "parsed.username or parsed.password" in body
    assert "registry download_url must not include userinfo" in body


def test_registry_storage_advertises_downloads_under_configured_base_url():
    body = _class_method_source(STORAGE, "ProfileStorage", "_profile_meta")

    assert 'download_url = f"{self.base_url}/profiles/{model_id}/download"' in body
    assert '"download_url": download_url' in body
    assert "localhost" not in body


def test_registry_server_base_url_is_env_configured_for_container_authority():
    source = _source(REGISTRY_MAIN)

    assert 'os.environ.get("ARKHEIA_REGISTRY_BASE_URL", "http://localhost:8200")' in source
    assert "ProfileStorage(profile_dir=profile_dir, base_url=base_url)" in source
