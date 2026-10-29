"""The unauthenticated local verify route must stay local by default."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_standalone_proxy_and_compose_publish_only_on_loopback():
    config = yaml.safe_load((ROOT / "proxy/arkheia-proxy.yaml").read_text())
    compose = yaml.safe_load((ROOT / "docker-compose.yaml").read_text())
    proxy = compose["services"]["proxy"]

    assert config["proxy"]["host"] == "127.0.0.1"
    assert proxy["ports"] == ["127.0.0.1:8098:8098"]
    assert "ARKHEIA_PROXY_HOST=0.0.0.0" in proxy["environment"]
