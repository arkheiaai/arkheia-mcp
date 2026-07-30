from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_proxy_main_import_does_not_load_or_override_cwd_dotenv(tmp_path):
    (tmp_path / ".env").write_text(
        "\n".join(
            [
                "JWT_SECRET=dotenv-jwt-secret-should-not-win-minimum-32chars",
                "ARKHEIA_API_KEY=dotenv-api-key-should-not-win",
                "ARKHEIA_HOSTED_URL=https://dotenv-hosted.example",
                "ARKHEIA_UPSTREAM_URL=https://dotenv-upstream.example/v1",
                "ARKHEIA_PROXY_PORT=65530",
                f"ARKHEIA_PROFILES_DIR={tmp_path / 'dotenv-profiles'}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    for key in list(env):
        if key == "JWT_SECRET" or key.startswith("ARKHEIA_"):
            env.pop(key)
    env.update(
        {
            "PYTHONPATH": str(ROOT),
            "JWT_SECRET": "os-jwt-secret-remains-authoritative-minimum-32chars",
            "ARKHEIA_API_KEY": "os-api-key-remains-authoritative",
            "ARKHEIA_HOSTED_URL": "https://os-hosted.example",
            "ARKHEIA_UPSTREAM_URL": "https://os-upstream.example/v1",
            "ARKHEIA_PROXY_PORT": "19098",
        }
    )

    code = textwrap.dedent(
        """
        import json
        import os

        import proxy.main  # noqa: F401 - import order is the regression target
        from proxy.config import settings

        print(json.dumps({
            "api_key": settings.arkheia_api_key.get_secret_value(),
            "hosted_url_env": os.environ.get("ARKHEIA_HOSTED_URL"),
            "jwt_secret_env": os.environ.get("JWT_SECRET"),
            "profile_dir_env": os.environ.get("ARKHEIA_PROFILES_DIR"),
            "settings_port": settings.proxy.port,
            "settings_profile_dir": settings.detection.profile_dir,
            "settings_upstream_url": settings.detection.upstream_url,
        }, sort_keys=True))
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout.strip().splitlines()[-1])

    assert observed["api_key"] == "os-api-key-remains-authoritative"
    assert observed["hosted_url_env"] == "https://os-hosted.example"
    assert observed["jwt_secret_env"] == "os-jwt-secret-remains-authoritative-minimum-32chars"
    assert observed["profile_dir_env"] is None
    assert observed["settings_port"] == 19098
    assert observed["settings_upstream_url"] == "https://os-upstream.example/v1"
    assert observed["settings_profile_dir"] != str(tmp_path / "dotenv-profiles")
