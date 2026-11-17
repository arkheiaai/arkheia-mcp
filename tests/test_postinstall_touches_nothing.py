"""B-288: installing the published package must change nothing in the user's home and expose no key.

David approved removing both home-directory edits on 29 Oct 2026 and again on 17 Nov (readiness plan D4). The
public installer still wrote a managed block into ~/.claude/CLAUDE.md, appended to a Codex instructions file,
saved an exported ARKHEIA_API_KEY to ~/.arkheia/config.json and printed part of the key into install logs.
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SETUP = ROOT / "npm-wrapper" / "scripts" / "setup.js"
FAKE_KEY = "ak_test_" + "f" * 40 + "B288"


def _tree(root: pathlib.Path):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@unittest.skipUnless(shutil.which("node"), "node is required")
class PostinstallTouchesNothing(unittest.TestCase):
    def run_postinstall(self, home: pathlib.Path):
        env = {"PATH": os.environ["PATH"], "HOME": str(home), "USERPROFILE": str(home), "ARKHEIA_API_KEY": FAKE_KEY}
        return subprocess.run(["node", str(SETUP)], env=env, capture_output=True, text=True, timeout=60)

    def test_no_file_is_created_or_changed_in_home(self):
        with tempfile.TemporaryDirectory() as d:
            home = pathlib.Path(d)
            (home / ".claude").mkdir()
            claude_md = home / ".claude" / "CLAUDE.md"
            claude_md.write_text("# my own instructions\n")
            before = _tree(home)
            r = self.run_postinstall(home)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(_tree(home), before, "postinstall created files in the user's home")
            self.assertEqual(claude_md.read_text(), "# my own instructions\n", "postinstall edited ~/.claude/CLAUDE.md")

    def test_no_part_of_the_key_is_printed(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_postinstall(pathlib.Path(d))
            out = r.stdout + r.stderr
            for fragment in (FAKE_KEY, FAKE_KEY[:8] + "...", FAKE_KEY[-4:]):
                self.assertNotIn(fragment, out, f"postinstall printed key material: {fragment!r}")


if __name__ == "__main__":
    unittest.main()


class FirstRunAndSetupLeakNothing(unittest.TestCase):
    """Codex B288 R1: default first run must not write in home; optional setup must never print the key."""

    def test_update_check_is_opt_in(self):
        src = (ROOT / "npm-wrapper" / "src" / "index.ts").read_text()
        dist = (ROOT / "npm-wrapper" / "dist" / "index.js").read_text()
        for name, text in (("src/index.ts", src), ("dist/index.js", dist)):
            self.assertIn("ARKHEIA_UPDATE_CHECK", text, f"{name}: the update check (which writes ~/.arkheia/.update-check) must be opt-in")

    @unittest.skipUnless(shutil.which("node"), "node is required")
    def test_setup_claude_never_prints_the_key_when_registration_fails(self):
        with tempfile.TemporaryDirectory() as d:
            home = pathlib.Path(d) / "home"; home.mkdir()
            bindir = pathlib.Path(d) / "bin"; bindir.mkdir()
            for cli in ("claude", "codex"):
                f = bindir / cli; f.write_text("#!/bin/sh\nexit 1\n"); f.chmod(0o755)
            env = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(home), "USERPROFILE": str(home),
                   "ARKHEIA_API_KEY": FAKE_KEY}
            r = subprocess.run(["node", str(ROOT / "npm-wrapper" / "scripts" / "setup-claude.js")],
                               env=env, capture_output=True, text=True, timeout=60)
            out = r.stdout + r.stderr
            self.assertIn("ARKHEIA_API_KEY", out, "the manual command should reference the variable")
            for fragment in (FAKE_KEY, FAKE_KEY[-12:]):
                self.assertNotIn(fragment, out, "setup printed the API key")


class VersionsAgree(unittest.TestCase):
    def test_every_version_field_is_the_release_version(self):
        import json, re
        pkg = json.loads((ROOT / "npm-wrapper" / "package.json").read_text())["version"]
        server = json.loads((ROOT / "npm-wrapper" / "server.json").read_text())
        server_versions = {server.get("version")} | {p.get("version") for p in server.get("packages", []) if isinstance(p, dict)}
        src = (ROOT / "npm-wrapper" / "src" / "index.ts").read_text()
        src_versions = set(re.findall(r'CURRENT_VERSION = "([^"]+)"', src)) | set(re.findall(r'name: "arkheia-trust", version: "([^"]+)"', src))
        self.assertEqual(server_versions - {None}, {pkg})
        self.assertEqual(src_versions, {pkg})
        self.assertNotEqual(pkg, "0.1.10", "0.1.10 is already published on npm")
