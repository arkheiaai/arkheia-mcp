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
