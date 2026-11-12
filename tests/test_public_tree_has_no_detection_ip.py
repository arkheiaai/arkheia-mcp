"""The public repository is a thin client: it carries the signal, never the method or the maths.

David, 12 Nov 2026: "our ip is our ip we only emit signal" and "messenger only - thats all a customer
needs, pure signal". Detection runs on Arkheia's servers. This package sends a model response to the
hosted API and returns the verdict. So nothing here may say HOW detection works:

  * no detection profiles (the per-model thresholds and weights),
  * no detection engine (the feature formulas and the scoring that combines them),
  * no profile registry or local scoring proxy.

This test fails if any of them comes back, by path or by content.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

FORBIDDEN_PATHS = ("profiles/", "proxy/", "registry_server/", "specs/")

#: Names that only the detection engine defines. A client has no reason to define any of them.
ENGINE_MARKERS = re.compile(
    r"^\s*(?:async\s+)?def\s+(classify_with_profile|compute_feature|extract_structural_features|"
    r"compute_token_entropies|grounding_uncertainty)\s*\(|profile_weighted_(?:vote|sum)",
    re.M,
)
#: A YAML detection block that carries numbers: `detection:` with thresholds, weights or alpha/bias.
PROFILE_BLOCK = re.compile(r"^detection:\s*$", re.M)
PROFILE_NUMBERS = re.compile(r"^\s+(thresholds|weight|alpha|bias|polarity)\s*:", re.M)


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
        return [line for line in out.stdout.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):   # an exported tree without .git
        return [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                if p.is_file() and ".git" not in p.parts and "node_modules" not in p.parts]


def test_no_engine_profile_or_registry_paths():
    hits = [f for f in _tracked_files() if f.startswith(FORBIDDEN_PATHS)]
    assert hits == [], f"detection IP paths are back in the public tree: {hits[:10]}"


def test_no_detection_engine_code():
    hits = []
    for f in _tracked_files():
        if f.endswith(".py") and f != pathlib.Path(__file__).relative_to(ROOT).as_posix():
            if ENGINE_MARKERS.search((ROOT / f).read_text(errors="ignore")):
                hits.append(f)
    assert hits == [], f"detection engine code is in the public tree: {hits}"


def test_no_profile_with_numbers():
    hits = []
    for f in _tracked_files():
        if f.endswith((".yaml", ".yml")) and not f.startswith(".github/"):
            text = (ROOT / f).read_text(errors="ignore")
            if PROFILE_BLOCK.search(text) and PROFILE_NUMBERS.search(text):
                hits.append(f)
    assert hits == [], f"a detection profile with numbers is in the public tree: {hits}"


def test_the_markers_would_catch_the_removed_code():
    """Positive control: the patterns above match what was removed on 12 Nov 2026."""
    assert ENGINE_MARKERS.search("def classify_with_profile(signals, profile):\n")
    assert ENGINE_MARKERS.search("    detection_method = 'profile_weighted_vote'\n")
    profile = "model: x\ndetection:\n  thresholds:\n    reasoning_ratio: 0.72\n"
    assert PROFILE_BLOCK.search(profile) and PROFILE_NUMBERS.search(profile)
