"""The public tree is a thin client: it carries the signal and nothing about how it is produced.

This guard fails if material that belongs only on the server side comes back, by path or by content.
It stores only SHA-256 hashes of the banned identifiers (lower-cased tokens split on non-word
characters), so the test itself names nothing it guards.
"""
from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _h(token: str) -> str:
    return hashlib.sha256(token.lower().encode()).hexdigest()


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"\W+", text.lower()) if t}


# Top-level folders that must not exist in the public tree.
BANNED_DIRS = frozenset({
    "d52fd337f01644a0d2063a040f14c508dbbf4d3a85b040e47f54417b94a4bc54",
    "1241936d4dd3aad68fe7bfbdfe854b935926bc678fc72377e15166078916227a",
    "f9c0d87e878fa550b0aa4fdf13b429d17408d8eb538e969000fd3c12f11887d6",
    "7846086ae9fcf5a5712bd796d77a79d09c49f69a3fe123868544c4db10af1dba",
})

# Identifiers that only the server side defines or uses. Banned anywhere in any tracked text file.
BANNED_IDENTIFIERS = frozenset({
    "17f5fdcb4c6ddca733f441e0c472cbc4cb8ffb941bc0effcb235d4e1c1e27ae8",
    "cd5410f5be89e990751dc42096b8bcbb4ae38a95de00a5e42277b3c182b739b8",
    "0233b52992c6813255e0ffe89b106652a99360bb001733890de4b156b1eaaeeb",
    "93d2c45c94d4c7efe39cd5cf1b875550eeb8275aeec8e8ba9bff9c4db3ae3498",
    "95d15ba1d7d84c1c3695a88a7ab9b6750db5ddcbc4839e50d7ca8837488ff7ee",
    "818e225d54a2e238f03f880341d42731d73e9f9740334b289f54d850c3d33c79",
    "0b631a33da361650dab63f4faabcb679dd0b0d46296a9bdbf6f267f047e6f003",
    "0b718ee3fca3ecc48e021d66a5966e2085cafe5cc5c97e4cb72266d65909bd62",
    "7884b117045c07a9766697f99a77c6665ce16b49d99bcfb8aea3279486f3a8da",
    "b6737b4b800b39986ac5bde009bc3e32505af50dd02e5c3f31924b9acad152d3",
    "bda5db785a2afa4488f850b2af30bdd90dd8d825e139386b4d10c1466236d865",
    "1cf95f404a2bb098ad1e0ba947295fe450e91e7e0fbf7bc6f9002a4834b807d3",
    "d354f638da17601e9795110e7c074df77e89a50de536e136bbcf93dcce82acdf",
    "fa6a55179056bc6f5e7d64f1d1cee31812a1ed0d5c79bf6eba8e3e7779f63ecf",
    "fa40eec2f5b29fb4a62c1a16c12b174c8febee8701ebcef6d6f78fc30af486ae",
})

# Configuration keys that must not appear in a YAML file that also has the banned block header.
BANNED_YAML_KEYS = frozenset({
    "f1b979a5fe2ec4987f9089966c2016d669b23fcc134f7cd3a6edab480c04e52f",
    "0844df8fee9eeadaa344bc7e1a7ae769602eba35e773c2093c8fb9c3e5ead14e",
    "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
    "fa4824e83746480e1029c47ad659fdc3854195c0fa76c9209807cef32e29243e",
    "91c81156245a63fe7d4d093cf3dee587ceb854c89d83c98c71b2d68c3892416d",
})
BANNED_YAML_BLOCK = "dad9a79bf7094d4e4604288b20606bf0c332ad493b99c12f1d458912c5ab4bdc"
CONTROL = "7c6b62426d5f89db904c79338fbe5f7afcc39dbc029178b8fea2095d65113a5b"   # positive control for the scanner below

_YAML_KEY = re.compile(r"^(\s*)([A-Za-z_][\w]*)\s*:", re.M)


def _tracked_files() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
        files = [line for line in out.stdout.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):   # an exported tree without .git
        files = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                 if p.is_file() and ".git" not in p.parts]
    return [f for f in files if "node_modules" not in pathlib.PurePosixPath(f).parts]


def _read(f: str) -> str | None:
    try:
        return (ROOT / f).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def banned_in(text: str, banned: frozenset[str]) -> list[str]:
    """Hashes of banned identifiers that occur in `text`."""
    return sorted(_h(t) for t in _tokens(text) if _h(t) in banned)


def yaml_has_banned_config(text: str) -> bool:
    keys = {(m.group(1), m.group(2)) for m in _YAML_KEY.finditer(text)}
    top = any(ind == "" and _h(k) == BANNED_YAML_BLOCK for ind, k in keys)
    return top and any(ind != "" and _h(k) in BANNED_YAML_KEYS for ind, k in keys)


def test_no_banned_paths():
    hits = [f for f in _tracked_files() if _h(f.split("/")[0]) in BANNED_DIRS and "/" in f]
    assert hits == [], f"server-side paths are back in the public tree: {hits[:10]}"


def test_no_banned_identifiers_anywhere():
    hits = {}
    for f in _tracked_files():
        text = _read(f)
        if text is None:
            continue
        found = banned_in(text, BANNED_IDENTIFIERS)
        if found:
            hits[f] = found
    assert hits == {}, f"banned identifiers (by hash) are in the public tree: {hits}"


def test_no_yaml_with_banned_configuration():
    hits = []
    for f in _tracked_files():
        if f.endswith((".yaml", ".yml")) and not f.startswith(".github/"):
            text = _read(f)
            if text and yaml_has_banned_config(text):
                hits.append(f)
    assert hits == [], f"banned configuration is in the public tree: {hits}"


def test_the_scanner_would_catch_a_banned_token():
    """Positive control, using a stand-in hash so no banned name is written here."""
    assert banned_in("x = ZzControlToken(1)", frozenset({CONTROL})) == [CONTROL]
    assert banned_in("nothing to see", frozenset({CONTROL})) == []
    assert BANNED_IDENTIFIERS and BANNED_DIRS and BANNED_YAML_KEYS
