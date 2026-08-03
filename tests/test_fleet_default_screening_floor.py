"""
FLOOR TIER — a model id configured as a FLEET DEFAULT must either have a detection profile
or be explicitly registered as knowingly-unprofiled.

Runs in the REQUIRED `floor-invariants` context (.github/workflows/floor-invariants.yml,
`pytest tests -o python_files="test_*_floor.py test_floor_*.py"`). That job installs pytest
and NOTHING else, so this file is stdlib only — ast, json, pathlib, re, datetime. Zero
project dependencies, no network, no interpreter variance.

WHY IT EXISTS. On 2026-07-26 the fleet default for `run_grok` moved to
`grok-4.20-non-reasoning` on David's explicit instruction. There is no detection profile for
grok version 4.20, and `ProfileRouter._resolve_grok` correctly returns None for it rather
than borrowing the grok-4 fingerprint. Net effect: **the fleet's default Grok path was not
screened at all** — and nothing in the build said so. The product's central promise is that
inference is screened; a default that silently is not is the most expensive kind of quiet.

The fix is not a fabricated profile. It is that an unscreened default must be IMPOSSIBLE TO
SHIP QUIETLY: it either resolves, or it is written down with an owner, a reason, what would
clear it, and an EXPIRY DATE that fails the build when it passes.

THE DEFAULT SET IS DERIVED FROM THE CODE, never hand-written — a hand-written list is a
second source of truth that goes stale exactly when it matters (a new provider wrapper). The
derivation is an ast walk over every shipped module's function signatures.

WHAT THIS FILE DOES **NOT** COVER — stated so a pass here is not mistaken for a clean sweep:

  * IT DOES NOT RE-IMPLEMENT ProfileRouter's RESOLUTION. It can only see EXACT profile ids
    (the `model:` field of each profiles/*.yaml, plus the stem of each .yaml.enc), because
    yaml is not installed in the floor tier and duplicating the router's prefix/family/
    version rules would create a second, drifting resolver. The bias is deliberately
    CONSERVATIVE: an id the router would resolve only fuzzily is treated here as unprofiled
    and must be registered. Over-registration is loud; under-detection is silent.
    THE AUTHORITATIVE RESOLUTION CHECK IS THE REAL ROUTER, exercised in the unit tier by
    mcp_server/tests/test_fleet_default_screening.py, which imports the derivation from THIS
    file so the two can never disagree about what a fleet default is.
  * WHETHER A PROFILE IS ANY GOOD. A profile whose features cannot be computed on a given
    path still returns UNKNOWN at runtime (measured: gemini-2.5-flash ->
    no_computable_features on the text-only /detect/verify path). "Has a profile" is not
    "is screened", and this file only claims the former.
  * ENCRYPTED profile CONTENT. For *.yaml.enc only the filename stem is available without the
    decryption key, so the id is taken from the name.
  * PROSE, docs and test fixtures. Retired/unprofiled ids discussed in text are not flagged
    (see tests/test_retired_model_ids_floor.py, which makes the same exclusion).
"""

from __future__ import annotations

import ast
import datetime
import json
import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE_DIR = REPO_ROOT / "profiles"
REGISTRY_PATH = REPO_ROOT / "tests" / "floor_baselines" / "knowingly_unprofiled_defaults.json"

# Directories holding shipped code. tests/ and profiles/ are excluded on purpose.
SOURCE_DIRS = ("mcp_server", "proxy", "registry_server")

# Parameter names whose default value is a model id. Same set as
# tests/test_retired_model_ids_floor.py — the two floors look at the same population for
# different properties, and share the vocabulary deliberately.
MODEL_PARAM_NAMES = frozenset({"model", "model_id", "default_model"})

REQUIRED_REGISTRY_FIELDS = (
    "model_id",
    "registered_on",
    "expires",
    "owner",
    "reason",
    "what_would_clear_it",
)

_MODEL_LINE = re.compile(r"""^model\s*:\s*["']?([^"'\s#]+)["']?\s*(?:#.*)?$""")
_METADATA_MODEL_ID_LINE = re.compile(r"""^\s+model_id\s*:\s*["']?([^"'\s#]+)["']?\s*(?:#.*)?$""")


# ---------------------------------------------------------------------------
# Derivation — the default set comes from the code
# ---------------------------------------------------------------------------

def _defaults_of(func) -> list[tuple[str, ast.expr]]:
    """(param_name, default_node) for every parameter of `func` that HAS a default."""
    args = func.args
    positional = args.posonlyargs + args.args
    pairs: list[tuple[str, ast.expr]] = []
    for arg, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
        pairs.append((arg.arg, default))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None:
            pairs.append((arg.arg, default))
    return pairs


def derive_fleet_defaults(root: pathlib.Path | None = None,
                          source_dirs: tuple[str, ...] = SOURCE_DIRS) -> dict[str, list[str]]:
    """
    {model_id: [call sites]} for every model-ish parameter default in shipped code.

    This is THE definition of "a fleet default" for both this floor and the unit-tier
    resolution test. Shared so there is exactly one answer to "what are the defaults?".
    """
    root = root or REPO_ROOT
    found: dict[str, list[str]] = {}
    for directory in source_dirs:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "tests" in path.parts or "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for param_name, default in _defaults_of(node):
                    if param_name not in MODEL_PARAM_NAMES:
                        continue
                    if not isinstance(default, ast.Constant):
                        continue
                    if not isinstance(default.value, str) or not default.value:
                        continue
                    site = (
                        f"{path.relative_to(root)}:{default.lineno} "
                        f"{node.name}({param_name}={default.value!r})"
                    )
                    found.setdefault(default.value, []).append(site)
    return found


def derive_profile_fallback_ids(root: pathlib.Path | None = None) -> dict[str, list[str]]:
    """
    {model_id: [sites]} for every STRING LITERAL passed to ProfileRouter._by_model_id — the
    hard-coded profile FALLBACKS the version routers reach for (gpt-5.4 as the nearest
    characterised API surface, gpt-5-codex, ...). A renamed or deleted profile silently turns
    one of these into a fall-through, which is the same silent-loss class as an unprofiled
    default. NOT covered: the f-string call (`zai-org/glm-{ver}`), which is dynamic — named
    here so its absence is not read as coverage.
    """
    root = root or REPO_ROOT
    found: dict[str, list[str]] = {}
    for path in sorted((root / "proxy").rglob("*.py")):
        if "tests" in path.parts or "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name != "_by_model_id" or not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value:
                found.setdefault(arg.value, []).append(
                    f"{path.relative_to(root)}:{arg.lineno} _by_model_id({arg.value!r})"
                )
    return found


def exact_profile_ids(profile_dir: pathlib.Path | None = None) -> set[str]:
    """
    Lower-cased model ids for which a profile FILE exists.

    Read with a line regex rather than a yaml parser: the floor tier has pytest and the
    standard library and nothing else. See the module docstring for what this therefore
    cannot see.
    """
    profile_dir = profile_dir or PROFILE_DIR
    ids: set[str] = set()
    if not profile_dir.is_dir():
        return ids

    for path in sorted(profile_dir.glob("*.yaml")):
        if path.name == "schema.yaml":
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            m = _MODEL_LINE.match(line)
            if m:
                ids.add(m.group(1).lower())
                break
        else:
            # No top-level `model:` — fall back to metadata.model_id, then the filename.
            text = path.read_text(encoding="utf-8")
            m = _METADATA_MODEL_ID_LINE.search(text)
            ids.add((m.group(1) if m else path.stem).lower())

    # Encrypted profiles: without the decryption key only the name is available.
    for path in sorted(profile_dir.glob("*.yaml.enc")):
        ids.add(path.name[: -len(".yaml.enc")].lower())

    return ids


def load_registry(path: pathlib.Path | None = None, key: str = "entries") -> list[dict]:
    path = path or REGISTRY_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get(key, []))


def all_registry_entries(path: pathlib.Path | None = None) -> list[tuple[str, dict]]:
    """(section, entry) for both waiver sections — fleet defaults and profile fallbacks."""
    return [
        (section, entry)
        for section in ("entries", "fallback_entries")
        for entry in load_registry(path, key=section)
    ]


def unprofiled_unregistered(defaults: dict[str, list[str]],
                            profiled: set[str],
                            registered: set[str]) -> dict[str, list[str]]:
    """
    THE PREDICATE, factored out so it can be run against a synthetic tree in the negative
    self-test below. {model_id: sites} for defaults that neither resolve nor are registered.
    """
    return {
        model_id: sites
        for model_id, sites in defaults.items()
        if model_id.lower() not in profiled and model_id.lower() not in registered
    }


def _flat(value) -> str:
    """Registry fields may be a string or a list of lines; both flatten to one string."""
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value or "")


# ---------------------------------------------------------------------------
# THE INVARIANT
# ---------------------------------------------------------------------------

def test_every_fleet_default_resolves_or_is_registered_as_knowingly_unprofiled():
    defaults = derive_fleet_defaults()
    profiled = exact_profile_ids()
    registry = load_registry()
    registered = {str(e.get("model_id", "")).lower() for e in registry}

    # POSITIVE CONTROLS, in the same test. Each names the units behind the work it claims to
    # have done, because "found no offenders" and "looked in the wrong place" are the same
    # green (DONE.md floor invariant 9).
    assert len(defaults) >= 4, (
        f"expected >=4 distinct model-id defaults across {SOURCE_DIRS}, derived "
        f"{len(defaults)}: {sorted(defaults)} — the ast scan is not finding what it must check"
    )
    assert len(profiled) >= 40, (
        f"only {len(profiled)} profile ids read from {PROFILE_DIR} — the profile scan is "
        "broken, so 'this default has no profile' below would be meaningless"
    )

    offenders = unprofiled_unregistered(defaults, profiled, registered)

    assert not offenders, (
        "these model ids are configured as fleet defaults but have NO detection profile and "
        "are NOT registered as knowingly-unprofiled, so traffic on them is UNSCREENED and "
        "nothing says so:\n  "
        + "\n  ".join(
            f"{mid!r} at {', '.join(sites)}" for mid, sites in sorted(offenders.items())
        )
        + f"\n\nEither ship a characterised profile, or add an entry to "
        f"{REGISTRY_PATH.relative_to(REPO_ROOT)} with an owner, a reason, what would clear "
        "it, and an expiry. Do NOT invent threshold values to make a profile exist."
    )


def test_every_profile_fallback_literal_names_a_profile_that_exists():
    """
    The version routers fall back to hard-coded profile ids. A renamed or deleted profile
    turns one into a silent fall-through — the same class of silent loss, one layer down.
    """
    fallbacks = derive_profile_fallback_ids()
    profiled = exact_profile_ids()
    waived = {str(e.get("model_id", "")).lower() for e in load_registry(key="fallback_entries")}

    assert len(fallbacks) >= 3, (
        f"expected >=3 literal _by_model_id fallbacks in proxy/, derived {len(fallbacks)}: "
        f"{sorted(fallbacks)} — the ast scan is not finding what it must check"
    )

    missing = {
        mid: sites
        for mid, sites in fallbacks.items()
        if mid.lower() not in profiled and mid.lower() not in waived
    }
    assert not missing, (
        "these profile FALLBACK ids are hard-coded in the router but no profile file "
        "provides them, so the fallback silently falls through and the crude prefix match "
        "can borrow another version's fingerprint:\n  "
        + "\n  ".join(f"{mid!r} at {', '.join(sites)}" for mid, sites in sorted(missing.items()))
        + f"\n\nFix the profile id, or register the id in "
        f"{REGISTRY_PATH.relative_to(REPO_ROOT)} under 'fallback_entries' with an owner, a "
        "reason, what would clear it, and an expiry."
    )


def test_no_two_profile_files_declare_the_same_model_id():
    """
    A duplicate declared model id is a SILENT DISCARD: ProfileRouter.load_all keys its dict by
    the declared id, so two files claiming one id collide and whichever the glob reaches last
    wins. The other file's characterisation is dead weight that looks live in the repo.

    Found the moment this floor was written: profiles/gpt-5.2-codex.yaml declares
    `model: "gpt-5-codex"`, colliding with profiles/gpt-5-codex.yaml, so its v4.0 content
    never loads. That collision is waived (with an expiry) in the registry because resolving
    it correctly means deciding WHICH profile characterises gpt-5.2-codex — a
    characterisation-owner decision, not a tidy-up.
    """
    waived_ids = {
        str(e.get("model_id", "")).lower()
        for e in load_registry(key="fallback_entries")
    }

    by_id: dict[str, list[str]] = {}
    for path in sorted(PROFILE_DIR.glob("*.yaml")):
        if path.name == "schema.yaml":
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            m = _MODEL_LINE.match(line)
            if m:
                by_id.setdefault(m.group(1).lower(), []).append(path.name)
                break

    assert len(by_id) >= 40, (
        f"only {len(by_id)} declared profile ids read — the scan is broken, so 'no duplicates' "
        "would be meaningless"
    )

    collisions = {
        mid: files
        for mid, files in by_id.items()
        if len(files) > 1
        # A collision is waived only when the LOSING file's stem is a registered fallback id.
        and not any(pathlib.Path(f).stem.lower() in waived_ids for f in files)
    }

    assert not collisions, (
        "these profile files declare the SAME model id, so all but one are silently "
        "discarded at load:\n  "
        + "\n  ".join(f"{mid!r} declared by {files}" for mid, files in sorted(collisions.items()))
    )


# ---------------------------------------------------------------------------
# Guarding the guard
# ---------------------------------------------------------------------------

def test_the_check_can_actually_find_an_unprofiled_default():
    """
    NEGATIVE SELF-TEST (DONE.md v1.19). This floor passes by finding nothing, so it must be
    shown capable of finding something. Runs the real predicate over a synthetic default that
    is neither profiled nor registered, and requires it to be reported — with the real
    profile set and the real registry, so a bug that made either look "everything is fine"
    would fail here.
    """
    profiled = exact_profile_ids()
    registered = {str(e.get("model_id", "")).lower() for e in load_registry()}

    synthetic = {"totally-made-up-model-9000": ["synthetic/site.py:1 f(model=...)"]}
    assert unprofiled_unregistered(synthetic, profiled, registered) == synthetic

    # ... and the opposite direction: a real, profiled default must NOT be reported, or the
    # predicate is just "everything is an offender".
    assert unprofiled_unregistered(
        {"phi4:14b": ["real/site.py:1"]}, profiled, registered
    ) == {}


def test_the_ast_derivation_can_actually_find_a_default():
    """
    Companion negative self-test for the DERIVATION rather than the predicate. Points the
    same walk at a synthetic source tree so a scan that silently stopped matching signatures
    (a rename, an ast change) cannot report an empty, clean-looking result.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        pkg = root / "fakepkg"
        pkg.mkdir()
        (pkg / "mod.py").write_text(
            'async def call_thing(prompt: str, model: str = "synthetic-model-1"):\n'
            "    return prompt\n"
            'def other(model_id="synthetic-model-2", *, default_model="synthetic-model-3"):\n'
            "    return model_id\n"
            "def not_a_model(temperature=0.5):\n"
            "    return temperature\n",
            encoding="utf-8",
        )
        derived = derive_fleet_defaults(root=root, source_dirs=("fakepkg",))

    assert set(derived) == {"synthetic-model-1", "synthetic-model-2", "synthetic-model-3"}


def test_every_registry_entry_is_complete_and_has_not_expired():
    """
    A waiver with no owner, no remedy or no end date is not a waiver — it is a silent gap that
    has learned to look official. An entry past its expiry FAILS THE BUILD.
    """
    registry = all_registry_entries()
    assert registry, (
        "the knowingly-unprofiled registry is EMPTY. If nothing needs waiving, delete the "
        "file and this test rather than leaving an empty allowlist that passes vacuously."
    )

    today = datetime.date.today()
    problems: list[str] = []

    for section, entry in registry:
        mid = f"{section}/{entry.get('model_id', '<no model_id>')}"
        for field in REQUIRED_REGISTRY_FIELDS:
            if not _flat(entry.get(field)).strip():
                problems.append(f"{mid}: missing or empty required field {field!r}")

        raw_expiry = _flat(entry.get("expires")).strip()
        try:
            expiry = datetime.date.fromisoformat(raw_expiry)
        except ValueError:
            problems.append(f"{mid}: expires={raw_expiry!r} is not an ISO date (YYYY-MM-DD)")
            continue
        if expiry < today:
            problems.append(
                f"{mid}: waiver EXPIRED on {raw_expiry}. Either the characterisation run has "
                "landed (delete this entry) or it has not (get it done, or re-register with a "
                "new expiry and a stated reason for the extension)."
            )

    assert not problems, "knowingly-unprofiled registry problems:\n  " + "\n  ".join(problems)


def test_no_registry_entry_is_stale():
    """
    The ledger must be self-cleaning in BOTH directions: an entry that names something which
    is no longer a fleet default, or which has since acquired a profile, is stale and hides
    real coverage behind a waiver. Remove it.
    """
    defaults = {k.lower() for k in derive_fleet_defaults()}
    profiled = exact_profile_ids()

    stale: list[str] = []
    for entry in load_registry():
        mid = str(entry.get("model_id", "")).lower()
        if mid not in defaults:
            stale.append(
                f"{mid!r} is registered as a knowingly-unprofiled FLEET DEFAULT but is no "
                "longer a default anywhere in shipped code — delete the entry"
            )
        if mid in profiled:
            stale.append(
                f"{mid!r} is registered as unprofiled but a profile for it now EXISTS — "
                "delete the entry so the coverage is visible"
            )

    assert not stale, "stale registry entries:\n  " + "\n  ".join(stale)
