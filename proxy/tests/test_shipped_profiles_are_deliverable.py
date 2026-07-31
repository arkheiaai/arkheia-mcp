"""Every profile we actually ship must survive registry delivery.

EARNED THE HARD WAY (2026-07-31). #46 made `run_smoke_test` return False when a profile has no
`smoke_test` block. Reasoning: "absence of a smoke test is not evidence that validation passed".
Sound in the abstract, and correct for the checksum half of the same PR. Wrong here, for two
reasons that only show up against the real corpus:

  1. NOTHING SHIPS ONE. 0 of 60 profiles carry a smoke_test, so registry delivery failed
     universally the moment it merged. The rule was unsatisfiable by the artifacts it governed.
  2. IT IS THE WEAKER EVIDENCE. Profiles are built and validated in the model lab against a
     labelled corpus; the `characterization` block in each file records that run (date, prompt
     count, features, methodology). Asking a delivered profile to re-prove itself with one canned
     prompt/response pair is strictly weaker than the run that already happened -- and it would
     gate the stronger evidence sitting in the same file.

Delivery is responsible for INTEGRITY (did the right bytes arrive), not for RE-CHARACTERISATION.
Integrity is the checksum, which is mandatory and satisfiable. This file pins both halves.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from proxy.registry.validator import ProfileValidator

_PROFILES = Path(__file__).resolve().parents[2] / "profiles"


def _profile_files():
    return sorted(_PROFILES.glob("*.yaml"))


@pytest.mark.skipif(not _PROFILES.is_dir(), reason="profiles/ not present in this checkout")
def test_the_corpus_is_not_empty():
    """Premise. Without this, every parametrised case below could vacuously pass."""
    files = _profile_files()
    assert len(files) >= 40, f"expected the shipped profile corpus, found {len(files)} file(s)"


@pytest.mark.skipif(not _PROFILES.is_dir(), reason="profiles/ not present in this checkout")
@pytest.mark.parametrize("path", _profile_files(), ids=lambda p: p.stem)
def test_every_shipped_profile_passes_validation(path):
    """THE REGRESSION TEST. Re-introducing the smoke-test requirement turns this RED 60 times."""
    data = yaml.safe_load(path.read_text()) or {}
    ok, reason = ProfileValidator().run_smoke_test(data)
    assert ok, (
        f"{path.name} cannot be delivered through the registry: {reason}\n"
        "A profile is proved by its model-lab characterisation run, not by a canned prompt pair "
        "asserted at delivery time."
    )


@pytest.mark.skipif(not _PROFILES.is_dir(), reason="profiles/ not present in this checkout")
def test_the_lab_provenance_is_actually_present():
    """The claim above is only honest if the characterisation really is recorded."""
    missing = [p.name for p in _profile_files()
               if not (yaml.safe_load(p.read_text()) or {}).get("characterization")]
    assert len(missing) <= 1, (
        "profiles without a `characterization` block, so the 'the lab already proved it' argument "
        f"does not hold for them: {missing}"
    )


def test_the_checksum_requirement_is_UNTOUCHED_and_still_bites():
    """The other half of #46 is correct and stays. Delivery owns integrity."""
    v = ProfileValidator()
    with pytest.raises(ValueError):
        v.require_checksum("")          # absent checksum must still be refused
    digest = hashlib.sha256(b"x").hexdigest()
    assert v.require_checksum(digest) == digest
