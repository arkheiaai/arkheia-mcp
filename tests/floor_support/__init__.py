"""
Stdlib-only support modules for the FLOOR TIER (`.github/workflows/floor-invariants.yml`).

Nothing in this package may import a project dependency. The floor job installs
`pytest` and nothing else, on purpose: a floor that needs `httpx` to run is a
floor that stops running the day an install step breaks, and a skipped floor is
indistinguishable from a passing one.

Nothing in this package is collected as a test. The floor job overrides
`python_files` to `test_*_floor.py test_floor_*.py`, so these modules are
imported by floors, never run as ones.

WHY THIS PACKAGE EXISTS AT ALL — read before adding a fourth copy of a parser.
Three floors in this repo answer questions about the same artifacts: what a
distribution ships (`test_packed_artifact_floor.py`), what it declares as
dependencies, and what its entry point imports. Each needs to parse the same
things — the Node launcher, the npm package manifest, the Python import graph.
Two parsers of one artifact will eventually disagree, and the disagreement is a
SILENT hole: floor A reads the launcher one way and passes, floor B reads it
another way and also passes, and the artifact satisfies neither reading. So the
parse lives here once, and a floor that needs a new form teaches this package.
"""
