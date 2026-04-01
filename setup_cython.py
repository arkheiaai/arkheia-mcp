"""Cython build configuration for Arkheia detection modules."""
from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup

COMPILED_MODULES = [
    "proxy/detection/features.py",
    "proxy/detection/engine.py",
    "proxy/router/profile_router.py",
]

COMPILER_DIRECTIVES = {
    "language_level": "3",
    "boundscheck": False,
    "wraparound": False,
}


def build_extensions():
    """Create extension modules lazily so the file remains importable in tests."""
    from Cython.Build import cythonize

    module_paths = [str(Path(module_path)) for module_path in COMPILED_MODULES]
    return cythonize(module_paths, compiler_directives=COMPILER_DIRECTIVES)


def main() -> None:
    setup(
        name="arkheia-mcp",
        ext_modules=build_extensions(),
        packages=find_packages(),
        zip_safe=False,
    )


if __name__ == "__main__":
    main()
