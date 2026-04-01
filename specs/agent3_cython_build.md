# Agent 3: Cython Build Config + Release Pipeline

## Repo: C:\arkheia-mcp

## Context
Detection algorithms in `proxy/detection/features.py` and `proxy/detection/engine.py` are
readable Python. Customers can extract our IP. Cython compilation produces native .so/.pyd
binaries that require assembly-level reverse engineering to extract algorithms.

## Task 1: Create setup_cython.py

**File to create:** `C:\arkheia-mcp\setup_cython.py`

```python
"""Cython build configuration for Arkheia detection modules."""
from setuptools import setup, find_packages
from Cython.Build import cythonize

COMPILED_MODULES = [
    "proxy/detection/features.py",
    "proxy/detection/engine.py",
    "proxy/router/profile_router.py",
]

setup(
    name="arkheia-mcp",
    ext_modules=cythonize(
        COMPILED_MODULES,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
        },
    ),
    packages=find_packages(),
    zip_safe=False,
)
```

## Task 2: Create build_release.py

**File to create:** `C:\arkheia-mcp\scripts\build_release.py`

Orchestrates a full release build:
1. Compile Cython modules → .so/.pyd
2. Encrypt profiles → .yaml.enc
3. Generate integrity manifest → integrity_manifest.json
4. Remove .py source files from dist/
5. Package into wheel

**Steps:**
```python
def main():
    # 1. Cython compile
    subprocess.run([sys.executable, "setup_cython.py", "build_ext", "--inplace"], check=True)

    # 2. Encrypt profiles
    master_key = base64.b64decode(os.environ["ARKHEIA_PROFILE_MASTER_KEY"])
    for yaml_file in Path("profiles").glob("*.yaml"):
        if yaml_file.name == "schema.yaml":
            continue
        profile_name = yaml_file.stem
        plaintext = yaml_file.read_bytes()
        encrypted = encrypt_profile(plaintext, master_key, profile_name)
        (yaml_file.parent / f"{profile_name}.yaml.enc").write_bytes(encrypted)
        yaml_file.unlink()  # Remove plaintext

    # 3. Generate integrity manifest
    generate_manifest(Path("proxy/detection"), Path("proxy/detection/integrity_manifest.json"))

    # 4. Remove .py source for compiled modules
    for mod in COMPILED_MODULES:
        Path(mod).unlink(missing_ok=True)

    # 5. Report
    print(f"Release build complete")
```

## Task 3: Add Cython to requirements

**File:** `C:\arkheia-mcp\requirements.txt` (or requirements-dev.txt)
Add: `Cython>=3.0`

## Task 4: Test Plan

### Unit tests (file: `tests/test_build_pipeline.py`)

1. **test_setup_cython_importable** — import setup_cython, verify COMPILED_MODULES list has 3 entries
2. **test_cython_compile_features** — run `python setup_cython.py build_ext --inplace` on features.py, verify .so/.pyd created
3. **test_cython_compiled_module_works** — import the compiled features module, call a known function, verify output matches Python version
4. **test_build_release_encrypts_profiles** — create temp profiles dir, run encryption step, verify .yaml.enc files created and .yaml removed
5. **test_build_release_generates_manifest** — run manifest generation, verify integrity_manifest.json contains hashes for .so files
6. **test_build_release_removes_source** — verify .py source files for compiled modules are deleted after build

### Integration test

7. **test_full_release_build** — run complete build_release.py in a temp directory, verify: no .py source for compiled modules, .yaml.enc files exist, integrity manifest exists, compiled modules importable

## Verification
```bash
# Compile test (requires Cython installed)
pip install Cython>=3.0
python setup_cython.py build_ext --inplace

# Verify compiled modules work
python -c "from proxy.detection.features import extract_features; print('OK')"

# Run tests
pytest tests/test_build_pipeline.py -v
```

## Notes
- Cython compilation is platform-specific (.so on Linux/Mac, .pyd on Windows)
- CI pipeline for cross-platform builds is a follow-up (GitHub Actions matrix)
- For now, this enables local compilation and validates the approach
