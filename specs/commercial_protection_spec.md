# MCP Commercial Protection Implementation Specification

## Overview

This document outlines the detailed implementation of the MCP Commercial Protection Spec, focusing on protecting critical components of the Arkheia MCP server. The implementation includes function signatures, cryptographic choices, build steps, threat modeling, and a migration path.

## Implementation Details

### Layer 1: Cython Compilation

**Objective:** Compile Python files to binary extensions to protect source code.

**Files to Compile:**
- `features.py`
- `engine.py`
- `profile_router.py`

**Function Signatures:**
- Use Cython to convert Python functions to C functions.
- Example for `features.py`:
  ```python
  def extract_features(data: bytes) -> List[float]:
      # Cython implementation
  ```

**Build Steps:**
1. Install Cython and necessary build tools.
2. Create a `setup.py` for each module:
   ```python
   from setuptools import setup
   from Cython.Build import cythonize

   setup(
       ext_modules=cythonize("features.pyx"),
   )
   ```
3. Run `python setup.py build_ext --inplace` to compile.
4. Package compiled binaries into wheels for distribution.

**Threat Model:**
- **Threat:** Source code extraction.
- **Mitigation:** Compile to binary, exclude source from distribution.

### Layer 2: Encrypted Profiles

**Objective:** Encrypt YAML profiles to prevent unauthorized access.

**Crypto Choice:**
- Use AES-256-GCM for encryption.

**Build Steps:**
1. Encrypt profiles during build using a tool like `pycryptodome`.
2. Embed the decryption key in the compiled binary.

**Function Signatures:**
- Encryption function:
  ```python
  def encrypt_profile(profile_data: bytes, key: bytes) -> bytes:
      # AES-256-GCM encryption
  ```
- Decryption function:
  ```python
  def decrypt_profile(encrypted_data: bytes, key: bytes) -> bytes:
      # AES-256-GCM decryption
  ```

**Threat Model:**
- **Threat:** Unauthorized profile access.
- **Mitigation:** Encrypt profiles, use key embedded in binary.

### Layer 3: Hosted Detection (Phone-Home)

**Objective:** Route detection requests to a hosted proxy for billing and control.

**Build Steps:**
1. Modify the MCP install script to auto-provision a free-tier key.
2. Implement a proxy server on Railway to handle detection requests.

**Function Signatures:**
- Provisioning function:
  ```python
  def provision_free_tier_key() -> str:
      # POST /v1/provision to get a key
  ```
- Detection function:
  ```python
  def detect(features: List[float], key: str) -> str:
      # Route to proxy if not enterprise
  ```

**Threat Model:**
- **Threat:** Bypassing payment.
- **Mitigation:** Use hosted detection with billing integration.

### Layer 4: Binary Integrity

**Objective:** Ensure binary integrity to prevent tampering.

**Crypto Choice:**
- Use SHA-256 for hash verification.

**Build Steps:**
1. Compute SHA-256 hash of binaries during build.
2. Store hash securely for verification at startup.

**Function Signatures:**
- Hash computation:
  ```python
  def compute_hash(binary_data: bytes) -> str:
      # Compute SHA-256 hash
  ```
- Verification function:
  ```python
  def verify_integrity(binary_data: bytes, expected_hash: str) -> bool:
      # Compare computed hash with expected hash
  ```

**Threat Model:**
- **Threat:** Binary tampering.
- **Mitigation:** Verify hash at startup, refuse to start if tampered.

## Degradation Handling

- **No Key:** Automatically provision a free-tier key.
- **Invalid Key:** Return UNKNOWN.
- **Quota Exceeded:** Return UNKNOWN + `upgrade_url`.
- **Endpoint Unreachable:** Return UNKNOWN.
- **Tampered Binary:** Refuse to start.

## Migration Path

1. **Phase 1:** Implement Cython compilation and distribute wheels.
2. **Phase 2:** Encrypt YAML profiles and update deployment scripts.
3. **Phase 3:** Set up hosted detection and modify billing integration.
4. **Phase 4:** Implement binary integrity checks.

## Future Considerations

- **Enterprise Offline Licensing:** Implement signed license files and usage receipts for offline licensing.

This implementation spec provides a comprehensive approach to protecting the MCP server's critical components, ensuring both security and compliance with licensing requirements.