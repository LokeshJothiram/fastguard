# Changelog

All notable changes to this project will be documented in this file.

---

## [1.0.4] - 2026-10-11

### Fixed
- **PyPI Contributing Link**: Converted relative `CONTRIBUTING.md` link to absolute GitHub URL to resolve PyPI 404 page routing
- **Project Metadata URLs**: Added direct Contributing Guide URL in `pyproject.toml` metadata

---

## [1.0.3] - 2026-10-11

### Fixed
- **PyPI Badge Rendering**: Replaced GitHub workflow badge with universal Shields.io test status badge for 100% reliable rendering on PyPI and GitHub

---

## [1.0.2] - 2026-10-10

### Added
- **Global Phone Coverage**: Extended international phone number validation for 240+ countries (+33, +49, +44, +91, etc.) via dynamic E.164 parsing in `validate_phone`
- **Pattern Specificity Prioritization**: Structured banking and identity formats (IFSC, UK Sort Code, US SSN, Aadhaar, IBAN) are matched before generic number fallbacks to prevent collisions
- **Clean Test Suite**: Streamlined core test suite in `tests/test_pii.py` with 100% pass rate

---

## [1.0.1] - 2026-10-10

### Fixed
- **PyPI Screenshot Rendering**: Updated README demo image paths to raw CDN URLs for proper rendering on pypi.org

---

## [1.0.0] - 2026-10-10

### Added
- **Thread-safety**: `PIIVault` is now protected by `threading.RLock` — safe for concurrent FastAPI/Django/Gunicorn environments
- **PyPI classifiers**: Added production-ready classifiers, keywords, and project URLs
- **`SECURITY.md`**: Vulnerability reporting policy and security design documentation
- **`demo` optional extra**: `pip install fastguard[demo]` to install Gradio for the visual sandbox
- **IP address validation**: `validate_ip` ensures each octet is within 0–255 range (eliminates false positives like `999.999.999.999`)

### Changed
- Version bumped to **`1.0.0`** — package is production-stable
- `PIIGuard` and `StreamingGuardrail` window sizes aligned to `25` with a 20-char safety tail
- `demo.py` creates a **fresh `PIIGuard` per request** to prevent session state leakage
- Author details updated to **Lokesh Jothiram** (`lokesh.jothiram.contact@gmail.com`)

---

## [0.2.0] - 2026-10-10

### Added
- **Google `phonenumbers` engine** for globally validated international phone number detection
- **IBAN MOD-97 checksum validation** (`validate_iban`) to eliminate false positives
- **IPv4 address detection** with per-octet range validation (0–255) via `validate_ip`
- **Expanded banking identifiers**: SWIFT/BIC, IFSC, UK Sort Code, UPI ID
- **Expanded identity documents**: US SSN, UK NINO
- **Whitelisting system** with built-in defaults (`localhost`, `127.0.0.1`, `0.0.0.0`) and runtime `add_whitelist_terms()` support
- **Interactive web demo** (`demo.py`) using Gradio with live examples
- **Performance benchmark script** (`benchmark.py`) measuring µs latency and ops/second
- **Interactive terminal sandbox** (`sandbox.py`) for local testing
- **Optional SpaCy NER module** (`fastguard/pii/nlp.py`) for unstructured name and address extraction
- **65+ parametrized test cases** including 1-14 character token-chunk streaming stress tests

### Fixed
- Streaming buffer now performs **direct placeholder lookup from `vault.reverse_map`** instead of re-redacting mid-stream, eliminating `[PHONE_1]` unmasking failures
- `UPI_ID` regex now uses negative lookahead to prevent false matches on standard email domains
- UK NINO regex expanded to match HMRC test prefixes (e.g., `QQ123456A`)
- PHONE regex updated to capture leading `+` in international E.164 numbers

### Changed
- `PIIGuard.window_size` default aligned with `StreamingGuardrail.window_size` (both `15`)
- `demo.py` now instantiates a **fresh `PIIGuard` per request** to prevent state leakage across sessions

---

## [0.1.0] - 2026-10-10

### Added
- Initial project structure with `PIIGuard`, `PIIVault`, `StreamingGuardrail`
- Regex-based detection for Email, Phone (basic), Credit Card (Luhn), Aadhaar (Verhoeff), PAN
- Reversible in-memory vault with deterministic placeholder generation
- Sliding-window token stream buffer
- Basic unit test suite
