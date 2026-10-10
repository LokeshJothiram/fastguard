# Changelog

All notable changes to this project will be documented in this file.

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
