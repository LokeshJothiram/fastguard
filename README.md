# fastguard 🛡️

[![PyPI version](https://img.shields.io/pypi/v/fastguard.svg?color=blue)](https://pypi.org/project/fastguard/)
[![Python versions](https://img.shields.io/pypi/pyversions/fastguard.svg)](https://pypi.org/project/fastguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/LokeshJothiram/fastguard/blob/main/LICENSE)
[![CI Tests](https://github.com/LokeshJothiram/fastguard/actions/workflows/ci.yml/badge.svg)](https://github.com/LokeshJothiram/fastguard/actions)

**Sub-millisecond, streaming-native PII guardrail & reversible vault for LLM applications.**

`fastguard` protects AI applications from PII leaks by redacting sensitive data before it reaches external LLM APIs and unmasking placeholders in real-time streaming responses.


---

## 🖥️ Interactive Web Demo

Test real-time PII sanitization, metric latency tracking, and reversible stream unmasking in your browser:

### 1. Interactive Sandbox Dashboard
![fastguard Interactive Sandbox Initial State](assets/sandbox_initial.png)

### 2. Live Redaction & Reversible Vault Inspection
![fastguard Live Sandbox Execution](assets/sandbox_demo.png)

```bash
# Launch the local visual sandbox
python demo.py
```

---

## Key Features

- **⚡ Sub-Millisecond Speed:** Processing latencies under 100 microseconds ($\mu\text{s}$).
- **🔄 Reversible Vault:** Replaces sensitive values with placeholders (`[EMAIL_1]`, `[PHONE_1]`) and restores them in streamed responses.
- **🌐 Global Coverage:** Google `libphonenumber` integration, Luhn credit card checks, Verhoeff checksums, IBAN MOD-97 validation, US SSN, PAN, and UK NINO support.
- **🛡️ Built-in Whitelisting:** Define safe domain names, IP addresses, or technical terms that must never be redacted.
- **🌊 Native Streaming Buffer:** Sliding-window engine designed for real-time token streams.

---

## Installation

```bash
pip install fastguard
```

To include optional SpaCy NER support for unstructured human names and physical addresses:

```bash
pip install "fastguard[nlp]"
```

---

## Quickstart

```python
from fastguard import PIIGuard

# Initialize guardrail
guard = PIIGuard(whitelist={"localhost", "api.internal"})

# 1. Redact PII before calling LLM
user_prompt = "Contact Alice at alice@test.com or call +1 650 253 0000 with PAN ABCDE1234F"
clean_prompt = guard.sanitize_prompt(user_prompt)

print(clean_prompt)
# Output: Contact Alice at [EMAIL_1] or call [PHONE_1] with PAN [PAN_1]

# 2. Wrap LLM output stream to automatically restore original values
llm_stream = ["Response ", "for ", "[EMAIL_1]", "."]
restored_stream = list(guard.wrap_stream(llm_stream))

print("".join(restored_stream))
# Output: Response for alice@test.com.
```

---

## ⚙️ Configuration & Advanced Options

`PIIGuard` provides granular controls for every stage of the guardrail:

```python
guard = PIIGuard(
    # Selective Entity Filtering
    enabled_entities={"CREDIT_CARD", "EMAIL"}, # Only detect specific entity types
    disabled_entities={"PHONE"},                 # Or disable specific entity types
    
    # Stage Toggles
    redact_input=True,    # Set False to disable incoming prompt redaction
    unmask_output=True,   # Set False to leave placeholders in output stream
    
    # Whitelisting & Performance
    whitelist={"support@company.com", "192.168.1.1"}, # Safe terms never masked
    window_size=25        # Sliding window buffer size for token streams
)
```

### 1. Selective Entity Masking
Target only high-risk financial identifiers or disable non-critical entities:

```python
# Only mask Credit Cards and US SSN, leave emails and phones intact
guard = PIIGuard(enabled_entities={"CREDIT_CARD", "US_SSN"})
clean = guard.sanitize_prompt("Email test@corp.com with card 4532 0123 4567 8910")
# Result: "Email test@corp.com with card [CREDIT_CARD_1]"
```

### 2. Whitelisting (Static & Dynamic)
Prevent internal IP addresses, API domains, or test accounts from being redacted:

```python
guard = PIIGuard(whitelist={"localhost", "127.0.0.1", "corp.internal"})

# Add terms at runtime dynamically
guard.add_whitelist_terms({"support@fastguard.ai", "api.staging.net"})
```

### 3. Stage Toggles (Audit / Redact-Only / Unmask-Only)
```python
# Leave placeholders in LLM stream without unmasking (Audit mode)
guard = PIIGuard(unmask_output=False)
```

---

## 🧩 Supported PII Entities & Validations

| Entity Identifier | Category | Algorithm / Validation Standard |
| :--- | :--- | :--- |
| `EMAIL` | Contact | RFC 5322 Standard Email Regex |
| `PHONE` | Contact | Google `libphonenumber` International E.164 & National |
| `IP_ADDRESS` | Network | IPv4 0–255 Per-Octet Range Validation |
| `CREDIT_CARD` | Financial | Luhn MOD-10 Algorithm Checksum (Visa, MC, Amex, etc.) |
| `IBAN` | Financial | ISO 13616 / MOD-97 International Bank Account Number |
| `SWIFT_BIC` | Financial | ISO 9362 Business Identifier Codes (8 or 11 chars) |
| `IFSC` | Financial | Indian Financial System Code Regex |
| `UK_SORT_CODE` | Financial | 6-digit UK Bank Sort Codes (`XX-XX-XX`) |
| `UPI_ID` | Financial | Unified Payments Interface Virtual Payment Addresses |
| `US_SSN` | Identity | US Social Security Number Format & Area Checks |
| `AADHAAR` | Identity | Verhoeff Dihedral Group Checksum Algorithm |
| `PAN` | Identity | Indian Permanent Account Number (Income Tax Dept) |
| `UK_NINO` | Identity | UK National Insurance Number Format & HMRC Prefixes |


---

## Performance Benchmark

| Engine | Latency | Memory Footprint | Streaming Support |
| :--- | :--- | :--- | :--- |
| **`fastguard`** | **< 0.1 ms** | **~10 MB** | **Native Real-time Buffer** |
| Heavy Transformer NER | 50 – 200 ms | 1 – 4 GB | Requires custom wrappers |
| Cloud Security APIs | 100 – 300 ms | External network call | High network overhead |

## Contributing

We welcome community contributions! Please read our [Contributing Guide](CONTRIBUTING.md) to get started with local development, running tests, and opening Pull Requests.

---

## License

MIT License © 2026

