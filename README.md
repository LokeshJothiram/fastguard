# fastguard 🛡️

**Sub-millisecond, streaming-native PII guardrail & reversible vault for LLM applications.**

`fastguard` protects AI applications from PII leaks by redacting sensitive data before it reaches external LLM APIs and unmasking placeholders in real-time streaming responses.

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

guard = PIIGuard(whitelist={"localhost", "api.internal"})

# Redact PII before calling LLM
user_prompt = "Contact Alice at alice@test.com or call +1 650 253 0000 with PAN ABCDE1234F"
clean_prompt = guard.sanitize_prompt(user_prompt)

print(clean_prompt)
# Output: Contact Alice at [EMAIL_1] or call [PHONE_1] with PAN [PAN_1]

# Wrap LLM output stream to automatically restore original values
llm_stream = ["Response ", "for ", "[EMAIL_1]", "."]
restored_stream = list(guard.wrap_stream(llm_stream))

print("".join(restored_stream))
# Output: Response for alice@test.com.
```

---

## Performance Benchmark

| Engine | Latency | Memory Footprint | Streaming Support |
| :--- | :--- | :--- | :--- |
| **`fastguard`** | **< 0.1 ms** | **~10 MB** | **Native Real-time Buffer** |
| Heavy Transformer NER | 50 – 200 ms | 1 – 4 GB | Requires custom wrappers |
| Cloud Security APIs | 100 – 300 ms | External network call | High network overhead |

---

## License

MIT License © 2026
