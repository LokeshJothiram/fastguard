# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Actively supported |
| < 1.0   | ❌ No longer supported |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in `fastguard`, please report it responsibly:

1. **Email**: [lokesh.jothiram.contact@gmail.com](mailto:lokesh.jothiram.contact@gmail.com)
2. **Subject line**: `[SECURITY] fastguard vulnerability report`
3. Include a clear description of the vulnerability, steps to reproduce it, and the potential impact.

You will receive a response within **72 hours**. Once the issue is confirmed, a patch will be released as soon as possible, typically within 7 days.

## Security Design Notes

`fastguard` is a **client-side, in-memory** PII guardrail. All redaction and unmasking happens locally — no data is sent to any external service.

Key security properties:
- **No network calls**: All processing is local and offline.
- **In-memory vault**: The `forward_map` / `reverse_map` in `PIIVault` lives only in your process memory and is never persisted to disk.
- **Thread-safe**: Vault state is protected by a `threading.RLock` for safe concurrent use.
- **No logging of PII**: The library does not log, print, or store any sensitive values internally.

> [!IMPORTANT]
> The vault is **session-scoped** by design. Do NOT share a single `PIIGuard` instance across users or HTTP sessions in a web application. Instantiate a fresh `PIIGuard` per request to prevent cross-user data leakage.
