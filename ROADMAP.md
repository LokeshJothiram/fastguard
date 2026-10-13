# FastGuard Product & Engineering Roadmap 🗺️

This document outlines the strategic engineering milestones, feature specifications, and architectural goals for **FastGuard**. 

FastGuard's mission is to remain the industry's fastest, lightest, and most reliable **sub-millisecond streaming PII guardrail & reversible vault** for Generative AI applications.

---

## 🏛️ Guiding Engineering Principles

Every feature added to FastGuard must adhere to four non-negotiable architectural tenets:
1. **⚡ Sub-Millisecond Speed:** Core hot-path operations must execute in under **250 microseconds ($\mu$s)** on commodity CPU hardware.
2. **🪶 Minimal Dependencies:** Keep the core runtime package footprint under 5MB with near-zero external dependencies. Heavy models (like SpaCy/Transformers) must always remain strictly optional opt-ins.
3. **🔄 Deterministic Reversibility:** Stream unmasking must remain mathematically lossless, reconstructing identical original data with zero truncation.
4. **🔒 In-Process Security (Zero-Egress):** All PII token-to-value mappings must live exclusively in local application memory (in-process RAM) inside the developer's private trust boundary (VPC), with zero external network egress.

---

## 📅 Release Milestones

```
  v1.1.0 (Current)       ──► Secrets/API Keys + IPv6 + Span Slicing + Dynamic Buffer
        │
  v1.2.0 (Q1 2027)       ──► FastAPI Middleware + LangChain/LlamaIndex + Async Streams
        │
  v1.3.0 (Q2 2027)       ──► Healthcare (HIPAA / NPI / DEA) + Global National IDs
        │
  v2.0.0 (Q3 2027)       ──► OpenTelemetry Metrics + Distributed Ephemeral Vaults
```

---

## ✅ Milestone 1: Core Engine Hardening & Secrets Detection (v1.1.0)
*Status: Completed & Released in v1.1.0*

### 1.1 Developer Secrets & Cloud API Key Detection
LLM prompts often accidentally contain pasted terminal logs, `.env` files, or configuration snippets. Expand detection to include high-risk secrets without degrading latency:
* **AWS Access Keys:** Regex pattern matching `AKIA[0-9A-Z]{16}`.
* **GitHub Tokens:** Personal Access Tokens matching `ghp_[A-Za-z0-9_]{36}` and fine-grained tokens `github_pat_[A-Za-z0-9_]{82}`.
* **OpenAI & Anthropic Keys:** Standard project keys `sk-proj-[A-Za-z0-9_-]{48,}`.
* **Generic Bearer Tokens:** Authorization headers `Bearer [A-Za-z0-9\-\._~\+\/]+=*`.
* **Private RSA/SSH Keys:** Boundaries matching `-----BEGIN (?:RSA )?PRIVATE KEY-----`.

### 1.2 Span / Offset-Based Redaction Engine
* **Current Behavior:** Global substring replacement via `str.replace(val, replacement)`.
* **Upgrade:** Migrate to character offset span replacement (slicing text from right to left using `match.start()` and `match.end()`).
* **Benefit:** Guarantees zero out-of-order replacements and prevents accidental substring collisions when identical tokens repeat in a single prompt.

### 1.3 Dynamic Sliding-Window Safety Tail
* **Current Behavior:** Fixed 20-character safety tail in `StreamingGuardrail`.
* **Upgrade:** Dynamically compute safety tail based on active vault placeholders:
  ```python
  tail_size = max((len(p) for p in self.vault.reverse_map), default=15)
  yield_len = max(1, len(buffer) - tail_size)
  ```
* **Benefit:** Completely eliminates truncation risk for longer custom entity tags like `[STREET_ADDRESS_100]`.

### 1.4 Comprehensive IPv6 & Network Validation
* Replace custom string splitting with Python standard library `ipaddress.ip_address`.
* Adds full support for compressed and full IPv6 addresses (`2001:0db8::1`, `::1`) with zero external dependencies.

---

## 🔌 Milestone 2: Framework Integrations & Async Streaming (v1.2.0)
*Target: Developer Ergonomics & Ecosystem Adoption*

### 2.1 Native FastAPI / Starlette Middleware
Allow engineering teams to secure all inbound prompts and outbound streams with a single line of code:
```python
from fastapi import FastAPI
from fastguard.integrations.fastapi import FastGuardMiddleware

app = FastAPI()
app.add_middleware(
    FastGuardMiddleware,
    redact_requests=True,
    unmask_responses=True,
    work_domains={"company.com"}
)
```

### 2.2 LangChain & LlamaIndex Integrations
* **LangChain Custom Runnable:** Drop-in pipeline transformation step:
  ```python
  chain = prompt_template | fastguard.as_runnable() | llm | fastguard.as_unmasker()
  ```
* **LlamaIndex Query Engine Guardrail:** Native hook on query inputs and synthesizer token outputs.

### 2.3 Asynchronous Token Stream Engine (`async_wrap_stream`)
* Provide native support for Python `AsyncIterable[str]` streams:
  ```python
  async def wrap_async_stream(self, token_stream: AsyncIterable[str]) -> AsyncGenerator[str, None]:
      # Asynchronous sliding window buffer for modern async LLM SDKs
  ```

---

## 🏥 Milestone 3: Healthcare & Global Compliance (v1.3.0)
*Target: Enterprise Healthcare & Global Identity Regulations*

### 3.1 HIPAA Medical PII Coverage (USA)
* **National Provider Identifier (NPI):** 10-digit medical provider IDs validated via Luhn checksum with fixed 80840 prefix calculation.
* **DEA Registration Numbers:** 9-character provider credentials validated via 2-letter prefix + checksum verification:
  $$\text{Sum} = (\text{odd digits}) + 2 \times (\text{even digits}) \implies \text{last digit matches check digit}.$$

### 3.2 Global National Identity Extensions
* **Europe:** German Tax ID (Steuer-ID), French INSEE social security code, and UK National Insurance Number enhancements.
* **Asia-Pacific:** Singapore NRIC/FIN with weighted modulus-11 check digit verification.

---

## 🏢 Milestone 4: Enterprise Scale & Observability (v2.0.0)
*Target: High-Throughput Production Infrastructure*

### 4.1 OpenTelemetry & Prometheus Metrics Export
Production AI platforms need visibility into what data is being intercepted:
* **Metric Counters:** `fastguard.redacted.total{entity_type="CREDIT_CARD"}`
* **Latency Histograms:** `fastguard.execution_latency_us`
* **Audit Tracing:** OpenTelemetry spans attached to active distributed traces.

### 4.2 Distributed Ephemeral Vault (Multi-Pod Clustering)
* *The Problem:* In massive Kubernetes clusters with decoupled gateway architectures, a request may arrive at Pod A, while its streaming response is handled by Pod B.
* *The Solution:* An optional, high-speed distributed cache adapter (e.g. Redis / DragonFly with TTL auto-expiration) so reverse maps can be resolved across distributed microservice instances while maintaining strict per-session expiration.

---

## 🤝 Community & Feedback

We welcome contributions, feature suggestions, and edge-case reports from the open-source community:
* **GitHub Issues:** [github.com/lokeshjothiramdev/fastguard/issues](https://github.com/lokeshjothiramdev/fastguard/issues)
* **PyPI Package:** [pypi.org/project/fastguard](https://pypi.org/project/fastguard/)
