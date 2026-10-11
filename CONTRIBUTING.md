# Contributing to FastGuard 🛡️

Thank you for your interest in contributing to **FastGuard**! We welcome contributions of all kinds: bug fixes, new PII pattern detectors, documentation improvements, test cases, and performance optimizations.

---

## 🚀 Getting Started

### 1. Fork and Clone the Repository

1. Click the **Fork** button at the top-right of [FastGuard on GitHub](https://github.com/lokeshjothiramdev/fastguard).
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/fastguard.git
   cd fastguard
   ```

### 2. Set Up a Virtual Environment

Create and activate a virtual environment:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install in Editable Mode with Development Dependencies

```bash
pip install --upgrade pip
pip install -e ".[dev,demo]"
```

---

## 🧪 Running Tests

Ensure all existing tests pass before making any changes:

```bash
pytest -v
```

To run performance benchmarks:
```bash
python benchmark.py
```

To launch the local interactive sandbox demo:
```bash
python demo.py
```

---

## 🛠️ Adding New Features or PII Entities

When adding a new PII entity detector (e.g. passport number, tax ID):

1. **Regex & Checksum**: Add regex pattern and any algorithmic checksum validation (Luhn, Mod-97, Verhoeff, etc.) in [`fastguard/pii/checksums.py`](https://github.com/lokeshjothiramdev/fastguard/blob/main/fastguard/pii/checksums.py) and [`fastguard/pii/vault.py`](https://github.com/lokeshjothiramdev/fastguard/blob/main/fastguard/pii/vault.py).
2. **Type Annotations**: Ensure all functions have proper Python type hints (PEP 561 compliance).
3. **Thread Safety**: Ensure all state mutations in `PIIVault` remain protected under `self._lock`.
4. **Unit Tests**: Add positive, negative, and edge-case unit tests in `tests/test_pii.py`.

---

## 📥 Submitting a Pull Request (PR)

1. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature/my-cool-feature
   ```
2. Commit your changes with a clear, concise message:
   ```bash
   git commit -m "feat: add driver license detection with checksum validator"
   ```
3. Push your branch to your GitHub fork:
   ```bash
   git push origin feature/my-cool-feature
   ```
4. Go to [FastGuard Pull Requests](https://github.com/lokeshjothiramdev/fastguard/pulls) and click **"New Pull Request"**.
5. Describe what changes you made and why.

---

## 💬 Questions or Security Reports?

- **General Questions / Ideas**: Open an issue on [GitHub Issues](https://github.com/lokeshjothiramdev/fastguard/issues).
- **Security Vulnerabilities**: Please review [`SECURITY.md`](https://github.com/lokeshjothiramdev/fastguard/blob/main/SECURITY.md) and report privately via email to `lokesh.jothiram.contact@gmail.com`.

Thank you for making FastGuard faster and safer for everyone! 🛡️
