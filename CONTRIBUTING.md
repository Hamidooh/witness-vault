# Contributing to Witness Vault

Thank you for your interest in contributing to **Witness Vault**!

## Development Philosophy
- **Simplicity Above All**: Zero bloated frameworks. The decryptor UI must stay lightweight, self-contained, and completely free of external dependencies or CDNs.
- **Strict Cryptographic Standards**: All crypto routines must remain 100% interoperable between Python `cryptography` and W3C `crypto.subtle`.
- **Air-Gapped by Design**: No telemetry, no external font requests, no network leaks.

## Local Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/witness-vault/witness-vault.git
   cd witness-vault
   ```
2. Install in editable mode:
   ```bash
   pip install -e .
   ```
3. Run the test suite:
   ```bash
   python -m unittest discover -s tests -p "test_*.py" -v
   ```

## Pull Request Guidelines
- Ensure all tests pass.
- Write tests for any new CLI features or cryptographic edge cases.
- Follow PEP 8 guidelines for Python code and clean ES6 standards for browser JavaScript.
