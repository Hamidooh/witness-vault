# Security Policy

## Cryptographic Specification & Threat Model

**Witness Vault** is engineered to provide local, zero-leakage, authenticated encryption for confidential files and text notes without relying on external cloud providers or client installations.

### Cryptographic Parameters
- **Symmetric Cipher**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Nonce / IV**: 96-bit (12 bytes) cryptographically secure pseudorandom value generated per vault (`os.urandom` in Python, `crypto.getRandomValues` in browser).
- **Salt**: 128-bit (16 bytes) CSPRNG salt generated per vault.
- **Key Derivation Function**: PBKDF2 with HMAC-SHA-256.
- **Default Iteration Count**: 600,000 rounds (exceeding OWASP Password Storage & Key Derivation recommendations).
- **Integrity Seal**: SHA-256 digest computed directly over the unencrypted payload before sealing, verified upon decryption.

### Client-Side Isolation
- Standalone vault files enforce strict Content Security Policy (CSP):
  ```http
  default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:; font-src data:;
  ```
- **Zero Network Traffic**: Generated HTML vaults do not load external fonts, analytics, tracking pixels, or remote scripts. They function identically on completely air-gapped systems.
- **Volatile Memory**: Includes a one-click "Zeroize Memory" button that overwrites memory buffers with zeroes before terminating the session.

### Reporting a Vulnerability
If you discover a potential vulnerability or weakness in the cryptographic implementation, please report it via private security advisory or email the maintainers directly. Do not open public issues for zero-day disclosures.
