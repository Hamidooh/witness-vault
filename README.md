# 🛡️ Witness Vault

<p align="center">
  <strong>Zero-install, air-gapped, self-decrypting HTML vaults.</strong><br>
  <em>Package confidential files and secret notes into portable, tamper-evident HTML capsules that unlock in any web browser without software, servers, or cloud dependencies.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-emerald?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Cipher-AES--256--GCM-06b6d4?style=flat-square" alt="Cipher">
  <img src="https://img.shields.io/badge/KDF-PBKDF2--600k-blueviolet?style=flat-square" alt="KDF">
  <img src="https://img.shields.io/badge/Air--Gapped-100%25-success?style=flat-square" alt="Air Gapped">
  <img src="https://img.shields.io/badge/Dependencies-Zero%20CDN-orange?style=flat-square" alt="Zero CDN">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square" alt="Python">
</p>

---

## ⚡ The Problem

Sending encrypted files or secret credentials usually forces both parties to:
- Install complex tools (`gpg`, `age`, 7-Zip, custom apps)
- Trust third-party cloud services or link-sharing websites
- Risk transmission of keys or telemetry metadata

## 💡 The Solution

**Witness Vault** transforms any file (PDF, image, binary, zip) or text note into a **single, standalone `.vault.html` file**:
- **Zero Software Required for the Recipient**: Opens in *any* web browser on iOS, Android, macOS, Linux, or Windows.
- **100% Air-Gapped & Offline**: Executes using native hardware-accelerated Web Cryptography (`window.crypto.subtle`). Disconnect your Wi-Fi, turn on Airplane mode — it decrypts identically.
- **Strict Content Security Policy (CSP)**: `default-src 'none'` forbids all outbound network requests, analytics, and phone-home telemetry.
- **Tamper-Evident Integrity**: Authenticated with **AES-256-GCM** and sealed with a pre-encryption **SHA-256** checksum.

---

## 🏗️ Architecture

```
┌─────────────────────────────────┐
│ Sensitive Payload (File / Text) │
└────────────────┬────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────┐
│ Cryptographic Seal Engine                              │
│ • PBKDF2-HMAC-SHA256 (600,000 iterations)              │
│ • Random 16-byte Salt + 12-byte IV                     │
│ • AES-256-GCM Authenticated Encryption                │
│ • SHA-256 Pre-Sealing Verification Digest             │
└────────────────┬───────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────┐
│ Portable .vault.html Capsule                           │
│ ┌────────────────────────────────────────────────────┐ │
│ │ Embedded Minimalist Decryptor UI (Vanilla JS & CSS)│ │
│ │ Strict Content Security Policy (Zero Outbound Nets)│ │
│ │ Encrypted JSON Envelope with Integrity Fingerprint │ │
│ └────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Quickstart

### 1. Install CLI via Pip

```bash
pip install witness-vault
```

*(Or clone the repository and run `pip install -e .`)*

### 2. Seal a Sensitive File

```bash
witness-vault seal secret_contract.pdf -o contract.vault.html
```
*(You will be prompted securely for a passphrase)*

### 3. Seal Direct Text / Credentials

```bash
witness-vault seal -t "recovery-seed-phrase: alpha brave charlie delta" \
  --title "Wallet Recovery 2026" \
  --hint "Favorite childhood city" \
  -o recovery.vault.html
```

### 4. Recipient Opens the File

Double-click `recovery.vault.html` in **any browser**. Enter the passphrase. Decrypt in microseconds.

---

## 🌐 Zero-Install Web App (No Python Required)

Want to seal files without installing Python? 

Open `web/index.html` in your browser, or launch the built-in local builder:
```bash
witness-vault web
```
- Drag and drop files or paste notes
- Select security profile (250k, 600k, or 1M PBKDF2 rounds)
- Click **"Seal & Download Standalone Vault"**
- The browser encrypts client-side in RAM and generates your standalone vault file instantly.

---

## 💻 CLI Commands

### Seal
```bash
witness-vault seal <file> [options]
  -t, --text TEXT           Encrypt raw text instead of a file
  -o, --output PATH         Custom destination file (default: <name>.vault.html)
  -p, --passphrase PASS     Provide passphrase directly (prompted if omitted)
  --title TITLE             Display title for the locked vault UI
  --hint HINT               Optional public hint shown on the lock screen
  --iterations ROUNDS       PBKDF2 round count (default: 600,000)
  --max-attempts N          Max unlock attempts before lockout (default: 5)
```

### Unseal (CLI Decryption)
```bash
witness-vault unseal sealed.vault.html -o decrypted_file.pdf
```
*(If payload is text and `-o` is omitted, prints cleanly to `stdout`)*

### Inspect (Metadata without Passphrase)
```bash
witness-vault inspect sealed.vault.html
```
Output:
```
[=] Witness Vault Inspection
    File:          recovery.vault.html
    Title:         Wallet Recovery 2026
    Public Hint:   Favorite childhood city
    Sealed At:     2026-10-01T12:18:53Z
    Cipher:        AES-256-GCM
    KDF:           PBKDF2-HMAC-SHA256
    Iterations:    600,000
    Max Attempts:  5
    Ciphertext:    1.2 KB
```

---

## 🔒 Cryptographic Specification

| Component | Standard / Value | Rationale |
| :--- | :--- | :--- |
| **Symmetric Cipher** | **AES-256-GCM** | Authenticated encryption prevents tampering & bit-flipping attacks. |
| **Key Derivation** | **PBKDF2-HMAC-SHA256** | Hardware-accelerated across all modern browsers and runtimes. |
| **KDF Iterations** | **600,000 rounds** | Complies with OWASP Password Storage Guidelines to defeat brute-force. |
| **Salt** | **128-bit (16 bytes)** | Cryptographically secure random bytes generated per sealed vault. |
| **Initialization Vector** | **96-bit (12 bytes)** | Unique random nonce per envelope, conforming to NIST SP 800-38D. |
| **Integrity Seal** | **SHA-256** | Computed over raw payload prior to encryption; validated post-decryption. |
| **Network Isolation** | **CSP `default-src 'none'`** | Cryptographically guaranteed zero-phone-home policy. |

---

## ⚔️ Comparison

| Feature | **Witness Vault** | PGP / GPG | Password-Protected ZIP | Cloud Pastebins |
| :--- | :---: | :---: | :---: | :---: |
| **Recipient Setup** | **Zero (Any Browser)** | High (Keyrings, Software) | Medium (ZIP Extractor) | Zero (Web Link) |
| **Air-Gapped Decryption** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ Requires Cloud |
| **Authenticated Cipher** | ✅ AES-256-GCM | ⚠️ Config-dependent | ❌ Often Legacy ZipCrypto | ❌ Server-dependent |
| **In-Browser Preview** | ✅ Yes | ❌ No | ❌ No | ⚠️ Unencrypted on Server |
| **Brute-Force Resistance** | ✅ 600,000 PBKDF2 | ✅ High | ⚠️ Low / Weak KDF | ❌ N/A |
| **RAM Scrubbing / Zeroize** | ✅ One-Click | ❌ No | ❌ No | ❌ No |

---

## 🧪 Test Suite

Run the unit and integration test suite:
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

All 7 test cases verify:
- SHA-256 integrity verification
- Text and binary round-trip encryption/decryption
- Tamper detection (single-bit corruption raises authentication rejection)
- Incorrect passphrase rejection
- HTML envelope parsing and round-trip extraction
- CLI execution and pipeline verification

---

## 📄 License

Witness Vault is open-source software licensed under the [MIT License](LICENSE).
