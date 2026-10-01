"""
Cryptographic engine for Witness Vault.
Standard: AES-256-GCM + PBKDF2-HMAC-SHA256 (600,000 iterations).
Byte-compatible with W3C Web Cryptography API (crypto.subtle).
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_ITERATIONS = 600_000
SALT_BYTES = 16
IV_BYTES = 12


def compute_sha256(data: bytes) -> str:
    """Compute the hexadecimal SHA-256 digest of arbitrary bytes."""
    return hashlib.sha256(data).hexdigest()


def derive_key(passphrase: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """
    Derive a 256-bit symmetric key from a passphrase and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_payload(
    data: bytes,
    passphrase: str,
    title: str = "Encrypted Witness Vault",
    filename: Optional[str] = None,
    mime_type: str = "text/plain",
    public_hint: Optional[str] = None,
    iterations: int = DEFAULT_ITERATIONS,
    max_attempts: int = 5,
) -> Dict[str, Any]:
    """
    Encrypts arbitrary data and packages it into a vault payload.
    """
    if not passphrase:
        raise ValueError("Passphrase must not be empty.")

    salt = os.urandom(SALT_BYTES)
    iv = os.urandom(IV_BYTES)
    created_at = datetime.now(timezone.utc).isoformat()
    integrity_hash = compute_sha256(data)

    # Internal confidential envelope
    inner_envelope = {
        "title": title,
        "filename": filename,
        "mime_type": mime_type,
        "created_at": created_at,
        "sha256": integrity_hash,
        "data_b64": base64.b64encode(data).decode("ascii"),
    }
    plaintext_bytes = json.dumps(inner_envelope, separators=(",", ":")).encode("utf-8")

    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)

    return {
        "version": 1,
        "cipher": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "public_title": title,
        "public_hint": public_hint or "",
        "max_attempts": max_attempts,
        "sealed_at": created_at,
    }


def decrypt_payload(vault_data: Dict[str, Any], passphrase: str) -> Tuple[bytes, Dict[str, Any]]:
    """
    Decrypts a vault envelope and verifies its SHA-256 integrity seal.
    Returns: (raw_data_bytes, metadata_dict)
    Raises: ValueError on invalid password or corrupted data.
    """
    if not passphrase:
        raise ValueError("Passphrase must not be empty.")

    try:
        salt = base64.b64decode(vault_data["salt"])
        iv = base64.b64decode(vault_data["iv"])
        ciphertext = base64.b64decode(vault_data["ciphertext"])
        iterations = int(vault_data.get("iterations", DEFAULT_ITERATIONS))
    except (KeyError, ValueError) as err:
        raise ValueError(f"Corrupted or invalid vault structure: {err}") from err

    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)

    try:
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    except Exception as err:
        raise ValueError("Decryption failed. Incorrect passphrase or corrupted ciphertext.") from err

    try:
        inner = json.loads(decrypted_bytes.decode("utf-8"))
        raw_data = base64.b64decode(inner["data_b64"])
    except Exception as err:
        raise ValueError(f"Failed to unpack decrypted payload: {err}") from err

    # Verify cryptographic integrity
    expected_sha256 = inner.get("sha256")
    actual_sha256 = compute_sha256(raw_data)
    if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            f"Integrity check failed! Expected SHA-256: {expected_sha256}, calculated: {actual_sha256}"
        )

    metadata = {
        "title": inner.get("title", "Witness Vault"),
        "filename": inner.get("filename"),
        "mime_type": inner.get("mime_type", "application/octet-stream"),
        "created_at": inner.get("created_at"),
        "sha256": actual_sha256,
        "sealed_at": vault_data.get("sealed_at"),
    }

    return raw_data, metadata
