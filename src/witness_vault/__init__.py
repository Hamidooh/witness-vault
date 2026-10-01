"""
Witness Vault - Zero-install, air-gapped, self-decrypting HTML vaults.
"""

__version__ = "1.0.0"
__author__ = "Witness Vault Authors"
__license__ = "MIT"

from .crypto import encrypt_payload, decrypt_payload, compute_sha256
from .template import generate_vault_html, extract_vault_data

__all__ = [
    "encrypt_payload",
    "decrypt_payload",
    "compute_sha256",
    "generate_vault_html",
    "extract_vault_data",
]
