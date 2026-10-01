"""
Unit tests for Witness Vault cryptography engine and HTML template generation.
"""

import os
import sys
import unittest
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from witness_vault.crypto import (
    compute_sha256,
    decrypt_payload,
    derive_key,
    encrypt_payload,
)
from witness_vault.template import extract_vault_data, generate_vault_html


class TestWitnessVaultCrypto(unittest.TestCase):
    def setUp(self):
        self.passphrase = "correct-horse-battery-staple-2026"
        self.sample_text = b"Witness Vault Classified Instructions"
        self.sample_binary = os.urandom(1024)

    def test_sha256(self):
        digest = compute_sha256(b"hello world")
        self.assertEqual(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )

    def test_encrypt_decrypt_text_roundtrip(self):
        vault = encrypt_payload(
            data=self.sample_text,
            passphrase=self.passphrase,
            title="Operation Silver",
            filename="instructions.txt",
            mime_type="text/plain",
            public_hint="XKCD reference",
            iterations=10_000,  # Fast iterations for tests
        )

        self.assertEqual(vault["public_title"], "Operation Silver")
        self.assertEqual(vault["public_hint"], "XKCD reference")

        decrypted_data, meta = decrypt_payload(vault, self.passphrase)
        self.assertEqual(decrypted_data, self.sample_text)
        self.assertEqual(meta["title"], "Operation Silver")
        self.assertEqual(meta["filename"], "instructions.txt")
        self.assertEqual(meta["sha256"], compute_sha256(self.sample_text))

    def test_encrypt_decrypt_binary_roundtrip(self):
        vault = encrypt_payload(
            data=self.sample_binary,
            passphrase=self.passphrase,
            title="Firmware Blob",
            filename="firmware.bin",
            mime_type="application/octet-stream",
            iterations=10_000,
        )

        decrypted_data, meta = decrypt_payload(vault, self.passphrase)
        self.assertEqual(decrypted_data, self.sample_binary)
        self.assertEqual(meta["filename"], "firmware.bin")
        self.assertEqual(meta["sha256"], compute_sha256(self.sample_binary))

    def test_wrong_passphrase_fails(self):
        vault = encrypt_payload(
            data=self.sample_text,
            passphrase=self.passphrase,
            iterations=10_000,
        )

        with self.assertRaises(ValueError):
            decrypt_payload(vault, "wrong-password")

    def test_tamper_detection(self):
        import base64

        vault = encrypt_payload(
            data=self.sample_text,
            passphrase=self.passphrase,
            iterations=10_000,
        )

        # Corrupt one byte of ciphertext
        raw_ct = bytearray(base64.b64decode(vault["ciphertext"]))
        raw_ct[0] ^= 0xFF
        vault["ciphertext"] = base64.b64encode(raw_ct).decode("ascii")

        with self.assertRaises(ValueError):
            decrypt_payload(vault, self.passphrase)

    def test_html_template_roundtrip(self):
        vault = encrypt_payload(
            data=self.sample_text,
            passphrase=self.passphrase,
            title="Self-Contained Vault",
            public_hint="Test hint",
            iterations=10_000,
        )

        html = generate_vault_html(vault)
        self.assertIn("Self-Contained Vault", html)
        self.assertIn("Witness Vault", html)

        extracted = extract_vault_data(html)
        self.assertEqual(extracted["ciphertext"], vault["ciphertext"])
        self.assertEqual(extracted["salt"], vault["salt"])
        self.assertEqual(extracted["iv"], vault["iv"])

        decrypted, meta = decrypt_payload(extracted, self.passphrase)
        self.assertEqual(decrypted, self.sample_text)


if __name__ == "__main__":
    unittest.main()
