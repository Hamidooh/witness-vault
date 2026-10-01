"""
Integration tests for Witness Vault CLI.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestWitnessVaultCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)
        self.sample_file = self.tmppath / "secret_document.txt"
        self.sample_file.write_text("Top secret payload for CLI testing.", encoding="utf-8")
        self.vault_file = self.tmppath / "sealed.vault.html"
        self.passphrase = "cli-secret-pass-2026"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_cli_seal_inspect_unseal(self):
        # 1. Seal
        seal_cmd = [
            sys.executable,
            "-m",
            "witness_vault.cli",
            "seal",
            str(self.sample_file),
            "-p",
            self.passphrase,
            "-o",
            str(self.vault_file),
            "--title",
            "CLI Vault Test",
            "--hint",
            "Password Hint Test",
            "--iterations",
            "10000",
        ]
        res = subprocess.run(
            seal_cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent / "src"),
        )
        self.assertEqual(res.returncode, 0, f"Seal failed: {res.stderr}")
        self.assertTrue(self.vault_file.exists())
        self.assertIn("Witness Vault successfully sealed", res.stdout)

        # 2. Inspect
        inspect_cmd = [
            sys.executable,
            "-m",
            "witness_vault.cli",
            "inspect",
            str(self.vault_file),
        ]
        res_inspect = subprocess.run(
            inspect_cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent / "src"),
        )
        self.assertEqual(res_inspect.returncode, 0)
        self.assertIn("CLI Vault Test", res_inspect.stdout)
        self.assertIn("Password Hint Test", res_inspect.stdout)

        # 3. Unseal
        extracted_file = self.tmppath / "extracted_output.txt"
        unseal_cmd = [
            sys.executable,
            "-m",
            "witness_vault.cli",
            "unseal",
            str(self.vault_file),
            "-p",
            self.passphrase,
            "-o",
            str(extracted_file),
        ]
        res_unseal = subprocess.run(
            unseal_cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent / "src"),
        )
        self.assertEqual(res_unseal.returncode, 0, f"Unseal failed: {res_unseal.stderr}")
        self.assertTrue(extracted_file.exists())
        self.assertEqual(
            extracted_file.read_text(encoding="utf-8"),
            "Top secret payload for CLI testing.",
        )


if __name__ == "__main__":
    unittest.main()
