"""
Command-line interface for Witness Vault.
"""

import argparse
import getpass
import mimetypes
import os
import sys
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional

from . import __version__
from .crypto import DEFAULT_ITERATIONS, compute_sha256, decrypt_payload, encrypt_payload
from .template import extract_vault_data, generate_vault_html


def format_size(num_bytes: int) -> str:
    """Format bytes into human-readable size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def get_passphrase_input(confirm: bool = True) -> str:
    """Prompt user securely for passphrase."""
    while True:
        pwd = getpass.getpass("Enter vault passphrase: ")
        if not pwd:
            print("Error: Passphrase cannot be empty.", file=sys.stderr)
            continue
        if not confirm:
            return pwd
        pwd2 = getpass.getpass("Confirm vault passphrase: ")
        if pwd == pwd2:
            return pwd
        print("Error: Passphrases do not match. Try again.", file=sys.stderr)


def cmd_seal(args: argparse.Namespace) -> int:
    """Seal a file or message into an encrypted HTML vault."""
    # Determine input data
    input_path: Optional[Path] = None
    filename: Optional[str] = None
    mime_type: str = "text/plain"

    if args.text is not None:
        data = args.text.encode("utf-8")
        title = args.title or "Encrypted Text Note"
        default_out = "note.vault.html"
    elif args.input_file:
        input_path = Path(args.input_file)
        if not input_path.is_file():
            print(f"Error: File not found: {args.input_file}", file=sys.stderr)
            return 1
        data = input_path.read_bytes()
        filename = input_path.name
        guessed_type, _ = mimetypes.guess_type(str(input_path))
        mime_type = guessed_type or "application/octet-stream"
        title = args.title or f"Vault: {input_path.name}"
        default_out = f"{input_path.stem}.vault.html"
    elif not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
        title = args.title or "Encrypted Stream"
        default_out = "stream.vault.html"
    else:
        print("Error: You must provide an input file, --text, or pipe input via stdin.", file=sys.stderr)
        return 1

    passphrase = args.passphrase
    if not passphrase:
        passphrase = get_passphrase_input(confirm=True)

    out_path = Path(args.output or default_out)

    print(f"[*] Sealing payload ({format_size(len(data))})...")
    vault_data = encrypt_payload(
        data=data,
        passphrase=passphrase,
        title=title,
        filename=filename,
        mime_type=mime_type,
        public_hint=args.hint,
        iterations=args.iterations,
        max_attempts=args.max_attempts,
    )

    html_content = generate_vault_html(vault_data)
    out_path.write_text(html_content, encoding="utf-8")

    digest = compute_sha256(data)
    print("\n[+] Witness Vault successfully sealed!")
    print(f"    Output:        {out_path.resolve()}")
    print(f"    Payload Size:  {format_size(len(data))}")
    print(f"    Vault Size:    {format_size(len(html_content.encode('utf-8')))}")
    print(f"    SHA-256 Seal:  {digest}")
    print(f"    Iterations:    {args.iterations:,} (PBKDF2-HMAC-SHA256)")
    print("\nYou can open this file in any web browser (online or offline) with zero dependencies.\n")
    return 0


def cmd_unseal(args: argparse.Namespace) -> int:
    """Unseal an encrypted HTML vault from the terminal."""
    vault_path = Path(args.vault_file)
    if not vault_path.is_file():
        print(f"Error: Vault file not found: {args.vault_file}", file=sys.stderr)
        return 1

    html_content = vault_path.read_text(encoding="utf-8")
    try:
        vault_data = extract_vault_data(html_content)
    except Exception as err:
        print(f"Error extracting vault data: {err}", file=sys.stderr)
        return 1

    passphrase = args.passphrase
    if not passphrase:
        passphrase = get_passphrase_input(confirm=False)

    try:
        data, meta = decrypt_payload(vault_data, passphrase)
    except Exception as err:
        print(f"[-] Decryption failed: {err}", file=sys.stderr)
        return 1

    print("\n[+] Cryptographic Integrity Verified!")
    print(f"    Title:         {meta.get('title')}")
    print(f"    MIME Type:     {meta.get('mime_type')}")
    print(f"    SHA-256 Seal:  {meta.get('sha256')}")

    out_path = args.output
    if out_path:
        Path(out_path).write_bytes(data)
        print(f"    Saved payload: {Path(out_path).resolve()}\n")
    elif meta.get("filename"):
        out_filename = meta["filename"]
        target = Path(out_filename)
        if target.exists():
            target = Path(f"decrypted_{out_filename}")
        target.write_bytes(data)
        print(f"    Extracted:     {target.resolve()}\n")
    else:
        # Print text to stdout
        try:
            text = data.decode("utf-8")
            print("\n--- Decrypted Payload ---")
            print(text)
            print("-------------------------\n")
        except UnicodeDecodeError:
            out_bin = Path("decrypted_payload.bin")
            out_bin.write_bytes(data)
            print(f"    Binary data saved to: {out_bin.resolve()}\n")

    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect public metadata of a vault without decrypting."""
    vault_path = Path(args.vault_file)
    if not vault_path.is_file():
        print(f"Error: Vault file not found: {args.vault_file}", file=sys.stderr)
        return 1

    html_content = vault_path.read_text(encoding="utf-8")
    try:
        data = extract_vault_data(html_content)
    except Exception as err:
        print(f"Error reading vault: {err}", file=sys.stderr)
        return 1

    print("\n[=] Witness Vault Inspection")
    print(f"    File:          {vault_path.resolve()}")
    print(f"    Title:         {data.get('public_title', 'Untitled')}")
    print(f"    Public Hint:   {data.get('public_hint') or '(none)'}")
    print(f"    Sealed At:     {data.get('sealed_at', 'unknown')}")
    print(f"    Cipher:        {data.get('cipher', 'AES-256-GCM')}")
    print(f"    KDF:           {data.get('kdf', 'PBKDF2-HMAC-SHA256')}")
    print(f"    Iterations:    {data.get('iterations', 600000):,}")
    print(f"    Max Attempts:  {data.get('max_attempts', 5)}")
    print(f"    Ciphertext:    {format_size(len(data.get('ciphertext', '')))}\n")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    """Launch the offline standalone Web Builder."""
    web_dir = Path(__file__).resolve().parent.parent.parent / "web"
    if not web_dir.is_dir() or not (web_dir / "index.html").is_file():
        print(f"Error: Web directory not found at {web_dir}", file=sys.stderr)
        return 1

    port = args.port
    host = args.host

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(web_dir), **kwargs)

        def log_message(self, format, *args):
            # Quiet log
            pass

    server = HTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"[*] Witness Vault Web Builder running at: {url}")
    print("    Press Ctrl+C to stop.")

    if not args.no_open:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser."""
    parser = argparse.ArgumentParser(
        prog="witness-vault",
        description="Witness Vault: Zero-install, air-gapped, self-decrypting HTML vaults.",
    )
    parser.add_argument(
        "--version", action="version", version=f"witness-vault {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # seal
    seal_p = subparsers.add_parser("seal", help="Seal a file or message into a standalone HTML vault")
    seal_p.add_argument("input_file", nargs="?", help="Path to file to seal")
    seal_p.add_argument("-t", "--text", help="Direct text content to seal")
    seal_p.add_argument("-o", "--output", help="Output path for .vault.html")
    seal_p.add_argument("-p", "--passphrase", help="Passphrase (prompted securely if omitted)")
    seal_p.add_argument("--title", help="Custom title for the vault")
    seal_p.add_argument("--hint", help="Optional public hint shown on lock screen")
    seal_p.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iteration count (default: {DEFAULT_ITERATIONS:,})",
    )
    seal_p.add_argument(
        "--max-attempts",
        type=int,
        default=5,
        help="Max unlocking attempts before locking in browser (default: 5)",
    )

    # unseal
    unseal_p = subparsers.add_parser("unseal", help="Decrypt and extract an existing vault HTML")
    unseal_p.add_argument("vault_file", help="Path to .vault.html file")
    unseal_p.add_argument("-p", "--passphrase", help="Passphrase (prompted if omitted)")
    unseal_p.add_argument("-o", "--output", help="Output file path (prints to stdout if text and omitted)")

    # inspect
    inspect_p = subparsers.add_parser("inspect", help="Inspect public metadata of a vault file")
    inspect_p.add_argument("vault_file", help="Path to .vault.html file")

    # web
    web_p = subparsers.add_parser("web", help="Launch the offline Web Builder in your browser")
    web_p.add_argument("--port", type=int, default=8383, help="Port to listen on (default: 8383)")
    web_p.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    web_p.add_argument("--no-open", action="store_true", help="Do not auto-open browser")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "seal":
        sys.exit(cmd_seal(args))
    elif args.command == "unseal":
        sys.exit(cmd_unseal(args))
    elif args.command == "inspect":
        sys.exit(cmd_inspect(args))
    elif args.command == "web":
        sys.exit(cmd_web(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
