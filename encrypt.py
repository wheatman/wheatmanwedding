#!/usr/bin/env python3

import base64
import getpass
import hashlib
import json
import mimetypes
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SOURCE_DIR = Path("private")
OUTPUT_FILE = Path("encrypted-site.json")

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the password."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt data with AES-256-GCM."""
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ciphertext


def get_mime_type(path: Path) -> str:
    """Determine the MIME type of a file."""
    mime_type, _ = mimetypes.guess_type(path)

    if mime_type is None:
        return "application/octet-stream"

    return mime_type


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not SOURCE_DIR.exists():
        raise SystemExit(
            f"ERROR: Source directory does not exist: {SOURCE_DIR}"
        )

    if not SOURCE_DIR.is_dir():
        raise SystemExit(
            f"ERROR: Source path is not a directory: {SOURCE_DIR}"
        )

    # -----------------------------------------------------------------------
    # Get password
    # -----------------------------------------------------------------------

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")

    if not password:
        raise SystemExit("ERROR: Password cannot be empty.")

    if password != confirmation:
        raise SystemExit("ERROR: Passwords do not match.")

    # -----------------------------------------------------------------------
    # Derive encryption key
    # -----------------------------------------------------------------------

    print()
    print("Generating encryption key...")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    # -----------------------------------------------------------------------
    # Find files
    # -----------------------------------------------------------------------

    files = sorted(
        path
        for path in SOURCE_DIR.rglob("*")
        if path.is_file()
    )

    if not files:
        raise SystemExit(
            f"ERROR: No files found in {SOURCE_DIR}"
        )

    print(f"Found {len(files)} file(s).")
    print()

    # -----------------------------------------------------------------------
    # Encrypt files
    # -----------------------------------------------------------------------

    encrypted_files = {}

    for path in files:
        # Store paths relative to private/
        relative_path = path.relative_to(SOURCE_DIR).as_posix()

        print(f"Encrypting {relative_path}...")

        data = path.read_bytes()
        nonce, ciphertext = encrypt_file(data, key)

        encrypted_files[relative_path] = {
            "mime": get_mime_type(path),
            "nonce": base64_encode(nonce),
            "ciphertext": base64_encode(ciphertext),
        }

    # -----------------------------------------------------------------------
    # Build encrypted site
    # -----------------------------------------------------------------------

    site = {
        "version": 2,
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64_encode(salt),
        "files": encrypted_files,
    }

    # -----------------------------------------------------------------------
    # Write output
    # -----------------------------------------------------------------------

    print()
    print(f"Writing {OUTPUT_FILE}...")

    OUTPUT_FILE.write_text(
        json.dumps(site, indent=2),
        encoding="utf-8",
    )

    print()
    print("Done!")
    print()
    print(f"Encrypted site: {OUTPUT_FILE}")
    print(f"Files encrypted: {len(encrypted_files)}")
    print()
    print("Nothing inside private/ was modified.")
    print("The plaintext files remain in private/ and should NOT be committed.")
    print()


if __name__ == "__main__":
    main()
