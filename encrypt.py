#!/usr/bin/env python3

import base64
import csv
import getpass
import hashlib
import json
import mimetypes
import os
import re
import unicodedata
from pathlib import Path

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SOURCE_DIR = Path("private")
GUESTS_FILE = SOURCE_DIR / "guests.csv"
WEDDING_HTML = SOURCE_DIR / "wedding.html"

OUTPUT_FILE = Path("encrypted-site.json")

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12

GUEST_PAGE_PREFIX = "wedding-guest-"
GUEST_PAGE_SUFFIX = ".html"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def encrypt_file(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ciphertext


def get_mime_type(path: Path) -> str:
    mime_type, _ = mimetypes.guess_type(path)
    return mime_type or "application/octet-stream"


def normalize_tag(tag: str) -> str:
    return tag.strip().lower()


def parse_tags(value: str) -> set[str]:
    if not value:
        return set()

    # Accept either commas or semicolons between tags.
    return {
        normalize_tag(tag)
        for tag in re.split(r"[,;]", value)
        if normalize_tag(tag)
    }


def make_slug(name: str) -> str:
    """
    Produce a predictable filename from a guest name.

    The same normalization will be used by the browser login code.
    """
    normalized = unicodedata.normalize("NFKD", name)
    normalized = normalized.encode("ascii", "ignore").decode("ascii")
    normalized = normalized.lower().strip()
    normalized = re.sub(r"[^a-z0-9]+", "-", normalized)
    return normalized.strip("-")


def encrypt_into(
    encrypted_files: dict,
    relative_path: str,
    data: bytes,
    key: bytes,
    mime_type: str,
):
    print(f"Encrypting {relative_path}...")

    nonce, ciphertext = encrypt_file(data, key)

    encrypted_files[relative_path] = {
        "mime": mime_type,
        "nonce": base64_encode(nonce),
        "ciphertext": base64_encode(ciphertext),
    }


# ---------------------------------------------------------------------------
# Guest CSV
# ---------------------------------------------------------------------------

def load_guests():
    if not GUESTS_FILE.exists():
        raise SystemExit(
            f"ERROR: Guest CSV does not exist: {GUESTS_FILE}"
        )

    guests = []
    seen_names = set()
    seen_slugs = set()

    with GUESTS_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or not {
            "name", "tags"
        }.issubset(reader.fieldnames):
            raise SystemExit(
                "ERROR: guests.csv must have columns named "
                "'name' and 'tags'."
            )

        for row_number, row in enumerate(reader, start=2):
            name = (row.get("name") or "").strip()
            tags = parse_tags(row.get("tags") or "")

            if not name:
                raise SystemExit(
                    f"ERROR: Missing guest name on CSV row {row_number}."
                )

            name_key = name.casefold()

            if name_key in seen_names:
                raise SystemExit(
                    f"ERROR: Duplicate guest name: {name}"
                )

            slug = make_slug(name)

            if not slug:
                raise SystemExit(
                    f"ERROR: Guest name cannot be converted into a "
                    f"usable filename: {name}"
                )

            if slug in seen_slugs:
                raise SystemExit(
                    f"ERROR: Guest names produce the same filename: "
                    f"{name}. Please make the names distinct."
                )

            seen_names.add(name_key)
            seen_slugs.add(slug)

            guests.append({
                "name": name,
                "tags": tags,
                "slug": slug,
            })

    if not guests:
        raise SystemExit("ERROR: No guests found in guests.csv.")

    return guests


# ---------------------------------------------------------------------------
# Personalized HTML
# ---------------------------------------------------------------------------

def generate_guest_html(
    original_html: str,
    guest_tags: set[str],
    guest_name: str,
) -> bytes:
    soup = BeautifulSoup(original_html, "html.parser")

    # Find all elements that have guest visibility rules.
    for element in list(
        soup.find_all(attrs={
            "data-guests": True
        })
    ) + list(
        soup.find_all(attrs={
            "data-exclude-guests": True
        })
    ):

        allowed_tags = parse_tags(
            element.get("data-guests", "")
        )

        excluded_tags = parse_tags(
            element.get("data-exclude-guests", "")
        )

        # data-guests means at least one matching tag is required.
        if allowed_tags and not (allowed_tags & guest_tags):
            element.decompose()
            continue

        # data-exclude-guests means any matching tag hides the element.
        if excluded_tags & guest_tags:
            element.decompose()
            continue

        # Remove the processing attributes from the final HTML.
        element.attrs.pop("data-guests", None)
        element.attrs.pop("data-exclude-guests", None)

    print(
        f"  Generated page for {guest_name} "
        f"({', '.join(sorted(guest_tags)) or 'no special tags'})"
    )

    return str(soup).encode("utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not SOURCE_DIR.exists() or not SOURCE_DIR.is_dir():
        raise SystemExit(
            f"ERROR: Source directory does not exist: {SOURCE_DIR}"
        )

    if not WEDDING_HTML.exists():
        raise SystemExit(
            f"ERROR: Wedding HTML does not exist: {WEDDING_HTML}"
        )

    # -----------------------------------------------------------------------
    # Load guests
    # -----------------------------------------------------------------------

    guests = load_guests()

    print(f"Found {len(guests)} guest(s).")

    # -----------------------------------------------------------------------
    # Get shared website password
    # -----------------------------------------------------------------------

    password = getpass.getpass("Website password: ")
    confirmation = getpass.getpass("Confirm website password: ")

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

    encrypted_files = {}

    # -----------------------------------------------------------------------
    # Generate and encrypt personalized wedding pages
    # -----------------------------------------------------------------------

    original_html = WEDDING_HTML.read_text(encoding="utf-8")

    print()
    print("Generating personalized wedding pages...")

    for guest in guests:
        guest_html = generate_guest_html(
            original_html,
            guest["tags"],
            guest["name"],
        )

        output_path = (
            f"{GUEST_PAGE_PREFIX}"
            f"{guest['slug']}"
            f"{GUEST_PAGE_SUFFIX}"
        )

        encrypt_into(
            encrypted_files,
            output_path,
            guest_html,
            key,
            "text/html",
        )

    # -----------------------------------------------------------------------
    # Encrypt all other private files
    # -----------------------------------------------------------------------

    print()
    print("Encrypting shared website files...")

    files = sorted(
        path
        for path in SOURCE_DIR.rglob("*")
        if path.is_file()
        and path != WEDDING_HTML
        and ".git" not in path.relative_to(SOURCE_DIR).parts
        and "__pycache__" not in path.relative_to(SOURCE_DIR).parts
    )

    for path in files:
        relative_path = path.relative_to(SOURCE_DIR).as_posix()

        # The guest CSV is encrypted like every other shared file.
        encrypt_into(
            encrypted_files,
            relative_path,
            path.read_bytes(),
            key,
            get_mime_type(path),
        )

    # -----------------------------------------------------------------------
    # Build encrypted site
    # -----------------------------------------------------------------------

    site = {
        "version": 3,
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64_encode(salt),
        "guest_page_prefix": GUEST_PAGE_PREFIX,
        "guest_page_suffix": GUEST_PAGE_SUFFIX,
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
    print(f"Guests: {len(guests)}")
    print(f"Encrypted files: {len(encrypted_files)}")
    print()
    print("Generated one personalized HTML page per guest.")
    print("The original private files were not modified.")
    print("The plaintext files should NOT be committed.")
    print()


if __name__ == "__main__":
    main()
