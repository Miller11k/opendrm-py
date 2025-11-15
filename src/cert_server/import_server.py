# import.py
"""
Import a certificate server bundle from a zip file.

Workflow:
    1. Safely extract the zip into a temporary directory.
    2. Run verifier.verify_all() against the extracted tree.
    3. If verification succeeds, replace (or create) the target root_dir.
    4. If anything fails, raise ValueError and leave existing data untouched.

This ensures only correctly structured / valid bundles are accepted.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from .verify_server import verify_all  # Uses verification suite


# --------- helpers ---------


def _safe_extract(zip_path: Path, target_dir: Path) -> None:
    """
    Safely extract a zip archive into target_dir.

    Guards against:
        - Absolute paths inside the archive.
        - Path traversal using "..".
        - Non-directory root (target_dir is created if needed).

    Args:
        zip_path (Path): Path to the .zip file.
        target_dir (Path): Directory where contents will be extracted.

    Raises:
        ValueError: If the zip is invalid or contains unsafe paths.
    """
    if not zip_path.is_file():
        raise ValueError(f"Zip file not found: {zip_path}")

    target_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                name = info.filename

                # Normalize to forward slashes and strip leading "./"
                # Zip spec always uses "/" internally.
                if name.startswith("./"):
                    name = name[2:]

                # Skip empty names
                if not name:
                    continue

                # Reject absolute paths
                if name.startswith("/") or name.startswith("\\"):
                    raise ValueError(f"Archive contains absolute path: {name}")

                # Reject traversal attempts
                parts = Path(name).parts
                if any(part == ".." for part in parts):
                    raise ValueError(f"Archive contains unsafe path: {name}")

                dest_path = target_dir.joinpath(*parts)

                # Create directories or files
                if name.endswith("/") or info.is_dir():
                    dest_path.mkdir(parents=True, exist_ok=True)
                else:
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as src, open(dest_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)

    except zipfile.BadZipFile as e:
        raise ValueError(f"Invalid zip file: {zip_path} ({e})") from e


def _replace_directory(src: Path, dest: Path) -> None:
    """
    Atomically-ish replace dest directory with src contents.

    Strategy:
        - If dest exists, move it to dest + ".bak" (once).
        - Move src -> dest.
        - If move fails, attempt to restore from backup.

    Args:
        src (Path): Source directory with verified content.
        dest (Path): Target directory to become the new root.

    Raises:
        ValueError: If replacement fails.
    """
    backup = dest.with_name(dest.name + ".bak")

    try:
        # Existing deployment -> backup
        if dest.exists():
            if backup.exists():
                # To keep semantics simple & safe, refuse if backup already exists.
                raise ValueError(
                    f"Destination {dest} already exists and backup {backup} already present; "
                    f"refusing to overwrite."
                )
            dest.rename(backup)

        # Move new tree into place
        shutil.move(str(src), str(dest))

        # If everything worked, optional: keep or delete backup.
        # For now, we leave backup in place for manual rollback.
    except Exception as e:
        # Try rollback if we had moved the original.
        if not dest.exists() and backup.exists():
            try:
                backup.rename(dest)
            except Exception:
                # If rollback fails, we surface the original error; operator must inspect manually.
                pass
        raise ValueError(f"Failed to install imported bundle: {e}") from e


# --------- public API ---------


def import_cert_server(
    zip_file: str,
    dest_root: str,
    *,
    # These must match how the bundle was created; callers can override as needed.
    intermediate_name: str = "issuing-ca-1",
    root_cn: str = "Example Root CA",
    intermediate_cn: str = "Example Issuing CA",
    server_hostname: str = "localhost",
    org: str = "Example Org",
    country: str = "US",
    passphrase: Optional[bytes] = None,
) -> Path:
    """
    Import a certificate server layout from a zip file, only if it passes verification.

    Steps:
        - Extracts zip into a temp directory.
        - Runs verifier.verify_all() against the extracted layout.
        - On success, replaces dest_root with the extracted tree.
        - On failure, raises ValueError and leaves dest_root unchanged.

    Args:
        zip_file (str): Path to the user-provided zip archive.
        dest_root (str): Destination directory where the CA layout should live.
        intermediate_name (str): Expected intermediate CA name.
        root_cn (str): Expected Root CA Common Name.
        intermediate_cn (str): Expected Intermediate CA Common Name.
        server_hostname (str): Expected server hostname.
        org (str): Expected organization.
        country (str): Expected country code.
        passphrase (bytes | None): Passphrase to decrypt keys (if encrypted).

    Returns:
        Path: The final destination directory path if import succeeds.

    Raises:
        ValueError: If the zip is unsafe, invalid, or fails verification.
    """
    zip_path = Path(zip_file)
    dest_path = Path(dest_root)

    # Use a temporary directory for extraction + verification to avoid partial installs.
    with tempfile.TemporaryDirectory(prefix="cert-import-") as tmp:
        tmp_root = Path(tmp) / "bundle"

        # 1. Safely extract.
        _safe_extract(zip_path, tmp_root)

        # 2. Verify structure & contents using existing verifier.
        verify_all(
            str(tmp_root),
            intermediate_name=intermediate_name,
            root_cn=root_cn,
            intermediate_cn=intermediate_cn,
            server_hostname=server_hostname,
            org=org,
            country=country,
            passphrase=passphrase,
        )

        # 3. If verify_all() didn't raise, we can install this bundle.
        _replace_directory(tmp_root, dest_path)

        return dest_path


def main() -> None:
    """
    Simple CLI entrypoint.

    Usage:
        python -m import_cert_server bundle.zip /path/to/dest \
            --passphrase "changeme"

    Note:
        - Passphrase is taken from the environment variable CERT_IMPORT_PASSPHRASE
          for simplicity. Adjust as needed for your environment.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Import a cert server bundle from zip.")
    parser.add_argument("zip_file", help="Path to the zip file to import.")
    parser.add_argument("dest_root", help="Destination directory for the imported CA layout.")
    parser.add_argument(
        "--passphrase-env",
        default="CERT_IMPORT_PASSPHRASE",
        help="Environment variable that holds the key passphrase (if any).",
    )
    parser.add_argument("--intermediate-name", default="issuing-ca-1")
    parser.add_argument("--root-cn", default="Example Root CA")
    parser.add_argument("--intermediate-cn", default="Example Issuing CA")
    parser.add_argument("--server-hostname", default="localhost")
    parser.add_argument("--org", default="Example Org")
    parser.add_argument("--country", default="US")

    args = parser.parse_args()

    passphrase_value = os.getenv(args.passphrase_env)
    passphrase = passphrase_value.encode("utf-8") if passphrase_value else None

    dest = import_cert_server(
        args.zip_file,
        args.dest_root,
        intermediate_name=args.intermediate_name,
        root_cn=args.root_cn,
        intermediate_cn=args.intermediate_cn,
        server_hostname=args.server_hostname,
        org=args.org,
        country=args.country,
        passphrase=passphrase,
    )

    print(f"Imported certificate server bundle into: {dest.resolve()}")


if __name__ == "__main__":
    main()
