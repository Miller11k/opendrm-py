# export.py
"""
Export the current CA layout as a zip archive, but only if it passes verification.

Workflow:
    1. Run verifier.verify_all() against the given root_dir.
    2. If verification succeeds, walk the directory tree.
    3. Write all files (and implicit directories) into a zip file.
    4. If verification fails, raise ValueError and do NOT create/overwrite the zip.

This ensures only a structurally valid / internally consistent CA can be exported.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path
from typing import Optional

from .verify_server import verify_all  # Uses the same verification logic as imports/initializer


# ---------- helpers ----------

def _normalize_zip_arcname(base: Path, path: Path) -> str:
    """
    Compute the archive name (relative path) for a file within the zip.

    Ensures:
        - Paths are stored relative to the CA root directory.
        - Forward slashes are used (zip standard).
        - No absolute paths are embedded.

    Args:
        base (Path): Root directory of the CA.
        path (Path): Absolute or child path to include.

    Returns:
        str: Normalized archive name for use inside the zip.
    """
    rel = path.relative_to(base)
    return rel.as_posix()


def _add_directory_to_zip(base: Path, zf: zipfile.ZipFile) -> None:
    """
    Recursively add the CA directory contents into a zip file.

    Notes:
        - Only files are explicitly added; directories are implied by file paths.
        - All paths are stored relative to 'base'.

    Args:
        base (Path): Root of the CA directory to archive.
        zf (zipfile.ZipFile): Open ZipFile object in write mode.
    """
    for path in base.rglob("*"):
        arcname = _normalize_zip_arcname(base, path)
        if path.is_dir():
            # Ensure empty directories are preserved
            zinfo = zipfile.ZipInfo(arcname + "/")
            zf.writestr(zinfo, "")
        else:
            zf.write(path, arcname)



# ---------- public API ----------

def export_cert_server(
    root_dir: str,
    output_zip: str,
    *,
    intermediate_name: str = "issuing-ca-1",
    root_cn: str = "Example Root CA",
    intermediate_cn: str = "Example Issuing CA",
    server_hostname: str = "localhost",
    org: str = "Example Org",
    country: str = "US",
    passphrase: Optional[bytes] = None,
    overwrite: bool = False,
) -> Path:
    """
    Export a verified certificate server layout as a zip file.

    Steps:
        - Runs verifier.verify_all() on root_dir with the expected parameters.
        - If verification passes, writes all files under root_dir into output_zip.
        - If verification fails, raises ValueError and does not produce a zip.

    Args:
        root_dir (str): Root directory of the CA deployment to export.
        output_zip (str): Path to the resulting zip file.
        intermediate_name (str, optional): Expected intermediate CA name.
        root_cn (str, optional): Expected Root CA Common Name.
        intermediate_cn (str, optional): Expected Intermediate CA Common Name.
        server_hostname (str, optional): Expected server certificate hostname.
        org (str, optional): Expected organization.
        country (str, optional): Expected country code.
        passphrase (bytes | None, optional): Passphrase to decrypt keys, if applicable.
        overwrite (bool, optional): If False, refuse to overwrite an existing zip.

    Returns:
        Path: Path to the created zip file.

    Raises:
        ValueError:
            - If root_dir does not exist or is not a directory.
            - If verification fails.
            - If output_zip exists and overwrite is False.
    """
    base = Path(root_dir)
    if not base.is_dir():
        raise ValueError(f"CA root directory does not exist or is not a directory: {base}")

    zip_path = Path(output_zip)

    # Prevent accidental overwrite unless explicitly allowed
    if zip_path.exists() and not overwrite:
        raise ValueError(f"Refusing to overwrite existing file: {zip_path}")

    # 1. Verify current state. This will raise ValueError on the first issue.
    verify_all(
        str(base),
        intermediate_name=intermediate_name,
        root_cn=root_cn,
        intermediate_cn=intermediate_cn,
        server_hostname=server_hostname,
        org=org,
        country=country,
        passphrase=passphrase,
    )

    # 2. Only if verification passes, create the zip.
    # Use ZIP_DEFLATED for reasonable compression of text/PEM/db files.
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        _add_directory_to_zip(base, zf)

    return zip_path


def main() -> None:
    """
    CLI entrypoint for exporting a verified CA layout.

    Example:
        python export.py /path/to/ca-root bundle.zip \
            --org "Example Org" \
            --server-hostname "localhost"

    Notes:
        - This uses the same expected parameters as verify_all(). Adjust flags as needed.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Export a verified certificate server as a zip bundle.")
    parser.add_argument("root_dir", help="Path to the CA root directory to export.")
    parser.add_argument("output_zip", help="Path to write the exported zip bundle.")
    parser.add_argument("--intermediate-name", default="issuing-ca-1")
    parser.add_argument("--root-cn", default="Example Root CA")
    parser.add_argument("--intermediate-cn", default="Example Issuing CA")
    parser.add_argument("--server-hostname", default="localhost")
    parser.add_argument("--org", default="Example Org")
    parser.add_argument("--country", default="US")
    parser.add_argument(
        "--passphrase-env",
        default="CERT_EXPORT_PASSPHRASE",
        help="Environment variable holding key passphrase (if keys are encrypted).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting an existing output zip file.",
    )

    args = parser.parse_args()

    # Pull optional passphrase from environment (to avoid passing secrets on CLI)
    import os
    passphrase_value = os.getenv(args.passphrase_env)
    passphrase = passphrase_value.encode("utf-8") if passphrase_value else None

    zip_path = export_cert_server(
        root_dir=args.root_dir,
        output_zip=args.output_zip,
        intermediate_name=args.intermediate_name,
        root_cn=args.root_cn,
        intermediate_cn=args.intermediate_cn,
        server_hostname=args.server_hostname,
        org=args.org,
        country=args.country,
        passphrase=passphrase,
        overwrite=args.overwrite,
    )

    print(f"Exported verified certificate server bundle to: {zip_path.resolve()}")


if __name__ == "__main__":
    main()