#!/usr/bin/env python
"""
Import a previously exported project state (directory, .zip, or .tar[.gz]) into the repository.

Behavior:
- If input is an archive it will be extracted to a temporary directory.
- Files and directories under the extracted root will be copied into the repository root,
  preserving relative paths.
- By default the script will not overwrite existing files unless --force is passed.
- Use --dry-run to show what would be copied.

I think that this should be most of what we need , but it is currently
a draft and will need some polishing once the export_state.py script is finalized.
"""
import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

LOGGER = logging.getLogger("import_state")


# --- cert-server export validation (optional profile) ---

EXPECTED_PATHS = {
    "cert-server-export/VERSION",
    "cert-server-export/manifest.json",
    "cert-server-export/manifest.sig",
    "cert-server-export/README-IMPORT.md",
    "cert-server-export/bundles/issuing-ca/ca/certs/issuing-ca.crt",
    "cert-server-export/bundles/issuing-ca/ca/private/issuing-ca.key.enc",
    "cert-server-export/bundles/issuing-ca/ca/serial",
    "cert-server-export/bundles/issuing-ca/ca/index.txt",
    "cert-server-export/bundles/issuing-ca/ca/crl/issuing-ca.crl",
    "cert-server-export/bundles/issuing-ca/ocsp/ocsp-signer.crt",
    "cert-server-export/bundles/issuing-ca/ocsp/ocsp-signer.key.enc",
    "cert-server-export/bundles/issuing-ca/api-tls/server.crt",
    "cert-server-export/bundles/issuing-ca/api-tls/server.key.enc",
    "cert-server-export/bundles/issuing-ca/config/policy.yml",
    "cert-server-export/bundles/issuing-ca/config/openssl.cnf",
    "cert-server-export/bundles/service-state/db/registry.sqlite.zst",
    "cert-server-export/bundles/service-state/db/audit.sqlite.zst",
    "cert-server-export/bundles/service-state/ctlog/log.db.zst",
    "cert-server-export/bundles/service-state/ctlog/log-signing-key.pem.enc",
    "cert-server-export/bundles/service-state/revocation/latest.crl",
    "cert-server-export/bundles/service-state/revocation/ocsp-cache/",
    "cert-server-export/bundles/service-state/csrs/",
    "cert-server-export/bundles/service-state/licenses/",
    "cert-server-export/bundles/service-state/app/env.sanitized",
    "cert-server-export/bundles/service-state/app/migrations.version",
    "cert-server-export/bundles/root-pack/ca/certs/root-ca.crt",
    "cert-server-export/bundles/root-pack/ca/private/root-ca.key.enc",
    "cert-server-export/bundles/root-pack/ca/serial",
    "cert-server-export/bundles/root-pack/ca/index.txt",
    "cert-server-export/bundles/root-pack/ca/crl/root-ca.crl",
    "cert-server-export/bundles/root-pack/policy-root.yml",
}

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

def _read_manifest_from_dir(dir_path: Path) -> tuple[dict, str, str]:
    """
    Read manifest.json and manifest.sig from a directory.
    """
    manifest_path = dir_path / "cert-server-export" / "manifest.json"
    sig_path = dir_path / "cert-server-export" / "manifest.sig"
    
    if not manifest_path.exists():
        raise IOError("manifest.json not found")
        
    manifest_str = manifest_path.read_text()
    manifest_dict = json.loads(manifest_str)
    
    sig_str = sig_path.read_text().strip() if sig_path.exists() else None
    return manifest_dict, manifest_str, sig_str

def _read_manifest_from_zip(zip_path: Path) -> tuple[dict, str, str]:
    """
    Read manifest.json and manifest.sig from a zip archive.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        try:
            manifest_str = zf.read("cert-server-export/manifest.json").decode()
            manifest_dict = json.loads(manifest_str)
            
            try:
                sig_str = zf.read("cert-server-export/manifest.sig").decode().strip()
            except KeyError:
                sig_str = None
                
            return manifest_dict, manifest_str, sig_str
            
        except KeyError:
            raise IOError("manifest.json not found in archive")
        except json.JSONDecodeError as e:
            raise IOError(f"Invalid manifest.json: {e}")

def verify_manifest_files_in_dir(dir_path: Path, manifest: dict) -> bool:
    """
    Verify file hashes in directory against manifest.
    """
    ok = True
    base_path = dir_path / "cert-server-export"
    
    for file_info in manifest["files"]:
        file_path = base_path / file_info["path"]
        if not verify_file_hash(file_path, file_info["sha256"]):
            LOGGER.error(f"Hash mismatch for {file_info['path']}")
            ok = False
            
    return ok

def verify_manifest_files_in_zip(zip_path: Path, manifest: dict) -> bool:
    """
    Verify file hashes in zip archive against manifest.
    """
    ok = True
    base_prefix = "cert-server-export/"
    
    with zipfile.ZipFile(zip_path, "r") as zf:
        for file_info in manifest["files"]:
            file_path = base_prefix + file_info["path"]
            try:
                file_data = zf.read(file_path)
                actual_hash = hashlib.sha256(file_data).hexdigest()
                if actual_hash != file_info["sha256"]:
                    LOGGER.error(f"Hash mismatch for {file_info['path']}")
                    ok = False
            except KeyError:
                LOGGER.error(f"File missing from archive: {file_info['path']}")
                ok = False
                
    return ok

def verify_manifest_signature(manifest_content: str, signature_content: str, public_key: str) -> bool:
    """
    Verify the Ed25519 signature of a manifest.
    """
    if not HAS_CRYPTO:
        LOGGER.error("cryptography package not available - cannot verify signatures")
        return False
        
    try:
        # Load public key
        key = load_pem_public_key(public_key.encode('utf-8'))
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("Not an Ed25519 public key")
            
        # Verify signature
        signature_bytes = bytes.fromhex(signature_content)
        key.verify(signature_bytes, manifest_content.encode('utf-8'))
        return True
        
    except (ValueError, InvalidSignature) as e:
        LOGGER.error(f"Signature verification failed: {str(e)}")
        return False

def verify_file_hash(file_path, expected_hash):
    """
    Verify the SHA256 hash of a file matches the expected value.
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    actual_hash = sha256.hexdigest()
    return actual_hash == expected_hash

def verify_manifest(state_dir, manifest_path, signature_path=None, public_key=None):
    """
    Verify a manifest and optionally its signature.
    """
    try:
        # Read and parse manifest
        with open(manifest_path, 'r') as f:
            manifest_content = f.read()
            manifest = json.loads(manifest_content)
            
        # Verify signature if provided
        if signature_path and public_key:
            with open(signature_path, 'r') as f:
                signature_content = f.read().strip()
            if not verify_manifest_signature(manifest_content, signature_content, public_key):
                return False
                
        # Verify all file hashes
        for file_info in manifest['files']:
            file_path = os.path.join(state_dir, file_info['path'])
            if not verify_file_hash(file_path, file_info['sha256']):
                LOGGER.error(f"Hash mismatch for {file_info['path']}")
                return False
                
        return True
        
    except (IOError, json.JSONDecodeError, KeyError) as e:
        LOGGER.error(f"Manifest verification failed: {str(e)}")
        return False

def validate_zip_file(path: Path) -> bool:
    """
    Return True if file exists and is zipfile.
    """
    return path.is_file() and zipfile.is_zipfile(path)


def get_zip_contents(input_path: Path) -> set[str]:
    """
    Return set of all file and directory names in the zip archive.
    Directories are represented with trailing slash.
    """
    with zipfile.ZipFile(input_path, "r") as zip_ref:
        names = [p.rstrip("/") for p in zip_ref.namelist()]
    
    return set(names)

def get_dir_contents(input_path: Path) -> set[str]:
    """
    Return set of all file and directory names in the directory.
    Directories are represented with trailing slash.
    """
    root = input_path
    names = set()
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        # represent directories with trailing slash to match EXPECTED_PATHS semantics
        s = str(rel).replace("\\", "/")
        if p.is_dir():
            s = s.rstrip("/") + "/"
        names.add(s)
    return names


def verify_cert_server_structure_from_zip(zip_path: Path) -> bool:
    """
    Verify that the zip archive at zip_path matches the expected cert-server export structure.
    """
    actual = get_zip_contents(zip_path)
    expected = {p.rstrip("/") for p in EXPECTED_PATHS}
    ok = True

    missing = expected - actual
    extra = actual - expected

    if missing:
        ok = False
        LOGGER.error("Missing entries in export:")
        for m in sorted(missing):
            LOGGER.error("  - %s", m)

    if extra:
        ok = False
        LOGGER.error("Unexpected entries in export:")
        for e in sorted(extra):
            LOGGER.error("  - %s", e)

    # check VERSION
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            version_bytes = zip_ref.read("cert-server-export/VERSION")
            version_str = version_bytes.decode().strip()
            if not SEMVER_RE.fullmatch(version_str):
                ok = False
                LOGGER.error("Invalid VERSION format: '%s' (expected x.y.z)", version_str)
    except KeyError:
        ok = False
        LOGGER.error("VERSION file missing or unreadable in archive")

    return ok

def verify_cert_server_structure_from_dir(dir_path: Path) -> bool:
    """
    Verify that the directory at dir_path matches the expected cert-server export structure.
    """
    actual = get_dir_contents(dir_path)
    expected = {p.rstrip("/") for p in EXPECTED_PATHS}
    ok = True

    missing = expected - actual
    extra = actual - expected

    if missing:
        ok = False
        LOGGER.error("Missing entries in export folder:")
        for m in sorted(missing):
            LOGGER.error("  - %s", m)

    if extra:
        ok = False
        LOGGER.error("Unexpected entries in export folder:")
        for e in sorted(extra):
            LOGGER.error("  - %s", e)

    # check VERSION
    version_file = dir_path / "cert-server-export" / "VERSION"
    if not version_file.exists():
        ok = False
        LOGGER.error("VERSION file missing in export folder")
    else:
        version_str = version_file.read_text().strip()
        if not SEMVER_RE.fullmatch(version_str):
            ok = False
            LOGGER.error("Invalid VERSION format: '%s' (expected x.y.z)", version_str)

    return ok

# --- end cert-server validation ---

def is_archive(path: Path) -> bool:
    """
    Return True if path is a supported archive type.
    """
    lower = path.name.lower()
    return lower.endswith(".zip") or lower.endswith(".tar") or lower.endswith(".tar.gz") or lower.endswith(".tgz")


def extract_archive(archive_path: Path, dest: Path) -> Path:
    """
    Extract archive into dest and return the extraction root path.
    If archive contains a single top-level directory, return that path. Otherwise return dest.
    """
    LOGGER.info("Extracting archive %s -> %s", archive_path, dest)
    if archive_path.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest)
    else:
        # support .tar, .tar.gz, .tgz
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(dest)

    # determine root
    children = [p for p in dest.iterdir() if p.name != "" ]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest


def copy_tree(src: Path, dst: Path, force: bool = False, dry_run: bool = False) -> list[tuple[Path, Path, str]]:
    """
    Recursively copy files from src into dst.
    Returns a list of (src, dst, action) where action is one of 'skipped','copied','overwritten'.
    """
    actions = []
    for root, dirs, files in shutil.walk(src):
        rel_root = Path(root).relative_to(src)
        target_root = dst.joinpath(rel_root)
        if not dry_run:
            target_root.mkdir(parents=True, exist_ok=True)
        for f in files:
            sfile = Path(root) / f
            dfile = target_root / f
            if dfile.exists():
                if force:
                    actions.append((sfile, dfile, "overwritten"))
                    if not dry_run:
                        shutil.copy2(sfile, dfile)
                else:
                    actions.append((sfile, dfile, "skipped"))
            else:
                actions.append((sfile, dfile, "copied"))
                if not dry_run:
                    shutil.copy2(sfile, dfile)
    return actions

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    ap = argparse.ArgumentParser(description="Import exported project state into repository")
    ap.add_argument("input", help="Path to exported folder or archive (.zip, .tar.gz, .tar)")
    ap.add_argument("--repo-root", help="Path to repository root to import into (defaults to parent of this script)", default=None)
    ap.add_argument("--profile", choices=["cert-server"], help="Optional profile to validate import against (e.g. cert-server)")
    ap.add_argument("--skip-validation", help="Skip profile validation (use with care)", action="store_true")
    ap.add_argument("--manifest-pubkey", help="Path to PEM public key used to verify manifest.sig (Ed25519 PEM)", default=None)
    ap.add_argument("--force", help="Overwrite existing files", action="store_true")
    ap.add_argument("--dry-run", help="List actions without copying", action="store_true")
    ap.add_argument("--verbose", "-v", action="count", default=0, help="Increase verbosity")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    log_level = logging.WARNING
    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose == 1:
        log_level = logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        LOGGER.error("Input path does not exist: %s", input_path)
        return 2

    # allow CERTIFICATE_SERVER_FOLDER from .env or environment when using cert-server profile
    if args.profile == "cert-server":
        try:
            # optional dotenv support
            from dotenv import load_dotenv  # type: ignore

            load_dotenv()
        except Exception:
            pass

    repo_root = None
    if args.repo_root:
        repo_root = Path(args.repo_root).expanduser().resolve()
    elif args.profile == "cert-server":
        env_dest = os.getenv("CERTIFICATE_SERVER_FOLDER")
        if env_dest:
            repo_root = Path(env_dest).expanduser().resolve()

    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]
    LOGGER.debug("Repository root: %s", repo_root)
    if not repo_root.exists():
        LOGGER.error("Repository root does not exist: %s", repo_root)
        return 3

    # If input is archive, optionally validate, then extract
    temp_dir: Path | None = None
    try:
        # profile validation
        if args.profile == "cert-server" and not args.skip_validation:
            # first run structural checks (file list + VERSION)
            if input_path.is_dir():
                ok = verify_cert_server_structure_from_dir(input_path)
            elif is_archive(input_path):
                if not validate_zip_file(input_path):
                    LOGGER.error("Input is not a valid ZIP archive for cert-server profile: %s", input_path)
                    return 5
                ok = verify_cert_server_structure_from_zip(input_path)
            else:
                LOGGER.error("Unsupported input type for cert-server profile: %s", input_path)
                return 6

            if not ok:
                LOGGER.error("cert-server profile structural validation failed. Aborting import.")
                return 7

            # Check if we need cryptography package for signature verification
            if args.manifest_pubkey and not HAS_CRYPTO:
                LOGGER.info("Installing cryptography package for signature verification...")
                try:
                    import subprocess
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
                    # Re-import after installation
                    global load_pem_public_key, ed25519, InvalidSignature, HAS_CRYPTO
                    from cryptography.hazmat.primitives.serialization import load_pem_public_key
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    from cryptography.exceptions import InvalidSignature
                    HAS_CRYPTO = True
                except Exception as e:
                    LOGGER.error(f"Failed to install cryptography package: {e}")
                    LOGGER.error("Unable to verify manifest signature without cryptography package")
                    return 12

            # next: manifest integrity and optional signature verification
            try:
                if input_path.is_dir():
                    manifest_dict, canonical, sig = _read_manifest_from_dir(input_path)
                    files_ok = verify_manifest_files_in_dir(input_path, manifest_dict)
                else:
                    manifest_dict, canonical, sig = _read_manifest_from_zip(input_path)
                    files_ok = verify_manifest_files_in_zip(input_path, manifest_dict)
                    
                if not files_ok:
                    LOGGER.error("Manifest file integrity check failed. Aborting import.")
                    return 8
                    
                # Optional signature verification
                if args.manifest_pubkey:
                    if not sig:
                        LOGGER.error("No manifest.sig found but --manifest-pubkey was specified")
                        return 9
                        
                    with open(args.manifest_pubkey, 'r') as f:
                        pubkey = f.read()
                        
                    if not verify_manifest_signature(canonical, sig, pubkey):
                        LOGGER.error("Manifest signature verification failed. Aborting import.")
                        return 10
                        
                    LOGGER.info("Manifest signature verified successfully")
                    
            except (IOError, json.JSONDecodeError) as e:
                LOGGER.error(f"Manifest processing failed: {e}")
                return 11
                LOGGER.error("manifest.json missing; cannot verify export manifest")
                return 8

            if not files_ok:
                LOGGER.error("Manifest file integrity checks failed. Aborting import.")
                return 9

            if args.manifest_pubkey:
                pubkey_path = Path(args.manifest_pubkey)
                if not pubkey_path.exists():
                    LOGGER.error("Provided manifest pubkey does not exist: %s", pubkey_path)
                    return 10
                sig_ok = verify_manifest_signature(canonical, sig, pubkey_path)
                if not sig_ok:
                    LOGGER.error("Manifest signature verification failed. Aborting import.")
                    return 11

        if input_path.is_dir():
            extraction_root = input_path
        elif is_archive(input_path):
            temp_dir = Path(tempfile.mkdtemp(prefix="import_state_"))
            extraction_root = extract_archive(input_path, temp_dir)
        else:
            LOGGER.error("Unsupported input type: %s", input_path)
            return 4

        LOGGER.info("Preparing to import from: %s", extraction_root)

        actions = copy_tree(extraction_root, repo_root, force=args.force, dry_run=args.dry_run)

        # summarize
        summary = {"copied": 0, "overwritten": 0, "skipped": 0}
        for _, _, act in actions:
            if act in summary:
                summary[act] += 1
        LOGGER.info("Import summary: copied=%d overwritten=%d skipped=%d", summary["copied"], summary["overwritten"], summary["skipped"])

        if args.dry_run:
            for s, d, act in actions:
                print(f"{act.upper():10} {s} -> {d}")
        else:
            LOGGER.info("Import completed.")
        return 0
    finally:
        # cleanup tempdir if used
        if temp_dir is not None:
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                LOGGER.debug("Failed to remove temporary dir %s", temp_dir)


if __name__ == "__main__":
    raise SystemExit(main())
