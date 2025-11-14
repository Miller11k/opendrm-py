# verifier.py
from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ---------- helpers ----------

def _read_text(p: Path) -> str:
    """
    Read a UTF-8 compatible text file.

    Args:
        p (Path): Path to the file that should contain text content.

    Returns:
        str: File contents as a string.

    Raises:
        ValueError: If the file is missing or cannot be decoded as text.
    """
    if not p.is_file(): # Ensure the file is there before reading
        raise ValueError(f"Missing file: {p}")
    try:    # Try reading the text from the file
        return p.read_text()
    except UnicodeDecodeError:
        raise ValueError(f"Expected text file but not decodable: {p}")

def _read_bytes(p: Path) -> bytes:
    """
    Read a file as raw bytes.

    Args:
        p (Path): Path to the file.

    Returns:
        bytes: Raw file contents.

    Raises:
        ValueError: If the file does not exist.
    """
    if not p.is_file(): # Ensure file exists before reading bytes
        raise ValueError(f"Missing file: {p}")
    return p.read_bytes()   # Return the bytes from the file

def _require_dirs(base: Path, rels: Iterable[str]) -> None:
    """
    Ensure that all required subdirectories exist under a base directory.

    Args:
        base (Path): Base directory path.
        rels (Iterable[str]): Iterable of relative directory paths.

    Raises:
        ValueError: If any required directory is missing.
    """
    missing = [str(base / r) for r in rels if not (base / r).is_dir()]  # Create an array of missing directories
    if missing: # If any missing directories, raise an error
        raise ValueError(f"Missing directories: {missing}")

def _name_str(name: x509.Name) -> str:
    """
    Render an x509.Name into a compact 'C=US,O=Org,CN=Name' style string.

    Args:
        name (x509.Name): Distinguished Name to stringify.

    Returns:
        str: Comma-separated short-form representation suitable for error messages.
    """
    # Map common OIDs to short keys; fall back to the OID's _name for anything else.
    parts = []
    for rdn in name:
        oid = rdn.oid
        if oid == NameOID.COUNTRY_NAME:
            k = "C"
        elif oid == NameOID.ORGANIZATION_NAME:
            k = "O"
        elif oid == NameOID.COMMON_NAME:
            k = "CN"
        else:
            k = oid._name  # fallback
        parts.append(f"{k}={rdn.value}")
    return ",".join(parts)

def _assert(cond: bool, msg: str) -> None:
    """
    Internal assertion helper that raises ValueError instead of AssertionError.

    Args:
        cond (bool): Condition that must be true.
        msg (str): Error message if condition fails.

    Raises:
        ValueError: If cond is False.
    """
    if not cond:    # If condition not met, raise value error with message 'msg'
        raise ValueError(msg)

def _load_pem_cert(p: Path) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.

    Args:
        p (Path): Path to PEM-encoded certificate.

    Returns:
        x509.Certificate: Parsed certificate object.

    Raises:
        ValueError: If loading/parsing fails.
    """
    try:    # Try to load the X.509 certificate
        return x509.load_pem_x509_certificate(_read_bytes(p))
    except Exception as e:
        raise ValueError(f"Invalid certificate PEM: {p} ({e})")

def _load_pem_crl(p: Path) -> x509.CertificateRevocationList:
    """
    Load an X.509 CRL from a PEM file.

    Args:
        p (Path): Path to PEM-encoded CRL.

    Returns:
        x509.CertificateRevocationList: Parsed CRL object.

    Raises:
        ValueError: If loading/parsing fails.
    """
    try:    # Try to load the X.509 CRL
        return x509.load_pem_x509_crl(_read_bytes(p))
    except Exception as e:
        raise ValueError(f"Invalid CRL PEM: {p} ({e})")

def _try_load_key(p: Path, passphrase: Optional[bytes]):
    """
    Load a PEM-encoded private key, trying with and without passphrase.

    This is used for:
      - RSA keys (Root/Intermediate/Server/OCSP)
      - Ed25519 keys (CT log key)

    Args:
        p (Path): Path to the private key.
        passphrase (bytes | None): Passphrase for decryption (if encrypted).

    Returns:
        Any: A private key object from `cryptography`.

    Raises:
        ValueError: If the key is invalid or encryption does not match expectation.
    """
    data = _read_bytes(p)
    # Try with provided passphrase (or None).
    # Supports both RSA and Ed25519.
    try:
        return serialization.load_pem_private_key(data, password=passphrase)
    except Exception as rsa_err:
        # Try Ed25519 (ctlog key)
        try:
            return serialization.load_pem_private_key(data, password=None)
        except Exception:
            raise ValueError(f"Invalid or improperly encrypted private key: {p} ({rsa_err})")

def _has_substrings(s: str, needles: Iterable[str]) -> None:
    """
    Ensure all required substrings are present in a configuration text.

    Args:
        s (str): Text to search.
        needles (Iterable[str]): Substrings that must be present.

    Raises:
        ValueError: If any expected token is missing.
    """
    for n in needles:
        if n not in s:
            raise ValueError(f"Config/text missing expected token: {n!r}")

def _eku_contains(cert: x509.Certificate, *oids) -> bool:
    """
    Check whether a certificate's Extended Key Usage includes all specified OIDs.

    Args:
        cert (x509.Certificate): Certificate to inspect.
        *oids: One or more ExtendedKeyUsage OIDs to require.

    Returns:
        bool: True if EKU extension exists and contains all requested OIDs,
              False otherwise.
    """
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value  # Grab Extended Key Usage (EKU)
        return all(oid in eku for oid in oids)  # Return all Object Identifiers (OIDs)
    except x509.ExtensionNotFound:
        return False


# ---------- expectations ----------

@dataclass(frozen=True)
class Expect:
    """
    Expected identity/metadata values for this deployment.

    Attributes:
        org (str): Expected Organization (O).
        country (str): Expected Country (C).
        root_cn (str): Expected Root CA Common Name.
        intermediate_cn (str): Expected Intermediate CA Common Name.
        server_hostname (str): Expected server certificate hostname.
        intermediate_name (str): Directory name used for the intermediate CA.
    """
    org: str
    country: str
    root_cn: str
    intermediate_cn: str
    server_hostname: str
    intermediate_name: str


# ---------- directory tree ----------

def verify_directory_tree(base: Path, exp: Expect) -> bool:
    """
    Verify that the directory structure laid out by the initializer exists.

    Args:
        base (Path): Root directory of the CA deployment.
        exp (Expect): Expected parameters (used for intermediate path).

    Returns:
        bool: True if all required directories exist.

    Raises:
        ValueError: If any required directory is missing.
    """
    _require_dirs(base, [
        "bin", "config",
        "ca/private", "ca/certs", "ca/crl", "ca/newcerts",
        f"intermediates/{exp.intermediate_name}/private",
        f"intermediates/{exp.intermediate_name}/certs",
        f"intermediates/{exp.intermediate_name}/crl",
        f"intermediates/{exp.intermediate_name}/newcerts",
        "keystores", "ctlog", "db", "licenses", "logs", "docker",
    ])
    return True


# ---------- config files ----------

def verify_openssl_cnf(path: Path, exp: Expect) -> bool:
    """
    Verify the OpenSSL configuration file used for issuing certificates.

    Checks for:
      - Core sections/fields (CA_default, dirs, serial/index, policy_any, usr_cert).
      - Reasonable defaults for days, key usage, EKU.
      - Presence of the expected organization name.

    Args:
        path (Path): Path to openssl.cnf.
        exp (Expect): Expected deployment parameters.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On missing directives or mismatched metadata.
    """
    txt = _read_text(path)  # Grab openssl config file as text
    _has_substrings(txt, [
        "[ ca ]", "default_ca = CA_default",
        "[ CA_default ]",
        "database          = ./index.txt",
        "new_certs_dir     = ./newcerts",
        "certificate       = ./certs/ca.crt",
        "serial            = ./serial",
        "private_key       = ./private/ca.key",
        "default_md        = sha256",
        "policy            = policy_any",
        "x509_extensions   = usr_cert",
        "default_days      = 397",
        "[ policy_any ]",
        "commonName              = supplied",
        "[ usr_cert ]",
        "basicConstraints=CA:FALSE",
        "keyUsage=digitalSignature,keyEncipherment",
        "extendedKeyUsage=serverAuth,clientAuth",
    ])
    _assert(exp.org in txt, "OpenSSL config should include organization name")
    return True

def verify_policy_yml(path: Path) -> bool:
    """
    Verify the issuance policy YAML file.

    Requirements:
      - Valid YAML.
      - Top-level 'profiles' key.
      - 'server' and 'client' profiles present.
      - Each profile has 'eku' (list) and 'days' == 397.

    Args:
        path (Path): Path to policy.yml.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: If structure or required fields are incorrect.
    """
    txt = _read_text(path)  # Grab Policy YAML as text
    try:
        y = yaml.safe_load(txt) # Load in the YAML
    except Exception as e:
        raise ValueError(f"policy.yml is not valid YAML: {e}")
    _assert(isinstance(y, dict) and "profiles" in y, "policy.yml should contain 'profiles'")
    profiles = y["profiles"]
    _assert("server" in profiles and "client" in profiles, "policy.yml must include server/client profiles")
    for k in ("server", "client"):
        prof = profiles[k]
        _assert("eku" in prof and isinstance(prof["eku"], list), f"{k} profile must include 'eku' list")
        _assert("days" in prof and int(prof["days"]) == 397, f"{k} profile must set days=397")
    return True


# ---------- root CA files ----------

def verify_root_key(path: Path, passphrase: Optional[bytes]) -> bool:
    """
    Verify the Root CA private key properties.

    Checks:
      - Key is RSA.
      - Key size is 4096 bits.
      - Encryption state matches whether a passphrase is provided.

    Args:
        path (Path): Path to Root CA key.
        passphrase (bytes | None): Expected passphrase (or None if unencrypted).

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On type/size mismatch or inconsistent encryption.
    """
    key = _try_load_key(path, passphrase)   # Try to load the key in
    _assert(isinstance(key, rsa.RSAPrivateKey), "Root key must be RSA") # Ensure key is of RSA type
    _assert(key.key_size == 4096, "Root RSA key_size must be 4096") # Ensure key size if 4096
    # Ensure encryption state matches passphrase expectation
    pem = _read_bytes(path) # Grab pem as bytes
    is_encrypted = b"ENCRYPTED" in pem  # Ensure pem is encrypted
    _assert((passphrase is None and not is_encrypted) or (passphrase is not None and is_encrypted),
            "Root key encryption state does not match expectation (passphrase provided vs PEM)")
    return True

def verify_root_cert(path: Path, exp: Expect) -> bool:
    """
    Verify the Root CA certificate.

    Checks:
      - Self-signed (issuer == subject).
      - Subject C/O/CN match expectations.
      - BasicConstraints: CA:TRUE, path_length=1.
      - KeyUsage: cert/CRL signing only.

    Args:
        path (Path): Path to Root CA certificate.
        exp (Expect): Expected subject fields.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On any mismatch with the expected Root profile.
    """
    cert = _load_pem_cert(path) # Load in the certificate
    # Subject/issuer identical for self-signed
    _assert(cert.issuer == cert.subject, "Root must be self-signed (issuer==subject)")
    # Subject fields
    subj = cert.subject # Grab subject fields
    expected = {
        NameOID.COUNTRY_NAME: exp.country,
        NameOID.ORGANIZATION_NAME: exp.org,
        NameOID.COMMON_NAME: exp.root_cn,
    }
    for oid, val in expected.items():
        _assert(subj.get_attributes_for_oid(oid)[0].value == val,
                f"Root subject mismatch for {oid._name}: {_name_str(subj)}")
    # BasicConstraints CA with path_length=1
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    _assert(bc.ca and bc.path_length == 1, "Root BasicConstraints should be CA:TRUE, path_length=1")
    # KeyUsage keyCertSign and crlSign, others off
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    _assert(ku.key_cert_sign and ku.crl_sign, "Root KeyUsage must allow cert/CRL signing")
    _assert(not any([
        ku.content_commitment, ku.key_encipherment, ku.data_encipherment,
        ku.key_agreement, ku.encipher_only, ku.decipher_only
    ]), "Root KeyUsage has unexpected flags enabled")
    return True

def verify_root_crl(path: Path, root_cert_path: Path) -> bool:
    """
    Verify the Root CA CRL.

    Checks:
      - Issuer matches Root CA subject.
      - nextUpdate is after lastUpdate.

    Args:
        path (Path): Path to Root CRL.
        root_cert_path (Path): Path to Root CA certificate.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On issuer mismatch or invalid dates.
    """
    crl = _load_pem_crl(path)   # Grab the CRL from the path
    issuer = _load_pem_cert(root_cert_path) # Grab the issuer
    _assert(crl.issuer == issuer.subject, "Root CRL issuer must match root subject")
    # Signature is checked indirectly by load; we can also ensure sane nextUpdate > lastUpdate
    _assert(crl.next_update > crl.last_update, "Root CRL nextUpdate must be after lastUpdate")
    return True

def verify_root_index_txt(path: Path) -> bool:
    """
    Verify the Root CA index.txt is empty at initialization.

    Args:
        path (Path): Path to index.txt.

    Returns:
        bool: True if empty.

    Raises:
        ValueError: If file is non-empty.
    """
    data = _read_bytes(path)    # Grab the bytes of the root index.txt
    _assert(data == b"" or data.strip() == b"", "index.txt should be empty at initialization")
    return True

def verify_root_serial(path: Path, expected_start: str = "1000") -> bool:
    """
    Verify the Root CA serial file.

    Requirements:
      - Single integer followed by newline.
      - Matches expected starting serial.

    Args:
        path (Path): Path to serial file.
        expected_start (str): Expected initial serial value.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On format error or mismatched starting value.
    """
    txt = _read_text(path)  # Grab contents of Root CA serial file
    _assert(re.fullmatch(r"\d+\n", txt) is not None, "serial must be an integer followed by newline")
    _assert(txt.strip() == expected_start, f"serial should start at {expected_start}")
    return True


# ---------- intermediate CA files ----------

def verify_intermediate_key(path: Path, passphrase: Optional[bytes]) -> bool:
    """
    Verify the Intermediate CA private key.

    Checks:
      - RSA key, 4096 bits.
      - Encryption state matches passphrase expectation.

    Args:
        path (Path): Path to intermediate key.
        passphrase (bytes | None): Expected passphrase (if encrypted).

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On type/size mismatch or encryption mismatch.
    """
    key = _try_load_key(path, passphrase)   # Load in the key
    _assert(isinstance(key, rsa.RSAPrivateKey), "Intermediate key must be RSA")
    _assert(key.key_size == 4096, "Intermediate RSA key_size must be 4096")
    pem = _read_bytes(path) # Load in the bytes of the pem
    is_encrypted = b"ENCRYPTED" in pem  # Check if pem is encrypted
    _assert((passphrase is None and not is_encrypted) or (passphrase is not None and is_encrypted),
            "Intermediate key encryption state does not match expectation")
    return True

def verify_intermediate_cert(path: Path, root_cert_path: Path, exp: Expect) -> bool:
    """
    Verify the Intermediate CA certificate.

    Checks:
      - Subject C/O/CN match expectations.
      - Issuer matches Root CA.
      - BasicConstraints: CA:TRUE, path_length=0.
      - KeyUsage: cert/CRL signing only.

    Args:
        path (Path): Path to intermediate certificate.
        root_cert_path (Path): Path to Root CA certificate.
        exp (Expect): Expected fields.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On any mismatch.
    """
    cert = _load_pem_cert(path) # Load in the intermediate certificate
    root = _load_pem_cert(root_cert_path)   # Load in the root certificate
    # Subject fields
    subj = cert.subject # Load in the certificate sujects
    expected = {
        NameOID.COUNTRY_NAME: exp.country,
        NameOID.ORGANIZATION_NAME: exp.org,
        NameOID.COMMON_NAME: exp.intermediate_cn,
    }
    for oid, val in expected.items():
        _assert(subj.get_attributes_for_oid(oid)[0].value == val,
                f"Intermediate subject mismatch for {oid._name}: {_name_str(subj)}")
    # Issuer is root
    _assert(cert.issuer == root.subject, "Intermediate issuer must be Root subject")
    # BasicConstraints CA with path_length=0
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    _assert(bc.ca and bc.path_length == 0, "Intermediate BasicConstraints should be CA:TRUE, path_length=0")
    # KeyUsage keyCertSign and crlSign only
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    _assert(ku.key_cert_sign and ku.crl_sign, "Intermediate KeyUsage must allow cert/CRL signing")
    _assert(not any([
        ku.content_commitment, ku.key_encipherment, ku.data_encipherment,
        ku.key_agreement, ku.encipher_only, ku.decipher_only
    ]), "Intermediate KeyUsage has unexpected flags enabled")
    return True

def verify_intermediate_crl(path: Path, intermediate_cert_path: Path) -> bool:
    """
    Verify the Intermediate CA CRL.

    Checks:
      - Issuer matches Intermediate CA subject.
      - nextUpdate is after lastUpdate.

    Args:
        path (Path): Path to Intermediate CRL.
        intermediate_cert_path (Path): Path to Intermediate certificate.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On issuer mismatch or invalid dates.
    """
    crl = _load_pem_crl(path)   # Load in the CRL
    icert = _load_pem_cert(intermediate_cert_path)  # Load in the intermediate certificate
    _assert(crl.issuer == icert.subject, "Intermediate CRL issuer must match intermediate subject")
    _assert(crl.next_update > crl.last_update, "Intermediate CRL nextUpdate must be after lastUpdate")
    return True

def verify_intermediate_index_txt(path: Path) -> bool:
    """
    Verify the Intermediate CA index.txt (delegates to root validation).

    Args:
        path (Path): Path to intermediate index.txt.

    Returns:
        bool: True if empty/valid.
    """
    return verify_root_index_txt(path)

def verify_intermediate_serial(path: Path, expected_start: str = "2000") -> bool:
    """
    Verify the Intermediate CA serial file.

    Args:
        path (Path): Path to intermediate serial file.
        expected_start (str): Expected starting serial.

    Returns:
        bool: True if valid.
    """
    return verify_root_serial(path, expected_start)


# ---------- keystore bundles ----------

def _split_pem_bundle(pem_bytes: bytes) -> list[bytes]:
    """
    Split a concatenated PEM bundle into individual PEM blocks.

    This is used for files like server.pem / ocsp_signer.pem that bundle
    certificate and key.

    Args:
        pem_bytes (bytes): Raw PEM contents.

    Returns:
        list[bytes]: List of individual PEM objects (each ending with newline).
    """
    parts: list[bytes] = [] # Save parts of pem bundle into an array
    chunk: list[bytes] = [] # Save chunks of pem bundle into an array
    for line in pem_bytes.splitlines(keepdims := False):  # type: ignore
        if line.startswith(b"-----BEGIN "): # Start when begin
            chunk = [line]
        elif line.startswith(b"-----END "): # End when end
            chunk.append(line)
            parts.append(b"\n".join(chunk) + b"\n")
            chunk = []
        else:
            if chunk:
                chunk.append(line)
    return parts

def verify_server_pem(path: Path, passphrase: Optional[bytes], exp: Expect) -> bool:
    """
    Verify the server.pem bundle (server certificate + private key).

    Checks:
      - Contains at least 2 PEM blocks (cert + key).
      - CN == expected server_hostname.
      - SAN includes server_hostname.
      - KeyUsage: digitalSignature + keyEncipherment.
      - EKU includes serverAuth.
      - Private key is 2048-bit RSA.
      - Key encryption state matches passphrase.

    Args:
        path (Path): Path to server.pem.
        passphrase (bytes | None): Expected passphrase for key encryption.
        exp (Expect): Expected deployment values.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On structure or semantic mismatch.
    """
    pem = _read_bytes(path) # Save bytes of pem
    parts = _split_pem_bundle(pem)  # Split pem into parts
    _assert(len(parts) >= 2, "server.pem must contain at least a cert and a key")
    # Load cert
    cert = x509.load_pem_x509_certificate(parts[0])
    # Check subject and SANs
    subj = cert.subject
    _assert(subj.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == exp.server_hostname,
            "Server CN must equal server_hostname")
    # SAN list may be empty; initializer adds [server_hostname]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [n.value for n in san.get_values_for_type(x509.DNSName)]
        _assert(exp.server_hostname in names, "Server SANs must include server_hostname")
    except x509.ExtensionNotFound:
        raise ValueError("Server cert must include subjectAltName")
    # KU and EKU
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    _assert(ku.digital_signature and ku.key_encipherment, "Server KeyUsage must enable digitalSignature and keyEncipherment")
    _assert(_eku_contains(cert, ExtendedKeyUsageOID.SERVER_AUTH), "Server EKU must include serverAuth")
    # Key
    key = serialization.load_pem_private_key(parts[1], password=passphrase)
    _assert(isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048, "Server key must be 2048-bit RSA")
    # Encryption matches expectation
    is_encrypted = b"ENCRYPTED" in parts[1]
    _assert((passphrase is None and not is_encrypted) or (passphrase is not None and is_encrypted),
            "server.pem key encryption state does not match expectation")
    return True

def verify_ocsp_signer_pem(path: Path, passphrase: Optional[bytes], exp: Expect) -> bool:
    """
    Verify the ocsp_signer.pem bundle (OCSP responder cert + key).

    Checks:
      - Contains cert + key.
      - CN is 'ocsp.<server_hostname>'.
      - EKU includes OCSP_SIGNING.
      - Key is 2048-bit RSA.
      - Encryption state matches passphrase.

    Args:
        path (Path): Path to ocsp_signer.pem.
        passphrase (bytes | None): Expected passphrase for key.
        exp (Expect): Expected deployment values.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On mismatch.
    """
    pem = _read_bytes(path) # Save bytes of pem
    parts = _split_pem_bundle(pem)  # Split pem int parts
    _assert(len(parts) >= 2, "ocsp_signer.pem must contain a cert and a key")
    cert = x509.load_pem_x509_certificate(parts[0])
    # Subject CN ocsp.<hostname>
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    _assert(cn == f"ocsp.{exp.server_hostname}", "OCSP signer CN must be 'ocsp.<server_hostname>'")
    _assert(_eku_contains(cert, ExtendedKeyUsageOID.OCSP_SIGNING), "OCSP signer must include EKU: OCSP Signing")
    key = serialization.load_pem_private_key(parts[1], password=passphrase)
    _assert(isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048, "OCSP key must be 2048-bit RSA")
    is_encrypted = b"ENCRYPTED" in parts[1]
    _assert((passphrase is None and not is_encrypted) or (passphrase is not None and is_encrypted),
            "ocsp_signer.pem key encryption state does not match expectation")
    return True


# ---------- ct log ----------

def verify_ctlog_key(path: Path) -> bool:
    """
    Verify the CT log signing key.

    Checks:
      - Key is Ed25519.
      - Key is unencrypted.

    Args:
        path (Path): Path to CT log key.

    Returns:
        bool: True if validation passes.

    Raises:
        ValueError: On type or encryption mismatch.
    """
    key = _try_load_key(path, passphrase=None)  # Load in the key
    _assert(isinstance(key, ed25519.Ed25519PrivateKey), "CT log key must be Ed25519")
    pem = _read_bytes(path) # Save bytes of pem
    _assert(b"ENCRYPTED" not in pem, "CT log key must be unencrypted")
    return True

def verify_ctlog_db(path: Path) -> bool:
    """
    Verify the CT log SQLite database schema.

    Requirements:
      - File exists.
      - Tables: entries, sth.
      - entries: (id, ts, leaf_hash, chain)
      - sth: (id, tree_size, sha256_root, ts)

    Args:
        path (Path): Path to CT log database.

    Returns:
        bool: True if schema matches.

    Raises:
        ValueError: If file missing or schema incorrect.
    """
    if not path.is_file():  # Ensure file exists
        raise ValueError(f"Missing CT log DB: {path}")
    with sqlite3.connect(path) as conn: # Open SQLite file
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        names = {r[0] for r in cur.fetchall()}
        _assert({"entries", "sth"}.issubset(names), "CT DB must contain tables: entries, sth")
        # Validate columns
        def cols(table: str) -> list[str]:
            cur.execute(f"PRAGMA table_info({table})")
            return [r[1] for r in cur.fetchall()]
        _assert(cols("entries") == ["id", "ts", "leaf_hash", "chain"],
                "CT entries schema mismatch")
        _assert(cols("sth") == ["id", "tree_size", "sha256_root", "ts"],
                "CT sth schema mismatch")
    return True


# ---------- service DBs ----------

def verify_registry_db(path: Path) -> bool:
    """
    Verify the registry.sqlite database used for certificate tracking.

    Requirements:
      - File exists.
      - Tables: certificates, csrs, revocations.
      - certificates: expected columns (serial, subject, sans, aki, ski, not_before, not_after, status).
      - csrs: (id, csr_pem, submitted_at).
      - revocations: (serial, reason, revoked_at).

    Args:
        path (Path): Path to registry.sqlite.

    Returns:
        bool: True if schema matches.

    Raises:
        ValueError: On missing file/tables or schema mismatch.
    """
    if not path.is_file():  # Ensure file exists
        raise ValueError(f"Missing registry DB: {path}")
    with sqlite3.connect(path) as conn: # Connect to database
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        names = {r[0] for r in cur.fetchall()}
        _assert("certificates" in names and "csrs" in names and "revocations" in names,
                "registry.sqlite must contain certificates, csrs, revocations")
        def cols(table: str) -> list[str]:
            cur.execute(f"PRAGMA table_info({table})")
            return [r[1] for r in cur.fetchall()]
        _assert(cols("certificates") == ["serial","subject","sans","aki","ski","not_before","not_after","status"],
                "certificates table schema mismatch")
        _assert(cols("csrs") == ["id","csr_pem","submitted_at"], "csrs table schema mismatch")
        _assert(cols("revocations") == ["serial","reason","revoked_at"], "revocations table schema mismatch")
    return True

def verify_audit_db(path: Path) -> bool:
    """
    Verify the audit.sqlite database schema.

    Requirements:
      - File exists.
      - Table: audit.
      - Columns: (id, ts, actor, action, resource, details).

    Args:
        path (Path): Path to audit.sqlite.

    Returns:
        bool: True if schema matches.

    Raises:
        ValueError: On missing file/tables or schema mismatch.
    """
    if not path.is_file():  # Ensure file exists
        raise ValueError(f"Missing audit DB: {path}")
    with sqlite3.connect(path) as conn: # Connect to database
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        names = {r[0] for r in cur.fetchall()}
        _assert("audit" in names, "audit.sqlite must contain audit table")
        cur.execute("PRAGMA table_info(audit)")
        cols = [r[1] for r in cur.fetchall()]
        _assert(cols == ["id","ts","actor","action","resource","details"], "audit table schema mismatch")
    return True


# ---------- placeholder files ----------

def verify_placeholder(path: Path) -> bool:
    """
    Verify a placeholder '.keep' file is empty (or whitespace only).

    Args:
        path (Path): Path to placeholder file.

    Returns:
        bool: True if empty/whitespace.

    Raises:
        ValueError: If non-empty.
    """
    data = _read_bytes(path)    # Read .keep file's contents and save as bytes
    _assert(data == b"" or data.strip() == b"", f"Placeholder {path.name} should be empty")
    return True


# ---------- wrapper ----------

def verify_all(
    root_dir: str,
    *,
    intermediate_name: str = "issuing-ca-1",
    root_cn: str = "Example Root CA",
    intermediate_cn: str = "Example Issuing CA",
    server_hostname: str = "localhost",
    org: str = "Example Org",
    country: str = "US",
    passphrase: Optional[bytes] = None,
) -> None:
    """
    Run the full verification suite against a certificate server layout.

    This is designed as the mirror of `initialize_cert_server` and will
    raise fast on the first detected inconsistency.

    Args:
        root_dir (str): Root directory of the CA deployment to verify.
        intermediate_name (str, optional): Intermediate CA directory/name.
        root_cn (str, optional): Expected Root CA Common Name.
        intermediate_cn (str, optional): Expected Intermediate CA Common Name.
        server_hostname (str, optional): Expected server certificate hostname.
        org (str, optional): Expected organization name.
        country (str, optional): Expected country code.
        passphrase (bytes | None, optional): Passphrase used to decrypt protected keys.

    Raises:
        ValueError: On the first failed check in any of the verification steps.

    Returns:
        None
    """
    base = Path(root_dir)
    exp = Expect(org=org, country=country, root_cn=root_cn,
                 intermediate_cn=intermediate_cn, server_hostname=server_hostname,
                 intermediate_name=intermediate_name)

    # directories
    verify_directory_tree(base, exp)

    # config
    verify_openssl_cnf(base / "config" / "openssl.cnf", exp)
    verify_policy_yml(base / "config" / "policy.yml")

    # root CA
    verify_root_key(base / "ca" / "private" / "ca.key", passphrase)
    verify_root_cert(base / "ca" / "certs" / "ca.crt", exp)
    verify_root_crl(base / "ca" / "crl" / "ca.crl", base / "ca" / "certs" / "ca.crt")
    verify_root_index_txt(base / "ca" / "index.txt")
    verify_root_serial(base / "ca" / "serial", "1000")

    # intermediate
    inter_base = base / "intermediates" / intermediate_name
    verify_intermediate_key(inter_base / "private" / "ca.key", passphrase)
    verify_intermediate_cert(inter_base / "certs" / "ca.crt", base / "ca" / "certs" / "ca.crt", exp)
    verify_intermediate_crl(inter_base / "crl" / "issuing.crl", inter_base / "certs" / "ca.crt")
    verify_intermediate_index_txt(inter_base / "index.txt")
    verify_intermediate_serial(inter_base / "serial", "2000")

    # keystores
    verify_server_pem(base / "keystores" / "server.pem", passphrase, exp)
    verify_ocsp_signer_pem(base / "keystores" / "ocsp_signer.pem", passphrase, exp)

    # ctlog
    verify_ctlog_key(base / "ctlog" / "log-signing-key.pem")
    verify_ctlog_db(base / "ctlog" / "log.db")

    # dbs
    verify_registry_db(base / "db" / "registry.sqlite")
    verify_audit_db(base / "db" / "audit.sqlite")

    # placeholders
    verify_placeholder(base / "licenses" / ".keep")
    verify_placeholder(base / "logs" / ".keep")
    verify_placeholder(base / "docker" / ".keep")

    # If we got here, everything passed.
    return