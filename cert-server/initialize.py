import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509 import (
    Name, NameAttribute, BasicConstraints, SubjectAlternativeName, DNSName,
    AuthorityKeyIdentifier, SubjectKeyIdentifier, KeyUsage, ExtendedKeyUsage
)

# ---- helpers ----

def _ensure_dir(p: Path) -> Path:
    """
    Ensure that the given directory exists, creating it if necessary.

    Args:
        p (Path): The directory path to ensure exists.

    Returns:
        Path: The same path object that was provided.
    """
    p.mkdir(parents=True, exist_ok=True)
    return p

def _write(path: Path, data: bytes | str) -> None:
    """
    Write data to a file that may or may not exist already.

    Args:
        path (Path): The file path that needs to be written to
        data (bytes or str): The data that needs to be written

    Returns:
        None: This function writes to a file but does not return a value
    """
    path.parent.mkdir(parents=True, exist_ok=True)  # Make sure the parent directory exists
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"    # Set mode to write (bytes if bytes are passed in)
    with open(path, mode) as f: # Write data to file
        f.write(data)

# ---- initializer ----

def initialize_cert_server(
    root_dir: str,
    *,
    intermediate_name: str = "issuing-ca-1",
    root_cn: str = "Example Root CA",
    intermediate_cn: str = "Example Issuing CA",
    server_hostname: str = "localhost",
    org: str = "Example Org",
    country: str = "US",
    passphrase: bytes | None = None,
) -> None:
    """
    Initializes the certificate server directory structure and generates CA/server certificates.

    Args:
        root_dir (str): Root directory where all certificate authority files will be created.
        intermediate_name (str, optional): Name for the intermediate CA directory.
            Defaults to "issuing-ca-1".
        root_cn (str, optional): Common Name for the Root CA certificate.
            Defaults to "Example Root CA".
        intermediate_cn (str, optional): Common Name for the Intermediate CA certificate.
            Defaults to "Example Issuing CA".
        server_hostname (str, optional): Hostname for the generated server certificate.
            Defaults to "localhost".
        org (str, optional): Organization name added as certificate metadata.
            Defaults to "Example Org".
        country (str, optional): Country code added as certificate metadata.
            Defaults to "US".
        passphrase (bytes | None, optional): Optional passphrase used to encrypt private keys.
            Defaults to None.

    Returns:
        None: This function performs setup but does not return a value.
    """

    base = Path(root_dir)
    
    # Ensure base directory exists
    _ensure_dir(base)

    # Clear all files within base directory
    for filename in os.listdir(base):
        filepath = os.path.join(base,filename)
        if os.path.isfile(filepath):
            try:
                os.remove(filepath)
            except OSError as e:
                print(f"Error deleting {filename}: {e}")

    # Ensure top level directories are created/exist
    for p in [
        "bin", "config",
        "ca/private", "ca/certs", "ca/crl", "ca/newcerts",
        f"intermediates/{intermediate_name}/private",
        f"intermediates/{intermediate_name}/certs",
        f"intermediates/{intermediate_name}/crl",
        f"intermediates/{intermediate_name}/newcerts",
        "keystores",
        "ctlog",
        "db",
        "licenses",
        "logs",
        "docker",
    ]:
        _ensure_dir(base / p)
    
    # Set default openssl config file
    openssl_cnf = f"""# Minimal OpenSSL config for {org}
    [ ca ]
    default_ca = CA_default

    [ CA_default ]
    dir               = .
    database          = ./index.txt
    new_certs_dir     = ./newcerts
    certificate       = ./certs/ca.crt
    serial            = ./serial
    private_key       = ./private/ca.key
    default_md        = sha256
    policy            = policy_any
    x509_extensions   = usr_cert
    default_days      = 397

    [ policy_any ]
    commonName              = supplied

    [ usr_cert ]
    basicConstraints=CA:FALSE
    keyUsage=digitalSignature,keyEncipherment
    extendedKeyUsage=serverAuth,clientAuth

    """
    _write(base / "config" / "openssl.cnf", openssl_cnf) # Write the config file

    # Set the default policy yaml
    policy_yml = """# issuance profiles
    profiles:
    server:
        eku: [serverAuth]
        days: 397
    client:
        eku: [clientAuth]
        days: 397
    """
    _write(base / "config" / "policy.yml", policy_yml)  # Write the default policy yaml

    


def main():
    print("Initialize.py")

    # Example:
    # initialize_cert_server(
    #     "cert-server",
    #     intermediate_name="issuing-ca-1",
    #     root_cn="Example Root CA",
    #     intermediate_cn="Example Issuing CA",
    #     server_hostname="localhost",
    #     org="Example Org",
    #     country="US",
    #     passphrase=None,   # or b"changeit"
    # )

if __name__ == "__main__":
    main()