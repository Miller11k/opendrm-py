import os
import sqlite3
from datetime import datetime, timedelta, timezone
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

def _cert_name(common_name: str, org: str = "Example Org", country: str = "US") -> Name:
    """
    Build a subject Distinguished Name (DN) for certificates.

    Args:
        common_name (str): Common Name (CN) to embed (e.g., hostname or label).
        org (str, optional): Organization (O) attribute. Defaults to "Example Org".
        country (str, optional): Country (C) attribute (2-letter code). Defaults to "US".

    Returns:
        cryptography.x509.Name: A Name object containing C, O, and CN.
    """
    return Name([
        NameAttribute(NameOID.COUNTRY_NAME, country),   # Set country in certificate name
        NameAttribute(NameOID.ORGANIZATION_NAME, org),  # Set organization in certificate name
        NameAttribute(NameOID.COMMON_NAME, common_name),    # Set common name in certificate name
    ])

def _new_serial() -> int:
    """
    Generate a certificate serial number.

    Returns:
        int: Integer serial based on the current UTC epoch seconds.

    Notes:
        This is simple and monotonic per second. For production CAs you may want
        random 64-128 bit serials to avoid predictability and ensure uniqueness
        across parallel issuance.
    """
    return int(datetime.now(timezone.utc).timestamp())

def _self_signed_root(common_name: str, days: int = 3650):
    """
    Create a self-signed Root CA certificate, private key, and an initial CRL.

    Args:
        common_name (str): Root CA Common Name (CN).
        days (int, optional): Validity period for the Root CA certificate in days.
            Defaults to 3650 (~10 years).

    Returns:
        tuple: (key, cert, crl)
            key  (RSAPrivateKey): Root CA private key (4096-bit RSA).
            cert (x509.Certificate): Self-signed Root CA certificate.
            crl  (x509.CertificateRevocationList): Initial CRL signed by the Root.

    Notes:
        - BasicConstraints is set with ca=True and path_length=1.
        - KeyUsage allows keyCertSign and cRLSign; no encipherment or agreement.
        - CRL nextUpdate is set to 30 days from issuance as a reasonable default.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)    # Generate an RSA key
    subject = issuer = _cert_name(common_name)  # Set the issuer/subject
    now = datetime.now(timezone.utc) # Set the time as now (in UTC)

    # Create builder for the certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)                                                                  # Set certificate's subject name
        .issuer_name(issuer)                                                                    # Set certificate's issuer name
        .public_key(key.public_key())                                                           # Set certificate's public key
        .serial_number(_new_serial())                                                           # Set certificate's serial number
        .not_valid_before(now - timedelta(days=1))                                              # Valid starting yesterday (clock-skew tolerance).
        .not_valid_after(now + timedelta(days=days))                                            # Certificate valid for set amount of days
        .add_extension(BasicConstraints(ca=True, path_length=1), critical=True)                 # Set certificate's basic constraints
        .add_extension(SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)  # Set certificate's public key identifier
        .add_extension(KeyUsage(    # Set certificate's key usage
            digital_signature=True,     # Can be used as a digital signature
            content_commitment=False,   # Non-repudiation/document-signing (off for CA).
            key_encipherment=False,     # Cannot be used as a TLS server key
            data_encipherment=False,    # Cannot be used to encrypt bulk data
            key_agreement=False,        # Disables key agreements with clients
            key_cert_sign=True,         # Can be used to sign other certificates
            crl_sign=True,              # Allows signing Certificate Revocation Lists (CRLs)
            encipher_only=False,        # Only valid if key_agreement=True, not applicable
            decipher_only=False         # Only valid if key_agreement=True, not applicable
        ), critical=True)
    )

    cert = builder.sign(private_key=key, algorithm=hashes.SHA256()) # Create the certificate from builder

    # Create an empty Certificate Revocation List (CRL)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer)    # Set the issuer
        .last_update(now)   # Set last update time as now
        .next_update(now + timedelta(days=30))  # Set update time as 30 days from now
        .sign(private_key=key, algorithm=hashes.SHA256())   # Sign the CRL with the key generated earlier
    )

    return key, cert, crl

def _pem_privkey(key, passphrase: bytes | None = None) -> bytes:
    """
    Serialize a private key to PEM.

    Args:
        key: A private key object (e.g., RSA/Ed25519) from cryptography.
        passphrase (bytes | None, optional): If provided, encrypt the PEM with
            BestAvailableEncryption using this passphrase. If None, output is unencrypted.

    Returns:
        bytes: PEM-encoded private key.
    """
    # If a passphrase is given, use it for encryption, otherwise do not encrypt
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,    # Encode using serialization encoding
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # Set format to traditional SSL
        encryption_algorithm=enc,   # Set encryption algorithm as set above (based on passphrase)
    )

def _pem_cert(cert: x509.Certificate) -> bytes:
    """
    Serialize an X.509 certificate to PEM.

    Args:
        cert (x509.Certificate): The certificate to encode.

    Returns:
        bytes: PEM-encoded certificate.
    """
    return cert.public_bytes(encoding=serialization.Encoding.PEM)   # Create PEM formatted certificate

def _sign_intermediate(root_key, root_cert, common_name: str, days: int = 1825):
    """
    Create an Intermediate CA certificate signed by the Root CA, plus an initial CRL.

    Args:
        root_key: Root CA private key used to sign the intermediate.
        root_cert (x509.Certificate): Root CA certificate.
        common_name (str): Intermediate CA Common Name (CN).
        days (int, optional): Validity period for the Intermediate CA certificate in days.
            Defaults to 1825 (~5 years).

    Returns:
        tuple: (key, cert, crl)
            key  (RSAPrivateKey): Intermediate CA private key (4096-bit RSA).
            cert (x509.Certificate): Intermediate CA certificate signed by the Root.
            crl  (x509.CertificateRevocationList): Initial CRL for the Intermediate.

    Notes:
        - BasicConstraints is set with ca=True and path_length=0 to prohibit
          additional subordinate CAs beneath this intermediate.
        - KeyUsage permits keyCertSign and cRLSign, not encipherment/agreement.
        - CRL nextUpdate is set to 14 days by default.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)  # Generate the Intermediate CA RSA private key
    now = datetime.utcnow()  # Set the current UTC time
    subject = _cert_name(common_name)  # Define the subject for the Intermediate CA certificate
    
    # Create certificate builder signed by the Root CA
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)                                                  # Set certificate's subject to Intermediate CA
        .issuer_name(root_cert.subject)                                         # Issued and signed by the Root CA
        .public_key(key.public_key())                                           # Public key for Intermediate CA
        .serial_number(_new_serial())                                           # Assign a unique serial number
        .not_valid_before(now - timedelta(days=1))                              # Allow slight clock skew (valid from yesterday)
        .not_valid_after(now + timedelta(days=days))                            # Set certificate validity period (default 5 years)
        .add_extension(BasicConstraints(ca=True, path_length=0), critical=True) # Mark as a CA certificate but restrict further subordinate CAs (path_length=0)

        .add_extension(
            SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )  # Identifier for this CA’s public key

        .add_extension(
            AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False
        )  # Links this cert to the Root CA through its key identifier

        .add_extension(KeyUsage(
            digital_signature=True,     # Allows signing of OCSP responses / CRLs
            content_commitment=False,   # Not used for document signing
            key_encipherment=False,     # Not allowed to encrypt keys like TLS servers
            data_encipherment=False,    # Not permitted for bulk data encryption
            key_agreement=False,        # Not used for DH/ECDH agreements
            key_cert_sign=True,         # Can sign end-entity certificates
            crl_sign=True,              # Can issue CRLs for end-entity revocation
            encipher_only=False,        # Only valid if key_agreement=True (not applicable)
            decipher_only=False         # Only valid if key_agreement=True (not applicable)
        ), critical=True)
    )

    cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())    # Sign the Intermediate CA certificate with the Root CA private key
    
    # Create an empty Certificate Revocation List (CRL) for the Intermediate CA
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)                     # The Root CA is the issuer of this Intermediate CA certificate
        .last_update(now)                                   # Current timestamp for CRL issue
        .next_update(now + timedelta(days=14))              # Update period (2 weeks)
        .sign(private_key=key, algorithm=hashes.SHA256())   # CRL signed by the Intermediate CA’s own key
    )

    return key, cert, crl  # Return Intermediate CA private key, certificate, and CRL

def _sign_leaf(
    issuer_key,
    issuer_cert,
    common_name: str,
    san_dns: list[str],
    eku: list[x509.ObjectIdentifier],
    days: int = 397,
):
    """
    Create an RSA end-entity (leaf) certificate signed by the given issuer (Intermediate CA).

    Args:
        issuer_key: Private key of the issuing CA used to sign the leaf certificate.
        issuer_cert: X.509 certificate of the issuing CA (for issuer fields / AKI linkage).
        common_name (str): Leaf certificate subject CN (e.g., hostname).
        san_dns (list[str]): Optional list of DNS names to place into subjectAltName.
        eku (list[x509.ObjectIdentifier]): Extended Key Usage OIDs (e.g., [ExtendedKeyUsageOID.SERVER_AUTH]).
        days (int, optional): Validity period for the leaf certificate. Defaults to 397 (CAB/F baseline max).

    Returns:
        (key, cert): Tuple containing the generated RSA private key and the signed X.509 certificate.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Generate server/client RSA key (2048-bit)
    now = datetime.utcnow()  # Use UTC "now" for validity bounds
    subject = _cert_name(common_name)  # Build subject DN (C, O, CN) using helper

    # Build end-entity certificate (not a CA)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)                               # Set subject DN for this leaf
        .issuer_name(issuer_cert.subject)                    # Link to issuing CA's subject
        .public_key(key.public_key())                        # Embed leaf public key
        .serial_number(_new_serial())                        # Unique serial (helper uses epoch seconds)
        .not_valid_before(now - timedelta(days=1))           # Allow small clock skew
        .not_valid_after(now + timedelta(days=days))         # Set validity window
        .add_extension(
            # subjectAltName with DNS entries if provided (empty list yields an empty SAN)
            SubjectAlternativeName([DNSName(d) for d in san_dns] if san_dns else []),
            critical=False
        )
        .add_extension(
            # Authority Key Identifier: tie leaf to issuer's public key (helps chain building)
            AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False
        )
        .add_extension(
            # Subject Key Identifier: identifier for this leaf's public key
            SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        )
        .add_extension(
            # Key Usage for typical TLS leaf: digital signature + key encipherment
            KeyUsage(
                digital_signature=True,   # Needed for TLS handshakes/signatures
                content_commitment=False, # Not for document signing/non-repudiation
                key_encipherment=True,    # Allow encrypting session keys (RSA key exchange)
                data_encipherment=False,  # Not used for bulk data encryption
                key_agreement=False,      # Not doing (EC)DH here
                key_cert_sign=False,      # Not allowed to sign certificates
                crl_sign=False,           # Not allowed to sign CRLs
                encipher_only=False,      # Only valid if key_agreement=True
                decipher_only=False       # Only valid if key_agreement=True
            ),
            critical=True
        )
        .add_extension(
            # Extended Key Usage: caller supplies OIDs (e.g., SERVER_AUTH, CLIENT_AUTH, OCSP_SIGNING)
            ExtendedKeyUsage(eku),
            critical=False
        )
    )

    # Sign with the issuer (Intermediate CA) using SHA-256
    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

    # Return the newly generated private key and its certificate
    return key, cert

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

    # ------------------- Resolve Base Path -------------------
    base = Path(root_dir)
    
    # ------------------- Ensure Base Directory -------------------
    _ensure_dir(base)

    # ------------------- Clean Existing Files (Top Level Only) -------------------
    for filename in os.listdir(base):
        filepath = os.path.join(base,filename)
        if os.path.isfile(filepath):
            try:
                os.remove(filepath)
            except OSError as e:
                print(f"Error deleting {filename}: {e}")

    # ------------------- Create Required Directory Tree -------------------
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
    
    # ------------------- Write Default OpenSSL Config -------------------
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

    # ------------------- Write Default Issuance Policy -------------------
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

    # ------------------- Root CA: Key, Cert, CRL -------------------
    # root_key: The private key used by the Root CA to sign certificates and CRLs
    # root_cert: The self-signed X.509 certificate representing the Root CA’s identity
    # root_crl: The initial Certificate Revocation List issued by the Root CA
    root_key, root_cert, root_crl = _self_signed_root(root_cn)
    _write(base / "ca" / "private" / "ca.key", _pem_privkey(root_key, passphrase))  # Set CA private key
    _write(base / "ca" / "certs" / "ca.crt", _pem_cert(root_cert))  # Set CA certificate
    _write(base / "ca" / "crl" / "ca.crl", root_crl.public_bytes(serialization.Encoding.PEM))   # Set CA CRL

    _write(base / "ca" / "index.txt", "")   # Write empty index.txt
    _write(base / "ca" / "serial", "1000\n")    # Write a starting serial number of 1000


    # ------------------- Intermediate CA: Key, Cert, CRL -------------------
    # int_key: The private key for the Intermediate CA, used to sign server/client certificates
    # int_cert: The Intermediate CA certificate, signed by the Root CA
    # int_crl: The initial Certificate Revocation List issued by the Intermediate CA
    int_key, int_cert, int_crl = _sign_intermediate(root_key, root_cert, intermediate_cn)

    _write(base / "intermediates" / intermediate_name / "private" / "ca.key", _pem_privkey(int_key, passphrase))  # Store the Intermediate CA private key
    _write(base / "intermediates" / intermediate_name / "certs" / "ca.crt", _pem_cert(int_cert))  # Store the Intermediate CA certificate for distribution
    _write(base / "intermediates" / intermediate_name / "crl" / "issuing.crl", int_crl.public_bytes(serialization.Encoding.PEM))  # Store the Intermediate CA CRL

    _write(base / "intermediates" / intermediate_name / "index.txt", "")  # Track certificates issued by the Intermediate CA
    _write(base / "intermediates" / intermediate_name / "serial", "2000\n")  # Initialize serial numbering for Intermediate-issued certificates

        # keystores: server.pem (cert + key) and ocsp_signer.pem (cert + key)

    # ------------------- Keystores: Server + OCSP (PEM Bundles) -------------------
    srv_key, srv_cert = _sign_leaf(
        int_key,                        # Issuer: Intermediate CA private key
        int_cert,                       # Issuer: Intermediate CA certificate
        server_hostname,                # CN subject for the server certificate
        [server_hostname],              # Subject Alternative Name (DNS)
        [ExtendedKeyUsageOID.SERVER_AUTH]  # EKU: Valid for TLS server authentication
    )

    # Combine cert and encrypted key into a single PEM file suitable for servers like Nginx/Apache
    server_pem = _pem_cert(srv_cert) + _pem_privkey(srv_key, passphrase)
    _write(base / "keystores" / "server.pem", server_pem)  # Store server identity material

    # Issue an OCSP responder signing certificate
    ocsp_key, ocsp_cert = _sign_leaf(
        int_key,                        # Issuer: Intermediate CA private key
        int_cert,                       # Issuer: Intermediate CA certificate
        f"ocsp.{server_hostname}",      # CN for OCSP service (common convention)
        [f"ocsp.{server_hostname}"],    # SAN: OCSP responder DNS name
        [ExtendedKeyUsageOID.OCSP_SIGNING]  # EKU: Only allowed to sign OCSP responses
    )

    # Store OCSP signing certificate + private key
    ocsp_pem = _pem_cert(ocsp_cert) + _pem_privkey(ocsp_key, passphrase)
    _write(base / "keystores" / "ocsp_signer.pem", ocsp_pem)

    # ------------------- Certificate Transparency (CT) Log -------------------
    # Generate a private key used to sign Certificate Transparency log entries
    ct_priv = ed25519.Ed25519PrivateKey.generate()
    _write(
        base / "ctlog" / "log-signing-key.pem",
        _pem_privkey(ct_priv, passphrase=None)  # Store Ed25519 key unencrypted
    )

    # Initialize CT log database schema
    ct_db_path = base / "ctlog" / "log.db"
    with sqlite3.connect(ct_db_path) as conn:
        cur = conn.cursor()
        # Table storing individual log entries (leaf_hash + cert chain)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS entries(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,         -- Timestamp of log entry submission
                leaf_hash BLOB NOT NULL,     -- Hash of the SCT leaf entry
                chain BLOB NOT NULL          -- DER-encoded certificate chain
            )
        """)
        # Signed Tree Head (global CT state)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sth(
                id INTEGER PRIMARY KEY,
                tree_size INTEGER NOT NULL,  -- Number of certificate entries
                sha256_root BLOB NOT NULL,   -- Merkle Tree root hash
                ts INTEGER NOT NULL          -- Timestamp of STH generation
            )
        """)
        conn.commit()

    # ------------------- Service Databases -------------------
    # Registry DB for issued certificates and revocation state
    with sqlite3.connect(base / "db" / "registry.sqlite") as conn:
        c = conn.cursor()
        # Track issued cert metadata — supports management and revocation later
        c.execute("""
            CREATE TABLE IF NOT EXISTS certificates(
                serial TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                sans TEXT,
                aki TEXT,
                ski TEXT,
                not_before TEXT,
                not_after TEXT,
                status TEXT NOT NULL DEFAULT 'good'  -- 'good', 'revoked', etc.
            )
        """)
        # Stores incoming CSRs for approval workflows
        c.execute("""
            CREATE TABLE IF NOT EXISTS csrs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                csr_pem TEXT NOT NULL,
                submitted_at TEXT NOT NULL
            )
        """)
        # Optional revocation log (for CRL publishing, auditing)
        c.execute("""
            CREATE TABLE IF NOT EXISTS revocations(
                serial TEXT NOT NULL,
                reason TEXT,
                revoked_at TEXT NOT NULL
            )
        """)
        conn.commit()

    # Audit log for operational security — tracks issuance + CA actions
    with sqlite3.connect(base / "db" / "audit.sqlite") as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,     -- Entity performing the action (e.g., admin username)
                action TEXT NOT NULL,    -- e.g., "issued cert", "revoked cert", etc.
                resource TEXT,           -- Affected cert or entity
                details TEXT             -- Optional JSON string with extra info
            )
        """)
        conn.commit()

    # ------------------- Placeholder Files -------------------
    # Ensure required directories remain under version control when empty
    _write(base / "licenses" / ".keep", "")
    _write(base / "logs" / ".keep", "")
    _write(base / "docker" / ".keep", "")

    # Completed setup log
    print(f"Initialized cert server at: {base.resolve()}")


def main():
    """
    Entry point for manual invocation/examples.

    Notes:
        This function does not run initialization by default. Uncomment the example
        call to `initialize_cert_server` to create a demo CA layout on disk.
    """
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
    #     passphrase=b"changeme",
    # )

if __name__ == "__main__":
    main()