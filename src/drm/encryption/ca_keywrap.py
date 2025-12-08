"""CA-based key wrapping for DRM license integration.

This module integrates the certificate authority system with media encryption:
- Symmetric media keys are wrapped (encrypted) with a certificate's public key
- Only holders of the corresponding private key (from CA-issued license) can unwrap
- Ties encrypted media to specific certificate holders
- Enables license-based access control
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import cipher


def load_certificate_from_pem(cert_path: str) -> x509.Certificate:
    """Load an X.509 certificate from PEM file."""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key_from_pem(
    key_path: str, password: Optional[bytes] = None
) -> rsa.RSAPrivateKey:
    """Load a private key from PEM file (with optional passphrase)."""
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def wrap_symmetric_key(
    symmetric_key: bytes, certificate_path: str
) -> bytes:
    """Wrap (encrypt) a symmetric key with a certificate's public key.

    Args:
        symmetric_key: The AES-GCM key to wrap (32 bytes)
        certificate_path: Path to X.509 certificate (PEM)

    Returns:
        Wrapped key (encrypted symmetric key)

    Raises:
        ValueError: If certificate is invalid or doesn't support encryption
    """
    cert = load_certificate_from_pem(certificate_path)

    # Verify cert has keyEncipherment capability
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_encipherment:
            raise ValueError(
                "Certificate KeyUsage does not allow key encipherment"
            )
    except x509.ExtensionNotFound:
        raise ValueError("Certificate missing KeyUsage extension")

    # Extract public key and wrap
    pub_key = cert.public_key()
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("Certificate must contain an RSA public key")

    wrapped = pub_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped


def unwrap_symmetric_key(
    wrapped_key: bytes, private_key_path: str, password: Optional[bytes] = None
) -> bytes:
    """Unwrap (decrypt) a symmetric key using a private key.

    Args:
        wrapped_key: The encrypted symmetric key
        private_key_path: Path to private key (PEM)
        password: Optional passphrase for encrypted key

    Returns:
        Unwrapped symmetric key (32 bytes)

    Raises:
        ValueError: If unwrapping fails
    """
    priv_key = load_private_key_from_pem(private_key_path, password=password)

    try:
        symmetric_key = priv_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return symmetric_key
    except Exception as e:
        raise ValueError(f"Failed to unwrap key: {e}") from e


def encrypt_media_for_license(
    input_path: str,
    output_path: str,
    certificate_path: str,
    metadata: Optional[dict] = None,
) -> str:
    """Encrypt a media file and wrap the key for a specific certificate holder.

    Workflow:
        1. Generate a symmetric key for the media
        2. Encrypt media with symmetric key (streaming AES-GCM)
        3. Wrap the symmetric key with the certificate's public key
        4. Store wrapped key in a sidecar file

    Args:
        input_path: Path to media file
        output_path: Path to write encrypted media
        certificate_path: Path to certificate (license)
        metadata: Optional metadata dict

    Returns:
        Path to encrypted media file
    """
    # Generate and encrypt media
    key = cipher.generate_key()
    if metadata is None:
        metadata = {}
    cipher.encrypt_stream(input_path, output_path, key, metadata=metadata)

    # Wrap key for this certificate
    wrapped_key = wrap_symmetric_key(key, certificate_path)

    # Store wrapped key in sidecar
    keyfile = Path(output_path).with_suffix(".keyfile")
    keyfile.write_bytes(wrapped_key)

    return str(Path(output_path))


def decrypt_media_with_license(
    encrypted_path: str,
    keyfile_path: str,
    output_path: str,
    private_key_path: str,
    password: Optional[bytes] = None,
) -> dict:
    """Decrypt a media file using a CA-issued license certificate.

    Workflow:
        1. Unwrap (decrypt) the symmetric key using private key
        2. Decrypt media using the unwrapped key
        3. Return metadata

    Args:
        encrypted_path: Path to encrypted media
        keyfile_path: Path to wrapped key file
        output_path: Path to write decrypted media
        private_key_path: Path to private key from license cert
        password: Optional passphrase for private key

    Returns:
        Metadata dict from encrypted file

    Raises:
        ValueError: If key or media decryption fails
    """
    # Unwrap the key
    wrapped_key = Path(keyfile_path).read_bytes()
    symmetric_key = unwrap_symmetric_key(
        wrapped_key, private_key_path, password=password
    )

    # Decrypt media
    metadata = cipher.decrypt_stream(encrypted_path, output_path, symmetric_key)
    return metadata
