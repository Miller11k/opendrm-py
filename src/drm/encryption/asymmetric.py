"""
Asymmetric encryption primitives for DRM system.

Provides RSA-based key encryption and digital signatures for DRM.
This module wraps the cryptography library to offer asymmetric
encryption for key transport and signature verification.

Supported algorithms:
- RSA-2048/RSA-4096: Public key encryption
- RSA-OAEP: Optimal Asymmetric Encryption Padding (recommended for key transport)
- RSA-PSS: Probabilistic Signature Scheme (recommended for signatures)
- PKCS1v15: Legacy padding support
"""

from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA public/private key pair.
    
    Args:
        key_size: RSA key size in bits (2048, 3072, 4096). Default 2048.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_oaep_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey,
                    hash_algorithm: Optional[str] = "sha256") -> bytes:
    """Encrypt using RSA with OAEP padding.
    
    OAEP (Optimal Asymmetric Encryption Padding) is the recommended padding
    for RSA encryption, especially for key transport in DRM systems.
    
    Args:
        plaintext: Data to encrypt (must be smaller than key size - hash overhead)
        public_key: RSA public key for encryption
        hash_algorithm: Hash algorithm ("sha256", "sha384", "sha512")
    
    Returns:
        Encrypted ciphertext
    """
    hash_alg = _get_hash_algorithm(hash_algorithm)
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hash_alg),
            algorithm=hash_alg,
            label=None
        )
    )
    return ciphertext


def rsa_oaep_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey,
                    hash_algorithm: Optional[str] = "sha256") -> bytes:
    """Decrypt RSA-OAEP encrypted data.
    
    Args:
        ciphertext: Encrypted data
        private_key: RSA private key for decryption
        hash_algorithm: Hash algorithm used during encryption
    
    Returns:
        Decrypted plaintext
    
    Raises:
        cryptography.exceptions.InvalidAsymmetricPadding: If decryption fails
    """
    hash_alg = _get_hash_algorithm(hash_algorithm)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hash_alg),
            algorithm=hash_alg,
            label=None
        )
    )
    return plaintext


def rsa_pkcs1v15_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypt using RSA with PKCS#1 v1.5 padding (legacy).
    
    PKCS#1 v1.5 is less secure than OAEP but provided for compatibility.
    
    Args:
        plaintext: Data to encrypt
        public_key: RSA public key for encryption
    
    Returns:
        Encrypted ciphertext
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.PKCS1v15()
    )
    return ciphertext


def rsa_pkcs1v15_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt RSA PKCS#1 v1.5 encrypted data.
    
    Args:
        ciphertext: Encrypted data
        private_key: RSA private key for decryption
    
    Returns:
        Decrypted plaintext
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )
    return plaintext


def rsa_sign(message: bytes, private_key: rsa.RSAPrivateKey,
            hash_algorithm: Optional[str] = "sha256",
            padding_type: str = "pss") -> bytes:
    """Sign a message using RSA.
    
    Args:
        message: Data to sign
        private_key: RSA private key for signing
        hash_algorithm: Hash algorithm ("sha256", "sha384", "sha512")
        padding_type: "pss" (recommended) or "pkcs1v15"
    
    Returns:
        Digital signature bytes
    """
    hash_alg = _get_hash_algorithm(hash_algorithm)
    
    if padding_type == "pss":
        sig_padding = padding.PSS(
            mgf=padding.MGF1(hash_alg),
            salt_length=padding.PSS.MAX_LENGTH
        )
    else:
        sig_padding = padding.PKCS1v15()
    
    signature = private_key.sign(message, sig_padding, hash_alg)
    return signature


def rsa_verify(message: bytes, signature: bytes, public_key: rsa.RSAPublicKey,
              hash_algorithm: Optional[str] = "sha256",
              padding_type: str = "pss") -> bool:
    """Verify an RSA digital signature.
    
    Args:
        message: Original signed data
        signature: Signature to verify
        public_key: RSA public key for verification
        hash_algorithm: Hash algorithm used during signing
        padding_type: "pss" (recommended) or "pkcs1v15"
    
    Returns:
        True if signature is valid, False otherwise
    """
    hash_alg = _get_hash_algorithm(hash_algorithm)
    
    if padding_type == "pss":
        sig_padding = padding.PSS(
            mgf=padding.MGF1(hash_alg),
            salt_length=padding.PSS.MAX_LENGTH
        )
    else:
        sig_padding = padding.PKCS1v15()
    
    try:
        public_key.verify(signature, message, sig_padding, hash_alg)
        return True
    except Exception:
        return False


def serialize_public_key(public_key: rsa.RSAPublicKey, format: str = "pem") -> bytes:
    """Serialize a public key to PEM or DER format.
    
    Args:
        public_key: RSA public key to serialize
        format: "pem" or "der"
    
    Returns:
        Serialized key bytes
    """
    enc_format = serialization.Encoding.PEM if format == "pem" else serialization.Encoding.DER
    return public_key.public_bytes(
        encoding=enc_format,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key(private_key: rsa.RSAPrivateKey, format: str = "pem",
                         password: Optional[bytes] = None) -> bytes:
    """Serialize a private key to PEM or DER format.
    
    Args:
        private_key: RSA private key to serialize
        format: "pem" or "der"
        password: Optional password for encryption (PEM only)
    
    Returns:
        Serialized key bytes
    """
    enc_format = serialization.Encoding.PEM if format == "pem" else serialization.Encoding.DER
    enc_method = (
        serialization.BestAvailableEncryption(password) if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=enc_format,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_method
    )


def deserialize_public_key(key_bytes: bytes) -> rsa.RSAPublicKey:
    """Deserialize a public key from PEM or DER format.
    
    Args:
        key_bytes: Serialized key data
    
    Returns:
        RSA public key
    """
    return serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend()
    )


def deserialize_private_key(key_bytes: bytes, 
                           password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """Deserialize a private key from PEM or DER format.
    
    Args:
        key_bytes: Serialized key data
        password: Password if key is encrypted
    
    Returns:
        RSA private key
    """
    return serialization.load_pem_private_key(
        key_bytes,
        password=password,
        backend=default_backend()
    )


def _get_hash_algorithm(name: Optional[str] = "sha256"):
    """Get cryptography hash algorithm instance.
    
    Args:
        name: Hash algorithm name
    
    Returns:
        Hash algorithm instance
    """
    if name == "sha256":
        return hashes.SHA256()
    elif name == "sha384":
        return hashes.SHA384()
    elif name == "sha512":
        return hashes.SHA512()
    else:
        return hashes.SHA256()  # Default
