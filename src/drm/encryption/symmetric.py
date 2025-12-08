"""
Symmetric encryption primitives for DRM system.

Provides AES-based encryption algorithms for media content protection.
This module wraps the cryptography library to offer a simple, focused
symmetric encryption interface.

Supported algorithms:
- AES-256-GCM: Authenticated encryption (primary)
- AES-256-CTR: Stream cipher mode (legacy support)
- AES-256-CBC: Block cipher mode with PKCS7 padding (legacy support)
"""

from typing import Tuple
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generate_symmetric_key(key_size: int = 256) -> bytes:
    """Generate a random symmetric key.
    
    Args:
        key_size: Key size in bits (128, 192, or 256). Default 256.
    
    Returns:
        Random bytes of requested length
    """
    byte_size = key_size // 8
    return os.urandom(byte_size)


def aes_gcm_encrypt(plaintext: bytes, key: bytes, 
                   associated_data: bytes = None) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.
    
    AES-GCM provides both confidentiality and authenticity.
    
    Args:
        plaintext: Data to encrypt
        key: 256-bit encryption key
        associated_data: Optional additional authenticated data
    
    Returns:
        Tuple of (nonce, ciphertext, tag)
    """
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def aes_gcm_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, 
                   key: bytes, associated_data: bytes = None) -> bytes:
    """Decrypt AES-GCM encrypted data.
    
    Args:
        nonce: Nonce used during encryption (96 bits)
        ciphertext: Encrypted data
        tag: Authentication tag from encryption
        key: Same key used during encryption
        associated_data: Same additional data as encryption
    
    Returns:
        Decrypted plaintext
    
    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def aes_ctr_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-CTR (counter mode).
    
    CTR mode provides confidentiality but not authenticity.
    Useful for streaming large files.
    
    Args:
        plaintext: Data to encrypt
        key: 256-bit encryption key
    
    Returns:
        Tuple of (nonce/IV, ciphertext)
    """
    nonce = os.urandom(16)  # 128-bit IV for CTR
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext


def aes_ctr_decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-CTR encrypted data.
    
    Args:
        nonce: IV/nonce used during encryption
        ciphertext: Encrypted data
        key: Same key used during encryption
    
    Returns:
        Decrypted plaintext
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-CBC with PKCS7 padding.
    
    CBC mode requires padding for block alignment.
    
    Args:
        plaintext: Data to encrypt
        key: 256-bit encryption key
    
    Returns:
        Tuple of (IV, ciphertext)
    """
    from cryptography.hazmat.primitives import padding
    
    iv = os.urandom(16)  # 128-bit IV for CBC
    
    # Apply PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext


def aes_cbc_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-CBC encrypted data with PKCS7 unpadding.
    
    Args:
        iv: IV used during encryption
        ciphertext: Encrypted data
        key: Same key used during encryption
    
    Returns:
        Decrypted plaintext
    """
    from cryptography.hazmat.primitives import padding
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext
