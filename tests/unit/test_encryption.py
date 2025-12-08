"""Tests for symmetric and asymmetric encryption modules."""

import pytest
from drm.encryption.symmetric import (
    generate_symmetric_key, aes_gcm_encrypt, aes_gcm_decrypt,
    aes_ctr_encrypt, aes_ctr_decrypt, aes_cbc_encrypt, aes_cbc_decrypt
)
from drm.encryption.asymmetric import (
    generate_rsa_keypair, rsa_oaep_encrypt, rsa_oaep_decrypt,
    rsa_sign, rsa_verify, serialize_public_key, serialize_private_key,
    deserialize_public_key, deserialize_private_key
)
from cryptography.exceptions import InvalidTag


class TestSymmetricEncryption:
    """Test symmetric encryption algorithms."""
    
    def test_aes_gcm_roundtrip(self):
        """Test AES-GCM encryption and decryption roundtrip."""
        key = generate_symmetric_key(256)
        plaintext = b"Hello, World! This is secret content."
        
        # Encrypt
        nonce, ciphertext, tag = aes_gcm_encrypt(plaintext, key)
        
        # Verify nonce and tag sizes
        assert len(nonce) == 12
        assert len(tag) == 16
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = aes_gcm_decrypt(nonce, ciphertext, tag, key)
        assert decrypted == plaintext
    
    def test_aes_gcm_with_aad(self):
        """Test AES-GCM with additional authenticated data."""
        key = generate_symmetric_key(256)
        plaintext = b"Secret message"
        aad = b"Device-1 license metadata"
        
        # Encrypt with AAD
        nonce, ciphertext, tag = aes_gcm_encrypt(plaintext, key, aad)
        
        # Decrypt with same AAD
        decrypted = aes_gcm_decrypt(nonce, ciphertext, tag, key, aad)
        assert decrypted == plaintext
        
        # Decrypt with wrong AAD should fail
        with pytest.raises(Exception):  # InvalidTag
            aes_gcm_decrypt(nonce, ciphertext, tag, key, b"wrong aad")
    
    def test_aes_gcm_tampering_detection(self):
        """Test that AES-GCM detects tampering."""
        key = generate_symmetric_key(256)
        plaintext = b"Important content"
        
        nonce, ciphertext, tag = aes_gcm_encrypt(plaintext, key)
        
        # Tamper with ciphertext
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0xFF  # Flip bits
        tampered_ct = bytes(tampered_ct)
        
        # Decryption should fail
        with pytest.raises(Exception):  # InvalidTag
            aes_gcm_decrypt(nonce, tampered_ct, tag, key)
    
    def test_aes_gcm_key_sizes(self):
        """Test AES-GCM with different key sizes."""
        plaintext = b"Test data"
        
        for key_size in [128, 192, 256]:
            key = generate_symmetric_key(key_size)
            assert len(key) == key_size // 8
            
            nonce, ct, tag = aes_gcm_encrypt(plaintext, key)
            decrypted = aes_gcm_decrypt(nonce, ct, tag, key)
            assert decrypted == plaintext
    
    def test_aes_ctr_roundtrip(self):
        """Test AES-CTR encryption and decryption."""
        key = generate_symmetric_key(256)
        plaintext = b"Stream cipher data for large files"
        
        nonce, ciphertext = aes_ctr_encrypt(plaintext, key)
        assert len(nonce) == 16
        assert ciphertext != plaintext
        
        decrypted = aes_ctr_decrypt(nonce, ciphertext, key)
        assert decrypted == plaintext
    
    def test_aes_cbc_roundtrip(self):
        """Test AES-CBC encryption and decryption with padding."""
        key = generate_symmetric_key(256)
        plaintext = b"Block cipher mode with PKCS7 padding"
        
        iv, ciphertext = aes_cbc_encrypt(plaintext, key)
        assert len(iv) == 16
        
        decrypted = aes_cbc_decrypt(iv, ciphertext, key)
        assert decrypted == plaintext
    
    def test_symmetric_key_generation(self):
        """Test symmetric key generation produces unique keys."""
        key1 = generate_symmetric_key(256)
        key2 = generate_symmetric_key(256)
        
        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2  # Keys should be random/unique


class TestAsymmetricEncryption:
    """Test asymmetric encryption and signatures."""
    
    def test_rsa_keypair_generation(self):
        """Test RSA key pair generation."""
        private_key, public_key = generate_rsa_keypair(2048)
        
        assert private_key is not None
        assert public_key is not None
        assert private_key.key_size == 2048
        assert public_key.key_size == 2048
    
    def test_rsa_oaep_roundtrip(self):
        """Test RSA-OAEP encryption and decryption."""
        private_key, public_key = generate_rsa_keypair(2048)
        plaintext = b"Secret key material"
        
        # Encrypt with public key
        ciphertext = rsa_oaep_encrypt(plaintext, public_key, "sha256")
        assert ciphertext != plaintext
        assert len(ciphertext) == 256  # 2048-bit key = 256 bytes
        
        # Decrypt with private key
        decrypted = rsa_oaep_decrypt(ciphertext, private_key, "sha256")
        assert decrypted == plaintext
    
    def test_rsa_oaep_with_different_hash_algorithms(self):
        """Test RSA-OAEP with SHA-256, SHA-384, SHA-512."""
        private_key, public_key = generate_rsa_keypair(2048)
        plaintext = b"Test message"
        
        for hash_alg in ["sha256", "sha384", "sha512"]:
            ct = rsa_oaep_encrypt(plaintext, public_key, hash_alg)
            pt = rsa_oaep_decrypt(ct, private_key, hash_alg)
            assert pt == plaintext
    
    def test_rsa_signature_roundtrip(self):
        """Test RSA-PSS signature creation and verification."""
        private_key, public_key = generate_rsa_keypair(2048)
        message = b"License certificate content"
        
        # Sign with private key
        signature = rsa_sign(message, private_key, "sha256", "pss")
        assert len(signature) == 256  # 2048-bit signature
        
        # Verify with public key
        assert rsa_verify(message, signature, public_key, "sha256", "pss") == True
    
    def test_rsa_signature_verification_fails_on_tampering(self):
        """Test that signature verification fails if message is tampered."""
        private_key, public_key = generate_rsa_keypair(2048)
        message = b"Original message"
        
        signature = rsa_sign(message, private_key, "sha256", "pss")
        
        # Verify with correct message
        assert rsa_verify(message, signature, public_key, "sha256", "pss") == True
        
        # Verify with tampered message
        tampered_msg = b"Modified message"
        assert rsa_verify(tampered_msg, signature, public_key, "sha256", "pss") == False
    
    def test_key_serialization_pem(self):
        """Test key serialization to PEM format."""
        private_key, public_key = generate_rsa_keypair(2048)
        
        # Serialize public key
        pub_pem = serialize_public_key(public_key, "pem")
        assert b"-----BEGIN PUBLIC KEY-----" in pub_pem
        assert b"-----END PUBLIC KEY-----" in pub_pem
        
        # Deserialize and verify
        restored_pub = deserialize_public_key(pub_pem)
        assert restored_pub.key_size == 2048
    
    def test_key_serialization_with_encryption(self):
        """Test private key serialization with password encryption."""
        private_key, _ = generate_rsa_keypair(2048)
        password = b"strong-password"
        
        # Serialize encrypted
        encrypted_pem = serialize_private_key(private_key, "pem", password)
        assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in encrypted_pem
        
        # Deserialize with password
        restored_key = deserialize_private_key(encrypted_pem, password)
        assert restored_key.key_size == 2048
    
    def test_rsa_key_sizes(self):
        """Test RSA key generation with different sizes."""
        for key_size in [2048, 3072, 4096]:
            private_key, public_key = generate_rsa_keypair(key_size)
            assert private_key.key_size == key_size
            assert public_key.key_size == key_size
