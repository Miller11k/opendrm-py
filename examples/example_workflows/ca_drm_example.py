"""Example: Complete DRM workflow using CA-issued licenses.

This example demonstrates:
1. Initializing a CA infrastructure
2. Issuing a license certificate to a user
3. Encrypting media for that license
4. Decrypting media with the license
"""

from pathlib import Path
import tempfile

# Example shows the architecture but requires actual CA setup to run
# In a real deployment:
# - Initialize CA: initialize_cert_server()
# - Issue license cert: CA issues a client certificate to user
# - Encrypt for user: encrypt_media_for_license() with user's cert
# - Decrypt with license: decrypt_media_with_license() with user's private key


def example_drm_architecture():
    """
    DRM Architecture Overview:
    
    1. CA Setup (one-time):
       - Initialize Root CA and Intermediate CA
       - Create certificate transparency log
       - Set up license database
    
    2. License Issuance (per user):
       - CA issues a certificate to user (client auth)
       - User receives certificate + private key (with passphrase)
    
    3. Media Encryption (publisher):
       - Generate symmetric key for media
       - Encrypt media with symmetric key (AES-GCM streaming)
       - Wrap symmetric key with user's certificate public key (RSA-OAEP)
       - Distribute encrypted media + wrapped key
    
    4. Media Decryption (license holder):
       - User unwraps symmetric key with their private key
       - User decrypts media with unwrapped symmetric key
       - Only valid license holders can access media
    
    Key Features:
    - Per-user encryption (each user gets unique wrapped key)
    - License revocation possible (CA can revoke certificates)
    - Streaming decryption (efficient for large media)
    - Metadata preserved (content_type, filename, chunk_size)
    - FIPS-compliant (RSA-2048+, AES-256, SHA-256, OAEP padding)
    """
    print(__doc__)


def example_usage():
    """
    Usage workflow (requires CA setup):
    
    1. Initialize CA:
        from cert_server.initialize_server import initialize_cert_server
        initialize_cert_server("/path/to/ca")
    
    2. Issue license to user (via CA):
        # CA issues certificate and key to user
        user_cert = "/path/to/user.crt"
        user_key = "/path/to/user.key"
    
    3. Encrypt media for user:
        from drm.encryption.ca_keywrap import encrypt_media_for_license
        encrypt_media_for_license(
            "movie.mp4",
            "movie.mp4.opdrm",
            user_cert,
            metadata={"title": "Exclusive Movie"}
        )
        # Creates: movie.mp4.opdrm (encrypted media)
        #          movie.mp4.opdrm.keyfile (wrapped key)
    
    4. User decrypts with license:
        from drm.encryption.ca_keywrap import decrypt_media_with_license
        decrypt_media_with_license(
            "movie.mp4.opdrm",
            "movie.mp4.opdrm.keyfile",
            "movie_decrypted.mp4",
            user_key,
            password=b"user_passphrase"
        )
        # Creates: movie_decrypted.mp4 (original media)
    
    CLI Usage:
        # Encrypt for license
        drm encrypt-media-for-license movie.mp4 user.crt -o movie.mp4.opdrm
        
        # Decrypt with license
        drm decrypt-media-with-license movie.mp4.opdrm movie.mp4.opdrm.keyfile user.key -p "passphrase" -o movie.mp4
    """
    print(__doc__)


if __name__ == "__main__":
    example_drm_architecture()
    print("\n" + "="*80 + "\n")
    example_usage()
