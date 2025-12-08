"""Full integration test: CA initialization → license issuance → DRM encryption/decryption."""
from pathlib import Path
import tempfile

from cert_server.initialize_server import initialize_cert_server
from drm.encryption import ca_keywrap, cipher


def test_full_ca_drm_workflow():
    """End-to-end test: Initialize CA, issue license, encrypt/decrypt media."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        
        # Step 1: Initialize CA infrastructure
        ca_root = tmp_path / "ca"
        ca_root.mkdir()
        initialize_cert_server(str(ca_root))
        
        # Step 2: Prepare media to encrypt
        media_file = tmp_path / "original_movie.txt"
        media_file.write_bytes(b"Confidential movie content - only for licensed users")
        
        # Step 3: Use the server certificate as a "license" for this user
        # (In production, CA would issue unique per-user certificates)
        server_pem_path = ca_root / "keystores" / "server.pem"
        
        # Extract just the certificate from the bundle for public key wrapping
        server_pem = server_pem_path.read_bytes()
        cert_path = tmp_path / "server.crt"
        # Find and extract certificate PEM block
        cert_start = server_pem.find(b"-----BEGIN CERTIFICATE-----")
        cert_end = server_pem.find(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
        if cert_start != -1 and cert_end > cert_start:
            cert_path.write_bytes(server_pem[cert_start:cert_end] + b"\n")        # Step 4: Encrypt media for the license holder
        encrypted_media = tmp_path / "movie.opdrm"
        ca_keywrap.encrypt_media_for_license(
            str(media_file),
            str(encrypted_media),
            str(cert_path),
            metadata={"title": "Exclusive Content", "content_type": "video"}
        )
        
        # Verify wrapped keyfile exists
        keyfile = encrypted_media.with_suffix(".keyfile")
        assert keyfile.exists(), "Wrapped keyfile should be created"
        
        # Step 5: Decrypt media using the license (private key)
        # Use the full server.pem which contains both certificate and key
        decrypted_media = tmp_path / "decrypted_movie.txt"
        metadata = ca_keywrap.decrypt_media_with_license(
            str(encrypted_media),
            str(keyfile),
            str(decrypted_media),
            str(server_pem_path),
            password=None  # server.pem is unencrypted for this test
        )
        
        # Step 6: Verify decryption worked
        assert decrypted_media.exists()
        assert decrypted_media.read_bytes() == b"Confidential movie content - only for licensed users"
        assert metadata.get("title") == "Exclusive Content"
        assert metadata.get("content_type") == "video"
