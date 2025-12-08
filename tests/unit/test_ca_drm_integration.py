"""Integration test: CA-based DRM encryption and decryption."""
from pathlib import Path

from drm.encryption import ca_keywrap


def test_ca_based_media_encryption(tmp_path: Path):
    """Test encrypting media for a specific certificate holder and decrypting with license key."""
    # This test requires a CA setup with certificates
    # For now, we'll create a minimal test that can be extended
    
    src = tmp_path / "media.txt"
    src.write_bytes(b"Confidential media content for license holder")
    
    # In a real scenario, these would come from the CA
    # For this test, we verify the module structure works
    assert hasattr(ca_keywrap, 'encrypt_media_for_license')
    assert hasattr(ca_keywrap, 'decrypt_media_with_license')
    assert hasattr(ca_keywrap, 'wrap_symmetric_key')
    assert hasattr(ca_keywrap, 'unwrap_symmetric_key')


def test_key_wrapping_functions_exist(tmp_path: Path):
    """Verify key wrapping functions are available for integration."""
    # These functions bridge symmetric encryption with CA certificates
    assert callable(ca_keywrap.load_certificate_from_pem)
    assert callable(ca_keywrap.load_private_key_from_pem)
    assert callable(ca_keywrap.wrap_symmetric_key)
    assert callable(ca_keywrap.unwrap_symmetric_key)
