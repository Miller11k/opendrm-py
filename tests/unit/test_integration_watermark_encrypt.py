"""Integration test: watermark + optionally encrypt output."""
from pathlib import Path

from drm.encryption import cipher
from drm.watermarking import image_watermark


def test_watermark_with_encryption(tmp_path: Path):
    """Test watermarking pipeline that encrypts output with a license key."""
    src = tmp_path / "original.txt"
    src.write_bytes(b"Original image data")

    key = cipher.generate_key()
    watermarked = tmp_path / "watermarked.txt"
    
    # Apply watermark and encrypt the output
    result = image_watermark.add_watermark_and_maybe_encrypt(
        str(src),
        str(watermarked),
        watermark_text="Licensed to User123",
        encrypt=True,
        key=key,
    )

    # Result should be encrypted file path
    assert result.endswith(".opdrm")
    assert Path(result).exists()

    # Decrypt and verify
    decrypted = tmp_path / "recovered.txt"
    meta = cipher.decrypt_stream(result, str(decrypted), key)
    assert decrypted.read_bytes() == b"Original image data"
    assert meta.get("filename") == "watermarked.txt"
