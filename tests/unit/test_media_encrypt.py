import tempfile
from pathlib import Path

from drm.encryption import cipher


def test_encrypt_decrypt_roundtrip(tmp_path: Path):
    src = tmp_path / "sample.bin"
    data = b"\x00\x01\x02hello world!" * 10
    src.write_bytes(data)

    key = cipher.generate_key()

    encrypted = tmp_path / "sample.bin.opdrm"
    cipher.encrypt_stream(str(src), str(encrypted), key, chunk_size=1024)

    decrypted = tmp_path / "sample.bin.dec"
    meta = cipher.decrypt_stream(str(encrypted), str(decrypted), key)

    assert decrypted.read_bytes() == data
    assert meta.get("filename") == "sample.bin"
