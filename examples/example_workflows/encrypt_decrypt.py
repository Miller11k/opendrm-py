"""Simple example: encrypt and decrypt a small file."""
from pathlib import Path

from drm.encryption import cipher


def demo():
	src = Path(__file__).parent.parent / "sample_media" / "example.txt"
	src.parent.mkdir(parents=True, exist_ok=True)
	src.write_text("This is an example media file (text).")

	key_path = Path("example_media.key")
	key = cipher.generate_key()
	cipher.save_key(str(key_path), key)

	encrypted = src.with_suffix(src.suffix + ".opdrm")
	cipher.encrypt_stream(str(src), str(encrypted), key, metadata={"content_type": "text/plain", "filename": src.name})

	decrypted = src.with_suffix(".dec")
	meta = cipher.decrypt_stream(str(encrypted), str(decrypted), key)

	print("Roundtrip ok:", decrypted.read_text() == src.read_text(), "metadata:", meta)


if __name__ == "__main__":
	demo()

