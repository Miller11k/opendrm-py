from __future__ import annotations

import json
import os
from pathlib import Path
from typing import BinaryIO, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# File format:
# MAGIC (6) | version (1) | header_len (4, big-endian) | header JSON bytes
# header JSON includes: {"filename": ..., "content_type": ..., "chunk_size": ...}
# Followed by sequence of chunks: [nonce (12) | chunk_ciphertext_length (4) | ciphertext]

MAGIC = b"OPDRM1"
VERSION = 1
NONCE_SIZE = 12


def generate_key() -> bytes:
    return os.urandom(32)


def save_key(path: str, key: bytes) -> None:
    Path(path).write_bytes(key)


def load_key(path: str) -> bytes:
    return Path(path).read_bytes()


def _write_header(out: BinaryIO, metadata: Dict[str, object]) -> None:
    header_json = json.dumps(metadata).encode("utf-8")
    out.write(MAGIC)
    out.write(bytes([VERSION]))
    out.write(len(header_json).to_bytes(4, "big"))
    out.write(header_json)


def _read_header(f: BinaryIO) -> Dict[str, object]:
    magic = f.read(len(MAGIC))
    if magic != MAGIC:
        raise ValueError("Not an OPDRM encrypted file")
    version = f.read(1)
    if not version:
        raise ValueError("Truncated file (no version)")
    ver = version[0]
    if ver != VERSION:
        raise ValueError(f"Unsupported version: {ver}")
    header_len = int.from_bytes(f.read(4), "big")
    header = f.read(header_len)
    return json.loads(header.decode("utf-8"))


def encrypt_stream(input_path: str, output_path: str, key: bytes, chunk_size: int = 64 * 1024, metadata: Dict[str, object] | None = None) -> None:
    """Stream-encrypt a file in chunks. Each chunk is encrypted with AES-GCM and its own nonce.

    The header stores metadata like original filename and content_type.
    """
    aes = AESGCM(key)
    if metadata is None:
        metadata = {}
    metadata.setdefault("filename", Path(input_path).name)
    metadata.setdefault("chunk_size", chunk_size)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        _write_header(fout, metadata)
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            nonce = os.urandom(NONCE_SIZE)
            ct = aes.encrypt(nonce, chunk, associated_data=None)
            fout.write(nonce)
            fout.write(len(ct).to_bytes(4, "big"))
            fout.write(ct)


def decrypt_stream(input_path: str, output_path: str, key: bytes) -> Dict[str, object]:
    """Decrypt a stream encrypted with `encrypt_stream`. Returns metadata dict."""
    aes = AESGCM(key)
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        metadata = _read_header(fin)
        while True:
            nonce = fin.read(NONCE_SIZE)
            if not nonce:
                break
            ct_len_b = fin.read(4)
            if len(ct_len_b) < 4:
                raise ValueError("Truncated chunk length")
            ct_len = int.from_bytes(ct_len_b, "big")
            ct = fin.read(ct_len)
            if len(ct) < ct_len:
                raise ValueError("Truncated ciphertext")
            pt = aes.decrypt(nonce, ct, associated_data=None)
            fout.write(pt)
    return metadata

