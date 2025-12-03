from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..encryption import cipher


def add_watermark_and_maybe_encrypt(
    input_path: str,
    output_path: str,
    watermark_text: Optional[str] = None,
    encrypt: bool = False,
    key: bytes | None = None,
):
    """Stub: apply a simple watermark (placeholder) and optionally encrypt output.

    This is a lightweight integration point so watermarking pipelines can produce encrypted assets.
    """
    # For now just copy file (watermarking not implemented); in a real impl use Pillow/OpenCV
    inp = Path(input_path)
    out = Path(output_path)
    out.write_bytes(inp.read_bytes())

    if encrypt:
        if key is None:
            raise ValueError("Encryption requested but no key provided")
        encrypted = out.with_suffix(out.suffix + ".opdrm")
        cipher.encrypt_stream(str(out), str(encrypted), key, metadata={"filename": out.name})
        return str(encrypted)
    return str(out)
