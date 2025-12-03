from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Literal


MediaKind = Literal["image", "video", "audio", "other"]


def detect_media_kind(path: str) -> MediaKind:
    """Return a high-level media kind for a file path based on mimetype."""
    mt, _ = mimetypes.guess_type(path)
    if mt is None:
        return "other"
    if mt.startswith("image"):
        return "image"
    if mt.startswith("video"):
        return "video"
    if mt.startswith("audio"):
        return "audio"
    return "other"


def read_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


def write_bytes(path: str, data: bytes) -> None:
    Path(path).write_bytes(data)
