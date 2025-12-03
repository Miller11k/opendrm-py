from __future__ import annotations

import os
from pathlib import Path
import typer

from .encryption import cipher
from .utils import media_io

app = typer.Typer()


@app.command("encrypt-media")
def encrypt_media(
    input: str = typer.Argument(..., help="Path to input media file"),
    output: str = typer.Option("", "-o", "--output", help="Path to write encrypted file"),
    keyfile: str | None = typer.Option(None, "-k", "--keyfile", help="Path to read/write symmetric key"),
):
    """Encrypt a media file and write encrypted output.

    If `--keyfile` is provided and doesn't exist, a key will be generated and saved there.
    """
    input_path = Path(input)
    if not input_path.exists():
        raise typer.BadParameter(f"Input file not found: {input}")

    out_path = Path(output) if output else input_path.with_suffix(input_path.suffix + ".opdrm")

    if keyfile:
        key_path = Path(keyfile)
        if key_path.exists():
            key = cipher.load_key(str(key_path))
        else:
            key = cipher.generate_key()
            cipher.save_key(str(key_path), key)
    else:
        key = cipher.generate_key()

    media_kind = media_io.detect_media_kind(str(input_path))
    metadata = {"content_type": media_kind, "filename": input_path}
    typer.echo(f"Encrypting {media_kind} file: {input_path} -> {out_path}")
    cipher.encrypt_stream(str(input_path), str(out_path), key, metadata=metadata)
    typer.echo("Encryption complete.")


@app.command("decrypt-media")
def decrypt_media(
    input: str = typer.Argument(..., help="Path to encrypted input file"),
    output: str = typer.Option("", "-o", "--output", help="Path to write decrypted file"),
    keyfile: str | None = typer.Option(None, "-k", "--keyfile", help="Path to read symmetric key"),
):
    """Decrypt an encrypted media file produced by `encrypt-media`."""
    input_path = Path(input)
    if not input_path.exists():
        raise typer.BadParameter(f"Input file not found: {input}")

    out_path = Path(output) if output else input_path.with_suffix(".dec")

    if not keyfile:
        raise typer.BadParameter("Key file required to decrypt (use --keyfile)")
    key_path = Path(keyfile)
    if not key_path.exists():
        raise typer.BadParameter(f"Key file not found: {keyfile}")
    key = cipher.load_key(str(key_path))

    typer.echo(f"Decrypting file: {input_path} -> {out_path}")
    metadata = cipher.decrypt_stream(str(input_path), str(out_path), key)
    typer.echo(f"Decryption complete. Metadata: {metadata}")
    typer.echo("Decryption complete.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
