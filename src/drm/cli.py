from __future__ import annotations

import os
from pathlib import Path
import typer

from .encryption import cipher, ca_keywrap
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


@app.command("encrypt-media-for-license")
def encrypt_media_for_license(
    input: str = typer.Argument(..., help="Path to input media file"),
    certificate: str = typer.Argument(..., help="Path to license certificate (PEM)"),
    output: str = typer.Option("", "-o", "--output", help="Path to write encrypted file"),
):
    """Encrypt a media file for a specific certificate holder (license).

    The symmetric key is wrapped with the certificate's public key.
    Only the holder of the matching private key can decrypt.
    """
    input_path = Path(input)
    if not input_path.exists():
        raise typer.BadParameter(f"Input file not found: {input}")

    cert_path = Path(certificate)
    if not cert_path.exists():
        raise typer.BadParameter(f"Certificate not found: {certificate}")

    out_path = Path(output) if output else input_path.with_suffix(input_path.suffix + ".opdrm")

    media_kind = media_io.detect_media_kind(str(input_path))
    metadata = {"content_type": media_kind, "filename": input_path.name}

    typer.echo(f"Encrypting {media_kind} for license: {input_path} -> {out_path}")
    ca_keywrap.encrypt_media_for_license(
        str(input_path), str(out_path), str(cert_path), metadata=metadata
    )
    typer.echo(f"Encryption complete. Key wrapped for certificate: {certificate}")
    typer.echo(f"Wrapped key saved to: {out_path}.keyfile")


@app.command("decrypt-media-with-license")
def decrypt_media_with_license(
    encrypted: str = typer.Argument(..., help="Path to encrypted media file"),
    keyfile: str = typer.Argument(..., help="Path to wrapped key file (.keyfile)"),
    private_key: str = typer.Argument(..., help="Path to license private key (PEM)"),
    output: str = typer.Option("", "-o", "--output", help="Path to write decrypted file"),
    password: str = typer.Option("", "-p", "--password", help="Password for encrypted private key"),
):
    """Decrypt a media file using a CA-issued license certificate.

    The wrapped key is unwrapped using the private key, then media is decrypted.
    """
    encrypted_path = Path(encrypted)
    if not encrypted_path.exists():
        raise typer.BadParameter(f"Encrypted file not found: {encrypted}")

    keyfile_path = Path(keyfile)
    if not keyfile_path.exists():
        raise typer.BadParameter(f"Key file not found: {keyfile}")

    key_path = Path(private_key)
    if not key_path.exists():
        raise typer.BadParameter(f"Private key not found: {private_key}")

    out_path = Path(output) if output else encrypted_path.with_suffix(".dec")

    pwd = password.encode("utf-8") if password else None

    typer.echo(f"Decrypting file: {encrypted_path} -> {out_path}")
    metadata = ca_keywrap.decrypt_media_with_license(
        str(encrypted_path), str(keyfile_path), str(out_path), str(key_path), password=pwd
    )
    typer.echo(f"Decryption complete. Metadata: {metadata}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
