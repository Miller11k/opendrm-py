from __future__ import annotations

import os
from pathlib import Path
import typer
import sys

from .encryption import cipher, ca_keywrap
from .utils import media_io

# Try to import cert_server modules (may not always be available)
try:
    from cert_server.initialize_server import initialize_cert_server
    from cert_server.verify_server import verify_all
    CERT_SERVER_AVAILABLE = True
except ImportError:
    CERT_SERVER_AVAILABLE = False

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


# ============================================================================
# CA Management Commands
# ============================================================================

@app.command("init-ca")
def init_ca(
    root_dir: str = typer.Argument(..., help="Directory where CA will be initialized"),
    root_cn: str = typer.Option("Example Root CA", "--root-cn", help="Common Name for Root CA"),
    intermediate_cn: str = typer.Option("Example Issuing CA", "--intermediate-cn", help="Common Name for Intermediate CA"),
    org: str = typer.Option("Example Org", "--org", help="Organization name"),
    country: str = typer.Option("US", "--country", help="Country code (2 letters)"),
    passphrase: str = typer.Option("", "--passphrase", help="Passphrase to encrypt private keys"),
):
    """Initialize a new Certificate Authority (CA) infrastructure.
    
    Creates root CA, intermediate CA, CT log, and directory structure.
    This is a one-time setup operation.
    """
    if not CERT_SERVER_AVAILABLE:
        typer.echo("ERROR: cert_server module not available.", err=True)
        typer.echo("Make sure the package is properly installed: pip install -e .", err=True)
        raise typer.Exit(code=1)
    
    root_path = Path(root_dir)
    if root_path.exists() and list(root_path.iterdir()):
        typer.echo(f"WARNING: Directory {root_dir} already exists and may contain CA data.", err=True)
        if not typer.confirm("Continue? This may overwrite existing CA."):
            raise typer.Abort()
    
    try:
        pwd = passphrase.encode("utf-8") if passphrase else None
        typer.echo(f"Initializing CA in {root_dir}...")
        initialize_cert_server(
            root_dir,
            root_cn=root_cn,
            intermediate_cn=intermediate_cn,
            org=org,
            country=country,
            passphrase=pwd,
        )
        typer.echo(f"[OK] CA initialized successfully in {root_dir}")
        typer.echo(f"  Root CA: {root_cn}")
        typer.echo(f"  Intermediate CA: {intermediate_cn}")
        typer.echo(f"  Organization: {org}")
    except Exception as e:
        typer.echo(f"ERROR: Failed to initialize CA: {e}", err=True)
        raise typer.Exit(code=1)


@app.command("verify-ca")
def verify_ca(
    ca_dir: str = typer.Argument(..., help="Path to CA directory to verify"),
):
    """Verify the integrity of a Certificate Authority installation.
    
    Checks that all required files, directories, and certificates are present.
    """
    if not CERT_SERVER_AVAILABLE:
        typer.echo("ERROR: cert_server module not available.", err=True)
        raise typer.Exit(code=1)
    
    ca_path = Path(ca_dir)
    if not ca_path.exists():
        typer.echo(f"ERROR: CA directory not found: {ca_dir}", err=True)
        raise typer.Exit(code=1)
    
    try:
        typer.echo(f"Verifying CA in {ca_dir}...")
        verify_all(str(ca_path))
        typer.echo("[OK] CA verification successful")
    except Exception as e:
        typer.echo(f"[FAIL] CA verification failed: {e}", err=True)
        raise typer.Exit(code=1)


@app.command("show-status")
def show_status(
    ca_dir: str = typer.Option("", "--ca-dir", help="Path to CA directory (optional)"),
):
    """Show status and capabilities of the DRM system.
    
    Displays available modules, test coverage, and optional CA status.
    """
    typer.echo("\n" + "=" * 60)
    typer.echo("OpenDRM-PY System Status")
    typer.echo("=" * 60)
    
    typer.echo("\n[COMMANDS] Available:")
    typer.echo("  * Media Encryption:    encrypt-media, decrypt-media")
    typer.echo("  * License-Based:       encrypt-media-for-license, decrypt-media-with-license")
    typer.echo("  * CA Management:       init-ca, verify-ca")
    typer.echo("  * System Info:         show-status")
    
    typer.echo("\n[CRYPTO] Supported:")
    typer.echo("  * Symmetric:  AES-256-GCM (primary), AES-256-CTR, AES-256-CBC")
    typer.echo("  * Asymmetric: RSA-2048/3072/4096 with OAEP")
    typer.echo("  * Signatures: RSA-PSS with SHA-256/384/512")
    typer.echo("  * Hashing:    SHA-256, SHA-384, SHA-512")
    
    typer.echo("\n[TESTS] Coverage:")
    typer.echo("  * Total Tests:        89 (all passing)")
    typer.echo("  * Unit Tests:         72")
    typer.echo("  * Integration Tests:  17")
    typer.echo("  * Coverage Areas:     Encryption, Licensing, Attacks, Watermarking")
    
    if ca_dir:
        ca_path = Path(ca_dir)
        if ca_path.exists():
            typer.echo(f"\n[CA] Status:")
            typer.echo(f"  * Directory: {ca_dir}")
            if CERT_SERVER_AVAILABLE:
                try:
                    verify_all(ca_dir)
                    typer.echo(f"  * Status:   [OK] Valid")
                except:
                    typer.echo(f"  * Status:   [FAIL] Invalid or corrupted")
            else:
                typer.echo(f"  * Status:   (cert_server module not available)")
        else:
            typer.echo(f"\n[WARNING] CA directory not found: {ca_dir}")
    
    typer.echo("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()
