"""
Tests for import_cert_server(), ensuring correct ZIP handling and
proper reconstruction of server directories.
"""

import tempfile
from pathlib import Path
import pytest

from cert_server.initialize_server import initialize_cert_server
from cert_server.export_server import export_cert_server
from cert_server.import_server import import_cert_server


def test_import_round_trip():
    """Test a valid export→import round-trip operation.

    Steps:
        1. Initialize a certificate server directory.
        2. Export it to a ZIP file.
        3. Import that ZIP into a new destination.
        4. Assert that the destination exists and contains required files.

    Ensures:
        - import_cert_server correctly extracts the bundle.
        - The CA certificate exists in the expected path.
    """
    with tempfile.TemporaryDirectory() as tmp:  # Run all tests in temporary directory
        root = Path(tmp) / "origin"
        root.mkdir()

        initialize_cert_server(str(root))   # Build and initialize CA structure

        
        zip_path = Path(tmp) / "bundle.zip" # Export to a bundle.zip
        export_cert_server(str(root), str(zip_path))

        dest = Path(tmp) / "imported"

        out = import_cert_server(str(zip_path), str(dest))  # Import the exported ZIP

         # --- Verification of results ---
        assert out.exists() # Make sure zip ezists
        assert (out / "ca" / "certs" / "ca.crt").is_file()  # Make sure ca.crt exists


def test_import_rejects_non_zip():
    """Ensure import_cert_server rejects invalid ZIP input.

    Creates a file that ends with '.zip' but is not a ZIP archive,
    then verifies that import_cert_server raises ValueError.

    Raises:
        ValueError: Expected when passing a non-ZIP file.
    """
    with tempfile.TemporaryDirectory() as tmp:  # Run all tests in temp directory
        bad = Path(tmp) / "garbage.zip" # Save garbage zip (not correct structure)
        bad.write_bytes(b"This is not a zip archive")

        dest = Path(tmp) / "dest"

        # Function should detect invalid ZIP and raise ValueError
        with pytest.raises(ValueError):
            import_cert_server(str(bad), str(dest))
