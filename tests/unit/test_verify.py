"""
Tests for verify_all(), particularly its error detection behavior
when the certificate server directory is malformed.
"""

import tempfile
from pathlib import Path
import pytest

from cert_server.initialize_server import initialize_cert_server
from cert_server.verify_server import verify_all


def test_verify_detects_missing_files():
    """Test that verify_all fails when required files are removed.

    Steps:
        1. Initialize a valid certificate server directory.
        2. Remove the root CA certificate (ca.crt).
        3. verify_all() should detect the missing file and raise ValueError.

    Ensures:
        - Structural corruption is consistently detected.
        - verify_all provides strong guarantees about integrity.

    Raises:
        ValueError: Expected due to missing CA certificate.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "ca"
        root.mkdir()
        initialize_cert_server(str(root))   # Build the server structure

        # --- Break the structure intentionally ---
        (root / "ca" / "certs" / "ca.crt").unlink() # Delete the CA certificate

        with pytest.raises(ValueError): # verify_all should now fail
            verify_all(str(root))
