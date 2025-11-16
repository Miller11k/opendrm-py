"""
Tests validating that initialize_cert_server() creates the expected
directory hierarchy and files for the certificate authority.
"""

import tempfile
from pathlib import Path

from cert_server.initialize_server import initialize_cert_server
from cert_server.verify_server import verify_all


def test_initialize_creates_required_structure():
    """Test that initialize_cert_server creates the correct CA layout.

    Expected behavior:
        - Required directories (private key store, intermediates, keystores)
          should be created automatically.
        - verify_all() should succeed immediately after initialization.

    Raises:
        AssertionError: If any required folder is missing.
        ValueError: If verify_all detects structural integrity issues.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "ca"
        root.mkdir()

        initialize_cert_server(str(root))   # Run initialization

        # --- Check required directories exist ---
        assert (root / "ca/private").is_dir()
        assert (root / "intermediates/issuing-ca-1/certs").is_dir()
        assert (root / "keystores").is_dir()

        # Ensure the freshly created layout validates correctly
        verify_all(str(root))
