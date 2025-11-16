"""
Tests covering the full lifecycle of a certificate server directory
(initialization → verification → export → re-import → verification).

Each test ensures that the high-level user workflow behaves correctly.
"""

import tempfile
from pathlib import Path

from cert_server.initialize_server import initialize_cert_server
from cert_server.verify_server import verify_all
from cert_server.export_server import export_cert_server
from cert_server.import_server import import_cert_server


def test_full_certificate_server_lifecycle():
    """Test the entire certificate server lifecycle end-to-end.

    This test simulates the real-world lifecycle:

    1. Create a fresh directory.
    2. Initialize the CA / intermediate / keystore structure.
    3. Verify that the created structure is valid.
    4. Export the server state into a ZIP bundle.
    5. Re-import that bundle into another directory.
    6. Verify the imported structure again.

    Ensures that export/import operations preserve correctness and layout.

    Raises:
        AssertionError: If any constructed directory or file doesn't exist.
        ValueError: If verify_all detects structural problems.
    """

    with tempfile.TemporaryDirectory() as tmp:  # Create temporary workspace
        base = Path(tmp)

        # --- Step 1: Initialize original CA directory ---
        original = base / "original"
        original.mkdir()
        initialize_cert_server(str(original))

        # --- Step 2: Verify structure after initialization ---
        verify_all(str(original))   # Raises ValueError if structure is invalid

        # --- Step 3: Export to ZIP bundle ---
        bundle = base / "bundle.zip"
        export_cert_server(str(original), str(bundle))

        assert bundle.exists()  # Ensure export worked

        # --- Step 4: Import ZIP into new directory ---
        imported = base / "imported"
        out = import_cert_server(str(bundle), str(imported))

        # --- Step 5: Verify imported directory ---
        verify_all(str(out))
