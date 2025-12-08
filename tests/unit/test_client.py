"""Tests for client emulator and licensing."""

import pytest
from datetime import datetime, timedelta, UTC
from drm.client.client_emulator import (
    ClientDevice, License, ClientEmulator, ClientSimulation
)


class TestClientDevice:
    """Test client device representation."""
    
    def test_device_creation(self):
        """Test creating a client device."""
        device = ClientDevice(device_id="device-1", device_name="Test Device")
        
        assert device.device_id == "device-1"
        assert device.device_name == "Test Device"
        assert device.certificate_path is None
        assert device.private_key_path is None
    
    def test_device_not_registered_without_certs(self):
        """Test that unregistered device has no certs."""
        device = ClientDevice(device_id="device-1", device_name="Device")
        assert device.is_registered() == False
    
    def test_device_registration_requires_both_files(self):
        """Test device registration requires cert and key."""
        device = ClientDevice(device_id="device-1", device_name="Device")
        device.certificate_path = "/nonexistent/cert.pem"
        device.private_key_path = "/nonexistent/key.pem"
        
        assert device.is_registered() == False


class TestLicense:
    """Test license management."""
    
    def test_license_creation(self):
        """Test creating a license."""
        lic = License(
            license_id="lic-1",
            device_id="dev-1",
            content_id="content-1",
            issued_at=datetime.now(UTC)
        )
        
        assert lic.license_id == "lic-1"
        assert lic.device_id == "dev-1"
        assert lic.usage_count == 0
        assert lic.is_valid() == True
    
    def test_license_expiration(self):
        """Test license expiration checking."""
        now = datetime.now(UTC)
        
        # Create expired license
        expired_lic = License(
            license_id="lic-1",
            device_id="dev-1",
            content_id="content-1",
            issued_at=now,
            expires_at=now - timedelta(days=1)
        )
        assert expired_lic.is_valid() == False
        
        # Create valid license
        valid_lic = License(
            license_id="lic-2",
            device_id="dev-1",
            content_id="content-1",
            issued_at=now,
            expires_at=now + timedelta(days=30)
        )
        assert valid_lic.is_valid() == True
    
    def test_license_usage_limit(self):
        """Test license usage limits."""
        lic = License(
            license_id="lic-1",
            device_id="dev-1",
            content_id="content-1",
            issued_at=datetime.now(UTC),
            max_usages=3
        )
        
        # Check validity before reaching limit
        assert lic.is_valid() == True
        
        # Use all plays
        lic.usage_count = 3
        assert lic.is_valid() == False
    
    def test_license_playback_check(self):
        """Test license can_playback method."""
        lic = License(
            license_id="lic-1",
            device_id="dev-1",
            content_id="content-1",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=1),
            max_usages=5
        )
        
        valid, msg = lic.can_playback()
        assert valid == True
        assert msg == "License valid"
        
        # Expire license
        lic.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        valid, msg = lic.can_playback()
        assert valid == False
        assert "expired" in msg.lower()


class TestClientEmulator:
    """Test client emulator functionality."""
    
    def test_client_creation(self):
        """Test creating a client emulator."""
        device = ClientDevice(device_id="dev-1", device_name="Device")
        client = ClientEmulator(device)
        
        assert client.device == device
        assert len(client.licenses) == 0
        assert len(client.playback_history) == 0
    
    def test_license_request(self):
        """Test requesting a license."""
        device = ClientDevice(device_id="dev-1", device_name="Device")
        client = ClientEmulator(device)
        
        # Request should fail without registration
        lic = client.request_license("content-1")
        assert lic is None
    
    def test_license_request_after_registration(self, tmp_path):
        """Test license request after device registration."""
        # Create dummy cert and key files
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(b"fake cert")
        key_file.write_bytes(b"fake key")
        
        device = ClientDevice(device_id="dev-1", device_name="Device")
        client = ClientEmulator(device)
        
        # Register device
        assert client.register_device(str(cert_file), str(key_file)) == True
        
        # Request license
        lic = client.request_license("content-1", duration_days=30, max_plays=5)
        assert lic is not None
        assert lic.device_id == "dev-1"
        assert lic.content_id == "content-1"
        assert lic.max_usages == 5
    
    def test_license_validation(self, tmp_path):
        """Test license validation."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(b"fake cert")
        key_file.write_bytes(b"fake key")
        
        device = ClientDevice(device_id="dev-1", device_name="Device")
        client = ClientEmulator(device)
        client.register_device(str(cert_file), str(key_file))
        
        lic = client.request_license("content-1")
        
        # Validate license
        valid, msg = client.validate_license(lic.license_id)
        assert valid == True
        
        # Validate nonexistent license
        valid, msg = client.validate_license("nonexistent")
        assert valid == False
        assert "not found" in msg.lower()
    
    def test_license_revocation(self, tmp_path):
        """Test revoking a license."""
        from datetime import datetime, timedelta
        
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(b"fake cert")
        key_file.write_bytes(b"fake key")
        
        device = ClientDevice(device_id="dev-1", device_name="Device")
        client = ClientEmulator(device)
        client.register_device(str(cert_file), str(key_file))
        
        lic = client.request_license("content-1")
        assert lic.is_valid() == True
        
        # Revoke license (sets expires_at to now)
        assert client.revoke_license(lic.license_id) == True
        # expires_at is set to now, which may still be > now() due to timing
        # So explicitly check it's been revoked by checking validity fails
        import time
        time.sleep(0.01)  # Ensure revocation time is in the past
        assert lic.is_valid() == False
    
    def test_playback_report(self, tmp_path):
        """Test generating playback report."""
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(b"fake cert")
        key_file.write_bytes(b"fake key")
        
        device = ClientDevice(device_id="dev-1", device_name="Device")
        client = ClientEmulator(device)
        client.register_device(str(cert_file), str(key_file))
        
        # Request multiple licenses
        lic1 = client.request_license("content-1")
        lic2 = client.request_license("content-2")
        
        # Update usage
        lic1.usage_count = 3
        lic2.usage_count = 1
        
        report = client.get_playback_report()
        assert report["device_id"] == "dev-1"
        assert report["total_licenses"] == 2
        assert report["total_playbacks"] == 4


class TestClientSimulation:
    """Test client simulation framework."""
    
    def test_simulation_creation(self):
        """Test creating a simulation."""
        sim = ClientSimulation()
        assert len(sim.clients) == 0
        assert len(sim.results) == 0
    
    def test_add_multiple_clients(self):
        """Test adding multiple clients to simulation."""
        sim = ClientSimulation()
        
        client1 = sim.add_client("dev-1", "Device 1")
        client2 = sim.add_client("dev-2", "Device 2")
        
        assert len(sim.clients) == 2
        assert "dev-1" in sim.clients
        assert "dev-2" in sim.clients
        assert client1.device.device_name == "Device 1"
        assert client2.device.device_name == "Device 2"
    
    def test_simulation_workflow(self):
        """Test running a workflow simulation."""
        sim = ClientSimulation()
        
        def test_workflow(simulation):
            client1 = simulation.clients["dev-1"]
            return {
                "clients_count": len(simulation.clients),
                "test_passed": True
            }
        
        # Add client
        sim.add_client("dev-1", "Device 1")
        
        # Run workflow
        result = sim.simulate_workflow("test_workflow", test_workflow)
        assert result["success"] == True
        assert result["workflow"] == "test_workflow"
        assert result["clients_count"] == 1
