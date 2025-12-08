"""Integration tests for DRM attack scenarios."""

import pytest
from pathlib import Path
from drm.client.attack_scenarios import (
    ReplayAttack, TamperingAttack, IdentitySpoofingAttack,
    RevocationBypassAttack, simulate_attack_scenario
)


class TestReplayAttack:
    """Test replay attack scenarios."""
    
    def test_replay_attack_creation(self):
        """Test creating a replay attack."""
        attack = ReplayAttack()
        assert attack.name == "Replay Attack"
        assert "reuse" in attack.description.lower()
        assert attack.success == False
    
    def test_replay_attack_with_nonexistent_license(self):
        """Test replay attack with missing license file."""
        attack = ReplayAttack()
        result = attack.execute(
            "/nonexistent/license.cert",
            "/nonexistent/media.enc",
            lambda *args: None
        )
        assert result == False
        assert "not found" in attack.details.get("error", "").lower()
    
    def test_replay_attack_simulation(self):
        """Test replay attack with mock decryption function."""
        attack = ReplayAttack()
        
        # Create temporary test files
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as lic_f:
            lic_f.write(b"fake license cert")
            lic_path = lic_f.name
        
        with tempfile.NamedTemporaryFile(delete=False) as media_f:
            media_f.write(b"encrypted media")
            media_path = media_f.name
        
        try:
            # Mock decryption function that always succeeds
            def mock_decrypt(media, license_path):
                return b"decrypted content"
            
            result = attack.execute(lic_path, media_path, mock_decrypt, num_attempts=3)
            assert result == True
            assert attack.details["successful_attempts"] == 3
            assert attack.details["total_attempts"] == 3
        finally:
            Path(lic_path).unlink()
            Path(media_path).unlink()
    
    def test_replay_attack_partial_success(self):
        """Test replay attack with partial success."""
        attack = ReplayAttack()
        
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as lic_f:
            lic_f.write(b"fake license")
            lic_path = lic_f.name
        
        with tempfile.NamedTemporaryFile(delete=False) as media_f:
            media_f.write(b"media")
            media_path = media_f.name
        
        try:
            # Decryption fails on 2nd attempt
            attempt_counter = {'count': 0}
            def mock_decrypt(media, license_path):
                attempt_counter['count'] += 1
                # Fail on 2nd and 3rd attempts
                if attempt_counter['count'] >= 2:
                    raise Exception("License revoked")
                return b"content"
            
            result = attack.execute(lic_path, media_path, mock_decrypt, num_attempts=3)
            assert result == False
            assert attack.details["successful_attempts"] == 1
        finally:
            Path(lic_path).unlink()
            Path(media_path).unlink()


class TestTamperingAttack:
    """Test tampering attack scenarios."""
    
    def test_tampering_attack_creation(self):
        """Test creating a tampering attack."""
        attack = TamperingAttack()
        assert attack.name == "Tampering Attack"
        assert "modify" in attack.description.lower()
    
    def test_tampering_attack_with_nonexistent_file(self):
        """Test tampering attack with nonexistent file."""
        attack = TamperingAttack()
        result = attack.execute("/nonexistent/file.enc", lambda f: None)
        assert result == False
        assert "not found" in attack.details.get("error", "").lower()
    
    def test_tampering_attack_execution(self):
        """Test executing tampering attack."""
        attack = TamperingAttack()
        
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"encrypted content")
            filepath = f.name
        
        try:
            # Modification function that flips bits
            def modify_file(path):
                content = bytearray(Path(path).read_bytes())
                content[0] ^= 0xFF
                Path(path).write_bytes(bytes(content))
            
            result = attack.execute(filepath, modify_file)
            assert result == True
            assert attack.details["tampering_attempted"] == True
            
            # File should be restored to original
            assert Path(filepath).read_bytes() == b"encrypted content"
        finally:
            Path(filepath).unlink(missing_ok=True)


class TestIdentitySpoofingAttack:
    """Test identity spoofing scenarios."""
    
    def test_spoofing_attack_creation(self):
        """Test creating identity spoofing attack."""
        attack = IdentitySpoofingAttack()
        assert attack.name == "Identity Spoofing Attack"
        assert "spoof" in attack.description.lower()
    
    def test_spoofing_attack_detection(self):
        """Test that spoofing is detected."""
        attack = IdentitySpoofingAttack()
        
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"license for device-1")
            lic_path = f.name
        
        try:
            # Verification function that checks device ID
            def verify_license(lic_path, device_id):
                content = Path(lic_path).read_bytes().decode()
                return device_id in content
            
            # This will fail because "device-2" is not in the license
            result = attack.execute(lic_path, "device-2", verify_license)
            assert result == True  # True means attack was detected
            assert attack.details["verification_passed"] == False
        finally:
            Path(lic_path).unlink()


class TestRevocationBypassAttack:
    """Test revocation bypass scenarios."""
    
    def test_revocation_bypass_creation(self):
        """Test creating revocation bypass attack."""
        attack = RevocationBypassAttack()
        assert attack.name == "Revocation Bypass Attack"
        assert "revoked" in attack.description.lower()
    
    def test_revocation_bypass_proper_enforcement(self):
        """Test that revocation is properly enforced."""
        attack = RevocationBypassAttack()
        
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cert") as f:
            f.write(b"revoked license cert")
            lic_path = f.name
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"encrypted media")
            media_path = f.name
        
        try:
            revocation_list = [Path(lic_path).name]
            
            # Decryption function that fails for revoked licenses
            def decrypt_with_revocation_check(media, lic):
                if Path(lic).name in revocation_list:
                    raise Exception("Certificate revoked")
                return b"content"
            
            result = attack.execute(
                lic_path, media_path, decrypt_with_revocation_check,
                revocation_list
            )
            assert result == True  # True = revocation properly enforced
            assert attack.details.get("revocation_properly_enforced") == True
        finally:
            Path(lic_path).unlink()
            Path(media_path).unlink()
    
    def test_revocation_bypass_failure(self):
        """Test detection of revocation bypass vulnerability."""
        attack = RevocationBypassAttack()
        
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".cert") as f:
            f.write(b"revoked license")
            lic_path = f.name
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"media")
            media_path = f.name
        
        try:
            revocation_list = [Path(lic_path).name]
            
            # Vulnerable decryption that ignores revocation
            def vulnerable_decrypt(media, lic):
                return b"content"  # Always succeeds!
            
            result = attack.execute(
                lic_path, media_path, vulnerable_decrypt,
                revocation_list
            )
            assert result == False  # False = vulnerability found
            assert attack.details.get("revocation_bypassed") == True
        finally:
            Path(lic_path).unlink()
            Path(media_path).unlink()


class TestAttackSimulationFramework:
    """Test the attack simulation framework."""
    
    def test_simulate_attack_scenario(self):
        """Test the attack scenario simulation function."""
        attack = ReplayAttack()
        attack.success = True
        attack.details = {"attempts": 3}
        
        result = simulate_attack_scenario(attack)
        
        assert result["scenario"] == "Replay Attack"
        assert "reuse" in result["description"].lower()
        assert result["success"] == True
        assert result["details"]["attempts"] == 3
    
    def test_multiple_attack_scenarios(self):
        """Test running multiple attack scenarios."""
        attacks = [
            ReplayAttack(),
            TamperingAttack(),
            IdentitySpoofingAttack(),
            RevocationBypassAttack()
        ]
        
        results = [simulate_attack_scenario(attack) for attack in attacks]
        
        assert len(results) == 4
        assert all(isinstance(r, dict) for r in results)
        assert all("scenario" in r for r in results)
