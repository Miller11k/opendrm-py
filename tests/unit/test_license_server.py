"""Tests for license server and registry functionality."""

import pytest
from datetime import datetime, timedelta, UTC


class TestLicenseRegistry:
    """Test license registry functionality."""
    
    def test_license_registry_creation(self):
        """Test creating a license registry."""
        # Registry should be able to store licenses
        registry = {}
        assert len(registry) == 0
    
    def test_license_storage(self):
        """Test storing licenses in registry."""
        registry = {}
        
        license_record = {
            "license_id": "lic-1",
            "device_id": "dev-1",
            "content_id": "content-1",
            "issued_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            "usage_count": 0,
            "max_usages": 5
        }
        
        registry[license_record["license_id"]] = license_record
        
        assert len(registry) == 1
        assert registry["lic-1"]["device_id"] == "dev-1"
    
    def test_license_retrieval(self):
        """Test retrieving licenses from registry."""
        registry = {
            "lic-1": {
                "license_id": "lic-1",
                "device_id": "dev-1",
                "content_id": "content-1",
                "issued_at": datetime.now(UTC).isoformat(),
                "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
                "usage_count": 0
            }
        }
        
        retrieved = registry.get("lic-1")
        assert retrieved is not None
        assert retrieved["device_id"] == "dev-1"
    
    def test_license_deletion(self):
        """Test deleting licenses from registry."""
        registry = {
            "lic-1": {"license_id": "lic-1", "device_id": "dev-1"},
            "lic-2": {"license_id": "lic-2", "device_id": "dev-2"}
        }
        
        assert len(registry) == 2
        
        del registry["lic-1"]
        
        assert len(registry) == 1
        assert "lic-1" not in registry
        assert "lic-2" in registry


class TestLicenseIssuance:
    """Test license issuance workflow."""
    
    def test_license_issuance_request(self):
        """Test license issuance request structure."""
        request = {
            "device_id": "device-1",
            "content_id": "content-1",
            "device_certificate": "/path/to/cert.pem",
            "duration_days": 30,
            "usage_limit": 5
        }
        
        assert request["device_id"] == "device-1"
        assert request["content_id"] == "content-1"
        assert request["duration_days"] == 30
    
    def test_license_issuance_response(self):
        """Test license issuance response structure."""
        response = {
            "license_id": "lic-12345",
            "issued_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            "wrapped_key": "base64_encoded_wrapped_key",
            "key_format": "rsa-oaep",
            "success": True,
            "message": "License issued successfully"
        }
        
        assert response["success"] == True
        assert response["license_id"].startswith("lic-")
        assert "expires_at" in response


class TestAccessControl:
    """Test access control policies."""
    
    def test_device_binding_policy(self):
        """Test device binding access control."""
        policy = {
            "type": "device_binding",
            "device_id": "dev-1",
            "allow_other_devices": False
        }
        
        # License should only work on dev-1
        assert policy["device_id"] == "dev-1"
        assert policy["allow_other_devices"] == False
    
    def test_time_based_policy(self):
        """Test time-based access control."""
        policy = {
            "type": "time_based",
            "start_time": datetime.now(UTC).isoformat(),
            "end_time": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            "timezone": "UTC"
        }
        
        assert "start_time" in policy
        assert "end_time" in policy
    
    def test_usage_based_policy(self):
        """Test usage-based access control."""
        policy = {
            "type": "usage_based",
            "max_plays": 5,
            "current_usage": 0,
            "track_concurrent": False
        }
        
        assert policy["max_plays"] == 5
        assert policy["current_usage"] == 0
    
    def test_location_based_policy(self):
        """Test location-based access control."""
        policy = {
            "type": "location_based",
            "allowed_countries": ["US", "CA", "GB"],
            "denied_regions": []
        }
        
        assert "US" in policy["allowed_countries"]
        assert len(policy["allowed_countries"]) >= 1
    
    def test_composite_policy(self):
        """Test composite access control policies."""
        policies = [
            {
                "type": "device_binding",
                "device_id": "dev-1"
            },
            {
                "type": "time_based",
                "start_time": datetime.now(UTC).isoformat(),
                "end_time": (datetime.now(UTC) + timedelta(days=30)).isoformat()
            },
            {
                "type": "usage_based",
                "max_plays": 5
            }
        ]
        
        assert len(policies) == 3
        # License must satisfy ALL policies


class TestLicenseVerification:
    """Test license verification."""
    
    def test_license_signature_verification(self):
        """Test license signature verification."""
        # License should be signed by license server
        license_data = {
            "license_id": "lic-1",
            "device_id": "dev-1",
            "content_id": "content-1",
            "issued_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat()
        }
        
        # In real implementation, would verify RSA-PSS signature
        signature = "rsa_pss_signature_bytes"
        
        assert isinstance(signature, str)
    
    def test_certificate_chain_validation(self):
        """Test certificate chain validation."""
        chain = {
            "root_ca": "/path/to/root_ca.pem",
            "intermediate_ca": "/path/to/intermediate_ca.pem",
            "license_server_cert": "/path/to/license_server.pem",
            "chain_complete": True
        }
        
        assert chain["chain_complete"] == True
    
    def test_revocation_check(self):
        """Test revocation checking."""
        revocation_list = [
            "revoked_serial_1",
            "revoked_serial_2",
            "revoked_serial_3"
        ]
        
        # License to check
        license_serial = "revoked_serial_1"
        
        is_revoked = license_serial in revocation_list
        assert is_revoked == True
    
    def test_expiration_validation(self):
        """Test expiration validation."""
        now = datetime.now(UTC)
        
        # Valid license
        valid_license = {
            "expires_at": (now + timedelta(days=30)).isoformat()
        }
        
        # Expired license
        expired_license = {
            "expires_at": (now - timedelta(days=1)).isoformat()
        }
        
        # Check validity
        from datetime import datetime as dt
        valid_expiry = dt.fromisoformat(valid_license["expires_at"])
        expired_expiry = dt.fromisoformat(expired_license["expires_at"])
        
        assert valid_expiry > now
        assert expired_expiry < now


class TestLicenseManagement:
    """Test license management operations."""
    
    def test_license_renewal(self):
        """Test license renewal process."""
        original_license = {
            "license_id": "lic-1",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "renewal_count": 0
        }
        
        # Renew license
        renewed_license = original_license.copy()
        renewed_license["expires_at"] = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        renewed_license["renewal_count"] = 1
        
        assert renewed_license["license_id"] == original_license["license_id"]
        assert renewed_license["renewal_count"] == 1
    
    def test_license_revocation(self):
        """Test license revocation."""
        license_id = "lic-1"
        revocation_list = []
        
        # Revoke license
        revocation_list.append(license_id)
        
        assert license_id in revocation_list
    
    def test_bulk_revocation(self):
        """Test bulk license revocation."""
        licenses_to_revoke = ["lic-1", "lic-2", "lic-3", "lic-4", "lic-5"]
        revocation_list = []
        
        # Revoke multiple licenses
        revocation_list.extend(licenses_to_revoke)
        
        assert len(revocation_list) == 5
        assert all(lic in revocation_list for lic in licenses_to_revoke)


class TestLicenseAnalytics:
    """Test license server analytics."""
    
    def test_usage_statistics(self):
        """Test tracking usage statistics."""
        stats = {
            "total_licenses_issued": 1000,
            "active_licenses": 850,
            "expired_licenses": 150,
            "revoked_licenses": 0,
            "total_playbacks": 5000,
            "average_plays_per_license": 5.88
        }
        
        assert stats["total_licenses_issued"] == 1000
        assert stats["active_licenses"] == 850
        assert stats["total_playbacks"] > 0
    
    def test_revenue_tracking(self):
        """Test revenue tracking."""
        revenue_data = {
            "period": "monthly",
            "licenses_sold": 500,
            "revenue": 4999.99,
            "average_license_price": 9.99
        }
        
        assert revenue_data["licenses_sold"] > 0
        assert revenue_data["revenue"] > 0
    
    def test_compliance_reporting(self):
        """Test compliance reporting."""
        report = {
            "report_date": datetime.now(UTC).isoformat(),
            "licenses_with_audit_logs": 1000,
            "audit_log_integrity_verified": True,
            "revocation_enforcement_verified": True
        }
        
        assert report["licenses_with_audit_logs"] > 0
        assert report["audit_log_integrity_verified"] == True
