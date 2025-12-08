"""
Client emulator for DRM system testing and simulation.

This module provides a realistic client implementation that can:
- Request licenses from the license server
- Decrypt protected content using valid licenses
- Verify license authenticity and validity
- Simulate playback and enforce access control policies
- Test attack scenarios against the DRM system
"""

from typing import Dict, Tuple, Optional, Any
from pathlib import Path
from dataclasses import dataclass
import json
from datetime import datetime, timedelta, UTC


@dataclass
class ClientDevice:
    """Represents a DRM-protected client device."""
    
    device_id: str
    device_name: str
    certificate_path: Optional[str] = None
    private_key_path: Optional[str] = None
    
    def is_registered(self) -> bool:
        """Check if device has valid certificate and key."""
        if not self.certificate_path or not self.private_key_path:
            return False
        return Path(self.certificate_path).exists() and Path(self.private_key_path).exists()


@dataclass
class License:
    """Represents a media license issued to a device."""
    
    license_id: str
    device_id: str
    content_id: str
    issued_at: datetime
    expires_at: Optional[datetime] = None
    usage_count: int = 0
    max_usages: Optional[int] = None
    device_restricted: bool = True
    certificate_path: Optional[str] = None
    
    def is_valid(self) -> bool:
        """Check if license is currently valid."""
        now = datetime.now(UTC)
        if self.expires_at and now > self.expires_at:
            return False
        if self.max_usages and self.usage_count >= self.max_usages:
            return False
        return True
    
    def can_playback(self) -> Tuple[bool, str]:
        """Check if playback is allowed.
        
        Returns:
            Tuple of (allowed, reason)
        """
        if not self.is_valid():
            if self.expires_at and datetime.now(UTC) > self.expires_at:
                return False, "License expired"
            if self.max_usages and self.usage_count >= self.max_usages:
                return False, f"Usage limit reached ({self.usage_count}/{self.max_usages})"
            return False, "License invalid"
        return True, "License valid"


class ClientEmulator:
    """Emulates a DRM-protected client device for testing."""
    
    def __init__(self, device: ClientDevice):
        """Initialize client emulator.
        
        Args:
            device: ClientDevice configuration
        """
        self.device = device
        self.licenses: Dict[str, License] = {}
        self.playback_history: list = []
        self.decryption_keys: Dict[str, bytes] = {}
    
    def register_device(self, cert_path: str, key_path: str) -> bool:
        """Register device with DRM system using certificate.
        
        Args:
            cert_path: Path to device certificate
            key_path: Path to device private key
        
        Returns:
            True if registration successful
        """
        if not Path(cert_path).exists() or not Path(key_path).exists():
            return False
        
        self.device.certificate_path = cert_path
        self.device.private_key_path = key_path
        return True
    
    def request_license(self, content_id: str, duration_days: int = 30,
                       max_plays: Optional[int] = None) -> Optional[License]:
        """Request a license for protected content.
        
        Args:
            content_id: Identifier of protected content
            duration_days: Number of days license is valid for
            max_plays: Maximum number of plays allowed (None = unlimited)
        
        Returns:
            License object if successful, None if request denied
        """
        if not self.device.is_registered():
            return None
        
        license_id = f"{self.device.device_id}_{content_id}_{datetime.now(UTC).timestamp()}"
        license_obj = License(
            license_id=license_id,
            device_id=self.device.device_id,
            content_id=content_id,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=duration_days),
            max_usages=max_plays,
            device_restricted=True,
            certificate_path=self.device.certificate_path
        )
        
        self.licenses[license_id] = license_obj
        return license_obj
    
    def validate_license(self, license_id: str) -> Tuple[bool, str]:
        """Validate a license for playback.
        
        Args:
            license_id: ID of license to validate
        
        Returns:
            Tuple of (valid, reason)
        """
        if license_id not in self.licenses:
            return False, "License not found"
        
        license_obj = self.licenses[license_id]
        valid, reason = license_obj.can_playback()
        return valid, reason
    
    def playback_content(self, license_id: str, content_path: str,
                        decryption_fn: Optional[callable] = None) -> Tuple[bool, str]:
        """Attempt to play protected content using a license.
        
        Args:
            license_id: ID of license to use for playback
            content_path: Path to encrypted content file
            decryption_fn: Optional decryption function
        
        Returns:
            Tuple of (success, message)
        """
        if not Path(content_path).exists():
            return False, "Content file not found"
        
        valid, reason = self.validate_license(license_id)
        if not valid:
            return False, f"License invalid: {reason}"
        
        license_obj = self.licenses[license_id]
        
        # Simulate decryption if function provided
        if decryption_fn:
            try:
                decryption_fn(content_path, license_obj.certificate_path)
            except Exception as e:
                return False, f"Decryption failed: {str(e)}"
        
        # Update usage
        license_obj.usage_count += 1
        
        # Record playback
        playback_record = {
            "license_id": license_id,
            "content_id": license_obj.content_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "device_id": self.device.device_id,
            "success": True
        }
        self.playback_history.append(playback_record)
        
        return True, "Playback successful"
    
    def revoke_license(self, license_id: str) -> bool:
        """Revoke a license (simulate DRM system revocation).
        
        Args:
            license_id: ID of license to revoke
        
        Returns:
            True if revocation successful
        """
        if license_id not in self.licenses:
            return False
        
        # Mark license as expired
        self.licenses[license_id].expires_at = datetime.now(UTC)
        return True
    
    def get_playback_report(self) -> Dict[str, Any]:
        """Get summary of client playback activity.
        
        Returns:
            Dictionary with playback statistics
        """
        total_plays = sum(lic.usage_count for lic in self.licenses.values())
        active_licenses = sum(1 for lic in self.licenses.values() if lic.is_valid())
        
        return {
            "device_id": self.device.device_id,
            "device_name": self.device.device_name,
            "total_licenses": len(self.licenses),
            "active_licenses": active_licenses,
            "total_playbacks": total_plays,
            "playback_history": self.playback_history
        }


class ClientSimulation:
    """Simulation framework for testing multiple DRM clients."""
    
    def __init__(self):
        """Initialize client simulation."""
        self.clients: Dict[str, ClientEmulator] = {}
        self.results = []
    
    def add_client(self, device_id: str, device_name: str) -> ClientEmulator:
        """Add a new client device to simulation.
        
        Args:
            device_id: Unique device identifier
            device_name: Human-readable device name
        
        Returns:
            ClientEmulator instance for the device
        """
        device = ClientDevice(device_id=device_id, device_name=device_name)
        client = ClientEmulator(device)
        self.clients[device_id] = client
        return client
    
    def simulate_workflow(self, workflow_name: str, 
                         workflow_fn: callable) -> Dict[str, Any]:
        """Run a client workflow simulation.
        
        Args:
            workflow_name: Name of the workflow being tested
            workflow_fn: Function that runs the workflow
        
        Returns:
            Dictionary with simulation results
        """
        try:
            result = workflow_fn(self)
            result["workflow"] = workflow_name
            result["success"] = True
            self.results.append(result)
            return result
        except Exception as e:
            error_result = {
                "workflow": workflow_name,
                "success": False,
                "error": str(e)
            }
            self.results.append(error_result)
            return error_result
