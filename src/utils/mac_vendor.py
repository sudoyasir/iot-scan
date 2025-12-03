"""MAC vendor lookup utility."""
import json
import os
from typing import Dict, Optional, Tuple
from pathlib import Path


class MACVendorLookup:
    """MAC address vendor lookup."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize MAC vendor lookup.
        
        Args:
            db_path: Path to MAC vendors JSON database
        """
        if db_path is None:
            # Default to mac-vendors.json in project root
            current_dir = Path(__file__).parent.parent.parent
            db_path = current_dir / "mac-vendors.json"
        
        self.db_path = db_path
        self.vendors: Dict = {}
        self._load_database()
    
    def _load_database(self) -> None:
        """Load MAC vendors database from JSON file."""
        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.vendors = data.get('vendors', {})
        except FileNotFoundError:
            self.vendors = {}
        except json.JSONDecodeError:
            self.vendors = {}
    
    def lookup(self, mac: str) -> Tuple[Optional[str], Optional[str], Optional[list]]:
        """Lookup vendor information by MAC address.
        
        Args:
            mac: MAC address (format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
            
        Returns:
            Tuple of (vendor_name, device_type, common_devices)
        """
        # Normalize MAC address format
        mac = mac.upper().replace('-', ':')
        
        # Extract OUI (first 3 octets)
        oui = ':'.join(mac.split(':')[:3])
        
        vendor_info = self.vendors.get(oui)
        
        if vendor_info:
            return (
                vendor_info.get('name'),
                vendor_info.get('type'),
                vendor_info.get('common_devices', [])
            )
        
        return None, None, None
    
    def is_iot_device(self, mac: str) -> bool:
        """Check if MAC address belongs to a known IoT device.
        
        Args:
            mac: MAC address
            
        Returns:
            True if device is identified as IoT device
        """
        _, device_type, _ = self.lookup(mac)
        return device_type in ['iot', 'camera']
    
    def get_vendor_name(self, mac: str) -> str:
        """Get vendor name for MAC address.
        
        Args:
            mac: MAC address
            
        Returns:
            Vendor name or 'Unknown'
        """
        vendor, _, _ = self.lookup(mac)
        return vendor or "Unknown"
