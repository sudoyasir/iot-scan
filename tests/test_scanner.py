"""
Unit tests for IoT-Scan modules.

Run tests with: pytest tests/
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.utils.mac_vendor import MACVendorLookup
from src.scanner.port_scan import PortScanner
from src.scanner.fingerprint import DeviceFingerprint


class TestMACVendorLookup:
    """Tests for MAC vendor lookup."""
    
    def test_lookup_espressif(self):
        """Test Espressif MAC lookup."""
        lookup = MACVendorLookup()
        vendor, device_type, devices = lookup.lookup("30:AE:A4:12:34:56")
        
        assert vendor == "Espressif Inc."
        assert device_type == "iot"
        assert "ESP32" in devices or "ESP8266" in devices
    
    def test_lookup_unknown(self):
        """Test unknown MAC lookup."""
        lookup = MACVendorLookup()
        vendor, device_type, devices = lookup.lookup("FF:FF:FF:FF:FF:FF")
        
        assert vendor is None
        assert device_type is None
        assert devices is None
    
    def test_is_iot_device(self):
        """Test IoT device identification."""
        lookup = MACVendorLookup()
        
        # Known IoT device
        assert lookup.is_iot_device("30:AE:A4:12:34:56") is True
        
        # Unknown device
        assert lookup.is_iot_device("FF:FF:FF:FF:FF:FF") is False
    
    def test_get_vendor_name(self):
        """Test vendor name retrieval."""
        lookup = MACVendorLookup()
        
        vendor = lookup.get_vendor_name("30:AE:A4:12:34:56")
        assert vendor == "Espressif Inc."
        
        vendor = lookup.get_vendor_name("FF:FF:FF:FF:FF:FF")
        assert vendor == "Unknown"
    
    def test_mac_normalization(self):
        """Test MAC address format normalization."""
        lookup = MACVendorLookup()
        
        # Test with different formats
        vendor1, _, _ = lookup.lookup("30:ae:a4:12:34:56")
        vendor2, _, _ = lookup.lookup("30-AE-A4-12-34-56")
        vendor3, _, _ = lookup.lookup("30:AE:A4:12:34:56")
        
        assert vendor1 == vendor2 == vendor3


class TestPortScanner:
    """Tests for port scanner."""
    
    def test_get_service_name(self):
        """Test service name mapping."""
        assert PortScanner._get_service_name(80) == "http"
        assert PortScanner._get_service_name(443) == "https"
        assert PortScanner._get_service_name(1883) == "mqtt"
        assert PortScanner._get_service_name(23) == "telnet"
        assert PortScanner._get_service_name(99999) == "unknown"
    
    def test_has_iot_ports(self):
        """Test IoT port detection."""
        # Mock open ports
        open_ports = [
            {'port': 80, 'service': 'http'},
            {'port': 1883, 'service': 'mqtt'}
        ]
        
        assert PortScanner.has_iot_ports(open_ports) is True
        
        # Non-IoT ports
        open_ports = [
            {'port': 80, 'service': 'http'},
            {'port': 443, 'service': 'https'}
        ]
        
        assert PortScanner.has_iot_ports(open_ports) is False
    
    def test_fast_mode_ports(self):
        """Test fast mode port list."""
        assert len(PortScanner.FAST_SCAN_PORTS) < len(PortScanner.COMMON_IOT_PORTS)
        assert 80 in PortScanner.FAST_SCAN_PORTS
        assert 1883 in PortScanner.FAST_SCAN_PORTS


class TestDeviceFingerprint:
    """Tests for device fingerprinting."""
    
    def test_identify_esp32_device(self):
        """Test ESP32 device identification."""
        fingerprinter = DeviceFingerprint()
        
        open_ports = [
            {'port': 80, 'service': 'http'},
            {'port': 1883, 'service': 'mqtt'}
        ]
        
        result = fingerprinter.identify_device(
            ip="192.168.1.100",
            mac="30:AE:A4:12:34:56",
            vendor="Espressif Inc.",
            open_ports=open_ports
        )
        
        assert 'device_type' in result
        assert result['confidence'] in ['low', 'medium', 'high']
    
    def test_identify_camera(self):
        """Test camera identification."""
        fingerprinter = DeviceFingerprint()
        
        open_ports = [
            {'port': 80, 'service': 'http'},
            {'port': 554, 'service': 'rtsp'}
        ]
        
        result = fingerprinter.identify_device(
            ip="192.168.1.120",
            mac="68:3E:34:12:34:56",
            vendor="Hikvision",
            open_ports=open_ports
        )
        
        assert 'camera' in result['device_type'].lower() or 'nvr' in result['device_type'].lower()
    
    def test_mqtt_device_detection(self):
        """Test MQTT device detection."""
        fingerprinter = DeviceFingerprint()
        
        open_ports = [
            {'port': 1883, 'service': 'mqtt'}
        ]
        
        result = fingerprinter.identify_device(
            ip="192.168.1.100",
            mac="30:AE:A4:12:34:56",
            vendor=None,
            open_ports=open_ports
        )
        
        characteristics = ' '.join(result.get('characteristics', []))
        assert 'mqtt' in characteristics.lower()


class TestARPScanner:
    """Tests for ARP scanner."""
    
    @patch('src.scanner.arp_scan.socket.socket')
    def test_get_local_ip(self, mock_socket):
        """Test local IP retrieval."""
        from src.scanner.arp_scan import ARPScanner
        
        # Mock socket
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ('192.168.1.10', 80)
        mock_socket.return_value = mock_sock
        
        ip = ARPScanner.get_local_ip()
        assert ip == '192.168.1.10'
    
    def test_guess_subnet(self):
        """Test subnet guessing."""
        from src.scanner.arp_scan import ARPScanner
        
        subnet = ARPScanner.guess_subnet('192.168.1.100')
        assert subnet == '192.168.1.0/24'
        
        subnet = ARPScanner.guess_subnet('10.0.0.50')
        assert subnet == '10.0.0.0/24'


class TestHTTPSecurityChecker:
    """Tests for HTTP security checker."""
    
    def test_assess_endpoint_severity(self):
        """Test endpoint severity assessment."""
        from src.scanner.http_check import HTTPSecurityChecker
        
        checker = HTTPSecurityChecker()
        
        assert checker._assess_endpoint_severity('/config', '') == 'HIGH'
        assert checker._assess_endpoint_severity('/admin', '') == 'HIGH'
        assert checker._assess_endpoint_severity('/status', '') == 'MEDIUM'
        assert checker._assess_endpoint_severity('/api', '') == 'MEDIUM'
    
    def test_find_sensitive_data(self):
        """Test sensitive data detection."""
        from src.scanner.http_check import HTTPSecurityChecker
        
        checker = HTTPSecurityChecker()
        
        content = "password: admin123, api_key: secret_key, ssid: MyWiFi"
        found = checker._find_sensitive_data(content)
        
        assert 'password' in found
        assert 'api_key' in found
        assert 'ssid' in found
    
    def test_extract_version_info(self):
        """Test version extraction."""
        from src.scanner.http_check import HTTPSecurityChecker
        
        content = "Firmware Version: 2.1.3"
        version = HTTPSecurityChecker._extract_version_info(content)
        
        assert version == "2.1.3"


class TestOTASecurityChecker:
    """Tests for OTA security checker."""
    
    @patch('src.scanner.ota_check.socket.socket')
    def test_rtsp_connection(self, mock_socket):
        """Test RTSP connection testing."""
        from src.scanner.ota_check import OTASecurityChecker
        
        # Mock successful connection
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"RTSP/1.0 200 OK"
        mock_socket.return_value = mock_sock
        
        result = OTASecurityChecker._test_rtsp_connection('192.168.1.120')
        assert result is True


# Pytest fixtures
@pytest.fixture
def sample_device():
    """Sample device data for testing."""
    return {
        'ip': '192.168.1.100',
        'mac': '30:AE:A4:12:34:56',
        'vendor': 'Espressif Inc.',
        'open_ports': [80, 1883],
        'device_type': 'ESP32 IoT Device'
    }


@pytest.fixture
def sample_vulnerabilities():
    """Sample vulnerabilities for testing."""
    return [
        {
            'severity': 'CRITICAL',
            'description': 'Unauthenticated MQTT access',
            'details': {'port': 1883}
        },
        {
            'severity': 'HIGH',
            'description': 'Exposed /config endpoint',
            'details': {'url': 'http://192.168.1.100/config'}
        }
    ]


def test_sample_device_fixture(sample_device):
    """Test sample device fixture."""
    assert sample_device['ip'] == '192.168.1.100'
    assert len(sample_device['open_ports']) == 2


def test_sample_vulnerabilities_fixture(sample_vulnerabilities):
    """Test sample vulnerabilities fixture."""
    assert len(sample_vulnerabilities) == 2
    assert sample_vulnerabilities[0]['severity'] == 'CRITICAL'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
