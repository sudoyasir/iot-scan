"""OTA (Over-The-Air) update security checker."""
import logging
from typing import List, Dict
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("iot-scan")


class OTASecurityChecker:
    """OTA update endpoint security checker."""
    
    # Common OTA update endpoints
    OTA_ENDPOINTS = [
        "/update",
        "/ota",
        "/firmware",
        "/upgrade",
        "/flash",
        "/upload",
        "/api/update",
        "/api/ota",
        "/api/firmware",
        "/admin/update",
        "/admin/firmware",
        "/system/update",
        "/system/firmware",
    ]
    
    # RTSP camera endpoints
    RTSP_PATHS = [
        "/",
        "/live",
        "/stream",
        "/video",
        "/cam",
        "/channel1",
        "/h264",
        "/Streaming/Channels/1",
    ]
    
    def __init__(self, timeout: int = 3):
        """Initialize OTA security checker.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
    
    def check_device(self, ip: str, open_ports: List[Dict]) -> List[Dict]:
        """Check device for OTA and camera vulnerabilities.
        
        Args:
            ip: Device IP address
            open_ports: List of open ports
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Check HTTP OTA endpoints
        http_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080, 8081]]
        
        for port in http_ports:
            protocol = "https" if port == 443 else "http"
            base_url = f"{protocol}://{ip}:{port}"
            
            ota_vulns = self._check_ota_endpoints(base_url)
            vulnerabilities.extend(ota_vulns)
        
        # Check RTSP camera streams
        if 554 in [p['port'] for p in open_ports]:
            rtsp_vulns = self._check_rtsp(ip)
            vulnerabilities.extend(rtsp_vulns)
        
        return vulnerabilities
    
    def _check_ota_endpoints(self, base_url: str) -> List[Dict]:
        """Check for vulnerable OTA update endpoints.
        
        Args:
            base_url: Base URL of device
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        for endpoint in self.OTA_ENDPOINTS:
            try:
                url = f"{base_url}{endpoint}"
                
                # Try GET request
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                # Check if endpoint exists
                if response.status_code in [200, 405]:  # 405 = Method Not Allowed (but exists)
                    # Check authentication
                    auth_header = response.headers.get('WWW-Authenticate', '')
                    
                    if not auth_header:
                        # Try POST to see if upload is possible
                        vuln = {
                            'severity': 'CRITICAL',
                            'description': f'Unauthenticated OTA update endpoint: {endpoint}',
                            'details': {
                                'url': url,
                                'status_code': response.status_code,
                                'risk': 'Device firmware can potentially be modified'
                            }
                        }
                        vulnerabilities.append(vuln)
                        logger.debug(f"Found vulnerable OTA endpoint: {url}")
                
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                logger.debug(f"Error checking OTA endpoint {endpoint}: {str(e)}")
                continue
        
        return vulnerabilities
    
    def _check_rtsp(self, ip: str) -> List[Dict]:
        """Check for open RTSP streams.
        
        Args:
            ip: Device IP address
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        # Check if RTSP is accessible
        for path in self.RTSP_PATHS:
            rtsp_url = f"rtsp://{ip}:554{path}"
            
            if self._test_rtsp_connection(ip, 554):
                vuln = {
                    'severity': 'HIGH',
                    'description': 'Open RTSP stream detected (possible unauthenticated camera access)',
                    'details': {
                        'rtsp_url': rtsp_url,
                        'port': 554,
                        'risk': 'Video stream may be accessible without authentication'
                    }
                }
                vulnerabilities.append(vuln)
                logger.debug(f"RTSP stream detected: {rtsp_url}")
                break  # Only report once per device
        
        return vulnerabilities
    
    @staticmethod
    def _test_rtsp_connection(ip: str, port: int = 554) -> bool:
        """Test RTSP connection.
        
        Args:
            ip: Device IP address
            port: RTSP port
            
        Returns:
            True if RTSP is accessible
        """
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Port is open, try RTSP DESCRIBE
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                
                # Send RTSP DESCRIBE request
                request = f"DESCRIBE rtsp://{ip}:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sock.send(request.encode())
                
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                # Check if we got RTSP response
                if 'RTSP' in response:
                    return True
            
            return False
            
        except socket.error:
            return False
        except Exception:
            return False
