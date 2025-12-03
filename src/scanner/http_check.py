"""HTTP security checks for IoT devices."""
import logging
from typing import List, Dict
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("iot-scan")


class HTTPSecurityChecker:
    """HTTP endpoint security checker."""
    
    # Common vulnerable endpoints
    VULNERABLE_ENDPOINTS = [
        "/status",
        "/config",
        "/api",
        "/api/config",
        "/setup",
        "/admin",
        "/system",
        "/device",
        "/info",
        "/debug",
        "/console",
        "/cgi-bin/",
        "/management",
        "/api/system",
        "/api/v1/system",
    ]
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        "password",
        "passwd",
        "api_key",
        "apikey",
        "token",
        "secret",
        "ssid",
        "wifi",
        "firmware",
        "version",
        "serial",
        "mac_address",
        "ip_address",
    ]
    
    def __init__(self, timeout: int = 3):
        """Initialize HTTP security checker.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
    
    def check_device(self, ip: str, open_ports: List[Dict]) -> List[Dict]:
        """Check device for HTTP security vulnerabilities.
        
        Args:
            ip: Device IP address
            open_ports: List of open ports
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Find HTTP ports
        http_ports = [p['port'] for p in open_ports if p['port'] in [80, 443, 8080, 8081, 8000, 8008, 8083, 9000]]
        
        for port in http_ports:
            protocol = "https" if port == 443 or port == 8443 else "http"
            base_url = f"{protocol}://{ip}:{port}"
            
            # Check for vulnerable endpoints
            endpoint_vulns = self._check_endpoints(base_url)
            vulnerabilities.extend(endpoint_vulns)
            
            # Check root for sensitive information
            root_vulns = self._check_root_page(base_url)
            vulnerabilities.extend(root_vulns)
        
        return vulnerabilities
    
    def _check_endpoints(self, base_url: str) -> List[Dict]:
        """Check for vulnerable endpoints.
        
        Args:
            base_url: Base URL of device
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        for endpoint in self.VULNERABLE_ENDPOINTS:
            try:
                url = f"{base_url}{endpoint}"
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                # Check if endpoint is accessible (not 404, 403, 401)
                if response.status_code in [200, 301, 302]:
                    # Check for authentication
                    auth_header = response.headers.get('WWW-Authenticate', '')
                    
                    if not auth_header and response.status_code == 200:
                        # No authentication required
                        severity = self._assess_endpoint_severity(endpoint, response.text)
                        
                        # Check for sensitive data
                        sensitive_data = self._find_sensitive_data(response.text)
                        
                        vuln = {
                            'severity': severity,
                            'description': f"Unauthenticated access to {endpoint}",
                            'details': {
                                'url': url,
                                'status_code': response.status_code,
                                'sensitive_data': sensitive_data
                            }
                        }
                        
                        if sensitive_data:
                            vuln['description'] += f" - Exposes: {', '.join(sensitive_data[:3])}"
                            vuln['severity'] = 'HIGH' if severity != 'CRITICAL' else 'CRITICAL'
                        
                        vulnerabilities.append(vuln)
                        logger.debug(f"Found vulnerable endpoint: {url}")
                
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                logger.debug(f"Error checking endpoint {endpoint}: {str(e)}")
                continue
        
        return vulnerabilities
    
    def _check_root_page(self, base_url: str) -> List[Dict]:
        """Check root page for security issues.
        
        Args:
            base_url: Base URL of device
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            response = requests.get(
                base_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                # Check for default credentials notice
                content_lower = response.text.lower()
                
                if 'admin' in content_lower and 'password' in content_lower:
                    vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'description': 'Possible default credentials in use (admin/password found in page)',
                        'details': {'url': base_url}
                    })
                
                # Check for firmware version disclosure
                if 'firmware' in content_lower or 'version' in content_lower:
                    version_info = self._extract_version_info(response.text)
                    if version_info:
                        vulnerabilities.append({
                            'severity': 'LOW',
                            'description': f'Firmware version disclosed: {version_info}',
                            'details': {'url': base_url, 'version': version_info}
                        })
                
                # Check for directory listing
                if '<title>Index of /' in response.text or 'Directory Listing' in response.text:
                    vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'description': 'Directory listing enabled',
                        'details': {'url': base_url}
                    })
        
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logger.debug(f"Error checking root page: {str(e)}")
        
        return vulnerabilities
    
    def _assess_endpoint_severity(self, endpoint: str, content: str) -> str:
        """Assess severity of exposed endpoint.
        
        Args:
            endpoint: Endpoint path
            content: Response content
            
        Returns:
            Severity level
        """
        high_risk_endpoints = ['/config', '/admin', '/system', '/debug', '/console']
        medium_risk_endpoints = ['/status', '/info', '/api']
        
        if any(e in endpoint for e in high_risk_endpoints):
            return 'HIGH'
        elif any(e in endpoint for e in medium_risk_endpoints):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _find_sensitive_data(self, content: str) -> List[str]:
        """Find sensitive data patterns in content.
        
        Args:
            content: Response content
            
        Returns:
            List of sensitive data types found
        """
        content_lower = content.lower()
        found = []
        
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern in content_lower:
                found.append(pattern)
        
        return found
    
    @staticmethod
    def _extract_version_info(content: str) -> str:
        """Extract version information from content.
        
        Args:
            content: Response content
            
        Returns:
            Version string or empty string
        """
        import re
        
        # Look for version patterns
        patterns = [
            r'version[:\s]+([0-9]+\.[0-9]+\.[0-9]+)',
            r'firmware[:\s]+([0-9]+\.[0-9]+\.[0-9]+)',
            r'v([0-9]+\.[0-9]+\.[0-9]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
