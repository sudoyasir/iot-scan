"""MQTT security checker."""
import logging
from typing import List, Dict, Optional
import paho.mqtt.client as mqtt
import socket

logger = logging.getLogger("iot-scan")


class MQTTSecurityChecker:
    """MQTT broker security checker."""
    
    def __init__(self, timeout: int = 5):
        """Initialize MQTT security checker.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    def check_device(self, ip: str, open_ports: List[Dict]) -> List[Dict]:
        """Check device for MQTT security vulnerabilities.
        
        Args:
            ip: Device IP address
            open_ports: List of open ports
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Check for MQTT ports
        mqtt_ports = [p['port'] for p in open_ports if p['port'] in [1883, 8883]]
        
        for port in mqtt_ports:
            # Check for anonymous access
            if self._check_anonymous_access(ip, port):
                severity = 'CRITICAL' if port == 1883 else 'HIGH'
                
                vuln = {
                    'severity': severity,
                    'description': f'MQTT broker allows anonymous access on port {port}',
                    'details': {
                        'port': port,
                        'protocol': 'MQTT' if port == 1883 else 'MQTTS',
                        'authentication': 'None'
                    }
                }
                
                if port == 1883:
                    vuln['description'] += ' (unencrypted)'
                
                vulnerabilities.append(vuln)
                logger.debug(f"MQTT anonymous access detected on {ip}:{port}")
        
        return vulnerabilities
    
    def _check_anonymous_access(self, ip: str, port: int) -> bool:
        """Check if MQTT broker allows anonymous access.
        
        Args:
            ip: Broker IP address
            port: MQTT port
            
        Returns:
            True if anonymous access is allowed
        """
        client = mqtt.Client(client_id="iot-scan-test")
        connected = False
        
        def on_connect(client, userdata, flags, rc):
            nonlocal connected
            if rc == 0:
                connected = True
        
        try:
            client.on_connect = on_connect
            client.connect(ip, port, keepalive=self.timeout)
            client.loop_start()
            
            # Wait for connection
            import time
            time.sleep(self.timeout)
            
            client.loop_stop()
            client.disconnect()
            
            return connected
            
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return False
        except Exception as e:
            logger.debug(f"MQTT connection error on {ip}:{port}: {str(e)}")
            return False
    
    def list_topics(self, ip: str, port: int = 1883, timeout: int = 5) -> List[str]:
        """List MQTT topics (if anonymous access is available).
        
        Args:
            ip: Broker IP address
            port: MQTT port
            timeout: Timeout in seconds
            
        Returns:
            List of discovered topics
        """
        topics = []
        client = mqtt.Client(client_id="iot-scan-enum")
        
        def on_message(client, userdata, message):
            topic = message.topic
            if topic not in topics:
                topics.append(topic)
        
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                # Subscribe to wildcard
                client.subscribe("#")
        
        try:
            client.on_connect = on_connect
            client.on_message = on_message
            client.connect(ip, port, keepalive=timeout)
            client.loop_start()
            
            import time
            time.sleep(timeout)
            
            client.loop_stop()
            client.disconnect()
            
        except Exception as e:
            logger.debug(f"Error listing MQTT topics: {str(e)}")
        
        return topics
