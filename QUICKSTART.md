# IoT-Scan Quick Reference

## Installation

```bash
# Quick setup
./setup.sh

# Or manual
pip install -r requirements.txt
pip install -e .
```

## Basic Commands

```bash
# Auto-detect and scan local network
sudo python -m src.cli --auto

# Scan specific subnet
sudo python -m src.cli --subnet 192.168.1.0/24

# Fast scan (fewer ports)
sudo python -m src.cli --subnet 192.168.1.0/24 --fast

# Full scan with verbose output
sudo python -m src.cli --subnet 192.168.1.0/24 --full --verbose

# Export to JSON
sudo python -m src.cli --subnet 192.168.1.0/24 --json results.json
```

## Scan Modes

| Mode | Ports Scanned | Speed | Use Case |
|------|---------------|-------|----------|
| Fast | 7 common ports | ⚡⚡⚡ | Quick security check |
| Default | 18 IoT ports | ⚡⚡ | Balanced scan |
| Full | All IoT ports | ⚡ | Comprehensive audit |

## Ports Scanned

### Fast Mode
- 23 (Telnet)
- 80 (HTTP)
- 443 (HTTPS)
- 554 (RTSP)
- 1883 (MQTT)
- 8080 (HTTP-Proxy)
- 8266 (ESP8266)

### Full Mode (Additional)
- 21 (FTP)
- 22 (SSH)
- 5000 (UPnP)
- 5683 (CoAP)
- 8000, 8008, 8081, 8083, 9000 (HTTP-Alt)
- 8443 (HTTPS-Alt)
- 8883 (MQTTS)

## Vulnerability Severity Levels

| Severity | Description | Examples |
|----------|-------------|----------|
| 🔴 CRITICAL | Immediate security risk | Unauth OTA, open MQTT |
| 🟠 HIGH | Significant risk | Exposed config, RTSP streams |
| 🟡 MEDIUM | Moderate risk | Version disclosure, status pages |
| 🔵 LOW | Minor information leak | Non-sensitive endpoints |

## Common Vulnerabilities Detected

### HTTP/HTTPS
- ✅ Unauthenticated `/config` endpoint
- ✅ Unauthenticated `/admin` panel
- ✅ Exposed `/api` endpoints
- ✅ Firmware version disclosure
- ✅ Sensitive data in responses
- ✅ Default credentials indicators

### MQTT
- ✅ Anonymous broker access (port 1883)
- ✅ Unencrypted MQTT connections
- ✅ No authentication required

### OTA/Firmware
- ✅ Open `/update` endpoint
- ✅ Accessible `/firmware` upload
- ✅ Unauthenticated OTA updates

### Cameras/RTSP
- ✅ Open RTSP streams (port 554)
- ✅ Unauthenticated camera access
- ✅ Exposed video feeds

## Supported Devices

### Microcontrollers
- ESP32, ESP8266
- Arduino
- NodeMCU

### Single Board Computers
- Raspberry Pi
- Similar SBCs

### Smart Home
- Smart Plugs (TP-Link, Sonoff)
- Smart Lights (Philips Hue, etc.)
- Tuya devices
- Xiaomi Mi Home

### Cameras
- IP Cameras (Hikvision, Dahua, Axis)
- NVR/DVR systems
- Ring devices
- Generic RTSP cameras

### Voice Assistants
- Amazon Echo/Alexa
- Google Home

### IoT Platforms
- Home Assistant
- Tasmota
- ESPHome
- Node-RED

## Output Format

### Console Output
- Device discovery table
- Port scan results
- Vulnerability report with severity
- Summary statistics

### JSON Output
```json
{
  "scan_date": "2025-12-03T10:30:15",
  "total_devices": 5,
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "30:AE:A4:XX:XX:XX",
      "vendor": "Espressif Inc.",
      "device_type": "ESP32",
      "open_ports": [80, 1883],
      "vulnerabilities": [...]
    }
  ]
}
```

## Troubleshooting

### "Permission denied" error
```bash
# ARP scanning requires root
sudo python -m src.cli --subnet 192.168.1.0/24
```

### "No devices found"
- Check you're on the correct network
- Verify subnet is correct
- Some devices may not respond to ARP
- Try increasing timeout in code

### Slow scanning
- Use `--fast` mode
- Reduce timeout in scanner modules
- Scan smaller subnets

### Import errors
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Or install in development mode
pip install -e .
```

## Programmatic Usage

```python
from src.scanner.arp_scan import ARPScanner
from src.scanner.port_scan import PortScanner
from src.scanner.http_check import HTTPSecurityChecker

# Discover devices
scanner = ARPScanner()
devices = scanner.scan("192.168.1.0/24")

# Scan ports
port_scanner = PortScanner()
open_ports = port_scanner.scan("192.168.1.100", fast_mode=True)

# Check vulnerabilities
http_checker = HTTPSecurityChecker()
vulns = http_checker.check_device("192.168.1.100", open_ports)
```

## Examples

```bash
# Example 1: Quick home network scan
sudo python -m src.cli --auto --fast --json home_scan.json

# Example 2: Scan single device (no sudo needed)
python examples/basic_usage.py 192.168.1.100

# Example 3: Comprehensive network audit
sudo python -m src.cli --subnet 192.168.1.0/24 --full --verbose --json audit.json

# Example 4: Run tests
pytest tests/ -v
```

## Best Practices

### Security
- ✅ Only scan authorized networks
- ✅ Get permission before scanning
- ✅ Use findings to improve security
- ❌ Don't exploit vulnerabilities
- ❌ Don't perform DoS attacks

### Scanning
- ✅ Start with fast scan
- ✅ Use full scan for audits
- ✅ Export results for reporting
- ✅ Document findings
- ✅ Verify manually

### Development
- ✅ Use virtual environment
- ✅ Follow PEP 8 style
- ✅ Add tests for new features
- ✅ Update documentation
- ✅ Check with `pylint`/`flake8`

## Configuration

### Adjust Timeouts
Edit scanner modules:
```python
# src/scanner/port_scan.py
def __init__(self, timeout: float = 1.0):  # Increase for slow networks

# src/scanner/http_check.py
def __init__(self, timeout: int = 3):  # Increase for slow devices
```

### Add Custom Ports
```python
# src/scanner/port_scan.py
COMMON_IOT_PORTS = [
    # Add your custom ports
    9090,
    7080,
]
```

### Add MAC Vendors
Edit `mac-vendors.json`:
```json
{
  "vendors": {
    "XX:XX:XX": {
      "name": "Your Vendor",
      "type": "iot",
      "common_devices": ["Device Model"]
    }
  }
}
```

## Getting Help

```bash
# Show help
python -m src.cli --help

# Show version
python -m src.cli --version

# Enable debug output
python -m src.cli --subnet 192.168.1.0/24 --verbose
```

## Resources

- GitHub: https://github.com/sudoyasir/iot-scan
- Issues: https://github.com/suddoyasir/iot-scan/issues
- Documentation: README.md
- Contributing: CONTRIBUTING.md

## License

MIT License - See LICENSE file for details

---

**Remember**: Use responsibly and ethically! 🔒
