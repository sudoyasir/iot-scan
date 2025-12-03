# IoT-Scan 🔍🔒

**A powerful CLI tool to discover and scan IoT devices for security vulnerabilities**

IoT-Scan is a professional-grade security scanner that helps identify and assess security weaknesses in IoT devices on your local network. It performs network discovery, port scanning, device fingerprinting, and comprehensive vulnerability assessment.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🌟 Features

### Network Discovery
- **ARP Scanning**: Fast device discovery using ARP requests
- **MAC Vendor Lookup**: Identify device manufacturers from MAC addresses
- **Auto-detection**: Automatically detect your local subnet

### Port Scanning
- **Asynchronous Scanning**: Fast, non-blocking port scans
- **IoT-Focused Ports**: Targets common IoT services (HTTP, MQTT, RTSP, Telnet, etc.)
- **Service Detection**: Identifies services running on open ports
- **Banner Grabbing**: Extracts service banners for fingerprinting

### Device Fingerprinting
- **IoT Device Identification**: Detects ESP32, ESP8266, Raspberry Pi, Arduino, and more
- **HTTP Header Analysis**: Identifies devices through HTTP responses
- **Smart Classification**: Categorizes devices (cameras, smart plugs, sensors, etc.)
- **Confidence Scoring**: Provides reliability metrics for identifications

### Security Vulnerability Checks

#### HTTP Security
- ✅ Unauthenticated endpoints (`/config`, `/status`, `/api`, etc.)
- ✅ Sensitive data exposure (passwords, API keys, tokens)
- ✅ Firmware version disclosure
- ✅ Default credentials detection
- ✅ Directory listing vulnerabilities

#### MQTT Security
- ✅ Anonymous broker access
- ✅ Unencrypted MQTT connections
- ✅ Topic enumeration

#### OTA/Firmware Security
- ✅ Unauthenticated OTA update endpoints
- ✅ Firmware upload vulnerabilities
- ✅ Insecure update mechanisms

#### Camera/RTSP Security
- ✅ Open RTSP streams
- ✅ Unauthenticated camera access
- ✅ Video feed exposure

### Reporting
- **Beautiful CLI Output**: Rich, colored terminal output with tables
- **Severity Ratings**: CRITICAL, HIGH, MEDIUM, LOW classifications
- **JSON Export**: Machine-readable output for automation
- **Detailed Reports**: Comprehensive vulnerability information

---

## 📋 Requirements

- Python 3.10 or higher
- Root/Administrator privileges (required for ARP scanning)
- Linux/macOS operating system (recommended)

---

## 🚀 Installation

### Method 1: Using pip (Recommended)

```bash
# Clone the repository
git clone https://github.com/sudoyasir/iot-scan.git
cd iot-scan

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Method 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/sudoyasir/iot-scan.git
cd iot-scan

# Install dependencies
pip install scapy requests paho-mqtt rich aiofiles
```

---

## 💻 Usage

### Basic Scan

```bash
# Scan a specific subnet (requires sudo)
sudo iot-scan --subnet 192.168.1.0/24
```

### Auto-detect Subnet

```bash
# Automatically detect and scan your local network
sudo iot-scan --auto
```

### Fast Scan Mode

```bash
# Quick scan with fewer ports (faster but less thorough)
sudo iot-scan --subnet 192.168.1.0/24 --fast
```

### Full Scan Mode

```bash
# Comprehensive scan of all IoT-related ports
sudo iot-scan --subnet 192.168.1.0/24 --full
```

### Export Results to JSON

```bash
# Save scan results to a JSON file
sudo iot-scan --subnet 192.168.1.0/24 --json results.json
```

### Verbose Output

```bash
# Enable debug logging for troubleshooting
sudo iot-scan --subnet 192.168.1.0/24 --verbose
```

---

## 📊 Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  ╦╔═╗╔╦╗   ╔═╗╔═╗╔═╗╔╗╔                                     ║
║  ║║ ║ ║ ═══╚═╗║  ╠═╣║║║                                     ║
║  ╩╚═╝ ╩    ╚═╝╚═╝╩ ╩╝╚╝                                     ║
║  IoT Device Security Scanner v1.0.0                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

╭─────────── Scan Configuration ────────────╮
│                                           │
│ Target Subnet: 192.168.1.0/24            │
│ Scan Type: FULL                           │
│ Start Time: 2025-12-03 10:30:15          │
│                                           │
╰───────────────────────────────────────────╯

→ Discovering devices via ARP scan...
✓ Found 12 devices

→ [1/12] Scanning 192.168.1.100...
→ [2/12] Scanning 192.168.1.105...
...

                         Discovered Devices
┌─────────────────┬───────────────────┬─────────────────────┬──────────────┬────────────┐
│ IP Address      │ MAC Address       │ Vendor              │ Device Type  │ Open Ports │
├─────────────────┼───────────────────┼─────────────────────┼──────────────┼────────────┤
│ 192.168.1.100   │ 30:AE:A4:XX:XX:XX │ Espressif Inc.      │ ESP32        │ 80, 1883   │
│ 192.168.1.105   │ B8:27:EB:XX:XX:XX │ Raspberry Pi        │ SBC          │ 22, 80     │
│ 192.168.1.120   │ 68:3E:34:XX:XX:XX │ Hikvision           │ IP Camera    │ 80, 554    │
└─────────────────┴───────────────────┴─────────────────────┴──────────────┴────────────┘

╔═══════════════════════════════════════════════════════════════╗
║                    Vulnerability Report                       ║
╚═══════════════════════════════════════════════════════════════╝

Device: 192.168.1.100 (Espressif Inc.)
MAC: 30:AE:A4:XX:XX:XX

 Severity    Vulnerability
────────────────────────────────────────────────────────────────
 CRITICAL    MQTT broker allows anonymous access on port 1883 (unencrypted)
 HIGH        Unauthenticated access to /config - Exposes: password, ssid, api_key
 MEDIUM      Firmware version disclosed: 2.1.3

Device: 192.168.1.120 (Hikvision)
MAC: 68:3E:34:XX:XX:XX

 Severity    Vulnerability
────────────────────────────────────────────────────────────────
 HIGH        Open RTSP stream detected (possible unauthenticated camera access)
 MEDIUM      Unauthenticated access to /status

╭─────────── Summary ───────────╮
│                               │
│ CRITICAL: 1  HIGH: 2          │
│ MEDIUM: 2  LOW: 0             │
│ Total Vulnerabilities: 5      │
│                               │
╰───────────────────────────────╯

✓ Report exported to: results.json
```

---

## 🗂️ Project Structure

```
iot-scan/
├── src/
│   ├── __init__.py
│   ├── cli.py                    # Main CLI interface
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── arp_scan.py          # ARP network scanner
│   │   ├── port_scan.py         # Asynchronous port scanner
│   │   ├── fingerprint.py       # Device fingerprinting
│   │   ├── http_check.py        # HTTP security checks
│   │   ├── mqtt_check.py        # MQTT security checks
│   │   └── ota_check.py         # OTA/RTSP security checks
│   └── utils/
│       ├── __init__.py
│       ├── logger.py            # Logging utility
│       ├── mac_vendor.py        # MAC vendor lookup
│       └── report.py            # Report generation
├── mac-vendors.json             # MAC vendor database
├── requirements.txt             # Python dependencies
├── setup.py                     # Package setup
└── README.md                    # Documentation
```

---

## 🔍 Detected Vulnerabilities

### Critical Severity
- Unauthenticated OTA/firmware update endpoints
- Anonymous MQTT broker access (unencrypted)

### High Severity
- Exposed configuration endpoints with sensitive data
- Open RTSP streams without authentication
- Anonymous MQTT access over TLS

### Medium Severity
- Unauthenticated status/info endpoints
- Firmware version disclosure
- Default credentials indicators
- Directory listing enabled

### Low Severity
- Non-sensitive endpoint exposure
- Verbose error messages

---

## 🎯 Supported IoT Devices

IoT-Scan can identify and assess security for:

### Microcontrollers & Boards
- ESP32 / ESP8266
- Arduino
- Raspberry Pi
- NodeMCU

### Smart Home Devices
- Smart Plugs (TP-Link, Sonoff, etc.)
- Smart Lights (Philips Hue, etc.)
- Smart Switches
- Tuya-based devices
- Xiaomi Mi Smart Home

### Cameras & Security
- IP Cameras (Hikvision, Dahua, Axis)
- NVR/DVR systems
- Ring Doorbells
- RTSP-enabled cameras

### Voice Assistants & Hubs
- Amazon Echo/Alexa
- Google Home
- Smart Home Hubs

### IoT Platforms
- Home Assistant
- Node-RED
- Tasmota
- ESPHome

---

## 🛠️ Advanced Usage

### Custom Port Range

Modify `COMMON_IOT_PORTS` in `src/scanner/port_scan.py`:

```python
COMMON_IOT_PORTS = [
    # Add your custom ports here
    9090,
    7080,
]
```

### Adding Custom Vulnerabilities

Extend the security checkers in `src/scanner/`:
- `http_check.py` - Add HTTP endpoints
- `mqtt_check.py` - Add MQTT checks
- `ota_check.py` - Add OTA patterns

### Extending MAC Vendor Database

Edit `mac-vendors.json`:

```json
{
  "vendors": {
    "XX:XX:XX": {
      "name": "Your Device Vendor",
      "type": "iot",
      "common_devices": ["Device Model"]
    }
  }
}
```

---

## ⚠️ Important Notes

### Root Privileges
ARP scanning requires root/administrator privileges. Always run with `sudo`:

```bash
sudo iot-scan --subnet 192.168.1.0/24
```

### Network Permissions
Ensure you have permission to scan the target network. Unauthorized network scanning may be illegal.

### Rate Limiting
The tool includes reasonable timeouts to avoid overwhelming devices. Adjust timeouts in scanner modules if needed.

### False Positives
Some vulnerabilities may be false positives. Always verify findings manually before taking action.

---

## 🧪 Testing

### Unit Tests (Coming Soon)

```bash
# Run unit tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=src tests/
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit your changes**: `git commit -m 'Add amazing feature'`
4. **Push to the branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup

```bash
# Clone the repository
git clone https://github.com/sudoyasir/iot-scan.git
cd iot-scan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .
```

### Code Style
- Follow PEP 8 guidelines
- Add docstrings to all functions
- Include type hints where appropriate
- Write descriptive commit messages

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔒 Security & Ethical Use

### Responsible Disclosure
If you discover security vulnerabilities in IoT-Scan itself, please report them responsibly to the maintainers.

### Ethical Guidelines
- Only scan networks you own or have explicit permission to test
- Respect privacy and data protection laws
- Use findings to improve security, not exploit weaknesses
- Do not perform denial-of-service attacks
- Follow coordinated vulnerability disclosure practices

---

## 📚 Resources

- [IoT Security Foundation](https://www.iotsecurityfoundation.org/)
- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)
- [NIST IoT Security Guidelines](https://www.nist.gov/topics/internet-things-iot)

---

## 🐛 Known Issues

- ARP scanning may not work in virtualized environments without proper network configuration
- Some devices may respond slowly to port scans (adjust timeout if needed)
- RTSP checks are basic and may miss authenticated streams

---

## 🗺️ Roadmap

- [ ] Add support for BLE (Bluetooth Low Energy) scanning
- [ ] Implement credential brute-forcing (optional, disabled by default)
- [ ] Add database persistence for historical scans
- [ ] Create web-based dashboard
- [ ] Add support for custom vulnerability plugins
- [ ] Implement automatic remediation suggestions
- [ ] Add integration with vulnerability databases (CVE)

---

## 👥 Author

[Yasir N.](https://sudoyasir.space)
Initial work and core development

---

## 🙏 Acknowledgments

- Scapy team for the excellent packet manipulation library
- Rich library for beautiful terminal output
- Eclipse Paho for MQTT support
- The cybersecurity community for IoT security research

---

## 📧 Contact

For questions, suggestions, or security reports:
- GitHub Issues: [https://github.com/sudoyasir/iot-scan/issues](https://github.com/sudoyasir/iot-scan/issues)
- Email: y451rmahar@gmail.com

---

## ⚡ Quick Start

```bash
# 1. Clone and install
git clone https://github.com/sudoyasir/iot-scan.git
cd iot-scan
pip install -r requirements.txt

# 2. Run your first scan
sudo python -m src.cli --auto

# 3. View results and enjoy! 🎉
```

---

**Made with ❤️ for IoT Security**
