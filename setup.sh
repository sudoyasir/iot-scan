#!/bin/bash

# IoT-Scan Quick Setup Script

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║  ╦╔═╗╔╦╗   ╔═╗╔═╗╔═╗╔╗╔                                     ║"
echo "║  ║║ ║ ║ ═══╚═╗║  ╠═╣║║║                                     ║"
echo "║  ╩╚═╝ ╩    ╚═╝╚═╝╩ ╩╝╚╝                                     ║"
echo "║  IoT Device Security Scanner - Setup                         ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "[*] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "[!] Error: Python 3.10 or higher is required"
    echo "    Current version: $python_version"
    exit 1
fi
echo "[+] Python version: $python_version"

# Check if running as root for installation
if [ "$EUID" -eq 0 ]; then
    echo "[!] Warning: Running setup as root"
    echo "    It's recommended to use a virtual environment instead"
fi

# Create virtual environment
echo ""
echo "[*] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "[!] Virtual environment already exists"
    read -p "    Remove and recreate? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf venv
        python3 -m venv venv
    fi
else
    python3 -m venv venv
fi

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

# Install package
echo "[*] Installing IoT-Scan..."
pip install -e . > /dev/null 2>&1

echo ""
echo "[+] Installation complete!"
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Quick Start Guide                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Run IoT-Scan (requires sudo for ARP scanning):"
echo "   sudo venv/bin/python -m src.cli --auto"
echo ""
echo "3. Or scan a specific subnet:"
echo "   sudo venv/bin/python -m src.cli --subnet 192.168.1.0/24"
echo ""
echo "4. For more options:"
echo "   python -m src.cli --help"
echo ""
echo "5. Run tests:"
echo "   pytest tests/"
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                      Important Notes                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "⚠️  ARP scanning requires root privileges"
echo "⚠️  Only scan networks you own or have permission to test"
echo "⚠️  Use responsibly and ethically"
echo ""
echo "For more information, see README.md"
echo ""
