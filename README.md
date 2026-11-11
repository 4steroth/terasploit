
# Terasploit - Exploitation Framework for Red Team Operations

## Requirements

**Python 3.14+ (Recommended)**

### Dependencies

```bash
sudo apt install python3-impacket python3-paramiko
```

## Installation

```bash
# Install dependencies
sudo apt install python3-impacket python3-paramiko

# Clone the repository
git clone https://github.com/4steroth/terasploit.git
cd terasploit

# No package installation step is required. The framework adds its own root to `sys.path` at startup.
./teraconsole
```

### System Installation

```bash
# Install dependencies
sudo apt install python3-impacket python3-paramiko

# Clone the repository
git clone https://github.com/4steroth/terasploit.git
cd terasploit

# Install via pip - be careful with '--break-system-packages'
python3 -m pip install -e . --break-system-packages

# Run the program
teraconsole
```

## Disclaimer

Terasploit is intended exclusively for **authorized security testing and educational research**. Use against systems you do not own or lack explicit written permission to test is illegal and unethical. The authors accept no liability for misuse.

<div align="center">
<sub>Built with Python · BSD-3-Clause · <a href="https://github.com/4steroth/terasploit">github.com/4steroth/terasploit</a></sub>
</div>
