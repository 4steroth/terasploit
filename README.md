
# Terasploit - Exploitation Framework for Red Team Operations

![Static Badge](https://img.shields.io/badge/python-3.14-blue?style=for-the-badge)
![Static Badge](https://img.shields.io/badge/Supported%200S-Linux-orange?style=for-the-badge)
![Static Badge](https://img.shields.io/badge/Contributions-Welcome-green?style=for-the-badge)


## Requirements

**Python 3.14** (recommended).

This software is built for and runs on **Python 3.14**. Check your installed version with `python --version`, and if it reports anything older, download and install python 3.14+ from [python.org](https://www.python.org/downloads/) and launch the program.

### Running on Python 3.13 (unofficial)

Python 3.13 is not officially supported, but may work if you add parentheses to any `except` clause that lists multiple exceptions. Python 3.14 allows these without parentheses (as long as there is no `as` clause); earlier versions raise a `SyntaxError`:

```python
# Python 3.14+
except ValueError, TypeError:

# Python 3.13
except (ValueError, TypeError):
```

Python 3.12 and older are untested. Python 2 is not supported.

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

## Contributing

Contributions are welcome. Please open an issue before working on significant changes. All modules should pass `ruff check` and `pyright` before submission.

## Disclaimer

Terasploit is intended exclusively for **authorized security testing and educational research**. Use against systems you do not own or lack explicit written permission to test is illegal and unethical. The authors accept no liability for misuse.

<div align="center">
<sub>Built with Python · BSD-3-Clause · <a href="https://github.com/4steroth/terasploit">github.com/4steroth/terasploit</a></sub>
</div>
