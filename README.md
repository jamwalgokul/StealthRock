# 🕵️ StealthRock - Advanced Network Port Scanner 🔍

## 🚀 Project Overview
StealthRock is a powerful, multi-threaded Python port scanning tool designed for comprehensive network reconnaissance and security analysis. It provides advanced features for scanning IP addresses, domain names, and CIDR ranges with precision and speed.

![Python Version](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Network%20Scanner-green?style=for-the-badge)

## ✨ Key Features
- 🌐 Supports scanning:
  - Single IP addresses
  - Domain names
  - CIDR ranges
- 🚀 Multi-threaded scanning for maximum performance
- 🔍 OS Fingerprinting capabilities
- 📊 Detailed port and service information
- 💾 CSV output support
- 🌈 Colorful console output

## 🛠 Technical Details
- **Language**: Python 3
- **Dependencies**: 
  - socket
  - threading
  - concurrent.futures
  - termcolor
  - pyfiglet
  - ipaddress

## 🔧 Installation

### Prerequisites
- Python 3.x
- pip package manager

### Setup
1. Clone the repository
```bash
git clone https://github.com/your-username/StealthRock.git
cd StealthRock
```

2. Install required libraries
```bash
pip install termcolor pyfiglet
```

## 🖥 Usage Examples

### Basic Scan
```bash
python3 stealthrock.py -t 192.168.1.1
```

### Scan Specific Port Range
```bash
python3 stealthrock.py -t example.com -s 1 -e 1000
```

### Scan with CSV Output
```bash
python3 stealthrock.py -t 192.168.1.0/24 -o scan_results.csv
```

## 🔍 Command Line Options
- `-t, --target`: Target IP/Domain (REQUIRED)
- `-s, --start_port`: Starting port (Default: 1)
- `-e, --end_port`: Ending port (Default: 65535)
- `-o, --output`: Output CSV filename
- `--threads`: Number of threads (Default: 100, Max: 1000)

## 🎯 Scanning Capabilities
- Multi-threaded port scanning
- Domain name resolution
- OS fingerprinting
- Service detection
- Comprehensive port analysis

## 🚨 Ethical Usage Disclaimer
⚠️ **Important**: This tool is for educational and authorized penetration testing purposes only. Always obtain proper authorization before scanning networks.

## 🔒 Security Considerations
- Use only on networks you own or have explicit permission to test
- Respect legal and ethical boundaries
- Do not use for malicious purposes

## 📈 Performance Metrics
- Supports scanning up to 65,535 ports
- Configurable thread count (1-1000)
- Concurrent scanning for faster results

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📝 License
This project is licensed under the MIT License.

## 👨‍💻 Author
**Gokul Jamwal**
- Cybersecurity Enthusiast
- Network Security Researcher

## 🌟 Star the Repository!
If you find this tool useful, please consider giving it a star ⭐ to show your support!

---

![Visitors](https://visitor-badge.laobi.icu/badge?page_id=jamwalgokul.StealthRock)


