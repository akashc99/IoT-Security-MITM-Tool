# IoT Security MITM Tool v1

**Author:** Akash Chathoth  
**Version:** 1.0 (September 2025)

A Python-based **Man-in-the-Middle (MITM) Security Analysis Tool** for auditing IoT devices on authorized networks.  
This tool helps security researchers and penetration testers analyze **HTTP traffic**, **TLS handshakes**, and **detect insecure configurations** in IoT ecosystems.

> ⚠ **Legal Disclaimer:**  
> This tool is intended **only** for use on networks and devices you are **explicitly authorized** to test.  
> Unauthorized use against systems you do not own or have permission to test is **illegal** and punishable by law.  
> The author assumes **no liability** for misuse or damages caused by this tool.



## ✨ Features

- **ARP Spoofing & MITM:** Redirects traffic between the IoT device and gateway.
- **HTTP Traffic Analysis:**
  - Detects plaintext credentials (passwords, API keys, tokens).
  - Logs HTTP requests and responses with full context.
- **TLS Security Analysis:**
  - Parses TLS Client Hello packets.
  - Detects deprecated TLS versions (SSL 3.0, TLS 1.0, TLS 1.1).
  - Flags weak cipher suites (RC4, NULL, EXPORT, 3DES, CBC-SHA, RSA key exchange).
- **Wireshark Capture Mode:** Captures all target traffic to `.pcap` file and auto-opens in Wireshark.
- **Verbose Logging & Reporting:**  
  Saves findings to a structured Markdown report.



## 📦 Dependencies

This tool relies on the following system utilities and Python modules:

### System Requirements
- **Linux-based OS** (Tested on Kali, Ubuntu)
- `nmap`
- `tshark`
- `arping`
- `wireshark` (optional, for auto-opening captures)

Install dependencies (Debian/Ubuntu/Kali):
```bash
sudo apt update
sudo apt install nmap tshark iputils-arping wireshark -y
```

### Python Requirements
- `scapy` (network packet manipulation)

Install via pip:
```bash
pip install scapy
```



## 🔧 Usage

Run the tool with **sudo/root privileges**:

```bash
sudo python3 mitm_tool.py -t <TARGET_IP> -g <GATEWAY_IP> -i <INTERFACE> [OPTIONS]
```

### Options

| Option | Description |
|-------|-------------|
| `-t`, `--target` | Target IoT device IP address (required). |
| `-g`, `--gateway` | Gateway/Router IP address (required). |
| `-i`, `--interface` | Network interface to use (default: `wlan0`). |
| `--scan` | Analyze only HTTP traffic. |
| `--sslscan` | Analyze only TLS handshakes. |
| `--wireshark` | Capture packets to `.pcap` file and open in Wireshark. |
| `--fullscan` | Perform both HTTP and TLS analysis. |
| `-o`, `--output` | Save results to Markdown file. |
| `-v`, `--verbose` | Enable verbose debug output. |



### Example Commands

Perform full HTTP + TLS analysis and generate a report:
```bash
sudo python3 mitm_tool.py -t 192.168.1.101 -g 192.168.1.1 -i wlan0 --fullscan -o report.md
```

Capture all packets and open in Wireshark:
```bash
sudo python3 mitm_tool.py -t 192.168.1.101 -g 192.168.1.1 --wireshark
```

Verbose HTTP analysis only:
```bash
sudo python3 mitm_tool.py -t 192.168.1.101 -g 192.168.1.1 --scan -v
```



## 📄 Output

### Console Output
- Color-coded log levels:  
  - 🟢 **INFO** – General information  
  - 🟡 **WARN** – Warnings  
  - 🔴 **ERROR/CRITICAL** – Critical issues  
  - 🟣 **VULN** – Security vulnerabilities

### Markdown Report Example

> # IoT Security MITM Tool Report
> **Scan Started:** 2025-09-25 16:30:21  
> **Target:** `192.168.1.101`  
> **Gateway:** `192.168.1.1`  
> **Interface:** `wlan0`
>
> ## Log
> **[VULN]** DEPRECATED TLS VERSION DETECTED! This is a high-risk finding.  
> **[VULN]** PLAINTEXT SENSITIVE DATA DETECTED over HTTP!  
> **[VULN]** Type: Password  
> **[VULN]** Data: admin123


## 🛡️ Security Notes

- This tool modifies ARP tables on the local network.  
- **Always restore ARP tables** after testing (the tool handles this automatically on exit).
- Use in a **controlled lab environment** whenever possible.



## 🚀 Roadmap / Future Improvements

- [ ] Support IPv6 MITM attacks.
- [ ] Add active SSL downgrade attack detection.
- [ ] JSON/HTML reporting format.



## 📜 License

This project is released under the **MIT License**.  
Use at your own risk.



## 🤝 Contributions

Pull requests and improvements are welcome.  
Make sure to follow secure coding practices and include clear documentation.



## 🙏 Acknowledgements

- **Scapy** for packet manipulation.
- **Wireshark/Tshark** for packet capture and analysis.
- Inspiration from common MITM techniques and IoT security research.
