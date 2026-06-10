import json
import time
import os
import sys
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf

# Global configurations
RULES_FILE = "ids_rules.json"
ALERT_LOG = "ids_alerts.log"

# In-memory tracking for rate-limiting detection
# Maps IP -> list of timestamps
syn_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)

# Mock Firewall Blacklist
blacklisted_ips = set()

# Load Rules
def load_rules():
    default_rules = {
        "syn_scan": {"enabled": True, "max_syn_packets": 15, "window_seconds": 5, "severity": "HIGH", "description": "Potential TCP SYN Port Scan Detected"},
        "icmp_flood": {"enabled": True, "max_packets": 10, "window_seconds": 5, "severity": "MEDIUM", "description": "Potential ICMP Ping Flood Detected"},
        "plaintext_credentials": {"enabled": True, "keywords": ["password", "passwd", "username", "login"], "severity": "HIGH", "description": "Plaintext Credentials in Transit Detected"}
    }
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading {RULES_FILE}: {e}. Using default rules.")
    return default_rules

rules = load_rules()

def trigger_alert(alert_type, src_ip, details, severity):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    alert_msg = f"[{timestamp}] [{severity}] {rules[alert_type]['description']} | Source IP: {src_ip} | Details: {details}"
    
    # Print to console
    color_code = "\033[91m" if severity == "HIGH" else "\033[93m"
    reset_code = "\033[0m"
    print(f"{color_code}[ALERT] {alert_msg}{reset_code}")
    
    # Log to file
    with open(ALERT_LOG, "a") as log:
        log.write(alert_msg + "\n")
        
    # Trigger active response mechanism
    if src_ip not in blacklisted_ips and src_ip != "127.0.0.1":
        active_response(src_ip, alert_type)

def active_response(ip, alert_type):
    # Simulate firewall blocking
    blacklisted_ips.add(ip)
    print(f"\033[95m[RESPONSE] ACTIVE COUNTERMEASURE TRIGGERED: IP {ip} has been blocked in local firewall simulation due to {alert_type} behavior!\033[0m")

def clean_tracker(tracker, window):
    # Remove timestamps older than the window
    now = time.time()
    for ip in list(tracker.keys()):
        tracker[ip] = [t for t in tracker[ip] if now - t <= window]
        if not tracker[ip]:
            del tracker[ip]

def packet_analyzer(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # 0. Check if IP is in firewall blacklist
    if src_ip in blacklisted_ips:
        # Silently drop packet simulation
        return

    now = time.time()

    # 1. Detect TCP SYN Scans
    if rules["syn_scan"]["enabled"] and packet.haslayer(TCP):
        flags = packet[TCP].flags
        # Check if only SYN flag is set (SYN Scan signature)
        if flags == 0x02: # S flag
            syn_tracker[src_ip].append(now)
            window = rules["syn_scan"]["window_seconds"]
            clean_tracker(syn_tracker, window)
            
            if len(syn_tracker[src_ip]) > rules["syn_scan"]["max_syn_packets"]:
                trigger_alert(
                    "syn_scan", 
                    src_ip, 
                    f"Received {len(syn_tracker[src_ip])} SYN packets in last {window}s.",
                    rules["syn_scan"]["severity"]
                )
                # Reset tracker count to prevent alert spamming
                syn_tracker[src_ip] = []

    # 2. Detect ICMP Ping Floods
    if rules["icmp_flood"]["enabled"] and packet.haslayer(ICMP):
        # Type 8 is Echo Request
        if packet[ICMP].type == 8:
            icmp_tracker[src_ip].append(now)
            window = rules["icmp_flood"]["window_seconds"]
            clean_tracker(icmp_tracker, window)
            
            if len(icmp_tracker[src_ip]) > rules["icmp_flood"]["max_packets"]:
                trigger_alert(
                    "icmp_flood", 
                    src_ip, 
                    f"Received {len(icmp_tracker[src_ip])} ICMP Echo Requests in last {window}s.",
                    rules["icmp_flood"]["severity"]
                )
                icmp_tracker[src_ip] = []

    # 3. Detect Plaintext Credentials
    if rules["plaintext_credentials"]["enabled"] and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        # Check for HTTP POST or keyword matches in payloads
        if any(keyword in payload.lower() for keyword in rules["plaintext_credentials"]["keywords"]):
            # Confirm it looks like a credentials post (avoiding false positives)
            if "login" in payload.lower() or "password" in payload.lower() or "username" in payload.lower():
                # Extract headers/data snippet
                details = payload[:150].replace('\r', '').replace('\n', ' | ')
                trigger_alert(
                    "plaintext_credentials",
                    src_ip,
                    f"Credential keywords matching in Raw data to {dst_ip}. Data: {details}",
                    rules["plaintext_credentials"]["severity"]
                )

def main():
    print("=" * 60)
    print("      CUSTOM PYTHON NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    print(f"[*] Loaded signatures and thresholds from: {RULES_FILE}")
    print(f"[*] Writing alerts to log: {ALERT_LOG}")
    print(f"[*] Active Interface: {conf.iface}")
    print("[*] Monitoring traffic... Press Ctrl+C to exit.")
    print("-" * 60)

    try:
        sniff(prn=packet_analyzer, store=0)
    except KeyboardInterrupt:
        print("\n[*] NIDS shutting down.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] ERROR: Permission Denied. You must run this script with administrative privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
