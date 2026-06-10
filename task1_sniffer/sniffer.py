import sys
from scapy.all import sniff, IP, TCP, UDP, Raw, conf

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Identify Protocol
        proto_name = "Unknown"
        payload_desc = ""
        
        if packet.haslayer(TCP):
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto_name = f"TCP ({sport} -> {dport})"
            
            # Check for Raw payload
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                # Decode try
                try:
                    payload_desc = raw_data.decode('utf-8', errors='ignore')[:100].strip()
                    payload_desc = f" | Payload: {payload_desc}"
                except Exception:
                    payload_desc = f" | Raw Payload ({len(raw_data)} bytes)"
                    
        elif packet.haslayer(UDP):
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto_name = f"UDP ({sport} -> {dport})"
            
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    payload_desc = raw_data.decode('utf-8', errors='ignore')[:100].strip()
                    payload_desc = f" | Payload: {payload_desc}"
                except Exception:
                    payload_desc = f" | Raw Payload ({len(raw_data)} bytes)"
                    
        elif proto == 1:
            proto_name = "ICMP"
        
        # Display the source to destination format as requested
        print(f"[IP] {src_ip} -> {dst_ip} | Protocol: {proto_name}{payload_desc}")

def main():
    print("=" * 60)
    print("           BASIC PYTHON NETWORK PACKET SNIFFER")
    print("=" * 60)
    print("[*] Active Interface:", conf.iface)
    print("[*] Starting packet capture... Press Ctrl+C to stop.")
    print("-" * 60)
    
    try:
        # Sniff packets continuously (store=0 to not keep them in memory)
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] ERROR: Permission Denied. You must run this script with administrative privileges (Administrator command prompt or sudo).")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
