from scapy.all import sniff, IP
import datetime

def analyze_packet(packet):
    if IP in packet:
        # Extract relevant information from the packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Example: Detect port scanning
        if packet.haslayer("TCP"):
            flags = packet["TCP"].flags
            # Check for SYN scan
            if flags == 2:
                print(f"[{datetime.datetime.now()}] Potential SYN scan detected from {src_ip} to {dst_ip}")
                # You can add additional actions here like logging, sending alerts, etc.
        # Add more detection rules for other types of suspicious activity
        
def start_nids():
    print("Starting Network Intrusion Detection System (NIDS)...")
    sniff(prn=analyze_packet, store=0)

if _name_ == "_main_":
    start_nids()