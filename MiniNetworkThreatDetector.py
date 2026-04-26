# Mini Network Threat Detector

from scapy.all import sniff, IP, TCP, UDP, DNS
import socket
import re
from collections import defaultdict

syn_counter = defaultdict(int)
dns_counter = defaultdict(int)

THRESHOLD_SYN = 10
THRESHOLD_DNS = 15

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        
        if packet.haslayer(TCP):
            if packet[TCP].flags == "S":
                syn_counter[src_ip] += 1

                if syn_counter[src_ip] > THRESHOLD_SYN:
                    print(f"[ALERT] Possible SYN scan from {src_ip}")

        # Here we can detect DNS traffic
        if packet.haslayer(DNS):
            dns_counter[src_ip] += 1

            if dns_counter[src_ip] > THRESHOLD_DNS:
                print(f"[ALERT] High DNS activity from {src_ip}")

        # Some suspicious ports
        if packet.haslayer(TCP):
            port = str(packet[TCP].dport)

            if re.match(r"(22|23|445|3389)", port):
                print(f"[WARNING] Connection to sensitive port {port} from {src_ip}")

def generate_report():
    print("\n Incident Report )

    print("\nTop SYN senders:")
    for ip, count in sorted(syn_counter.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip} -> {count} SYN packets")

    print("\nTop DNS senders:")
    for ip, count in sorted(dns_counter.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip} -> {count} DNS queries")

if __name__ == "__main__":
    print("[*] Starting packet capture... (Press CTRL+C to stop)")

    try:
        sniff(prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")
        generate_report()
