import sys
import os
from scapy.all import *
from datetime import datetime

#run with: sudo python3 sniffer.py en0 verbose


pcap_filename = "capture.pcap" 
packet_list = []  # store packets for saving to PCAP for later analysis with wireshark
verbose = False # just as a default

# Function to handle each packet
def handle_packet(packet):
    global packet_list
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = ""

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_entry = f"[{timestamp}] [TCP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
        
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            log_entry = f"[{timestamp}] [UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
        
        elif packet.haslayer(ICMP):
            log_entry = f"[{timestamp}] [ICMP] Ping from {src_ip} to {dst_ip}\n"

    elif packet.haslayer(ARP):
        src_mac = packet.hwsrc
        dst_mac = packet.hwdst
        log_entry = f"[{timestamp}] [ARP] {src_mac} -> {dst_mac} | Who has {packet.pdst}?\n"

    if log_entry:
        if verbose:
            print(log_entry, end="")  # Print to console
        
        with open("sniffer_log.txt", "a") as logfile:
            logfile.write(log_entry)  # Append to file
        
        packet_list.append(packet)  # Store packet for PCAP saving

def save_to_pcap():
    print(f"{len(packet_list)} packets captured.")
    if packet_list:
        wrpcap(pcap_filename, packet_list)
        print(f"Packets saved to {pcap_filename}") #open with the command: wireshark pcap_filename

def analyze_packets(filename: str):
    open(filename)

    #capture packets from a certain time period or certain amount of packets?
    # maybe look at percentage of UDP/TCP/Other
    # analyze ports to/from, percentages
    # odd looking ports - security?
    # repeated attempts on the same things?

# Main function to start packet sniffing
def main(interface, verbose_flag=False):
    global verbose
    verbose = verbose_flag
    if os.geteuid() != 0:
        print("This script requires root privileges. Run with sudo.")
        sys.exit(1)
    
    print(f"[*] Starting packet sniffing on {interface} (Press Ctrl+C to stop)")
    
    try:
        sniff(iface=interface, prn=handle_packet, store=1)
        #sniff(iface="en0", prn=lambda pkt: pkt.summary(), store=1) #for capturing all packets (UDP, TCP, ICMP, ARP)

    except KeyboardInterrupt:
        print("\n[!] Stopping packet sniffer...")        
    finally:
        print("[*] Finally block executing.")  # Debug: Is this being reached?
        save_to_pcap()  # Ensure saving on exit
        sys.exit(0)

# Entry point
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: sudo python sniffer.py <interface> [verbose]")
        sys.exit(1)

    verbose = len(sys.argv) == 3 and sys.argv[2].lower() == "verbose"
    main(sys.argv[1], verbose)


'''
import sys
import os
from scapy.all import *
from datetime import datetime
from collections import defaultdict

# Run with: sudo python3 sniffer.py en0 verbose

pcap_filename = "capture.pcap" 
packet_list = []  # store packets for saving to PCAP

# Track activity
known_devices = {"192.168.0.1", "192.168.0.101", "192.168.0.102"}  # Modify with your actual known devices
traffic_count = defaultdict(int)  # Track packet count per device
failed_attempts = defaultdict(int)  # Track failed connection attempts

suspicious_ports = {22, 3389, 5432, 3306}  # SSH, RDP, PostgreSQL, MySQL

# Function to handle each packet
def handle_packet(packet):
    global packet_list
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        traffic_count[src_ip] += 1  # Track traffic

        # Detect unauthorized devices
        if src_ip not in known_devices:
            print(f"[!] Unauthorized device detected: {src_ip}")

        # Detect unusual traffic patterns
        if traffic_count[src_ip] > 100:  # Adjust threshold as needed
            print(f"[!] High traffic volume detected from {src_ip}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Detect frequent failed connections (Port Scanning)
            if packet[TCP].flags == "S":  # SYN packet
                failed_attempts[src_ip] += 1
                if failed_attempts[src_ip] > 10:  # Adjust threshold
                    print(f"[!] Possible port scanning from {src_ip}")

            # Detect unusual protocols
            if dst_port in suspicious_ports:
                print(f"[!] Suspicious protocol usage detected: {src_ip} -> {dst_ip}:{dst_port}")

            log_entry = f"[{timestamp}] TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
            
            if verbose:
                print(log_entry, end="")
            
            with open("sniffer_log.txt", "a") as logfile:
                logfile.write(log_entry)

            packet_list.append(packet)

# Save packets to PCAP
def save_to_pcap():
    if packet_list:
        wrpcap(pcap_filename, packet_list)
        print(f"Packets saved to {pcap_filename}")

# Main function to start packet sniffing
def main(interface, verbose_flag=False):
    global verbose
    verbose = verbose_flag
    if os.geteuid() != 0:
        print("This script requires root privileges. Run with sudo.")
        sys.exit(1)
    
    print(f"[*] Starting packet sniffing on {interface} (Press Ctrl+C to stop)")
    
    try:
        sniff(iface=interface, prn=handle_packet, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopping packet sniffer...")
    finally:
        save_to_pcap()
        sys.exit(0)

# Entry point
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: sudo python sniffer.py <interface> [verbose]")
        sys.exit(1)
    
    verbose = len(sys.argv) == 3 and sys.argv[2].lower() == "verbose"
    main(sys.argv[1], verbose)
'''
