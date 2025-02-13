import sys
import os
from scapy.all import *
from datetime import datetime

#run with: sudo python3 sniffer.py en0 verbose


pcap_filename = "capture.pcap" 
packet_list = []  # store packets for saving to PCAP for later analysis with wireshark

# Function to handle each packet
def handle_packet(packet):
    global packet_list

    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        log_entry = f"[{timestamp}] TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
        
        if verbose:
            print(log_entry, end="")  # Print to console
        
        with open("sniffer_log.txt", "a") as logfile:
            logfile.write(log_entry)  # Append to file
        
        # Store packet for PCAP saving
        packet_list.append(packet)

        #print(log_entry, end="")  # Print to console
        #with open("sniffer_log.txt", "a") as logfile:
        #    logfile.write(log_entry)  # Append to file

def save_to_pcap():
    print("pcap")
    print(len(packet_list))
    if packet_list:
        wrpcap(pcap_filename, packet_list)
        print(f"[+] Packets saved to {pcap_filename}")

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


