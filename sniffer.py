
import sys
import os
from scapy.all import *
from datetime import datetime
from collections import defaultdict
import geoip2.database

# Path to the GeoLite2 database
GEOIP_DB_PATH = "GeoLite2-City_20250221/GeoLite2-City.mmdb"
reader = geoip2.database.Reader(GEOIP_DB_PATH)# Load the GeoIP database once (global scope)

# Run with: 
# source venv/bin/activate  
# sudo python3 sniffer.py en0 verbose

pcap_filename = "capture.pcap" 
recent_sniff_filename = "recent_sniff"
packet_list = []  # store packets for saving to PCAP

# Track activity
known_devices = {"192.168.0.1", "192.168.0.101", "192.168.0.100"}  # Modify with your actual known devices
# 192.168.0.1 is my router, 192.168.0.101 is my iphone, 192.168.0.100 is my laptop
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

        src_location = get_geoip_info(src_ip)
        dst_location = get_geoip_info(dst_ip)

        
        if src_ip not in known_devices: #unauthorized devices (not in auth list)
            print(f"[!] Unauthorized device detected: {src_ip}")

        if traffic_count[src_ip] > 100:  #a lot of traffic from this src
            print(f"[!] High traffic volume detected from {src_ip}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # frequent failed connections (Port Scanning)
            if packet[TCP].flags == "S":  # SYN packet
                failed_attempts[src_ip] += 1
                if failed_attempts[src_ip] > 10:  # adjust as needed
                    print(f"[!] Possible port scanning from {src_ip}")

            # Detect unusual protocols
            if dst_port in suspicious_ports:
                print(f"[!] Suspicious protocol usage detected: {src_ip} -> {dst_ip}:{dst_port}")

            log_entry = f"[{timestamp}] TCP Connection: {src_ip}:{src_port}-({src_location}) -> {dst_ip}:{dst_port}-({dst_location})\n"
            
            if verbose:
                print(log_entry, end="")
            
            with open("sniffer_log.txt", "a") as logfile:
                logfile.write(log_entry)
            
            with open("recent_sniff.txt", "a") as recentlogfile:
                recentlogfile.write(log_entry)

            packet_list.append(packet)

# Save packets to PCAP
def save_to_pcap():
    if packet_list:
        print(f"\n{len(packet_list)} packets captured.")
        wrpcap(pcap_filename, packet_list)
        print(f"Packets saved to {pcap_filename}")

def clear_file(file_path):
    """Clears the content of a text file.
     Args:
        file_path: The path to the text file.
    """
    try:
        with open(file_path, 'w') as file:
            file.truncate(0)
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")


def get_geoip_info(ip):
    """ Returns city and country info for an IP address using GeoIP. """
    try:
        response = reader.city(ip)
        city = response.city.name if response.city.name else "Unknown"
        country = response.country.name if response.country.name else "Unknown"
        return f"{city}, {country}"
    except Exception:
        return "Unknown Location"

def analyze_packets():
    # break down type of packet
    # unauthorized ports and how much traffic
    # sus behavior
    # other analytics that would be fun
    packet_list


# Main function to start packet sniffing
def main(interface, verbose_flag=False):
    global verbose
    verbose = verbose_flag
    clear_file("recent_sniff.txt")
    if os.geteuid() != 0:
        print("This script requires root privileges. Run with sudo.")
        sys.exit(1)

    reader = geoip2.database.Reader('GeoLite2-City_20250221/GeoLite2-City.mmdb')
    response = reader.city('8.8.8.8')

    print(response.city.name, response.country.name)

    # Path to your GeoLite2 database file
    GEOIP_DB_PATH = "GeoLite2-City_20250221/GeoLite2-City.mmdb"

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





#'''
