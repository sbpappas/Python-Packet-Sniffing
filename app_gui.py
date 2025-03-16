import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import threading
import sniffer
'''
class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("600x400")

        # Start Button
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

        # Stop Button
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack()

        # Text Output
        self.text_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.text_area.pack()

        self.sniffing = False

    def packet_callback(self, packet):
        """Handles each captured packet"""
        self.text_area.insert(tk.END, f"{packet.summary()}\n")
        self.text_area.yview(tk.END)

    def start_sniffing(self):
        """Starts packet sniffing in a separate thread"""
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        """Stops packet sniffing"""
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        """Runs packet sniffing"""
        sniff(prn=self.packet_callback, store=False, stop_filter=lambda x: not self.sniffing)

# Run the GUI
root = tk.Tk()
app = PacketSnifferApp(root)
root.mainloop()
'''

import tkinter as tk
import threading
import sniffer  # Import your sniffer script

def start_sniffer():
    interface = "en0"  # Change this to your actual network interface
    verbose = True  # Set to False if you don’t want detailed logs
    
    # Run sniffer in a separate thread to prevent freezing the GUI
    thread = threading.Thread(target=sniffer.main, args=(interface, verbose))
    thread.daemon = True
    thread.start()

# Create GUI window
print("asdf")
root = tk.Tk()
root.title("Packet Sniffer")

start_button = tk.Button(root, text="Start Sniffer", command=start_sniffer)
start_button.pack(pady=20)

root.mainloop()
