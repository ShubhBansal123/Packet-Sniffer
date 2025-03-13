from scapy.all import sniff
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import matplotlib.pyplot as plt
from collections import Counter
import threading

# Dictionary to track ARP cache for spoof detection
arp_cache = {}
packet_counts = Counter()
stop_sniffing = False

# GUI Setup
root = tk.Tk()
root.title("Packet Sniffer & ARP Spoof Detector")
root.geometry("800x500")
root.configure(bg="#2C2F33")  # Dark theme

# Initialize StringVar after creating root window
selected_filter = tk.StringVar()
selected_filter.set("All")

# Header Label
header_label = tk.Label(root, text="Packet Sniffer & ARP Spoof Detector", font=("Arial", 16, "bold"), bg="#2C2F33", fg="white")
header_label.pack(pady=5)

# Frame for Logs
frame = tk.Frame(root, bg="#23272A")
frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

# Scrollable text area for logs
text_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=100, height=20, bg="#23272A", fg="white", font=("Courier", 10))
text_area.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

# Function to update GUI log
def update_gui_log(message):
    text_area.insert(tk.END, message + "\n")
    text_area.see(tk.END)

# Function to log captured packets
def log_packet(packet):
    global packet_counts, stop_sniffing
    if stop_sniffing:
        return False
    log_entry = f"{datetime.datetime.now()} | {packet.summary()}"
    with open("packet_log.txt", "a") as log_file:
        log_file.write(log_entry + "\n")
    update_gui_log(log_entry)

    # Classify packet types properly for visualization
    if packet.haslayer(ARP):
        packet_counts["ARP"] += 1
    elif packet.haslayer(DNS):
        packet_counts["DNS"] += 1
    elif packet.haslayer(TCP):
        packet_counts["TCP"] += 1
    elif packet.haslayer(UDP):
        packet_counts["UDP"] += 1
    elif packet.haslayer(IP):
        packet_counts["IP"] += 1
    else:
        packet_counts["Other"] += 1
    
    return True

# Function to detect ARP spoofing
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet.op == 2:
        if packet.psrc in arp_cache:
            if arp_cache[packet.psrc] != packet.hwsrc:
                alert_msg = f"⚠️ Potential ARP Spoofing! IP: {packet.psrc} MAC: {packet.hwsrc}"
                update_gui_log(alert_msg)
                messagebox.showwarning("ARP Spoofing Alert!", alert_msg)  # Pop-up alert
                with open("alerts.txt", "a") as alert_file:
                    alert_file.write(alert_msg + "\n")
        else:
            arp_cache[packet.psrc] = packet.hwsrc

# Function to start sniffing
def start_sniffing():
    global stop_sniffing
    stop_sniffing = False
    update_gui_log("[+] Starting packet sniffing...")
    filter_option = selected_filter.get()
    filters = {
        "All": None,
        "ARP": "arp",
        "DNS": "udp port 53",
        "TCP": "tcp",
        "UDP": "udp",
        "HTTP": "tcp port 80 or tcp port 443"
    }
    sniff(prn=log_packet if filter_option != "ARP" else detect_arp_spoof, store=0, filter=filters[filter_option], stop_filter=lambda x: stop_sniffing)

# Function to stop sniffing
def stop_sniffing_func():
    global stop_sniffing
    stop_sniffing = True
    update_gui_log("[!] Stopping packet sniffing...")

# Function to show packet statistics
def show_stats():
    if not packet_counts:
        messagebox.showinfo("No Data", "No packets captured yet.")
        return
    plt.figure(figsize=(7, 4))
    plt.bar(packet_counts.keys(), packet_counts.values(), color=['blue', 'red', 'green', 'orange', 'purple', 'gray'])
    plt.xlabel("Packet Types")
    plt.ylabel("Count")
    plt.title("Packet Distribution")
    plt.xticks(rotation=45)
    plt.show()

# Start/Stop Buttons & Filters
button_frame = tk.Frame(root, bg="#2C2F33")
button_frame.pack(pady=10, fill=tk.X)

start_button = ttk.Button(button_frame, text="Start Sniffing", command=lambda: threading.Thread(target=start_sniffing, daemon=True).start())
start_button.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)

stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing_func)
stop_button.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)

stats_button = ttk.Button(button_frame, text="Show Stats", command=show_stats)
stats_button.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)

# Filter Selection
filter_label = tk.Label(button_frame, text="Filter: ", bg="#2C2F33", fg="white")
filter_label.pack(side=tk.LEFT, padx=10, pady=5)

filter_options = ["All", "ARP", "DNS", "TCP", "UDP", "HTTP"]
filter_menu = ttk.Combobox(button_frame, textvariable=selected_filter, values=filter_options, state="readonly")
filter_menu.pack(side=tk.LEFT, padx=10, pady=5)

# Run GUI main loop
root.mainloop()
