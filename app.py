#A complete, real-time network security dashboard.
#Combines a packet sniffer and a Flask web application.

#Live Mode (Default): Open VS Code w/ admin perms and run python app.py
#Interface Mode: python app.py -i "VirtualBox Host-Only Ethernet Adapter 2"
#Offline Mode (for PCAP analysis): python app.py -f x.pcap (replace x.pcap with actual PCAP filename)

# --- Imports ---
import math
import time
import threading
import queue
import argparse # <--- CHANGE 1: Added to handle command-line arguments
from collections import Counter
from datetime import datetime

#Flask for the web dashboard
from flask import Flask, render_template_string

#Scapy for packet sniffing
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP

# --- Configuration and Global Variables ---

# Analysis Thresholds
DNS_LENGTH_THRESHOLD = 100
DNS_ENTROPY_THRESHOLD = 3.2
ICMP_PAYLOAD_THRESHOLD = 128
BEACON_MIN_PACKETS = 5
BEACON_JITTER_THRESHOLD = 1.0

#Stores connection timestamps
CONNECTION_TRACKER = {}

#Passes alerts from sniffer to web app
ALERTS_QUEUE = queue.Queue()

# --- Analysis Logic ---

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for count in Counter(data).values():
        p_x = count / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy

def analyze_dns(packet):
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0:
        query_name = packet[DNSQR].qname.decode('utf-8')
        entropy = calculate_entropy(query_name)
        if len(query_name) > DNS_LENGTH_THRESHOLD:
            ALERTS_QUEUE.put(f"Suspiciously Long DNS Query: {query_name[:50]}...")
        if entropy > DNS_ENTROPY_THRESHOLD:
            ALERTS_QUEUE.put(f"High Entropy DNS Query (E: {entropy:.2f}): {query_name[:50]}...")

def analyze_icmp(packet):
    if ICMP in packet and packet[ICMP].type in [0, 8]:
        payload_size = len(packet[ICMP].payload)
        if payload_size > ICMP_PAYLOAD_THRESHOLD:
            ALERTS_QUEUE.put(f"Large ICMP Payload Detected (Size: {payload_size} bytes). Possible Tunneling.")

def analyze_beaconing():
    import numpy as np # Import numpy only when this function is called
    for conn_key, timestamps in list(CONNECTION_TRACKER.items()):
        if len(timestamps) > BEACON_MIN_PACKETS:
            intervals = np.diff(timestamps)
            jitter = np.std(intervals)
            if jitter < BEACON_JITTER_THRESHOLD:
                mean_interval = np.mean(intervals)
                ALERTS_QUEUE.put(f"Potential C2 Beaconing Detected: {conn_key[0]} -> {conn_key[1]} (Interval: {mean_interval:.2f}s, Jitter: {jitter:.2f}s)")
                del CONNECTION_TRACKER[conn_key]

# --- Packet Sniffer Worker ---

def packet_handler(packet):
    #Populate connection tracker for beaconing analysis
    if IP in packet:
        conn_key = (packet[IP].src, packet[IP].dst)
        if conn_key not in CONNECTION_TRACKER:
            CONNECTION_TRACKER[conn_key] = []
        CONNECTION_TRACKER[conn_key].append(packet.time)

    #Pass packet to respective analyzer
    if packet.haslayer(DNS):
        analyze_dns(packet)
    elif packet.haslayer(ICMP):
        analyze_icmp(packet)

# --- CHANGE 2: Updated the run_sniffer function ---
def run_sniffer(pcap_file=None, interface=None):
    """The main packet sniffing loop. Supports three modes."""
    if pcap_file:
        # --- OFFLINE MODE ---
        print(f"[*] Starting sniffer in OFFLINE mode from file: {pcap_file}")
        try:
            sniff(offline=pcap_file, prn=packet_handler, store=0)
            print("[*] PCAP file processing complete. Running final beaconing analysis...")
            analyze_beaconing()
            print("[*] Analysis complete. View results on the dashboard.")
        except Exception as e:
            print(f"[!!!] Error reading PCAP file: {e}")
    else:
        # --- LIVE MODE ---
        if interface:
            print(f"[*] Starting packet sniffer in LIVE mode on interface: {interface}")
        else:
            print("[*] Starting packet sniffer in LIVE mode on default interface.")
        
        while True:
            # The 'iface' parameter tells Scapy which network interface to listen on.
            # If 'interface' is None, Scapy automatically chooses the default one.
            sniff(iface=interface, filter="ip", prn=packet_handler, store=0, timeout=60)
            analyze_beaconing()


# --- Flask Web Application ---

#Initialize Flask
app = Flask(__name__)

#Define HTML template for dashboard
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Security Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-gray-900 text-gray-200">
    <div class="container mx-auto p-4 md:p-8">
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-white">Live Network Security Dashboard</h1>
            <p class="text-gray-400 text-lg mt-2">Actively monitoring network traffic for threats...</p>
        </div>
        <div class="bg-gray-800 rounded-xl shadow-2xl p-6">
            <h2 class="text-2xl font-semibold text-white mb-4 border-b border-gray-700 pb-2">Real-Time Alerts</h2>
            <div id="alerts" class="space-y-3">
                {% if alerts %}
                    {% for alert in alerts %}
                        <div class="bg-red-900/50 border border-red-700 text-red-300 px-4 py-3 rounded-lg flex items-center">
                            <span class="font-bold mr-3">[!] ALERT</span>
                            <span>{{ alert }}</span>
                        </div>
                    {% endfor %}
                {% else %}
                    <div class="text-center py-8 text-gray-500">
                        <p class="text-xl">No alerts detected.</p>
                        <p>System is operating normally.</p>
                    </div>
                {% endif %}
            </div>
        </div>
        <footer class="text-center text-gray-600 mt-8">
            <p>Dashboard refreshes every 5 seconds. Last updated: {{ timestamp }}</p>
        </footer>
    </div>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Renders the main dashboard page."""
    alerts_list = []
    #Get current alerts
    while not ALERTS_QUEUE.empty():
        alerts_list.append(ALERTS_QUEUE.get())
    
    #Readable timestamp for the footer
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    #Render the HTML, passing in the list of alerts
    return render_template_string(HTML_TEMPLATE, alerts=alerts_list, timestamp=now)

# --- CHANGE 3: Updated the Main Execution Block ---

if __name__ == "__main__":
    # Setup command-line argument parsing
    parser = argparse.ArgumentParser(description="A network security dashboard.")
    parser.add_argument('-f', '--file', help="Path to a PCAP file for offline analysis.")
    parser.add_argument('-i', '--interface', help="Name of the network interface to sniff (e.g., 'en0' or 'Wi-Fi').")
    args = parser.parse_args()

    # Pass the arguments to the sniffer thread
    sniffer_thread = threading.Thread(target=run_sniffer, args=(args.file, args.interface), daemon=True)
    sniffer_thread.start()
    
    # Start the Flask web server.
    # host='0.0.0.0' makes it accessible from other devices on your network.
    print("[*] Starting Flask web server on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)
