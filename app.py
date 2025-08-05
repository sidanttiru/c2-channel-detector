#A complete, real-time network security dashboard.
#Combines a packet sniffer and a Flask web application.

#Live Mode (Default): Open VS Code w/ admin perms and run python app.py
#Interface Mode: python app.py -i "VirtualBox Host-Only Ethernet Adapter 2"
#Offline Mode (for PCAP analysis): python app.py -f x.pcap (replace x.pcap with actual PCAP filename)

#--- Imports ---
import math
import time
import threading
import argparse
from collections import Counter
from datetime import datetime

#Flask for the web dashboard
from flask import Flask, render_template_string, redirect, url_for

#Scapy for packet sniffing
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP

#--- Configuration and Global Variables ---

#Analysis Thresholds
DNS_LENGTH_THRESHOLD = 100
DNS_ENTROPY_THRESHOLD = 3.2
ICMP_PAYLOAD_THRESHOLD = 128
BEACON_MIN_PACKETS = 5
BEACON_JITTER_THRESHOLD = 1.0

#Stores connection timestamps
CONNECTION_TRACKER = {}

#Stores all alerts
ALL_ALERTS = []
ALERTS_LOCK = threading.Lock()

SNIFFER_RUNNING = True
STATE_LOCK = threading.Lock()

#--- Analysis Logic ---

def add_alert(message):
    with ALERTS_LOCK:
        timestamp = datetime.now().strftime("%H:%M:%S")
        ALL_ALERTS.append(f"({timestamp}) {message}")

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
            add_alert(f"Suspiciously Long DNS Query: {query_name}")
        if entropy > DNS_ENTROPY_THRESHOLD:
            add_alert(f"High Entropy DNS Query (E: {entropy:.2f}): {query_name}")

def analyze_icmp(packet):
    if ICMP in packet and packet[ICMP].type in [0, 8]:
        payload_size = len(packet[ICMP].payload)
        if payload_size > ICMP_PAYLOAD_THRESHOLD:
            add_alert(f"Large ICMP Payload Detected (Size: {payload_size} bytes). Possible Tunneling.")

def analyze_beaconing():
    import numpy as np
    for conn_key, timestamps in list(CONNECTION_TRACKER.items()):
        if len(timestamps) > BEACON_MIN_PACKETS:
            intervals = np.diff(timestamps)
            jitter = np.std(intervals)
            if jitter < BEACON_JITTER_THRESHOLD:
                mean_interval = np.mean(intervals)
                add_alert(f"Potential C2 Beaconing Detected: {conn_key[0]} -> {conn_key[1]} (Interval: {mean_interval:.2f}s, Jitter: {jitter:.2f}s)")
                del CONNECTION_TRACKER[conn_key]

#--- Packet Sniffer Handler ---

def packet_handler(packet):
    if IP in packet:
        conn_key = (packet[IP].src, packet[IP].dst)
        if conn_key not in CONNECTION_TRACKER:
            CONNECTION_TRACKER[conn_key] = []
        CONNECTION_TRACKER[conn_key].append(packet.time)

    if packet.haslayer(DNS):
        analyze_dns(packet)
    elif packet.haslayer(ICMP):
        analyze_icmp(packet)

def run_sniffer(pcap_file=None, interface=None):
    last_beacon_check = time.time()
    if pcap_file:
        print(f"[*] Starting sniffer in OFFLINE mode from file: {pcap_file}")
        try:
            sniff(offline=pcap_file, prn=packet_handler, store=0)
            print("[*] PCAP file processing complete. Running final beaconing analysis...")
            analyze_beaconing()
            print("[*] Analysis complete. View results on the dashboard.")
        except Exception as e:
            add_alert(f"Error reading PCAP file: {e}")
    else:
        if interface:
            print(f"[*] Starting packet sniffer in LIVE mode on interface: {interface}")
        else:
            print(f"[*] Starting packet sniffer in LIVE mode on default interface.")
        
        while True:
            with STATE_LOCK:
                is_running = SNIFFER_RUNNING
            
            if is_running:
                sniff(iface=interface, filter="ip", prn=packet_handler, store=0, timeout=2)
                
                if time.time() - last_beacon_check > 60:
                    analyze_beaconing()
                    last_beacon_check = time.time()
            else:
                time.sleep(1)


#--- Flask Web Application ---

app = Flask(__name__)

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
        .alert-text { word-break: break-all; }
        .btn {
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-weight: 600;
            text-align: center;
            transition: background-color 0.2s;
            display: inline-block;
        }
        .btn-green { background-color: #22c55e; color: white; }
        .btn-green:hover { background-color: #16a34a; }
        .btn-yellow { background-color: #eab308; color: white; }
        .btn-yellow:hover { background-color: #ca8a04; }
        .btn-red { background-color: #ef4444; color: white; }
        .btn-red:hover { background-color: #dc2626; }
    </style>
</head>
<body class="bg-gray-900 text-gray-200">
    <div class="container mx-auto p-4 md:p-8">
        <div class="text-center mb-6">
            <h1 class="text-4xl font-bold text-white">Live Network Security Dashboard</h1>
            <p class="text-gray-400 text-lg mt-2">Actively monitoring network traffic for threats...</p>
        </div>

        <div class="flex justify-center items-center gap-4 mb-6">
            {% if sniffer_is_running %}
                <a href="/toggle_sniffer" class="btn btn-yellow">Pause Sniffer</a>
            {% else %}
                <a href="/toggle_sniffer" class="btn btn-green">Resume Sniffer</a>
            {% endif %}
            <a href="/clear_alerts" class="btn btn-red">Clear Alerts Log</a>
        </div>

        <div class="bg-gray-800 rounded-xl shadow-2xl p-6">
            <h2 class="text-2xl font-semibold text-white mb-4 border-b border-gray-700 pb-2">Threat Alerts Log</h2>
            <div id="alerts" class="space-y-3">
                {% if alerts %}
                    {% for alert in alerts %}
                        <div class="bg-red-900/50 border border-red-700 text-red-300 px-4 py-3 rounded-lg flex items-start">
                            <span class="font-bold mr-3">[!]</span>
                            <span class="alert-text">{{ alert }}</span>
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
    with ALERTS_LOCK:
        alerts_to_display = ALL_ALERTS[::-1]
    with STATE_LOCK:
        is_running = SNIFFER_RUNNING
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(HTML_TEMPLATE, alerts=alerts_to_display, timestamp=now, sniffer_is_running=is_running)

@app.route('/toggle_sniffer')
def toggle_sniffer():
    global SNIFFER_RUNNING
    with STATE_LOCK:
        SNIFFER_RUNNING = not SNIFFER_RUNNING
        status = "resumed" if SNIFFER_RUNNING else "paused"
        print(f"[*] Sniffer has been {status}.")
    return redirect(url_for('dashboard'))

@app.route('/clear_alerts')
def clear_alerts():
    with ALERTS_LOCK:
        ALL_ALERTS.clear()
        print("[*] Alerts log has been cleared.")
    return redirect(url_for('dashboard'))

#--- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A network security dashboard.")
    parser.add_argument('-f', '--file', help="Path to a PCAP file for offline analysis.")
    parser.add_argument('-i', '--interface', help="Name of the network interface to sniff (e.g., 'en0' or 'Wi-Fi').")
    args = parser.parse_args()

    sniffer_thread = threading.Thread(target=run_sniffer, args=(args.file, args.interface), daemon=True)
    sniffer_thread.start()
    
    print("[*] Starting Flask web server on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)
