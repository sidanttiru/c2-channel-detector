import math
import numpy as np
import time
from collections import Counter
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP

#DNS alerts thresholds
DNS_LENGTH_THRESHOLD = 100
DNS_ENTROPY_THRESHOLD = 3.2
ICMP_PAYLOAD_THRESHOLD = 128
CONNECTION_TRACKER = {}     #stores connection timestamps
BEACON_INTERVAL_THRESHOLD_SECONDS = 300     #5 min threshold
BEACON_JITTER_THRESHOLD = 0.5      #low standard deviation in seconds


def calculate_entropy(data):
    if not data:
        return 0
    #Using Counter to get frequency of each character
    entropy = 0
    for count in Counter(data).values():
        p_x = count / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy

def analyze_dns(packet):
    #Analyze DNS packet for tunneling

    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0: #standard query
        query_name = packet[DNSQR].qname.decode('utf-8')
        entropy = calculate_entropy(query_name)

        if len(query_name) > DNS_LENGTH_THRESHOLD:
            print(f"[!] ALERT [!]: Suspiciously long DNS query detected: {query_name}")
        
        if entropy > DNS_ENTROPY_THRESHOLD:
            print(f"[!] ALERT [!]: High entropy DNS query detected (Entropy: {entropy:.2f}): {query_name}")

def analyze_icmp(packet):
    if ICMP in packet and packet[ICMP].type in [0, 8]:
        payload_size = len(packet[ICMP].payload)
        if payload_size > ICMP_PAYLOAD_THRESHOLD:
            print(f"[!] ALERT [!]: Large ICMP payload detected (Size: {payload_size} bytes). Possible ICMP tunneling")

def analyze_beaconing():
    for conn_key, timestamps in list(CONNECTION_TRACKER.items()):
        if len(timestamps) > 5:
            intervals = np.diff(timestamps)
            mean_interval = np.mean(intervals)
            jitter = np.std(intervals)
        
            if mean_interval > 10 and jitter < BEACON_JITTER_THRESHOLD:
                print(f"[!] ALERT [!]: Potential C2 beaconing detected for connection {conn_key}.")
                print(f"    --> Average Interval: {mean_interval:.2f}s, Jitter: {jitter:.2f}s")
                del CONNECTION_TRACKER[conn_key]


def packet_handler(packet):
    if IP in packet:
        
        #Make timestamp readable
        readable_time = datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")

        packet_info = {
            'timestamp': readable_time,
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'payload_size': len(packet.payload)
        }

        if TCP in packet:
            packet_info['protocol'] = 'TCP'
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport

        elif UDP in packet:
            packet_info['protocol'] = 'UDP'
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport

        conn_key = (packet[IP].src, packet[IP].dst)
        if conn_key not in CONNECTION_TRACKER:
            CONNECTION_TRACKER[conn_key] = []
        CONNECTION_TRACKER[conn_key].append(packet.time)

        if time.time() % 60 < 1:
            analyze_beaconing()


        if packet.haslayer(DNS):
            analyze_dns(packet)
        elif packet.haslayer(ICMP):
            analyze_icmp(packet)

        print(packet_info)


def main():
    print("Packet sniffer initializing... Capturing 10 packets.")
    sniff(count=10, filter="ip", prn=packet_handler, store=0)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\nSniffer terminated. Exiting...")

