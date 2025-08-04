from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

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

        print(packet_info)

def main():
    print("Packet sniffer initiating... Capturing 10 packets.")
    sniff(count=10, filter="ip", prn=packet_handler, store=0)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\nSniffer terminated. Exiting...")

