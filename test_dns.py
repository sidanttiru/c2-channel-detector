import math
from collections import Counter
from scapy.all import IP, UDP, DNS, DNSQR

print("--- SCRIPT STARTED ---")

#--- Part 1: Diagnostic Functions ---

DNS_LENGTH_THRESHOLD = 100
DNS_ENTROPY_THRESHOLD = 3.2

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for count in Counter(data).values():
        p_x = count / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy

def analyze_dns_diagnostic(packet):
    print("\n  [DEBUG] analyze_dns_diagnostic function entered.")
    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0:
        print("  [DEBUG] Packet is a standard DNS query. Proceeding...")
        query_name = packet[DNSQR].qname.decode('utf-8')
        print(f"  [DEBUG] Decoded query_name: {query_name}")
        query_length = len(query_name)
        print(f"  [DEBUG] Calculated length: {query_length}")
        entropy = calculate_entropy(query_name)
        print(f"  [DEBUG] Calculated entropy: {entropy:.4f}")
        print("  [DEBUG] Checking length condition...")
        if query_length > DNS_LENGTH_THRESHOLD:
            print("  [DEBUG] ---> Length condition MET. Firing alert.")
            print(f"  [!] ALERT: Suspiciously long DNS query detected (Length: {query_length}): {query_name}")
        else:
            print("  [DEBUG] ---> Length condition NOT MET.")
        print("  [DEBUG] Checking entropy condition...")
        if entropy > DNS_ENTROPY_THRESHOLD:
            print("  [DEBUG] ---> Entropy condition MET. Firing alert.")
            print(f"  [!] ALERT: High entropy DNS query detected (Entropy: {entropy:.2f}): {query_name}")
        else:
            print("  [DEBUG] ---> Entropy condition NOT MET.")
    else:
        print("  [DEBUG] Packet is NOT a standard DNS query. Skipping analysis.")

#--- Part 2: Test Run with explicit packet creation ---

def run_diagnostic_test():
    print("--- Running Definitive Diagnostic Test ---")

    malicious_qname = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6.malicious.com"
    
    #Explicity set opcode and ancount fields
    malicious_packet = IP() / UDP() / DNS(
        opcode=0,     
        ancount=0,     
        qd=DNSQR(qname=malicious_qname)
    )
    # -----------------------
    
    print("\n[TEST 1] Simulating a malicious DNS query...")
    analyze_dns_diagnostic(malicious_packet)

    normal_qname = "www.google.com"
    normal_packet = IP() / UDP() / DNS(
        opcode=0,
        ancount=0,
        qd=DNSQR(qname=normal_qname)
    )

    print("\n[TEST 2] Simulating a normal DNS query...")
    analyze_dns_diagnostic(normal_packet)
    
    print("\n--- Definitive Test Complete ---")

if __name__ == "__main__":
    run_diagnostic_test()