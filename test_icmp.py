import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import analyze_icmp
from scapy.all import IP, ICMP

def run_icmp_tests():
    """
    This function creates fake ICMP packets to test the analyzer.
    """
    print("--- Running ICMP Analyzer Unit Tests ---")

    #--- Test Case 1: Malicious Packet (Large Payload) ---
    #Creates payload much larger than 128-byte threshold.
    print("\n[TEST 1] Simulating an ICMP packet with a large payload...")
    
    #Create a 512-byte payload by repeating the character 'X'
    large_payload = 'X' * 512
    
    #Build fake packet: IP layer -> ICMP layer -> Large Payload
    malicious_packet = IP() / ICMP() / large_payload
    
    #Pass the fake packet to our function
    analyze_icmp(malicious_packet)


    #--- Test Case 2: Normal Packet (Small Payload) ---
    print("\n[TEST 2] Simulating a normal ICMP packet...")
    
    normal_payload = "this is a standard ping payload"
    
    normal_packet = IP() / ICMP() / normal_payload
    
    analyze_icmp(normal_packet)

    print("\n--- ICMP Tests Complete ---")

if __name__ == "__main__":
    run_icmp_tests()