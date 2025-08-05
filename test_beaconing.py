import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import analyze_beaconing, CONNECTION_TRACKER

def run_beaconing_tests():
    print("--- Running Beaconing Analyzer Unit Tests ---")

    #--- Test Case 1: Malicious Beaconing (Highly Regular Traffic) ---
    print("\n[TEST 1] Simulating a regular, machine-like beacon...")
    
    #Clear tracker for a clean test
    CONNECTION_TRACKER.clear()
    
    #Create fake connection key
    malicious_conn = ('10.0.0.5', '123.123.123.123') # Malware -> C2 Server
    
    #Create list of timestamps exactly 30 seconds apart
    CONNECTION_TRACKER[malicious_conn] = [
        1700000000.0, # Start
        1700000030.0, # +30s
        1700000060.0, # +30s
        1700000090.0, # +30s
        1700000120.0, # +30s
        1700000150.0, # +30s
    ]
    
    #Run analyzer
    analyze_beaconing()


    #--- Test Case 2: Normal User Traffic (Irregular) ---
    print("\n[TEST 2] Simulating normal, irregular user traffic...")
    CONNECTION_TRACKER.clear()
    
    normal_conn = ('10.0.0.5', '222.111.222.111') # User -> Website
    
    # Create list of timestamps that are irregular
    CONNECTION_TRACKER[normal_conn] = [
        1700000005.2, # Start
        1700000007.8, 
        1700000015.1, 
        1700000016.3, 
        1700000035.9, 
        1700000050.5,
    ]
    
    # Run analyzer
    analyze_beaconing()

    print("\n--- Beaconing Tests Complete ---")

if __name__ == "__main__":
    run_beaconing_tests()