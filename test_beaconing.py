# test_beaconing.py

# --- Fix for importing from the main script ---
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# -----------------------------------------

# 1. Import the function AND the global dictionary we want to test
from main import analyze_beaconing, CONNECTION_TRACKER

def run_beaconing_tests():
    """
    This function creates fake connection histories to test the beaconing analyzer.
    """
    print("--- Running Beaconing Analyzer Unit Tests ---")

    # --- Test Case 1: Malicious Beaconing (Highly Regular Traffic) ---
    print("\n[TEST 1] Simulating a regular, machine-like beacon...")
    # Clear the tracker to ensure a clean test
    CONNECTION_TRACKER.clear()
    
    # Create a fake connection key
    malicious_conn = ('10.0.0.5', '123.123.123.123') # Malware -> C2 Server
    
    # Create a list of timestamps that are EXACTLY 30 seconds apart
    # This simulates a perfect, low-jitter beacon
    CONNECTION_TRACKER[malicious_conn] = [
        1700000000.0, # Start time
        1700000030.0, # +30s
        1700000060.0, # +30s
        1700000090.0, # +30s
        1700000120.0, # +30s
        1700000150.0, # +30s
    ]
    
    # Run the analyzer on our fake data. It should find the low jitter.
    analyze_beaconing()


    # --- Test Case 2: Normal User Traffic (Irregular) ---
    print("\n[TEST 2] Simulating normal, irregular user traffic...")
    CONNECTION_TRACKER.clear()
    
    normal_conn = ('10.0.0.5', '222.111.222.111') # User -> Website
    
    # Create a list of timestamps that are random and irregular
    # This simulates a human browsing a website
    CONNECTION_TRACKER[normal_conn] = [
        1700000005.2, # Start
        1700000007.8, # User clicks something
        1700000015.1, # Reads for a bit...
        1700000016.3, # Another click
        1700000035.9, # Goes to another page
        1700000050.5, # Finishes
    ]
    
    # Run the analyzer. It should find high jitter and NOT fire an alert.
    analyze_beaconing()

    print("\n--- Beaconing Tests Complete ---")


# This makes the script runnable
if __name__ == "__main__":
    run_beaconing_tests()