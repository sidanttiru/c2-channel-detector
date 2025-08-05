# Command and Control Channel Detector
## A Real-Time Network Analysis and Threat Detection Dashboard

**Author:** Sidant Tiru
**Date:** July 2025
**Tools Used:** Python, Scapy, Flask, NumPy, VirtualBox, Kali Linux

---

### 1. Summary

This project is my attempt at a functional network security tool, developed in Python. It is designed to detect command and control (C2) channels commonly used by malware and advanced persistent threats (APTs). The tool actively monitors network traffic and applies statistical analysis to identify anomalous patterns that violate traditional signature-based detection. Key functionalities include the successful identification of DNS tunneling via entropy analysis, ICMP tunneling through payload size inspection, and C2 beaconing by measuring connection interval jitter. All alerts are displayed in a real-time, interactive web dashboard built with Flask, which includes sniffer controls for live session management.

---

### 2. Introduction & Objectives

Adversaries often hide their C2 traffic within legitimate-looking protocols to evade detection. Standard firewalls may permit DNS and ICMP traffic, creating an opportunity for data exfiltration and remote control. This project aimed to build a tool to reveal these tactics.

* **Objective 1:** Develop a module to detect **DNS tunneling** by analyzing query length and entropy.
* **Objective 2:** Implement a module to detect **ICMP tunneling** by flagging packets with abnormally large payloads.
* **Objective 3:** Create a stateful analysis module to identify **C2 beaconing** by tracking connection timestamps and calculating jitter.
* **Objective 4:** Build a user-friendly dashboard to visualize threats and provide live session management.

---

### 3. Methodology

The detection methodology is based on establishing a baseline for normal protocol behavior and flagging statistical outliers.

1.  **Packet Interception:** The core of this tool is a packet sniffer built with the **Scapy** library. It can capture live traffic from a default interface, a specified network interface, or analyze pre-recorded traffic from a `.pcap` file for forensic analysis.
2.  **DNS Tunneling Analysis:** All DNS queries are inspected. An alert is triggered if a query meets one of the following checks:
    * **High Entropy:** The Shannon entropy of the query name exceeds a threshold of 3.2, indicating a high degree of randomness, characteristic of encoded data.
    * **Abnormal Length:** The query name is longer than 100 characters. Traffic exceeding this threshold is a strong signal of malicious activity. This threshold will avoid false positives.
3.  **ICMP Tunneling Analysis:** ICMP echo-request and echo-reply packets (types 8 and 0) are monitored. An alert is triggered if the packet's payload size exceeds 128 bytes, suggesting it is being used to carry data rather than for simple connectivity checks.
4.  **C2 Beaconing Analysis:** The tool performs stateful analysis of connection patterns over time.
    * Logs timestamps for all `(source_ip, destination_ip)` communication pairs.
    * Every 60 seconds, it calculates the standard deviation (**jitter**) of the time intervals between packets for each connection.
    * A connection with a jitter of less than 1 second is flagged as a potential machine-like C2 beacon.

---

### 4. Implementation & Results

The analysis logic was integrated into a single application with a Flask-based web dashboard for real-time visualization and session control. The tool's effectiveness was verified by simulating each of the three threat types within both the local VS code terminal and an isolated Kali Linux VM.

| Threat Type       | Simulation Method                         | Expected Alert                                           |
| :---------------- | :---------------------------------------- | :------------------------------------------------------- |
| **DNS Tunneling** | `nslookup` of a long, random hostname & `dig` @(IP) of a long, random hostname (in VM) | `Suspiciously Long DNS Query` and `High Entropy DNS Query` |
| **ICMP Tunneling**| `ping` command with a large data payload (`-s 512`) | `Large ICMP Payload Detected`                            |
| **C2 Beaconing** | `curl` command in a timed `while` loop & `curl` command in timed `while` loop within Bash script (in VM) | `Potential C2 Beaconing Detected`                        |

The application includes controls to pause and resume the live sniffer, as well as a button to clear the alerts log, providing a fully interactive user experience.

---

### 5. Conclusion & Future Work

This project demonstrates how statistical analysis can be applied to detect evasive threats hidden in network metadata. By using methods such as inspecting DNS query entropy, checking ICMP payload size, and calculating jitter, I gained extremely valuable insight into a red-teaming mindset in order to build defenses as a blue-teamer.

Future improvements include:

* **Porting Critical Components:** Moving the performance-critical packet processing loop from Python to Go to significantly increase throughput.
* **Encrypted Traffic Analysis:** Adding a module to analyze TLS/SSL handshakes for suspicious attributes, such as unusual cipher suites or self-signed certificates.
* **Machine Learning Integration:** Developing a model to learn a baseline of "normal" network behavior and flag deviations, moving beyond hardcoded thresholds.

---

### Appendix: How to Run the Tool

This project requires Python 3.13.5 and the packages listed in `requirements.txt`.

**1. Clone and Setup Environment**
# Clone the repository
`git clone https://github.com/sidanttiru/c2-channel-detector.git`

cd c2-detector

# Create and activate a virtual environment
`python -m venv venv`
`source venv/bin/activate`

# Install dependencies
`pip install -r requirements.txt`

# Run application
Open IDE as administrator and run `python app.py` OR if IDE not opened as admin, run `sudo python app.py`
