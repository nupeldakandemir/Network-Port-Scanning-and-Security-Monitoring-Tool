# Network-Port-Scanning-and-Security-Monitoring-Tool

This project is an advanced command-line tool that monitors the state of ports on an IP address, performs security analysis with a rule-based Intrusion Detection System (IDS), tracks changes over time, and logs all findings to a central file.

## Main Features
 
* Port Scanning: Efficiently detects open ports within the specified range on the target IP.

* Rule-Based Security Analysis (IDS): Analyzes detected open ports for known vulnerabilities (Telnet, RDP), risks (open SSH ports), and suspicious activities (multiple open ports, malware ports).

* Change Detection: Instantly reports changes in network configuration (newly opened or closed ports) by comparing each scan with the previous one.

* Persistent Status Recording: Enables change tracking by storing the latest scan status for each IP in a .json file.

* Central Alert Logging: Provides retrospective analysis and auditing by recording all detected security alerts with a timestamp to the alerts.log file.

## Project Architecture
The project consists of three main Python files with separated tasks:

### 1) main.py (Orchestrator):

* Gets the target IP from the user.

* Starts the port scan using scanner.py.

* Triggers the security analysis using ids.py.

* Prints the results and changes to the screen.

* Save/read the scan results to a .json file.

### 2) scanner.py (Scanner):

* Performs the scan on the given IP and port range.

* Returns a list of open ports to main.py.

### 3) ids.py (Analysis Engine):

* Gets the list of open ports.

* Analyzes this list according to its own security rules.

* Returns the risks it finds as a list of alerts to main.py and records them in the alerts.log file.

