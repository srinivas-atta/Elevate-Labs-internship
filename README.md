# Srinivas Atta

# Elevate Labs – Cyber Security Internship  
**By:** Ministry of MSME, Govt. of India  

---

## Task 1: Scan Your Local Network for Open Ports

### Objective
Discover and list open ports in your local network to understand network service exposure.

### Tools Required
- Nmap (free)  
- Wireshark (optional)

### Execution Steps / Guide
1. Install **Nmap**.
2. Identify your local network IP range (e.g., `192.168.1.0/24`).
3. Run a TCP SYN scan:  
nmap -sS 192.168.1.0/24

text
4. Note down active IPs and open ports.
5. Optionally capture packets using Wireshark.
6. Research discovered services and potential risks.
7. Save scan results for documentation.

### Findings / Results
- Multiple devices found with open ports including HTTP (80), SSH (22), MySQL (3306), Telnet (23).
- Screenshots and logs taken for evidence.

### Security Analysis
Open ports may expose devices to unauthorized access. Insecure services like Telnet are especially risky.

### Recommendations
- Disable unused services and close unnecessary ports.
- Use firewalls to restrict access.
- Prefer secure services (e.g., SSH over Telnet).
- Keep all systems updated.

### Outcome
- Gained skill in network scanning with Nmap.
- Understood exposure and risks from open ports.

### Key Concepts
- Port scanning
- TCP SYN scan
- IP ranges
- Network reconnaissance
- Open ports security

---

## Task 2: Analyze a Phishing Email Sample

### Objective
Identify phishing characteristics in a suspicious email sample to enhance email threat analysis skills.

### Tools Required
- Email client or saved email file (text format)  
- Free online header analyzer (e.g., MXToolbox, Google Admin Toolbox)

### Execution Steps / Guide
1. Obtain a phishing email.
2. Examine sender address for spoofing or misspellings.
3. Analyze headers for SPF/DKIM/DMARC fails, Return-Path mismatches, or suspicious IPs.
4. Hover over links for mismatched domains.
5. Inspect risky attachments (e.g., .exe, .zip, .docm).
6. Note urgency or scare tactics.
7. Check for typos or awkward English.
8. Summarize all phishing indicators.

### Findings / Results
- Sender spoofed (e.g., `support@micros0ft.com`)
- SPF failure and Return-Path mismatch.
- Suspicious links (e.g., PayPal text pointing to `paypl-secure-login[.]ru`)
- Malware attachment (`Invoice.exe`)
- Threat/urgency language to coerce response.
- Multiple spelling/grammar issues.
- Social engineering tactics deployed.

### Security Analysis
Combines spoofed domains, malicious links, and fear tactics to maximize click-through and exploitation chances.

### Recommendations
- Verify sender and domain authenticity before clicking.
- Train users to recognize phishing red flags.
- Implement SPF/DKIM/DMARC.
- Block/scan suspicious attachments.

### Outcome
- Practiced real-world phishing detection.
- Analyzed email headers and attack methods.
- Improved understanding of social engineering.

### Key Concepts
- Phishing  
- Email spoofing  
- Header analysis  
- Social engineering  
- Threat detection

---

## Task 3: Perform a Basic Vulnerability Scan on Your PC

### Objective
Use vulnerability scanners to identify weaknesses and learn risk analysis.

### Tools Required
- OpenVAS Community Edition or Nessus Essentials (free for personal use)

### Execution Steps / Guide
1. Install OpenVAS or Nessus Essentials.
2. Target scan to local machine (`localhost`).
3. Run “Full and Fast” scan.
4. Review generated report.
5. Highlight found issues by severity.
6. Research vulnerabilities and remediation.

### Findings / Results
- Outdated OpenSSH version (potential RCE).
- Unpatched OS vulnerabilities.
- Open and unused network ports (e.g., FTP, RDP).
- Screenshots taken of key vulnerabilities.

### Security Analysis
Combination of outdated software and unnecessary open ports increases risk of remote exploitation or privilege escalation.

### Recommendations
- Patch/update all software and OS regularly.
- Disable or close unnecessary network services and ports.
- Enable automatic updates where possible.
- Schedule monthly scans.

### Outcome
- Practical experience with vulnerability scanners.
- Learned CVE/CVSS-based risk prioritization.
- Understood the importance of patching.

### Key Concepts
- Vulnerability scanning  
- Risk assessment  
- CVSS scores  
- Remediation  
- Security best practices

---

## Task 4: Setup and Use a Firewall on Windows/Linux

### Objective
Configure and test firewall rules to manage network traffic and increase security.

### Tools Required
- Windows Firewall (built-in)
- UFW (Uncomplicated Firewall) on Linux

### Execution Steps / Guide
1. Open firewall tool:  
- Windows: “Windows Defender Firewall with Advanced Security”  
- Linux:  
  ```
  sudo apt install ufw
  ```
2. List current rules:  
- Windows:  
  ```
  netsh advfirewall firewall show rule name=all
  ```
- Linux:  
  ```
  sudo ufw status numbered
  ```
3. Block Telnet port 23:  
- Windows: Create inbound rule → TCP port 23 → Block.  
- Linux:  
  ```
  sudo ufw deny 23
  ```
4. Test the rule by attempting a connection.
5. Allow SSH on Linux:  
sudo ufw allow 22

text
6. Remove test block:  
- Linux:  
  ```
  sudo ufw delete deny 23
  ```
7. Document steps and screenshot settings.

### Findings / Results
- Successfully blocked Telnet port.
- Verified with failed connection attempts.
- Allowed SSH (secure access) while Telnet was blocked.
- Configuration restored after testing.

### Security Analysis
Properly configured firewall rules significantly reduce attack vectors. Blocking insecure ports (Telnet) and allowing only what’s needed (SSH) is best practice.

### Recommendations
- Always keep Telnet disabled.
- Regularly review firewall rules and disable unused ports/services.
- Use logging and pair firewall with IDS/IPS.
- Document all config changes.

### Outcome
- Configured and tested firewall rules on both OSes.
- Practiced restricting insecure traffic and authorizing secure services.
- Learned firewall concepts and their impact on system security.

### Key Concepts
- Firewall rule configuration  
- Network traffic filtering  
- Service and port management  
- UFW basics  
- Windows Firewall management
