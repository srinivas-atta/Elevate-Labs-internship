# Srinivas Atta

# Elevate Labs – Cyber Security Internship  
**By:** Ministry of MSME, Govt. of India  

---

## Task 1: Scan Your Local Network for Open Ports

### Objective
Discover and list open ports in your local network using Nmap to understand network exposure.

### Tools Required
- Nmap (free)  
- Wireshark (optional)

### Execution Steps / Guide
1. Install Nmap.
2. Identify your local network IP range (`192.168.1.0/24`).
3. Run a TCP SYN scan:
nmap -sS 192.168.1.0/24

text
4. Note active IPs and open ports.
5. Optionally use Wireshark for packet analysis.
6. Research detected services and their risks.
7. Save results for documentation.

### Findings / Results
- Multiple devices/services detected (e.g., HTTP, SSH, MySQL, Telnet).
- Screenshots and scan logs attached.

### Security Analysis
Open ports may expose devices to attack; insecure services like Telnet pose additional risks.

### Recommendations
- Disable unused services/ports.
- Use firewalls to control access.
- Prefer secure protocols (SSH over Telnet).
- Keep systems updated.

### Outcome
- Learned basic port scanning and exposure assessment.

### Key Concepts
- Port scanning
- TCP SYN scan
- IP ranges
- Network reconnaissance
- Open ports security

---

## Task 2: Analyze a Phishing Email Sample

### Objective
Identify phishing characteristics in a suspicious email to improve threat analysis skills.

### Tools Required
- Email client/text file  
- Online header analyzer (e.g., MXToolbox)

### Execution Steps / Guide
1. Obtain a phishing email sample.
2. Check sender address for spoofing/misspellings.
3. Analyze headers for SPF/DKIM/DMARC and Return-Path.
4. Hover over links for mismatched domains.
5. Inspect attachments for risk.
6. Note urgency/fear tactics.
7. Summarize all phishing indicators.

### Findings / Results
- Spoofed sender domain.
- SPF failure and Return-Path mismatch.
- Suspicious links.
- Malware attachment.
- Urgent/threatening language.
- Grammar issues.
- Social engineering tactics.

### Security Analysis
Combined tactics enhance exploitation success against targets.

### Recommendations
- Verify sender authenticity.
- Train users to spot phishing.
- Enforce SPF/DKIM/DMARC.
- Block/scan risky attachments.

### Outcome
- Developed real-world phishing detection and analysis.

### Key Concepts
- Phishing
- Email spoofing
- Header analysis
- Social engineering
- Threat detection

---

## Task 3: Perform a Basic Vulnerability Scan on Your PC

### Objective
Use vulnerability scanners to identify and prioritize risks.

### Tools Required
- OpenVAS or Nessus Essentials (free)

### Execution Steps / Guide
1. Install scanner.
2. Set scan target (localhost).
3. Run full scan.
4. Review report for issues.
5. Research and note remediations.

### Findings / Results
- Outdated software detected.
- Unpatched system vulnerabilities.
- Open ports/services present.

### Security Analysis
Unpatched software and exposed services increase exploitation risk.

### Recommendations
- Apply all updates/patches.
- Disable unused services.
- Schedule regular scans.

### Outcome
- Learned practical vulnerability scanning and risk mitigation.

### Key Concepts
- Vulnerability scanning
- CVSS ratings
- Risk prioritization
- Remediation
- Security best practices

---

## Task 4: Setup and Use a Firewall on Windows/Linux

### Objective
Configure and test firewall rules to secure network traffic.

### Tools Required
- Windows Firewall
- UFW (Linux)

### Execution Steps / Guide
1. Open firewall tool (Windows/Linux).
2. List current rules.
3. Block Telnet port 23.
4. Test rule for effectiveness.
5. Allow SSH on Linux.
6. Remove test block rule.
7. Document steps/screenshots.

### Findings / Results
- Blocked Telnet.
- Allowed SSH.
- Restored firewall setup.

### Security Analysis
Well-configured firewalls reduce attack vectors via unused or insecure ports (like Telnet).

### Recommendations
- Disable Telnet.
- Review firewall rules regularly.
- Pair with IDS/IPS for enhanced security.
- Log all firewall changes.

### Outcome
- Acquired firewall management skills.

### Key Concepts
- Firewall configuration
- Traffic filtering
- Ports/protocols
- UFW & Windows Firewall

---

## Task 5: Capture and Analyze Network Traffic Using Wireshark

### Objective
Capture live packets and identify major protocols for hands-on network analysis.

### Tools Required
- Wireshark (free)

### Execution Steps / Guide
1. Install Wireshark.
2. Start packet capture.
3. Generate network traffic (browsing, ping).
4. Filter and analyze HTTP, DNS, TCP packets.
5. Export .pcap file.
6. Summarize findings.

### Findings / Results
- Identified protocols: HTTP, DNS, TCP.
- Packet details noted (headers, queries).
- Screenshots attached.

### Security Analysis
Traffic capture reveals unencrypted data and protocol flows; useful for diagnosis but shows privacy risks.

### Recommendations
- Prefer encrypted protocols.
- Use filters for focused analysis.
- Monitor traffic for threats.

### Outcome
- Practiced packet capture and protocol ID.

### Key Concepts
- Packet capture
- Protocol analysis
- TCP/IP
- Wireshark filtering

---

## Task 6: Create a Strong Password and Evaluate Its Strength

### Objective
Understand password strength characteristics and test in online checkers.

### Tools Required
- Online password strength checker (e.g., passwordmeter.com)

### Execution Steps / Guide
1. Create multiple sample passwords with varying complexity.
2. Test each password.
3. Note feedback and crack time.
4. Summarize findings and best practices.

### Findings / Results

| Example Password  | Length | Components           | Strength  | Estimated Crack Time         | Tool Feedback                     |
|-------------------|--------|----------------------|-----------|------------------------------|-----------------------------------|
| password123       | 11     | Lowercase, Numbers   | Weak      | Few seconds                  | Common word, easy to guess        |
| Pa$$w0rd!         | 9      | Mixed characters     | Medium    | Minutes/hours                | Slightly better, still predictable|
| gR7@xLpQ!zK#9%t   | 15     | Mixed, Random        | Very Strong| Centuries/Millions of years  | Complex and long                  |

### Security Analysis
Complex, longer passwords resist brute force and dictionary attacks.

### Recommendations
- Minimum 12–16 characters.
- Mix cases, numbers, symbols.
- Use passphrases.
- Store in a password manager.
- Enable multi-factor authentication.

### Outcome
- Learned password security fundamentals.

### Key Concepts
- Password strength
- Brute force/dictionary attack
- Authentication
- Best practices

---

## Task 7: Identify and Remove Suspicious Browser Extensions

### Objective
Spot and remove dangerous or unused browser extensions.

### Tools Required
- Chrome/Firefox browser extension manager

### Execution Steps / Guide
1. Open extensions/add-ons manager.
2. Review installed extensions, permissions, and reviews.
3. Remove suspicious/unnecessary extensions.
4. Restart browser, check improvement.
5. Document extensions removed.

### Findings / Results
- Removed two extensions with high-risk permissions/untrustworthy publishers.
- Kept only reputable, well-reviewed extensions.

### Security Analysis
Malicious extensions may steal data, inject ads, or serve as backdoors.

### Recommendations
- Install only from official sources.
- Regularly review and remove unused or risky extensions.
- Keep extensions updated.

### Outcome
- Developed browser security management skills.

### Key Concepts
- Extension permissions
- Browser malware
- Safe browsing practices

---

## Task 8: Setup and Test a VPN for Privacy Protection

### Objective
Set up a VPN, confirm privacy benefits, and test its practical effects.

### Tools Required
- Free VPN client (ProtonVPN or Windscribe)
- IP checker (whatismyipaddress.com)

### Execution Steps / Guide
1. Choose and install reputable VPN.
2. Connect and verify IP change.
3. Browse websites, confirm encryption.
4. Disconnect VPN and compare speed/IP.
5. Research VPN security features.

### Findings / Results
- VPN installed and connected.
- Public IP changed; traffic encrypted.
- Speed slightly affected; privacy enhanced.

### Security Analysis
VPN protects web traffic from local/network surveillance but does not provide total anonymity or stop all threats.

### Recommendations
- Use trusted, no-log VPNs.
- Verify DNS/IP leak protection.
- Combine VPN with other security tools.

### Outcome
- Hands-on VPN usage and privacy understanding.

### Key Concepts
- VPN encryption
- Tunneling protocols
- IP masking
- Privacy tools
