# Network Walks - Batch B084 (Week 1)
### Cybersecurity Lab Setup & Wireshark Traffic Analysis

This repository contains in-depth packet capture (PCAP) inspection, network reconnaissance detection, cleartext protocol vulnerability analysis, and VoIP signaling review completed across Week 1 hands-on labs with 100% verified assessment scores.

---

## 📋 Comprehensive Lab Documentation & Technical Notes

---

### LAB 3: IDENTIFY THE ATTACKER'S IP

* **Lab Milestone:** Lab 3 - Identify the Attacker's IP (Completed)
* **Final Score:** 100/100 (100%) (`04_lab3_results_100.png`)[cite: 2]

#### Tasks Breakdown & Technical Analysis:
* **Task 2 of 10 - Show Only Packets that Start a TCP Connection**
  * **Evidence:** `01_syn_flag_filter_displayed.png`[cite: 2]
  * **Filter Applied:** `tcp.flags.syn == 1`
  * **Result:** 73 displayed packets out of 309 total (23.6%)
  * **Technical Analysis:** The display filter isolated all frames with the SYN control flag enabled. This captures both client connection initiation requests (`[SYN]`) and server acknowledgments (`[SYN, ACK]`) during the initial TCP 3-way handshake phase.

* **Task 3 of 10 - Identify the Attacker's IP Address**
  * **Evidence:** `02_task3_attacker_ip_identified.png`[cite: 2]
  * **Filter Applied:** `tcp.flags.syn == 1 && tcp.flags.ack == 0`
  * **Identified Attacker IP:** `192.168.10.66`
  * **Key Takeaway:** While legitimate internal hosts generated occasional single connections, `192.168.10.66` initiated rapid, sequential connection probes across multiple ports, characteristic of network reconnaissance.

* **Task 6 of 10 - Identify Number of Ports Probed by Attacker**
  * **Evidence:** `03_task6_ports_probed_scan.png`[cite: 2]
  * **Filter Applied:** `ip.src == 192.168.10.66 and ip.dst == 192.168.10.20 and tcp.flags.syn == 1`
  * **Result:** 40 displayed packets (12.9% of total traffic)
  * **Technical Analysis:** By isolating outbound SYN frames from the attacker's IP (`192.168.10.66`) to the target server (`192.168.10.20`), exactly 40 connection requests were observed originating from a single source port (`52311`) across multiple target destination ports (e.g., 3306, 445, 22, 8080, 21, 3389, 139, 80), confirming active port scanning behavior.

* **Task 9 of 10 - Identify Number of Closed Ports**
  * **Calculation / Filter:** Out of 40 probed ports, 3 returned `[SYN, ACK]` and 37 returned `[RST, ACK]`.
  * **Result:** 37 closed ports.
  * **Technical Analysis:** Verified that the server rejected 37 out of 40 connection attempts by responding with RST/ACK flags, confirming that the remaining scanned services were not running or accessible.

* **Core Findings Summary:**
  * Inbound SYN flood/reconnaissance originated from attacker IP `192.168.10.66` targeting `192.168.10.20`.
  * Probe methodology utilized a fixed source port (`52311`) scanning 40 unique destination ports.
  * Server port assessment: 3 open ports (22 SSH, 80 HTTP, 443 HTTPS) returning `[SYN, ACK]`; 37 closed ports returning `[RST, ACK]`.

---

### LAB 4: FOLLOW TCP STREAM (PLAINTEXT CHAT)

* **Lab Milestone:** Lab 4 - Follow TCP Stream (Completed)
* **Final Score:** 100/100 (100%) (`06_lab4_results_100.png`)[cite: 2]

#### Tasks Breakdown & Technical Analysis:
* **Task 2 of 10 - Identify Non-Standard Plaintext Chat Port**
  * **Evidence:** `05_lab4_task2_chat_port_conversations.png`[cite: 2]
  * **Method:** Wireshark Statistics -> Conversations -> TCP tab
  * **Result:** Port `5000` (Stream ID: `5`)
  * **Technical Analysis:** While all other sessions communicate over standard web ports (80 HTTP / 443 HTTPS), host `192.168.10.45` established a distinct TCP session to `192.168.10.20` on destination port `5000` spanning 24 packets (1.7 kB), isolating the unencrypted office chat application.

* **Core Findings Summary:**
  * Analyzed capture containing mixed web (HTTP/HTTPS) and proprietary internal traffic.
  * Identified anomalous communication between `192.168.10.45` and `192.168.10.20` over non-standard port `5000` (Stream ID: `5`).
  * Leveraged Wireshark's "Follow TCP Stream" feature to reconstruct the full duplex conversation payload, exposing unencrypted, cleartext office chat transmissions directly readable from the packet stream.

---

### LAB 5: FOLLOW TCP STREAM, PART 2 (HIDDEN DATA)

* **Lab Milestone:** Lab 5 - Follow TCP Stream, Part 2 (Completed)
* **Final Score:** 100/100 (100%) (`09_lab5_results_100.png`)[cite: 2]

#### Tasks Breakdown & Technical Analysis:
* **Task 2 of 10 - Locate Page with Hidden Developer Note**
  * **Evidence:** `07_lab5_task2_hidden_comment_stream7.png`[cite: 2]
  * **Display Filter Used:** `tcp.stream eq 7` (or `http.request.method == "GET"`)
  * **Target Resource:** `/staff.html` (Host: `intranet.company.local`)
  * **Stream Analyzed:** TCP Stream 7
  * **Evidence Found:**
    * HTTP GET request fetched `/staff.html`.
    * Server response (`HTTP/1.1 200 OK`) returned HTML payload containing an unstripped comment:
      `<!-- IT note: backup server is 192.168.10.77, access code Falcon-9921. Remove before publishing. -->`
  * **Technical Analysis:** Highlighted the risk of cleartext HTTP and information leakage in production code. Sensitive operational details (internal backup IP address and access credentials) were exposed within client-side HTML source comments because the transport was unencrypted and the comment was not purged prior to deployment.

* **Task 9 of 10 - Identify Plaintext Downloaded File**
  * **Evidence:** `08_lab5_task9_plaintext_download_stream11.png`[cite: 2]
  * **Filter Applied:** `http.request.uri contains "download"` (Stream: `tcp.stream eq 11`)
  * **Extracted Filename:** `report.txt`
  * **Host / Path:** `intranet.company.local/download/report.txt`
  * **Recovered Payload Content:**
    * `Quarterly report`
    * `Total sales: 48200`
    * `Prepared by: Nadia`
    * `Status: Final`
  * **Technical Analysis:** Evaluated unencrypted file transfers over standard HTTP. By filtering on URI patterns matching download endpoints and reconstructing the TCP stream, the full plaintext content of the corporate sales report was recovered in cleartext without needing decryption keys.

* **Core Findings Summary:**
  * Inspected unencrypted internal web traffic (HTTP over TCP port 80) across intranet sessions.
  * Discovered sensitive credentials and internal network layout exposed via unstripped HTML developer comments on `/staff.html` (Stream 7: backup IP `192.168.10.77` and access code `Falcon-9921`).
  * Extracted cleartext business data from unencrypted downloads via URI filtering (`/download/report.txt` in Stream 11) demonstrating lack of transport layer protection.

---

### LAB 6: HTTP PLAIN TEXT CREDENTIALS

* **Lab Milestone:** Lab 6 - HTTP Plain Text Credentials (Completed)
* **Score:** 100/100 marks (100% Outstanding) (`12_lab6_results_100.png`)[cite: 2]

#### Tasks Breakdown & Technical Analysis:
* **Task 4 of 10 - Identify Destination Page Path for Form Submission**
  * **Evidence:** `10_lab6_task4_http_login_form_stream4.png`[cite: 2]
  * **Filter / Stream Analyzed:** `tcp.stream eq 4`
  * **Host:** `portal.company.local`
  * **Destination Path:** `/login`
  * **Evidence Found:**
    * Initial `GET /login` returns HTML containing: `<form method="post" action="/login">`
    * Follow-up request issues: `POST /login HTTP/1.1`
    * `Content-Type: application/x-www-form-urlencoded`
  * **Technical Analysis:** The web application serves an unencrypted authentication form over plaintext HTTP (port 80). The HTML form action targets the endpoint `/login` using the HTTP POST method, setting up cleartext credential exposure in the subsequent request payload.

* **Task 8 of 10 - Intercept Successful Authentication Credentials**
  * **Evidence:** `11_lab6_task8_cleartext_credentials_stream4.png`[cite: 2]
  * **Filter / Stream Analyzed:** `tcp.stream eq 4`
  * **Intercepted Credentials:**
    * **Username:** `farhan.k`
    * **Initial Failed Password:** `Mango2025` (Response: "Invalid username or password")
    * **Successful Second Password:** `Mango#2026` (Response: "Welcome back, farhan.k")
  * **Technical Analysis:** Reconstructed the TCP stream of an unencrypted HTTP POST submission. Because the application lacked TLS/HTTPS encryption, credentials transmitted via the `application/x-www-form-urlencoded` body were fully exposed in plaintext across the network wire. Both the failed login attempt and the successful authentication token were recovered directly without needing brute-force attacks or decryption keys.

* **Completed Tasks Breakdown:**
  * Task 1: Traffic Capture Initialization
  * Task 2: Protocol Identification (HTTP / Port 80)
  * Task 3: Form Method Identification (POST)
  * Task 4: Login Endpoint Target (`/login`)
  * Task 5: Client Workstation Identification
  * Task 6: Authentication Attempts Count (2 attempts analyzed)
  * Task 7: Harvested Account Username (`farhan.k`)
  * Task 8: Harvested Account Passwords (Failed: `Mango2025` | Success: `Mango#2026`)
  * Task 9: Packet Details Layer Inspection (HTML Form URL Encoded)
  * Task 10: Remediation Control (Enforce HTTPS / TLS encryption on Port 443)

* **Final Takeaway:** Unencrypted HTTP transmits sensitive form payloads without cryptographic protection. Anyone with network wiretap or passive sniffing access can extract authentication credentials in plaintext. Remediation mandates deprecating cleartext HTTP portals in favor of TLS (HTTPS), accompanied by HSTS enforcement and MFA.

---

### LAB 7: BRUTE FORCE CATCH (FTP RECON & AUTH)

* **Lab Milestone:** Lab 7 - Brute Force Catch (Completed)
* **Final Score:** 100/100 marks (100% Outstanding) (`14_lab7_results_100.png`)[cite: 2]

#### Tasks Breakdown & Technical Analysis:
* **Task 7 of 10 - Quantify Failed Authentication Attempts**
  * **Evidence:** `13_lab7_task7_ftp_failed_logins_count.png`[cite: 2]
  * **Display Filter Applied:** `ftp.response.code == 530`
  * **Targeted Service:** File Transfer Protocol (FTP / Port 21)
  * **Involved Hosts:**
    * Server (FTP Responder): `192.168.10.20`
    * Attacking Client (Requester): `192.168.10.66`
  * **Quantitative Evidence:**
    * Total Capture Size: 369 packets
    * Filter Matches: 24 displayed packets (6.5% of total capture)
    * Response Diagnostic: `Response: 530 Login incorrect`
  * **Technical Analysis:** Utilized application-layer response filtering to isolate authentication rejection responses. The presence of 24 rapid, sequential 530 failure codes originating from `192.168.10.66` against the internal FTP server confirms an automated dictionary or brute-force credential stuffing attack.

* **Completed Tasks Breakdown:**
  * Task 1: Traffic Capture Initialization
  * Task 2: Protocol Identification via Hierarchy (FTP / Port 21)
  * Task 3: Target Server Identification (`192.168.10.20`)
  * Task 4: Attacker Source IP Identification (`192.168.10.66`)
  * Task 5: Targeted Account Username Extraction
  * Task 6: FTP Authentication Failure Code Identification (Response 530)
  * Task 7: Quantified Failed Login Attempts (24 rejections via `ftp.response.code == 530`)
  * Task 8: FTP Authentication Success Code Identification (Response 230)
  * Task 9: Compromised / Working Password Recovery
  * Task 10: Attack Classification (Brute Force / Credential Guessing Attack)

* **Technical Analysis:** Leveraged Wireshark Protocol Hierarchy Statistics and explicit application-layer response filters (FTP codes 530 vs. 230) to reconstruct an active credential-stuffing sequence. Correlated high-frequency authentication rejections originating from `192.168.10.66` against `192.168.10.20`, pinpointing the exact transition from repeated automated failures to successful compromise.

---

### LAB 8: VOIP CALL REPLAY

* **Lab Milestone:** Lab 8 - VoIP Call Replay (Completed)
* **Score:** 100/100 marks (100% Outstanding) (`lab8results.png` / `16_lab8_results_100.png`)[cite: 2]

#### Tasks Breakdown & Technical Analysis:
* **Task 4 of 10 - Identify Caller Extension Number from SIP INVITE**
  * **Evidence:** `15_lab8_task4_sip_invite_caller_101.png`[cite: 2]
  * **Display Filter Applied:** `sip.Method == "INVITE"`
  * **Packet Analyzed:** Packet 51 (SIP INVITE)
  * **Signaling Endpoint Breakdown:**
    * Calling Host (Source): `192.168.10.45:5060`
    * Caller Extension / Identity: `101` (`Contact: <sip:101@192.168.10.45:5060>`)
    * Recipient Target (Destination): `192.168.10.52:5060`
    * Recipient Extension / Identity: `202` (`To: "Sara" <sip:202@192.168.10.52>`)
    * Client User-Agent: `NW-Phone/1.0`
  * **Technical Analysis:** Inspected the SIP signaling initiation sequence using the method filter `sip.Method == "INVITE"`. While the Request-URI and "To" header identify the dialed target (Sara at extension 202), the originating endpoint is confirmed via the "Contact" header URI parameter revealing extension 101 originating from `192.168.10.45`.

* **Completed Tasks Breakdown:**
  * Task 1: Traffic Capture Initialization
  * Task 2: Call Setup Signaling Protocol (SIP / UDP 5060)
  * Task 3: Voice Media Stream Protocol (RTP)
  * Task 4: Originating Caller Extension (101 via Contact header)
  * Task 5: Caller Name Identification
  * Task 6: Audio Codec Identification (G.711 / PCMU/PCMA)
  * Task 7: Call Recipient Identification (Sara at Ext 202)
  * Task 8: Intercepted Payment Card Number
  * Task 9: Intercepted Expiration Date
  * Task 10: Security Remediation Control (Implement SRTP for media encryption & SIPS/TLS for signaling)

* **Technical Analysis:** Leveraged Wireshark's VoIP Call Analysis and RTP stream playback capabilities to reconstruct an unencrypted voice transmission. Because unencrypted RTP and plaintext SIP signaling were employed, both session metadata (caller/callee endpoints, extensions, User-Agent) and sensitive spoken payload information (financial payment data) were intercepted and extracted from the cleartext audio payload. Remediation mandates deploying Secure Real-Time Transport Protocol (SRTP) alongside SIP over TLS (SIPS).

---

## 🛠 Key Tools & Protocols
* **Primary Tool:** Wireshark
* **Protocols Inspected:** TCP, SYN, HTTP, FTP, SIP, RTP, VoIP
* **Core Investigation Capabilities:** Handshake Analysis, Port Scan Reconstruction, Payload Stream Assembly, Response Code Enumeration, Cleartext Vulnerability Assessment
