# Cyber Defense Lab

A comprehensive portfolio of 10 practical cybersecurity defensive tools, traffic analyzers, and security utility applications.

## Projects Overview

| # | Project Directory | Stack | Description |
|---|-------------------|-------|-------------|
| 01 | [01-websec-scanner](./01-websec-scanner) | Python, Flask, Requests, BS4 | Lightweight web security scanner checking for missing headers, insecure cookies, exposed endpoints, and basic vulnerability vectors. |
| 02 | [02-phishing-simulator](./02-phishing-simulator) | Python, Flask / HTML | Educational phishing simulator demonstrating email red flags, link mismatch detection, and scoring mechanisms. |
| 03 | [03-ransomware-detector](./03-ransomware-detector) | Python, Watchdog, Logging | Defensive monitor tracking directory activity for rapid file modifications, mass renaming, and entropy changes. |
| 04 | [04-password-analyzer](./04-password-analyzer) | Python, Streamlit / Tkinter | Password evaluation utility measuring entropy, character diversity, and pattern vulnerability with secure suggestions. |
| 05 | [05-pcap-analyzer](./05-pcap-analyzer) | Python, Scapy / PyShark | Network traffic analysis tool reading PCAP captures and generating protocol, IP, port, and anomaly statistics. |
| 06 | [06-simple-nids](./06-simple-nids) | Python, Scapy | Rule-based Network Intrusion Detection System detecting multi-port scanning and abnormal traffic rates. |
| 07 | [07-file-integrity-monitor](./07-file-integrity-monitor) | Python, Hashlib | File Integrity Monitoring (FIM) utility tracking file modifications, deletions, and replacements via SHA-256 baseline hashing. |
| 08 | [08-log-analyzer](./08-log-analyzer) | Python, Regex, Pandas | Server and application log parser pinpointing failed authentication attempts, suspicious IP patterns, and security events. |
| 09 | [09-crypto-utility](./09-crypto-utility) | Python, Cryptography | Utility for secure file encryption and decryption using verified standard cryptographic primitives. |
| 10 | [10-header-analyzer](./10-header-analyzer) | Python, Requests, Flask | HTTP security response header analyzer verifying CSP, HSTS, X-Content-Type-Options, and providing scoring recommendations. |

## License
Distributed under the MIT License.
