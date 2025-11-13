# Network Security Monitoring Lab: Zeek and Suricata

## Overview
I analysed a PCAP from malware-traffic-analysis.net, specifically the 2025-06-13 “Traffic Analysis Exercise: It’s a Trap!” dataset. For my local workspace I renamed the file to sample.pcap. The analysis used Zeek 6.0 and Suricata 8.0.1 on a REMnux workstation to explore how protocol aware telemetry and signature based alerts expose suspicious behaviour. This study forms the first part of my SOC visibility triad before moving on to cloud SIEM detection. Detailed step by step logs and screenshots are available in the case study at ./docs/CASESTUDY.md.

## Objectives
- Build a reproducible offline workflow for Zeek and Suricata analysis.
- Distinguish malicious or suspicious patterns (WPAD, LDAP, HTTP beacons) from typical Microsoft background traffic.
- Correlate Zeek telemetry with Suricata alerts for investigative prioritisation.
- Capture artefacts and screenshots for portfolio evidence.

## Environment and Tools
- Host platform: REMnux virtual machine configured for network forensics.
- Dataset: Originally 2025-06-13-traffic-analysis-exercise.pcap from Malware-Traffic-Analysis.net (LAN segment 10.6.13.0/24, domain massfriction.com), locally renamed to ~/nsm_lab/pcaps/sample.pcap. Source: https://www.malware-traffic-analysis.net/2025/06/13/index.html
- Tools: Zeek 6.0, Suricata 8.0.1, and Unix utilities (jq, column, egrep, head, mkdir).
- Evidence storage: Directories ./artefacts/ and ./screenshots/ for logs and visuals.

## Workflow
1. Zeek processing  
   ```bash
   mkdir -p zeek
   cd zeek
   zeek -r ../pcaps/sample.pcap -C
   ```
2. DNS triage for WPAD LDAP and Microsoft lookups  
   ```bash
   column -t -s $'\t' dns.log | egrep "wpad|ldap|desktop|msftconnect|msftncsi|wns" | head -n 12
   ```
3. Suricata workspace  
   ```bash
   mkdir -p ~/nsm_lab/suricata
   ```
4. Offline Suricata execution  
   ```bash
   suricata -r ~/nsm_lab/pcaps/sample.pcap -l ~/nsm_lab/suricata
   ```
5. Alert metadata review  
   ```bash
   jq 'select(.event_type=="alert") | {time:.timestamp, sig:.alert.signature, src:.src_ip, dst:.dst_ip, proto:.proto}' \
     ~/nsm_lab/suricata/eve.json | head -n 10
   ```
6. Archive evidence (“./artefacts/”, “./screenshots/”).

## What Actually Happened
- Tuning Suricata proved difficult as I iterated multiple times until alerts appeared meaningfully.
- Zeek logs were voluminous; the breakthrough occurred when I applied keyword filtering to DNS logs for WPAD and LDAP and found actionable indicators.
- I understood how packet level telemetry supports detection workflows; the insights from this lab helped when analysing SIEM alerts in the next phase.
- Completing this phase provided a strong foundation for the next part of my SOC triad portfolio.

## Key Findings
- Zeek DNS logs showed repeated WPAD lookups for wpad.massfriction.com suggesting proxy auto discovery exploitation.
- _ldap._tcp SRV queries surfaced, showing probable Active Directory reconnaissance from the infected host.
- Suricata flagged outbound HTTP traffic from 10.6.13.133 to 23.192.223.206:80 supporting suspicion of exfiltration behaviour.
- Genuine Microsoft connectivity checks (msftconnecttest.com dns.msftncsi.com wns.windows.com) were present and documented to avoid misclassification of benign flows.

## MITRE ATT&CK Mapping
| Technique | ID        | Evidence                                                                                  |
|-----------|-----------|-------------------------------------------------------------------------------------------|
| Application Layer Protocol DNS             | T1071.004 | WPAD lookups in Zeek DNS logs (`./screenshots/02-zeek-dnslog.png`)                       |
| Remote System Discovery                    | T1018     | LDAP SRV query observed (`./screenshots/02-zeek-dnslog.png`)                              |
| Application Layer Protocol Web             | T1071.001 | Suricata HTTP alert for outbound to 23.192.223.206 (`./screenshots/01-suricata-alert.png`) |
| Obfuscated or Encoded Files or Information | T1027     | Suricata signature referencing encoded payloads (`./screenshots/01-suricata-alert.png`)   |

## Lessons Learned
- Filtering DNS telemetry via keywords rapidly surfaces adversary behaviour without overwhelming data volumes.
- Segregating Zeek and Suricata workspaces prevented artefact collisions when iterating.
- Combining telemetry and alerts strengthened prioritisation when escalating investigative leads.
- Documenting legitimate baseline traffic prevented incorrect attribution of benign behaviour.

## Next Steps
- Incorporate the Emerging Threats ruleset into Suricata and craft custom detection logic for WPAD and LDAP anomalies.
- Feed Zeek and Suricata logs into a dashboard solution (ELK or Security Onion) to cross correlate more efficiently.
- Automate PCAP replay alert extraction and packaging via Python scripts for future analysis.

## Resources That Helped
- YouTube tutorials on Zeek log architecture and Suricata offline processing.
- Peer forum discussions which addressed Suricata rule tuning and log directory configuration.
- Dataset documentation at Malware-Traffic-Analysis.net (June 2025) with LAN and domain metadata.

## Actual Timeline
- September 2024: Setup of REMnux and initial Zeek processing.
- October 2024: Suricata rule tuning and workspace configuration.
- November 2024: DNS triage, HTTP alert correlation and capture of key findings.
- December 2024: Transition into the Microsoft Sentinel lab with the lessons carried forward.

## Skills Demonstrated
- Offline PCAP replay and analysis using Zeek.
- Suricata configuration for alert generation in a lab environment.
- Correlating DNS LDAP and HTTP telemetry with IDS alerts.
- MITRE ATT&CK application in network forensic workflows.
- Structured evidence capture and professional documentation.

## Author
Ayrton Cook  
BSc Computer Science with Year in Industry  
Cybersecurity Focus  
University of East Anglia

[Back to Portfolio Index](./README.md)
