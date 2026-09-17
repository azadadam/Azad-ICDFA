# Lab 5 — ARP Poisoning Forensics  
   
## Assignment Information  
   
| Field | Details |  
|---|---|  
| **Lab Title** | Lab 5 — ARP Poisoning Forensics |  
| **Assignment Title** | ARP Poisoning Forensics |  
| **Student Name** | Bashir Adam |  
| **Student ID** | 2025/FWSD/11509 |  
| **Course Name** | SBT-DF203 — Basic Networking Skills for Digital Forensics |  
| **Instructor Name** | Aminu Idris |  
| **Date of Submission** | 17 Sep, 2026 |  
| **Version** | Version 2.3.4 |  
| **Platform** | Kali Linux or Ubuntu Forensic Workstation / VM |  
   
## Lab Overview  
   
Explain ARP resolution; inspect ARP caches; distinguish requests and replies; detect conflicting or unsolicited ARP claims; analyse supplied poisoning evidence; document an optional bounded host-only simulation; restore ARP state and recommend controls.  
   
## Introduction  
   
Address Resolution Protocol (ARP) is used on local networks to associate IPv4 addresses with hardware (MAC) addresses. Because devices rely on these mappings to communicate, incorrect or manipulated ARP entries can disrupt communication or enable traffic interception.  
   
This lab, **SBT-DF203 Lab 5: ARP Poisoning Forensics**, investigates normal ARP behaviour and the indicators used to identify possible ARP poisoning. The practical work includes capturing and examining normal ARP requests and replies, preserving and analyzing the supplied packet capture, reviewing IP-to-MAC claims, and documenting the observed findings. The optional controlled host-only simulation was skipped because the required approved isolated environment and instructor-provided script were not available.  
   
## Step 1 — Folder, Evidence, Tools, Hash, and Baseline Information  
   
**Fig01: Folder**  
   
Evidence hash: `342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e` (original and working copy identical).  
   
Interface inventory: **wlan0** is my active interface (`192.168.0.101/24`, gateway `192.168.0.1` via `wlan0`); **eth0** is present but DOWN; **pan1** is a Bluetooth PAN interface (`10.92.142.1/24`).  
   
Initial ARP table shows exactly one learned entry:  
   
`192.168.0.1 (gateway) → 34:a5:b4:0c:08:24, state REACHABLE`  
   
This is my baseline, trusted gateway MAC address, which becomes the reference value for detecting any later conflicting claim.  
   
### Chain-of-Custody Worksheet  
   
| Field | Entry |  
|---|---|  
| Case/lab identifier | SBT-DF203-Lab5-BashirAdam |  
| Trainee name | Bashir Adam (Azad) |  
| Date/time started | 17 Sep 2026, ~14:43 WAT |  
| Evidence file(s) | `arp.pcap` (supplied); `normal_arp.pcapng` (locally generated) |  
| Source/generation method | `arp.pcap`: downloaded authorized training file; `normal_arp.pcapng`: generated on `wlan0` |  
| Original SHA-256 | `342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e` |  
| Analysis workstation | Kali Linux, Lenovo ThinkPad L440 |  
| Notes | Baseline gateway MAC: `34:a5:b4:0c:08:24` (`wlan0`); interface is wireless, not `eth0` |  
   
**Fig02: Tools Installation**  
   
## Part A — Observe Normal ARP Resolution  
   
After capturing normal ARP traffic and successfully pinging the default gateway, I checked the ARP table again.  
   
The output showed that the gateway IP address, `192.168.0.1`, remained associated with MAC address `34:a5:b4:0c:08:24` on interface `wlan0`. The entry was in the `REACHABLE` state.  
   
This observation is consistent with the initial ARP baseline. No change in the gateway's IP-to-MAC mapping was observed after the ping.  
   
**Evidence file:** `reports/arp_table_after_ping.txt`  
   
**Observation:** The gateway mapping remained unchanged after normal ARP resolution.  
   
**Fig03: Normal API Baseline**  
   
## Part B — Analyze ARP Request and Reply Fields  
   
The normal ARP capture contains four packets, consisting of two request-and-reply exchanges.  
   
In Frame 1, my Kali system (`192.168.0.101`) sent a broadcast ARP request to identify the MAC address associated with the default gateway (`192.168.0.1`). The Ethernet destination was `ff:ff:ff:ff:ff`, and the ARP opcode was `1`, indicating a request.  
   
In Frame 2, the gateway responded with an ARP reply (opcode `2`), identifying its MAC address as `34:a5:b4:0c:08:24`. The reply was directed to my Kali system's MAC address, `58:91:cf:6f:b5`.  
   
Frames 3 and 4 show the reverse exchange. The gateway requested the MAC address associated with my Kali system's IP address, and Kali replied with its MAC address.  
   
The capture demonstrates normal ARP resolution in both directions. The gateway's MAC address agrees with the initial ARP-table baseline.  
   
**Evidence file:** `evidence/normal_arp.pcapng`  
   
**Analysis output:** `reports/normal_arp_fields.tsv`  
   
### Packet Analysis  
   
| Frame | Type | Sender IP → Target IP | Observation |  
|---:|---|---|---|  
| 1 | Request (1) | `192.168.0.101` → `192.168.0.1` | Kali broadcasts a request for the gateway's MAC address. |  
| 2 | Reply (2) | `192.168.0.1` → `192.168.0.101` | Gateway replies with MAC `34:a5:b4:0c:08:24`. |  
| 3 | Request (1) | `192.168.0.1` → `192.168.0.101` | Gateway broadcasts a request for Kali's MAC address. |  
| 4 | Reply (2) | `192.168.0.101` → `192.168.0.1` | Kali replies with MAC `58:91:cf:6f:b5:cb`. |  
   
**Fig04: ARP Resolution**  
   
## Part C — Analyze the Supplied Poisoning Capture  
   
The supplied ARP capture was analyzed using TShark. The ARP reply inventory identified two replies, recorded in Frames 4 and 6.  
   
Frame 4 contains an ARP reply from IP address `136.160.215.194`, associated with MAC address `00:50:56:86:02:65`. The reply was directed to MAC address `00:50:56:86:cb`.  
   
Frame 6 contains an ARP reply from IP address `136.160.215.15`, associated with MAC address `00:50:56:86:cb`. The reply was directed to MAC address `00:50:56:86:02:65`.  
   
The IP-to-MAC claim summary shows one occurrence of each mapping. Both replies were unicast.  
   
**Preliminary finding:** The extracted ARP replies show two different IP-to-MAC mappings. These results alone do not establish that either IP address was claimed by multiple MAC addresses. Further inspection of the complete capture is required to determine whether the replies were solicited, unsolicited, or associated with other suspicious ARP activity.  
   
### Evidence Files  
   
- `reports/arp_replies.tsv`  
- `reports/ip_mac_claims.txt`  
- `reports/unicast_arp_replies.tsv`  
   
**Fig05: ARP Poisoning**  
   
## Part D — Detection Logic and Timeline  
   
| Time | Claimed IP | Claimed MAC | Target / request seen first? | Assessment |  
|---|---|---|---|---|  
| `04:22:03.059513` | `136.160.215.1` | `00:1b:17:00:0a:30` | Gratuitous ARP; no preceding request shown | Not proof of poisoning by itself |  
| `04:22:44.904124` | `136.160.215.194` | `00:50:56:86:02:65` | Yes — Frame 3 requests this IP | Reply follows a request |  
| `04:22:49.943044` | `136.160.215.15` | `00:50:56:86:cb:fc` | Yes — Frame 5 requests this IP | Reply follows a request |  
| `04:23:03.059263` | `136.160.215.1` | `00:1b:17:00:0a:30` | Gratuitous ARP; no preceding request shown | Not proof of poisoning by itself |  
   
The supplied ARP capture was reviewed for conflicting IP-to-MAC claims, replies without a corresponding recent request, and a MAC address claiming both victim and gateway IP addresses.  
   
The capture contains two ARP replies. Each follows a request for the same target IP address. The capture also contains gratuitous ARP requests from `136.160.215.1`, using MAC address `00:1b:17:00:0a:30`. These requests are not, by themselves, proof of ARP poisoning.  
   
No conflicting gateway MAC address or clear man-in-the-middle pattern was established from the supplied capture. Therefore, the available evidence does not confirm ARP poisoning.  
   
Part D was skipped because the required approved host-only simulation environment and instructor-provided script were not available.  
   
## Part E — Restoration and Prevention  
   
Part D, the optional controlled host-only simulation, was skipped; therefore, no ARP-poisoning script was run and no simulation-related ARP changes required restoration.  
   
The final neighbor-table check showed the gateway `192.168.0.1` mapped to MAC address `34:a5:b4:0c:08:24` on interface `wlan0`, matching the initial baseline. The process check returned no matching `arp.py` or `scapy` process.  
   
### Preventive Controls  
   
Preventive controls include:  
   
- Dynamic ARP Inspection with DHCP snooping on managed switches where available.  
- Network segmentation.  
- Port security.  
- Monitoring gateway IP-to-MAC consistency.  
- Using encrypted application protocols.  
- Correlating ARP alerts with switch and endpoint logs.  
   
**Fig06: Restoration**  
   
## Conclusion  
   
This lab provided practical experience in capturing and examining ARP traffic, interpreting request and reply fields, and reviewing IP-to-MAC address claims. In the supplied capture, the two ARP replies followed corresponding requests, while the observed gratuitous ARP packets were requests. The available evidence did not establish a conflicting gateway MAC address or confirm an ARP-poisoning or man-in-the-middle event.  
   
Part D, the optional controlled host-only simulation, was not performed. The final neighbor-table check showed the gateway `192.168.0.1` mapped to `34:a5:b4:0c:08:24` on `wlan0`, matching the earlier baseline, and the process check found no matching `arp.py` or `scapy` process.  
   
Overall, the lab reinforced the importance of preserving evidence, interpreting packet details carefully, documenting limitations, and applying preventive controls such as Dynamic ARP Inspection, network segmentation, and monitoring gateway IP-to-MAC consistency.  
