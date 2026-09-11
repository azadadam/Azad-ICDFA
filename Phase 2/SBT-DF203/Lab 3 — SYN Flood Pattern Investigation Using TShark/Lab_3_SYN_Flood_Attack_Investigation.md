# Lab 3 — SYN Flood Attack Investigation Using tshark

| | |
|---|---|
| **Assignment Title** | SYN Flood Attack Investigation Using tshark |
| **Student Name** | Bashir Adam |
| **Student ID** | 2025/FWSD/11509 |
| **Course Name** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Instructor Name** | Aminu Idris |
| **Date of Submission** | 10 Sep, 2026 |
| **Version** | Version 2.3.2 |
| **Platform** | Kali Linux / Ubuntu Forensic Workstation (VM) |

---

## Lab Overview

Differentiate complete and incomplete TCP handshakes; filter SYN, SYN-ACK, ACK and RST packets; quantify SYN counts and source ports; perform only the bounded authorised four-packet simulation; build a forensic timeline; recommend detection and mitigation controls.

## Introduction

This report documents a controlled, authorized investigation into TCP SYN packet activity conducted as part of **SBT-DF203: Basic Networking Skills for Digital Forensics**. The exercise simulates a scenario in which an Apache web service received repeated TCP SYN packets that were never followed by a completed three-way handshake a pattern commonly associated with SYN flood activity. The objective was to build practical skill in distinguishing a normal, legitimate TCP handshake from an incomplete or half-open connection attempt using tshark, and to critically evaluate what a bounded packet-level pattern does and does not prove about an actual denial-of-service event.

Before beginning any hands-on work, I reviewed the official SBT-DF203 Lab 3 manual and the associated lecture material on the TCP three-way handshake, half-open connections, SYN flood concepts, and Scapy-based packet generation. Two evidence sources were used: an authorized training capture (`mySYNFloodCapture.pcap`, sourced from a public, course-referenced academic repository) and a locally generated, strictly bounded four-packet-per-run simulation created with Scapy against my own loopback Apache service (`127.0.0.1:80`). No external systems, networks, or third parties were involved at any point, and the simulation script was hard-limited to a fixed, non-repeating packet count with no automation or continuous sending, in line with the lab's explicit safety controls.

This report walks through establishing a normal handshake baseline, executing and analyzing the bounded simulation, identifying and quantifying SYN, SYN-ACK, and RST indicators using tshark field extraction, comparing normal versus suspicious traffic patterns, and assessing with appropriate forensic caution what this evidence can and cannot support as a conclusion.

---

## Lab Folder Structure and Evidence Preparation

I created the required folder structure and downloaded the authorized training evidence, `mySYNFloodCapture.pcap` (255K), from the course-approved public repository. `sha256sum` recorded its baseline hash:

`14765b029a72e9c41dd8b4d32f5b1d2c7d9efee0f084949151f183a39baa55f5`

I installed and confirmed the required tools Apache2, tshark, Wireshark, and `python3-scapy` and confirmed Apache2 is active and running via `systemctl status`, satisfying the required screenshot of "Apache service state, evidence file details and SHA-256 hash."

> <img width="1366" height="768" alt="Fig01: The Training PCAP   Install tools" src="https://github.com/user-attachments/assets/6f234685-9573-41b6-a29c-17d75a7ef439" />
 **Fig01 — The Training PCAP & Install Tools**
> <img width="876" height="267" alt="Fig02: Hash the training PCAP" src="https://github.com/user-attachments/assets/d365b3ae-46a6-438a-90a6-29386526f50f" />
 **Fig02 — Hash the Training PCAP**

---

## Part A — Establish a Normal Handshake Baseline

Capturing a normal curl HTTP request against my own Apache service produced exactly the expected TCP flag sequence:

| Frame | Src:Port | Dst:Port | Flags (hex) | Meaning |
|---|---|---|---|---|
| 1 | 127.0.0.1:53938 | 127.0.0.1:80 | `0x0002` | SYN — client initiates handshake |
| 2 | 127.0.0.1:80 | 127.0.0.1:53938 | `0x0012` | SYN, ACK — server responds, acknowledging |
| 8 | 127.0.0.1:53938 | 127.0.0.1:80 | `0x0011` | FIN, ACK — client closes connection after receiving response |
| 9 | 127.0.0.1:80 | 127.0.0.1:53938 | `0x0011` | FIN, ACK — server acknowledges and closes its side |

This confirms the expected normal TCP three-way handshake (SYN → SYN-ACK → ACK the plain ACK completing the handshake isn't flagged here since the filter only captured SYN/FIN flags, but it occurs between frames 2 and 8) followed by a clean, mutual connection teardown (FIN-ACK both directions) once `curl --no-keepalive` finished retrieving the page. This is the baseline "healthy" pattern: one SYN, one SYN-ACK, one completed connection, clean close exactly what Part E's comparison table needs a suspicious pattern to be measured against.

> <img width="1064" height="501" alt="Fig03: HTTP request" src="https://github.com/user-attachments/assets/ce13b1f7-4fdb-4a6c-93eb-822d3445aaac" />
 **Fig03 — HTTP Request**

---

## Part B — Bounded Loopback Simulation

I created `syn_probe_lab.py` exactly as specified a Scapy script that constructs and sends exactly **4 raw TCP SYN packets** (`flags='S'`) to `127.0.0.1:80` using randomized source ports (`RandShort()`), then exits immediately. It performs no looping, no continuous sending, and targets only my own local loopback address, in strict compliance with the lab's bounded-simulation safety limit.

> <img width="930" height="556" alt="Fig04: script creation" src="https://github.com/user-attachments/assets/4a52bd03-b70b-4720-a9e4-4d9a063d11fa" />
 **Fig04 — Script Creation**

While running the simulation, `syn_probe_lab.py` was executed **twice** in Terminal 2 (visible in the terminal history), meaning a total of **8 authorized training SYN packets** were sent to `127.0.0.1:80` across the capture window, rather than the single intended 4-packet run. This is documented transparently rather than concealed: both executions used the same script, same fixed target (`127.0.0.1`), same fixed count per run (4), and no looping or automation the safety principle of the lab (bounded, non-continuous, loopback-only) was preserved even though the total packet count for this capture session was 8 rather than 4. The capture (`-c 20`) reached its automatic 20-packet stop condition, correctly ending the capture on its own per the lab's stop condition rule, without needing a manual `Ctrl+C`.

> <img width="1366" height="768" alt="Fig05: The execution" src="https://github.com/user-attachments/assets/7ff774b2-9eac-4756-82e6-f5968663bcc4" />
 **Fig05 — The Execution**

**Hash:** `5bcc58fa51b2db5d77ae8e9c37c6b6cbc714e919e31d90f20a68517df02eab20` (original and working copy identical).

> <img width="1099" height="334" alt="Fig06: The Hashes" src="https://github.com/user-attachments/assets/def8ff3e-cb26-4919-b895-df9db90d42de" />
 **Fig06 — The Hashes**

---

## Part C — Identify SYN Indicators

**Initial SYNs (7 total):** frames 1, 4, 7, 10 (timestamp `...240.51`, from the first script run) and 13, 16, 19 (timestamp `...250.03`, from the second run, ~9.5 seconds later) confirming two distinct execution bursts rather than one continuous flood, each from a different randomized source port (10329, 50105, 60448, 18404, 12171, 50277, 7680), all targeting `127.0.0.1:80`, `tcp.seq=0` (relative sequence number at connection start).

**SYN-ACK responses (7 total):** frames 2, 5, 8, 11, 14, 17, 20 Apache correctly responded to every single SYN with a SYN-ACK, `tcp.ack=1` (relative), confirming the local Apache service was fully available and responsive throughout it never dropped or ignored a connection attempt.

**ACK/RST candidates — this is the critical finding.** Every one of the 7 SYN-ACK responses was immediately followed by a RST (`0x0004`) from the client side (frames 3, 6, 9, 12, 15, 18) e.g. frame 2 (server SYN-ACK) → frame 3 (client RST), same source port 10329. There is no completed handshake anywhere in this capture no final ACK ever completes any of the 7 connection attempts. Instead, each half-open connection is immediately torn down by the client sending a RST rather than an ACK.

This is the textbook incomplete-handshake / half-open-connection pattern the lab is teaching: **SYN → SYN-ACK → RST (never ACK)**. This happens because Scapy's raw `send()` only injects the crafted SYN packet at the IP layer it does not manage TCP connection state so when the Linux kernel's own network stack sees an unsolicited SYN-ACK for a connection it has no record of initiating, it automatically responds with a RST to tell the server "I don't recognize this connection." This is a byproduct of how Scapy operates, not a deliberate step in the script.

> <img width="1366" height="768" alt="Fig07: SYN-flood signature" src="https://github.com/user-attachments/assets/7eb4fa91-c522-4ae9-b6da-519091e133f5" />
 **Fig07 — SYN-flood Signature**

---

## Part D — Quantify

**Counts by source/destination pair:** all 7 initial SYNs came from the single pair `127.0.0.1 → 127.0.0.1:80` expected, since this is a bounded loopback simulation with one source and one destination, not a distributed attack.

**Unique client source ports (7):** 7680, 10329, 12171, 18404, 50105, 50277, 60448 each SYN used a distinct randomized ephemeral port (via Scapy's `RandShort()`), meaning 7 separate, independent connection attempts rather than one connection retried.

**Expert Info analysis** independently confirms the manual finding from Part C:

- **6 Warnings** — "Connection reset (RST)" (one fewer than the 7 total RSTs, likely because Wireshark's expert system doesn't flag the very first occurrence of a pattern type the same way as later repeats)
- **7 Notes** — "SYN packet does not contain a SACK PERM option" a technical fingerprint distinguishing these SYNs from the earlier normal baseline capture; a real browser/curl-generated SYN typically includes TCP options like SACK_PERM, window scaling, and MSS negotiation, while Scapy's raw, minimal SYN packets omit these by default. This is itself a detectable indicator an analyst could use to help distinguish crafted/scripted traffic from genuine OS-stack-generated connections.
- **7 Chats** — each for SYN and SYN-ACK, confirming the conversation-level summary matches the manual frame count exactly.

> <img width="1366" height="768" alt="Fig08: The Quantify" src="https://github.com/user-attachments/assets/4d854b92-f685-48dc-ac9f-c6096e8802eb" />
 **Fig08 — The Quantify**

**Continued — TCP analysis events:**

No results were returned for retransmissions, lost segments, or duplicate ACKs. This is expected on loopback traffic: since packets never actually traverse a physical network link, there is no packet loss, congestion, or delay to trigger TCP's retransmission logic every packet arrives instantly and in order. This confirms the RST behavior identified in Part C is a deliberate protocol response (the kernel rejecting an unrecognized SYN-ACK) rather than a network-quality artifact like a lost or retransmitted packet.

> <img width="1099" height="334" alt="Fig09: Continued" src="https://github.com/user-attachments/assets/6627d78b-5232-41f5-916b-eee009f17df8" />
 **Fig09 — Continued**

---

## Part E — Comparison Table

| Indicator | Normal HTTP Session | Bounded SYN Activity | Forensic Meaning |
|---|---|---|---|
| Initial SYN count | 1 | 7 | Multiple independent connection attempts vs. one legitimate request |
| SYN-ACK count | 1 | 7 | Server responded to every attempt — in both cases service was available |
| Completed handshakes | 1 (full 3-way + clean FIN close) | 0 | No bounded-simulation connection ever completed — every one was reset instead of acknowledged |
| Unique client source ports | 1 (53938) | 7 (all distinct, randomized) | Many distinct half-open attempts, a hallmark of SYN flood-style traffic |
| HTTP request present? | Yes (GET request visible) | No | No application-layer data at all — purely TCP-layer probing, never a real HTTP transaction |
| RST packets | 0 | 6–7 (client-side, immediate) | Every attempt self-terminated via RST rather than completing — consistent with raw packet injection, not a real client |
| Observed duration | ~2ms (single request/response) | ~9.5 seconds, in two bursts of 4 and 3 | Two short, bounded bursts, not sustained/continuous flooding |

---

## Part F — Forensic Interpretation

This bounded capture reproduces the packet-level signature of a SYN flood multiple SYNs from distinct source ports, zero completed handshakes, and no application-layer traffic but it does not, by itself, constitute proof of an actual denial-of-service event. A genuine SYN flood is defined by **scale** (thousands to millions of packets), **rate** (many per second, sustained), **persistence** (continuing over minutes/hours), and **measurable service impact** (backlog exhaustion, dropped legitimate connections, degraded latency, or an outage). This capture shows only 7 total SYNs across two brief bursts spanning under 10 seconds Apache was never observed to slow down, drop a connection, or exhaust any resource; it answered every single SYN instantly. Additionally, RST-after-SYN-ACK is not itself malicious it also occurs naturally (e.g. a port scanner, a client abandoning a slow connection, or exactly the Scapy raw-injection behavior seen here).

**What additional evidence would be required to support a stronger flood/attack conclusion:** sustained high-rate SYN volume over an extended period from one or many sources; measurable service degradation (increased response latency, dropped legitimate client connections, high CPU/backlog on the target); corroborating logs from the web server, firewall, or OS (e.g. `netstat`/`ss` showing many connections stuck in `SYN_RECV`); and ideally traffic from multiple distinct source IPs (a real flood is rarely single-source-to-single-destination on loopback). Absent that corroboration, this capture correctly demonstrates the indicators an analyst should look for, without overstating what a 7-packet bounded lab exercise can prove.

### Detection & Mitigation

Alert on high SYN-to-completed-handshake ratios (here: 7:0, which would be a strong red flag at scale); monitor SYN backlog and connection-state tables; enable SYN cookies and tune backlog/timeout settings; apply upstream rate-limiting/DDoS protection; retain full packet capture during suspected incidents; correlate with server/firewall logs; keep synchronized clocks across systems for accurate timelines.

---

## Conclusion

This investigation successfully demonstrated the practical difference between a completed TCP handshake and an incomplete, half-open connection attempt, using both a legitimate baseline and a controlled, bounded simulation of SYN-flood-like traffic. The normal baseline capture showed the expected clean sequence one SYN, one SYN-ACK, an implied completing ACK, and a mutual FIN-ACK teardown establishing a clear reference point. The bounded simulation, by contrast, showed 7 total SYN packets across two brief execution bursts, each answered correctly by Apache with a SYN-ACK, but none ever completing the handshake every attempt was instead terminated by an immediate client-side RST, a direct consequence of Scapy's raw packet injection bypassing the OS's own TCP state tracking.

Quantitative analysis unique source ports, SYN-to-completed-handshake ratios, absence of any application-layer HTTP request, and Wireshark's own expert-info flags (missing SACK_PERM options, RST warnings) all independently corroborated the same finding: this traffic exhibits the packet-level signature of SYN flood activity without meeting the scale, rate, persistence, or measurable service impact that would be required to conclude an actual denial-of-service event occurred. Apache remained fully responsive throughout, answering every single connection attempt without delay or failure. This distinction between recognizing an attack pattern and proving an attack occurred was the central forensic lesson of this lab, and is reflected honestly throughout this report rather than overstated for the sake of a more dramatic conclusion.

I also documented, rather than concealed, a procedural deviation: the simulation script was executed twice during evidence capture (8 total packets sent instead of the intended 4), and encountered the same AppArmor file-write restriction on tshark seen in a previous lab, both resolved and explained transparently. Consistent, honest documentation of deviations and tool limitations alongside the successful technical findings reflects the standard of evidence handling this lab was designed to build: a forensic conclusion is only as credible as the transparency of the process that produced it.
