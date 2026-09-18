# Lab 6 — Firewall Traffic Control and Forensic Verification

| | |
|---|---|
| **Assignment Title** | Firewall Traffic Control and Forensic Verification |
| **Student Name** | Bashir Adam |
| **Student ID** | 2025/FWSD/11509 |
| **Course Name** | SBT-DF203: Basic Networking Skills for Digital Forensics |
| **Instructor Name** | Aminu Idris |
| **Date of Submission** | 17 Sep, 2026 |
| **Version** | Version 2.3.5 |
| **Platform** | Kali Linux / Ubuntu Forensic Workstation (VM) |

---

## Lab Overview

Validate whether a Linux host based firewall correctly blocks HTTP traffic from one authorized lab client while allowing another. Capture baseline traffic, apply a narrowly scoped iptables rule, capture the blocked connection behaviour, prove the rule hit using counters, remove the rule, and document the evidential differences.

## Introduction

This report documents SBT-DF203 Lab 6, Firewall Traffic Control and Forensic Verification, conducted entirely on a single Kali Linux workstation (Bashir-Adam-Kali) using Linux network namespaces to simulate the two-host topology the lab specifies, in place of a physical or virtual second machine. A dedicated network namespace (`labclient`) connected to the root namespace via a veth pair played the role of two lab clients, an allowed client (`192.168.60.11`) and a blocked client (`192.168.60.12`), while the root namespace hosted Apache2 and the iptables firewall under test.

The objective was to validate that a narrowly scoped, source specific iptables DROP rule on TCP port 80 correctly blocks HTTP traffic from one client while leaving another client's access untouched, and to forensically prove this using packet capture, firewall rule counters, and client side behaviour, rather than relying on any single source of evidence alone. The investigation followed the full evidence lifecycle required by the lab: preserving and hashing the original ruleset before any change, capturing a clean baseline, applying and verifying the rule, capturing the blocked condition, correlating packet level evidence with firewall counters, removing the rule, and confirming full restoration. An optional NFQUEUE demonstration was also carried out, showing live kernel to userspace packet interception and verdict based forwarding under a strict listener first, rule second, immediate cleanup safety discipline.

---

## Lab Folder Structure and Evidence Preparation

Evidence directory tree created under `~/SBT-DF203-Lab6` (`evidence`, `working`, `exported`, `reports`, `screenshots`, `scripts`). Apache2 (2.4.68-2) installed/upgraded and enabled via systemd; the training page `firewall_lab.html` was written to `/var/www/html/` and its content verified by direct output.

Original firewall state exported before any change: `iptables-save` shows default policies of `ACCEPT` on `INPUT`/`FORWARD`/`OUTPUT`, with three pre existing `FORWARD` rules and one NAT `MASQUERADE` rule tied to `pan1` (the Bluetooth PAN interface). These are host defaults, not lab artefacts, and are called out here so the marker doesn't mistake them for lab rules. `iptables -L -n -v` confirms the `INPUT` chain is currently empty (0 rules, `ACCEPT` policy) at time zero, this is the clean baseline the lab rule will later be inserted into and removed from.

**Original ruleset SHA-256:** `df8106021520a179cc39451c5e69ef5afe70dec797a68b761d52ec0e3adef0d1` (`reports/iptables_before.rules`)

### Chain of Custody Worksheet

| Field | Entry |
|---|---|
| Case/lab identifier | SBT-DF203-Lab6-BashirAdam |
| Trainee name | Bashir Adam (Azad) |
| Date/time started | 18 Sep 2026, 22:22 WAT |
| Evidence file(s) | `iptables_before.rules` |
| Environment | Single Kali host; server = root network namespace; client simulated via `labclient` netns + veth pair |
| Original ruleset SHA-256 | `df8106021520a179cc39451c5e69ef5afe70dec797a68b761d52ec0e3adef0d1` |
| Analysis workstation | Kali Linux (Lenovo ThinkPad L440) |
| Notes | `INPUT` chain empty at baseline (0 rules); pre existing FORWARD/NAT rules on `pan1` are unrelated host config, not lab artefacts |

> 📸 **Fig01 — File Structure**

### Topology Setup

Two host topology simulated via Linux network namespaces on a single Kali workstation: root namespace acts as the server; `labclient` namespace acts as both lab clients (two IPs bound to the same `veth-cli` interface, since a real two VM setup would give each client its own NIC). Link layer connectivity verified: `veth-srv` (`192.168.60.1/24`) up in the root namespace, `veth-cli` (`192.168.60.11/24` primary, `192.168.60.12/24` secondary) up inside `labclient`, with an ICMP round trip (0.054 to 0.064 ms, 0% loss) confirming the path before any HTTP traffic is generated.

| Role | Namespace | Interface | IP |
|---|---|---|---|
| Server (Apache + firewall) | root (default) | `veth-srv` | `192.168.60.1/24` |
| Allowed client | `labclient` | `veth-cli` | `192.168.60.11/24` |
| Blocked client | `labclient` | `veth-cli` | `192.168.60.12/24` |

> 📸 **Fig02 — Network Topology**

---

## Part A — Lab Network and Baseline Access

Server addressing confirmed: `veth-srv` at `192.168.60.1/24` with the corresponding route added to the kernel table (`192.168.60.0/24 dev veth-srv`). Apache is listening on `*:80` (PID 29341 and worker children), confirming the service is live before any traffic capture.

Baseline curl from both simulated clients succeeded identically:

| Client | Result |
|---|---|
| Allowed client (`192.168.60.11`) | Connected to `192.168.60.1:80`, `HTTP/1.1 200 OK`, 119 byte page body returned, connection closed cleanly |
| Blocked client (`192.168.60.12`) | Connected to `192.168.60.1:80`, `HTTP/1.1 200 OK`, same 119 byte body, connection closed cleanly |

> 📸 **Fig03 — Lab Network**

---

## Part B — Capture the Allowed HTTP Baseline

Captured live traffic between the server (`192.168.60.1`) and the allowed client (`192.168.60.11`) on `veth-srv` during a controlled 15 second window, with the HTTP request generated mid capture. 10 packets captured, comprising the TCP handshake, HTTP GET/response exchange, and connection teardown for the successful `firewall_lab.html` retrieval (`HTTP/1.1 200 OK`, 119 byte body). This is the reference "allowed" capture that Part E will compare the blocked capture against.

| Item | Value |
|---|---|
| Evidence file | `evidence/http_allowed.pcapng` |
| SHA-256 | `ce4ebdb3d479fa1a06c6d297dbd36944c64e43439a6b1f5fdef5c9b019c35939` |

> 📸 **Fig04 — HTTP Baseline**

---

## Part C — Apply and Verify the Blocking Rule

A narrowly scoped DROP rule was inserted at `INPUT` position 1, matching only source IP `192.168.60.12` on destination TCP port 80, leaving all other traffic (including the allowed client, `192.168.60.11`) unaffected. Rule placement at the top of `INPUT` ensures it is evaluated before any broader `ACCEPT` rule could short circuit it. `iptables -L INPUT -n -v --line-numbers` confirms the rule is present with 0 packets/0 bytes matched so far (recorded before any blocked traffic has hit it, this counter will be the evidence in Part D). `iptables -C` returned success, formally verifying the exact rule (source, protocol, destination port, target) exists in the live table rather than relying on visual inspection alone.

| Item | Value |
|---|---|
| Rule inserted | `-A INPUT -s 192.168.60.12 -p tcp --dport 80 -j DROP` |
| Position | 1, `INPUT` chain |

> 📸 **Fig05 — Blocking Rule**

---

## Part D — Capture Blocked Traffic and Rule Counters

The curl attempt from `192.168.60.12` received no response of any kind, no RST, no error page, nothing, and hung for the full 10 second connect timeout before curl reported `curl: (28) Connection timed out after 10003 milliseconds`. This absence of response is the defining forensic signature of DROP: the packet is silently discarded by the firewall, so from the client's perspective the server appears simply unreachable, indistinguishable at the application layer from a dead host or a broken link.

The rule counter is the corroborating server side evidence: it went from 0 packets/0 bytes (Part C) to 7 packets/420 bytes matched after the test, 420 bytes divided by 7 packets equals 60 bytes per packet, consistent with repeated bare SYN retransmissions (no payload), which is exactly what a TCP client does when it gets no SYN-ACK and no RST: it keeps retrying the handshake until it gives up.

| Item | Value |
|---|---|
| Evidence file | `evidence/http_blocked.pcapng` |
| SHA-256 | `a6b419ec97b37f33898fffa8fc91f21ef437b927c05e49b5aebd0768be68e8ae` |
| Rule counter after test | 7 packets / 420 bytes matched on the DROP rule |

> 📸 **Fig06 — Blocked Traffic**

---

## Part E — Compare Allowed and Blocked Captures

**Allowed capture** (`192.168.60.11` → `192.168.60.1`): a complete, healthy TCP/HTTP exchange in under 1ms: SYN (`0x0002`) → SYN-ACK (`0x0012`) → ACK+PSH carrying the GET request (`0x0018`, `/firewall_lab.html`) → ACK+PSH response (`0x0018`, HTTP 200). Four frames, no retransmissions, connection fully established and torn down normally.

**Blocked capture** (`192.168.60.12` → `192.168.60.1`): Frame 1 is the client's initial SYN (`0x0002`) at t=0. No SYN-ACK ever arrives. Frames 2 through 7 are all SYN retransmissions (`tcp.analysis.retransmission = 1`) of the identical packet, at classic TCP exponential backoff intervals: approximately 1.0s, 1.0s, 1.0s, 1.0s, 1.0s, then 2.0s, the growing gap between the last two attempts is the backoff timer roughly doubling, which is standard Linux TCP retry behaviour when no response is ever received. The capture ends at frame 7 with no SYN-ACK, no RST, and no HTTP layer ever established; curl's own 10 second connect timeout cut the attempt short of the kernel's full retry cycle.

### Allowed vs. Blocked Comparison

| Metric | Allowed (192.168.60.11) | Blocked (192.168.60.12) |
|---|---|---|
| SYN sent | 1 | 7 (1 original + 6 retransmissions) |
| SYN-ACK received | Yes (frame 2, 0.03ms) | Never |
| HTTP request/response | GET → 200 OK | Never reached |
| Total capture frames | 4 | 7 |
| Client outcome | Page retrieved | `curl: (28) Connection timed out` |
| Firewall evidence | No matching DROP rule | Rule counter: 7 pkts / 420 bytes |

The retransmission pattern is itself diagnostic: 7 client side SYN attempts line up exactly with the 7 packet/420 byte counter on the DROP rule, every single retry was silently discarded, none reached the application layer, which is what distinguishes DROP forensically from REJECT (which would show a single RST or ICMP unreachable, not a retry storm).

> 📸 **Fig07 — Blocked Capture**

---

## Part F — Remove the Rule and Restore Access

The DROP rule was removed via `iptables -D`. Verification via `iptables -C` correctly failed to find the rule (`iptables: Bad rule (does a matching rule exist in that chain?)`), this negative result is the expected confirmation of removal, not a fault, since `-C` is designed to fail when the specified rule no longer exists. `iptables -L INPUT` confirms the chain is now empty (0 rules), matching the original baseline state recorded earlier.

Restored access was then verified functionally: the previously blocked client (`192.168.60.12`) issued the same request and received `HTTP/1.1 200 OK` with the full 119 byte page body, connection closed cleanly, access is fully restored to the pre-lab state.

| Stage | INPUT rule count | 192.168.60.12 access |
|---|---|---|
| Before | 0 | Allowed |
| After rule added (Part C) | 1 (DROP) | Not yet tested |
| After block test (Part D) | 1 (DROP, 7 pkts hit) | Blocked (timeout) |
| After removal (Part F) | 0 | Allowed |

> 📸 **Fig08 — Restore Access**

---

## Part G — Optional NFQUEUE Observation

NFQUEUE was demonstrated live rather than only described. A userspace Python listener (`scripts/nfqueue_listener.py`, using `python3-netfilterqueue`) was started first and bound to queue number 0, before any diversion rule was added, this ordering is deliberate: a queue with no listener stalls all matching traffic indefinitely, so the listener must exist before the rule that feeds it.

A narrowly scoped rule diverted only the allowed client's HTTP traffic into the queue:

```
-A INPUT -s 192.168.60.11 -p tcp --dport 80 -j NFQUEUE --queue-num 0
```

Every packet the kernel handed to userspace was intercepted, logged, and explicitly `.accept()`-ed by the callback, so the client's request proceeded normally end to end (`HTTP/1.1 200 OK`), this proves the mechanism (kernel → userspace → verdict → kernel) without altering traffic.

The listener log confirms the full TCP conversation passed through the queue individually, packet by packet:

| Packet | Flags | Length | Role |
|---|---|---|---|
| 1 | S | 60 | SYN (handshake start) |
| 2 | A | 52 | ACK (handshake complete) |
| 3 | PA | 145 | PSH+ACK, HTTP GET request |
| 4 | A | 52 | ACK of server's response |
| 5 | FA | 52 | FIN+ACK (client closing) |
| 6 | A | 52 | Final ACK |

Cleanup was performed immediately after the one test request: the NFQUEUE rule was deleted (`iptables -D`), then the listener process was terminated (`kill`). `iptables -L INPUT` afterward confirms the chain is empty again, no NFQUEUE rule left active, satisfying the manual's explicit warning against leaving one running without a listener.

> 📸 **Fig09 — NFQUEUE Python & Installation**
> 📸 **Fig10 — NFQUEUE Listener**
> 📸 **Fig11 — Python Unbuffered**

---

## Forensic Interpretation Questions

### 1. Why does DROP commonly cause SYN retransmissions and a timeout?

DROP silently discards the packet at the firewall with no reply of any kind, no SYN-ACK, no RST, no ICMP message. From the client's TCP stack, this is indistinguishable from the packet simply vanishing in transit. TCP's only response to "no answer" is to assume the segment was lost and retransmit, following an exponential backoff schedule. This is exactly what was observed in Parts D and E: the client sent 7 SYNs at growing intervals (approximately 1s, 1s, 1s, 1s, 1s, 2s) before curl's own `--connect-timeout` gave up at 10 seconds. The client never learns why there was no response, only that there wasn't one.

### 2. How would a REJECT rule differ in the packet capture and client output?

REJECT actively tells the client the connection was refused, typically by sending a TCP RST (for `--reject-with tcp-reset`) or an ICMP "port unreachable"/"host prohibited" message. In the capture, this would appear as a single reply packet immediately following the client's SYN, no retransmission storm, because the client's TCP stack receives a definitive answer and closes the attempt immediately. On the client side, curl would report a fast, explicit error (e.g. `curl: (7) Failed to connect... Connection refused`) within milliseconds, rather than the 10 second silent hang seen with DROP.

### 3. Why are firewall counters valuable corroborating evidence?

A packet capture shows what happened on the wire, but not why. A counter tied to a specific rule proves the firewall itself is the mechanism responsible, not an unrelated fault. In this lab, the DROP rule's counter moved from 0 packets/0 bytes (Part C, before the test) to 7 packets/420 bytes (Part D, after), a number that matches exactly the 7 SYN attempts seen in the PCAP. That correlation is what turns "the client couldn't connect" into "the client couldn't connect because this specific rule matched this specific traffic," which is the standard a forensic conclusion needs to meet.

### 4. What evidence would show that the web server was down rather than firewall blocked?

If Apache itself were down (not the firewall), the OS would still respond at the TCP layer, the client's SYN would receive an immediate RST because nothing is listening on port 80, producing a fast `curl: (7) Connection refused` almost instantly, not a 10 second timeout. Server side, `ss -lntp | grep ':80'` would show no LISTEN entry at all (contrast with Part A's output, which showed Apache's PID actively bound to `*:80`). Additionally, the iptables rule counter would stay at 0 forever, since a service down failure never touches the firewall's DROP rule at all, the two failure modes are cleanly distinguishable by combining these three data points.

### 5. What is the risk of deleting a rule by line number after other rules have changed?

`iptables -D <chain> <line_number>` deletes whatever rule currently occupies that position, not a specific rule by identity. If any rule was added, removed, or reordered between when you noted the line number and when you run the delete, you can silently remove the wrong rule (potentially opening a hole you didn't intend, or leaving the real blocking rule in place). This is why Parts C and F both specified the rule by its exact match criteria (`-s IP -p tcp --dport 80 -j DROP`) rather than by line number, deleting by full specification always removes the intended rule regardless of what else has changed in the chain, and `iptables -C` before/after gives an auditable confirmation independent of position.

---

## Conclusion

The evidence gathered across Parts A through G supports a single, internally consistent forensic conclusion: the observed loss of access for `192.168.60.12` was caused specifically and exclusively by the inserted iptables DROP rule, not by any fault in the server, the network path, or the application.

Three independent lines of evidence converge on this finding. First, packet level evidence: the allowed client's capture shows a complete four packet handshake to response exchange, while the blocked client's capture shows only repeated, unanswered SYN retransmissions at standard TCP backoff intervals, with no SYN-ACK, RST, or ICMP response at any point. Second, firewall state evidence: the DROP rule's counter moved from exactly 0 packets/0 bytes immediately after insertion to exactly 7 packets/420 bytes after the blocked client's attempt, a count that matches the 7 SYN packets observed in the capture precisely, tying the rule directly to the observed traffic loss. Third, client behaviour evidence: curl reported a clean `HTTP/1.1 200 OK` for the allowed client and a `curl: (28) Connection timed out` for the blocked client under otherwise identical conditions (same server, same page, same time window), isolating the client's source IP as the only variable.

The DROP versus REJECT distinction discussed above was borne out directly by this evidence: DROP produced silence and a retry storm rather than an immediate, explicit refusal, which is the defining signature that separates the two rule types in both packet captures and end user experience.

Restoration was verified rather than assumed: after rule removal, `iptables -L` showed the `INPUT` chain returned to its original empty state, and a functional curl test from the previously blocked client confirmed access was fully restored, closing the loop back to the pre-lab baseline.

The optional NFQUEUE exercise further demonstrated that firewall based traffic control extends beyond simple ACCEPT/DROP decisions to programmable, packet by packet inspection in userspace, while reinforcing the operational discipline (listener before rule, immediate cleanup) needed to use that capability safely.

All evidence files, hashes, and command outputs referenced in this report are preserved under `~/SBT-DF203-Lab6/{evidence,reports}` as itemised throughout this document, and are available in the accompanying submission package.
