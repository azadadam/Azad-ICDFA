# Lab 8 — DNS Spoofing Forensics

| | |
|---|---|
| **Assignment Title** | DNS Spoofing Forensics |
| **Student Name** | Bashir Adam |
| **Student ID** | 2025/FWSD/11509 |
| **Course Name** | SBT-DF203: Basic Networking Skills for Digital Forensics |
| **Instructor Name** | Aminu Idris |
| **Date of Submission** | 14 Sep, 2026 |
| **Version** | Version 2.3.7 |
| **Platform** | Kali Linux / Ubuntu Forensic Workstation (VM) |

---

## Lab Overview

Explain the ARP/MITM/DNS spoofing relationship; capture normal DNS and ARP baseline evidence; detect conflicting answers and abnormal responder MAC/IP information; correlate DNS response with subsequent connection; distinguish spoofing from legitimate DNS variation; document cleanup and defences.

## Executive Summary

This report documents SBT-DF203 Lab 8, DNS Spoofing Forensics, conducted entirely on a single Kali Linux workstation (Bashir-Adam-Kali) using Linux network namespaces to simulate the three host topology the exercise requires: a victim, an analyst/gateway acting as the man in the middle, and a separate authoritative DNS server, in place of physical or virtual machines. The exercise was self authorized as an isolated, host only training simulation, using only the reserved, non production domain `portal.icdfa.test` and a harmless warning page containing no credential fields, per the manual's legal and safety requirements.

The objective was to capture a legitimate DNS/ARP baseline, execute an instructor style controlled DNS spoofing simulation using the provided `arp.py` and `dns_spoof.py` tools, and forensically identify the indicators that distinguish a genuine spoofing attack from normal DNS variation, then fully restore the environment afterward.

The investigation successfully demonstrated the complete ARP poisoning to DNS spoofing attack chain: `arp.py` positioned the analyst host as a man in the middle by falsely binding the gateway's IP to its own MAC address; `dns_spoof.py` then intercepted a genuine DNS response in flight via an NFQUEUE hook on the FORWARD chain and rewrote the answer from the legitimate server's IP (`192.168.71.2`) to the analyst's own IP (`192.168.70.1`); the victim's browser accepted this forged answer and connected to the attacker controlled host within approximately 27 milliseconds, receiving the ICDFA training warning page. All evidence was preserved and hashed at each stage, and the environment was fully restored to its original state afterward, forwarding, firewall rules, ARP tables, and all lab created network namespaces and processes were verified clean.

---

## Lab Folder Structure and Evidence Preparation

Lab folder structure created under `~/SBT-DF203-Lab8` (`evidence`, `working`, `exported`, `reports`, `screenshots`, `scripts`). Apache2 installed and enabled. The training page was written to `/var/www/html/index.html`, containing only the ICDFA authorized simulation warning and analyst name, with no credential fields.

**Training page SHA-256:** `951cbc61130ae2be4f33c88e274fcb780a9207d5df8b63844588dc162f07620d`

Interface inventory: `wlan0` (`192.168.0.102/24`) is the real uplink; `veth-srv` (`192.168.70.1/24`) was created as the analyst/gateway side of an isolated host only link, with a `labclient` network namespace on the other end (`veth-cli`, `192.168.70.11/24`) simulating the victim machine, since a second physical/virtual host was not available. Initial ARP table on the analyst side showed no pre existing entry for the victim, confirming a clean starting state.

The instructor supplied scripts `arp.py` and `dns_spoof.py` were downloaded into `scripts/` and reviewed before execution. `dns_spoof.py`'s `hostDict` was edited to add the reserved training domain `portal.icdfa.test` → `192.168.70.1`, alongside the script's existing entries, so the spoof only ever targets the authorized training name.

A local authoritative resolver (`dnsmasq`) was configured on the analyst side, bound to `veth-srv` (`192.168.70.1`), serving `portal.icdfa.test` → `192.168.70.1`, with the victim namespace's resolver pointed at it via `/etc/netns/labclient/resolv.conf`. This was necessary because the victim's default network path could not reach the real upstream DNS server from inside the isolated namespace.

<img width="1366" height="768" alt="Fig01: Lab folder" src="https://github.com/user-attachments/assets/e6ac46af-1328-4682-8b8d-4f797917833e" />

**Fig01: Lab Folder**

### Mini Evidence and Chain of Custody Worksheet

| Field | Entry |
|---|---|
| Case/lab identifier | SBT-DF203-Lab8-BashirAdam |
| Trainee name | Bashir Adam (Azad) |
| Date/time started | 24 Sep 2026, approximately 22:34 WAT |
| Evidence file(s) | `dns_baseline.pcapng` |
| Environment | Single Kali host; analyst/gateway = root namespace (`192.168.70.1`); victim = `labclient` namespace (`192.168.70.11`) |
| Training domain | `portal.icdfa.test` (reserved, non production) |
| Training page SHA-256 | `951cbc61130ae2be4f33c88e274fcb780a9207d5df8b63844588dc162f07620d` |
| Baseline capture SHA-256 | `8cccaf45c2b04e69cc4cd2f581ca4115f9a955d927acc096aebdecb28b68173f` |
| Analysis workstation | Kali Linux (Lenovo ThinkPad L440) |
| Notes | Victim resolver pointed at a local `dnsmasq` instance on the analyst host (`192.168.70.1`), authoritative only for `portal.icdfa.test`, since the isolated namespace cannot reach the real upstream DNS server |

---

## Part A — Document the Baseline

| Field | Value |
|---|---|
| Victim IP / interface | `192.168.70.11` (`veth-cli`, `labclient` netns) |
| Analyst/gateway IP / interface | `192.168.70.1` (`veth-srv`) |
| Victim MAC (learned by analyst) | `ea:8e:3c:2c:2c:18` |
| DNS resolver | `192.168.70.1` (`dnsmasq`, authoritative for `portal.icdfa.test`) |
| Query | `portal.icdfa.test`, A |
| Response code | 0 (NOERROR) |
| Legitimate answer | `192.168.70.1` |
| TTL | 0s (`dnsmasq`'s static `address=` entries serve TTL 0 by design, not cached, always freshly authoritative) |
| Query time | 0 msec (local, no external hop) |
| HTTP confirmation | `curl` to `http://portal.icdfa.test/` → HTTP 200 (training page loads correctly via legitimate resolution) |

**Evidence file:** `evidence/dns_baseline.pcapng`
**SHA-256:** `8cccaf45c2b04e69cc4cd2f581ca4115f9a955d927acc096aebdecb28b68173f`

<img width="1366" height="768" alt="Fig02:Document the Baseline" src="https://github.com/user-attachments/assets/5c63f65f-9d3f-4a43-90d5-4ae37fb1d37e" />

**Fig02: Document the Baseline**

---

## Part B — Prepare the Authorized Simulation

IP forwarding was recorded as **already enabled** (`net.ipv4.ip_forward = 1`) prior to any lab action. This is noted precisely because it is not the assumed default; the restoration step in Part F must return this to **1**, not 0, to avoid mis restoring the host's actual prior state.

The pre existing firewall ruleset was exported and preserved: FORWARD chain shows three pre existing rules tied to `pan1` (Bluetooth PAN interface) with a NAT MASQUERADE rule for `10.92.142.0/24`, both unrelated host configuration carried over from before this lab, not artefacts of the DNS spoofing exercise. No rule yet exists affecting `veth-srv` or the `192.168.70.0/24` lab network.

Direct reachability to the training page was confirmed by IP (bypassing DNS entirely): `curl http://192.168.70.1/` returned the exact training page content, confirming the web server is reachable at its true IP before any spoofing is introduced, this is the control the later spoofed connection evidence (Parts D/E) will be measured against.

The `arp.py` and `dns_spoof.py` scripts were reviewed line by line before execution: `arp.py` performs bidirectional ARP spoofing between two specified IPs using scapy, restoring genuine ARP mappings on `Ctrl+C`; `dns_spoof.py` binds an NFQUEUE hook on the FORWARD chain, inspects DNS response packets, and rewrites the answer only for names present in its `hostDict`, confirmed to contain only the reserved training domain (`portal.icdfa.test`) pointed at the analyst IP, with no real domains or credential collection logic anywhere in either script.

**Evidence files:** `reports/ip_forward_before.txt`, `reports/iptables_before.rules`, `reports/direct_page_test.html`, `reports/arp_script_review.txt`, `reports/dns_script_review.txt`

<img width="1366" height="768" alt="Fig03:Authorized Simulation" src="https://github.com/user-attachments/assets/f88526bb-f6f0-47f3-b04a-0b6d8a55d774" />

**Fig03: Authorized Simulation**

---

## Part C — Capture the Controlled Spoofing Event

The controlled DNS spoofing simulation was executed under self authorization (analyst and instructor role combined for this isolated exercise), strictly confined to the reserved training domain `portal.icdfa.test` and an isolated host only network with no real domains, credential fields, or external connectivity involved.

**Topology correction note:** an initial attempt placed the DNS resolver on the same host as the analyst/gateway, which meant DNS responses never traversed the FORWARD chain (they were locally generated, i.e. OUTPUT), so NFQUEUE had nothing to intercept. This was corrected by introducing a third, separate network namespace (`dnsserver`, `192.168.71.2`) acting as the genuine authoritative resolver, positioned so that all victim DNS traffic genuinely passes **through** the analyst/gateway to reach it, matching the real world topology the attack model assumes. The baseline (Part A) was re captured against this corrected topology before proceeding.

### Sequence Executed

1. Packet capture started on `veth-srv`, scoped to the victim IP and ARP/DNS/HTTP traffic only.
2. `arp.py` launched against the victim (`192.168.70.11`) and gateway (`192.168.70.1`), performing bidirectional ARP spoofing, positioning the analyst host as the man in the middle for traffic between the victim and its gateway.
3. `dns_spoof.py` launched, binding an NFQUEUE hook to the FORWARD chain and inspecting all forwarded DNS responses for names in its `hostDict` (limited to the training domain).
4. From the victim, `dig portal.icdfa.test A` and a `curl` request were issued during the active window.

### Live Evidence Observed During Execution

- `dns_spoof.py` logged `[original] DNSRR` followed immediately by `[modified] DNSRR`, direct confirmation that a genuine response was intercepted and altered in flight.
- The victim's `dig` output showed `SERVER: 192.168.71.2#53` (the real resolver was queried) but returned `ANSWER SECTION: portal.icdfa.test. 0 IN A 192.168.70.1`, the analyst's IP, not the legitimate server's, a direct, captured forged response indicator.
- The victim's `curl` request returned HTTP 200, confirming the browser was successfully redirected to and served the ICDFA training warning page at the forged address.
- `arp.py` reported sending ARP replies claiming victim↔gateway IP to MAC mappings, consistent with the man in the middle positioning required before DNS interception was possible.

**Evidence file:** `evidence/dns_spoof_controlled.pcapng`
**SHA-256:** `7f522ca556f4beb2f7af346b4a35397d79bca319db5dffcfc0e2593e43b0fdbe`

<img width="1366" height="768" alt="Fig04: Capture the Controlled Spoofing Event" src="https://github.com/user-attachments/assets/01d4b6eb-6a58-4da5-95ac-b3a4b1970df7" />

**Fig04: Capture the Controlled Spoofing Event**

---

## Part D — Detect DNS Spoofing Indicators

30 packets captured over 27.45 seconds (3,632 bytes).

**Evidence file:** `evidence/dns_spoof_controlled.pcapng`
**SHA-256:** `7f522ca556f4beb2f7af346b4a35397d79bca319db5dffcfc0e2593e43b0fdbe`

### DNS Queries and Responses

| Frame | Time | Src MAC | Dst MAC | Query/Answer | Txn ID | Response? | Answer |
|---|---|---|---|---|---|---|---|
| 6 | .576371 | `ea:8e:3c:2c:2c:18` (victim) | `e6:a2:9f:f9:57:1c` | `portal.icdfa.test`, A | `0x79c3` | Query | — |
| 7 | .579498 | `e6:a2:9f:f9:57:1c` | `ea:8e:3c:2c:2c:18` | `portal.icdfa.test`, A | `0x79c3` | Response | **`192.168.70.1`**, TTL 0 |
| 8 | .604912 | victim | — | `portal.icdfa.test`, type 28 (AAAA) | `0x1af1` | Query | — |
| 9 | .605919 | — | victim | AAAA response | `0x1af1` | Response | rcode 5 (REFUSED) |

**Conflicting/forged answer indicator:** Frame 7's answer is `192.168.70.1`, the **analyst's own IP**, not the legitimate resolver's answer (`192.168.71.2`, confirmed in the corrected baseline). The transaction ID (`0x79c3`) and source IP in the packet correctly claim to be from the real resolver (`192.168.71.2` would be expected), but here the *Ethernet* source is `e6:a2:9f:f9:57:1c`, the analyst's interface, not the `dnsserver` namespace's real MAC, a textbook forged response signature: **the responder's claimed identity does not match the Ethernet layer origin of the packet.**

### ARP Claims During the Event

| Frame | Time | Claim |
|---|---|---|
| 2, 4 | .3078, .3554 | `192.168.70.1` (gateway) is-at `e6:a2:9f:f9:57:1c`, **false claim**; this is the analyst's MAC, not the real gateway's |
| 5, 25, 29 | .3629, 262.52, 272.66 | `192.168.70.11` (victim) is-at `ea:8e:3c:2c:2c:18`, reciprocal poisoning direction |
| 22, 24, 26, 28, 30 | throughout | Repeated re-assertions of the forged gateway mapping, consistent with `arp.py`'s continuous re-send loop (every approximately 3s) needed to keep ARP caches poisoned |

### Subsequent HTTP Connection (Victim Followed the Forged Answer)

| Frame | Time | Event |
|---|---|---|
| 12 | .606848 | TCP SYN: victim (`192.168.70.11:50622`) → **`192.168.70.1:80`** (the forged IP, not the real server) |
| 13 | .606882 | SYN-ACK from `192.168.70.1:80` |
| 15 | .606959 | HTTP GET `/` with `Host: portal.icdfa.test`, delivered to `192.168.70.1` |

**Time delta, DNS answer to connection:** 0.606959 minus 0.579498 (frame 7) is approximately **0.027 s (approximately 27 ms)**, the victim connected to the forged IP within milliseconds of receiving the forged answer, confirming direct cause and effect: the browser trusted and acted on the spoofed record immediately.

<img width="1366" height="768" alt="Fig05:Detect DNS Spoofing Indicators" src="https://github.com/user-attachments/assets/27ed9db0-6b59-43ee-87b0-7bb0c61e45d5" />

**Fig05: Detect DNS Spoofing Indicators**

---

## Part E — Baseline versus Spoof Comparison

| Indicator | Baseline (Legitimate) | Controlled Spoof Event |
|---|---|---|
| DNS query name/type | `portal.icdfa.test`, A | `portal.icdfa.test`, A |
| Transaction ID | Baseline `dig`, id 39052 (separate query) | `0x79c3` |
| Claimed responder (SERVER line / source IP) | `192.168.71.2` (real `dnsserver`) | `192.168.71.2` expected, but Ethernet layer response actually injected by analyst at `192.168.70.1`'s interface |
| Response code | NOERROR | NOERROR (forged response also returns NOERROR, no error flag alerts the victim) |
| **A record returned** | **`192.168.71.2`** (genuine server) | **`192.168.70.1`** (analyst/attacker IP, mismatched) |
| TTL | 0s | 0s (identical, attacker copied the legitimate record's TTL convention, not a distinguishing signal here) |
| Number of responses per query | One response observed | One response observed (in this run the forged answer alone reached the victim, no competing legitimate response was captured racing it) |
| ARP: gateway (`192.168.70.1`) mapping | Not applicable (no poisoning) | Falsely mapped to analyst MAC `e6:a2:9f:f9:57:1c` (frames 2, 4, 22, 24, 26, 28, 30, repeated every approximately 3s) |
| ARP: victim (`192.168.70.11`) mapping | Not applicable | Falsely mapped to analyst MAC `ea:8e:3c:2c:2c:18` claimed toward gateway direction (frames 5, 25, 29) |
| Subsequent HTTP connection destination | `192.168.71.2` (real server, via forwarded path) | **`192.168.70.1`** (forged IP, victim's browser trusted the poisoned answer) |
| HTTP response | 200 OK, genuine training page | 200 OK, **but served by the analyst's own Apache instance**, not the authorized `dnsserver` |
| Time from DNS answer to TCP SYN | Not separately timed in baseline | **Approximately 27 ms** (frame 7 → frame 12), near instantaneous use of the forged answer |
| Overall verdict | Consistent, single trustworthy answer, correct server reached | Forged answer accepted, ARP poisoned path enforced it, victim redirected to attacker controlled host within milliseconds |

---

## Part F — Cleanup and Verification

All lab processes (`arp.py`, `dns_spoof.py`, `dnsmasq`, the temporary HTTP server) were terminated. Any residual NFQUEUE rules were explicitly removed from the FORWARD chain. IP forwarding was restored to 1, matching its originally recorded pre lab value (Part B), not disabled, since disabling it would have mis restored a setting that was already enabled before this lab began.

Post cleanup `iptables -L` confirms the FORWARD chain contains only the three pre existing `pan1` related rules present since Part B, with **zero** lab created rules (DROP, ACCEPT, or NFQUEUE) remaining. ARP tables were flushed on both the analyst host and the victim namespace before namespace teardown, eliminating all poisoned entries. A process check for any of `arp.py`, `dns_spoof.py`, `dnsmasq`, or the training HTTP server returned no matches, confirming full termination. The lab only network namespaces (`labclient`, `dnsserver`) and the `veth-srv` interface were deleted entirely, since they were created solely for this exercise. Final interface inventory shows only the host's genuine interfaces (`lo`, `eth0`, `wlan0`, `pan1`), no lab artefacts remain on the system.

**Cleanup verification evidence:** `reports/iptables_after_cleanup.txt`, `reports/arp_after_cleanup.txt`, `reports/process_cleanup_check.txt`, `reports/interfaces_after_cleanup.txt`

<img width="1366" height="768" alt="Fig06:Cleanup and Verification" src="https://github.com/user-attachments/assets/ffa68351-9054-4fbd-af1f-59e796b2c03d" />

**Fig06: Cleanup and Verification**

---

## Detection and Defensive Recommendations

**Monitor DNS responses from unexpected MAC addresses or hosts.**
This lab's own capture demonstrates exactly why: the forged response's Ethernet source (`e6:a2:9f:f9:57:1c`, the analyst's interface) did not match the real resolver's known MAC, even though the IP layer still claimed to originate from the trusted resolver. A network monitoring baseline of "which MAC normally answers on port 53" would have flagged this immediately.

**Detect multiple answers for the same transaction with conflicting IPs.**
In this run only the forged answer reached the victim, but the general defence still applies: any DNS monitoring tool that tracks transaction IDs and alerts on two differing answers for the same ID is a direct, high confidence detection method for exactly this attack class.

**Use DNSSEC validation where supported, and encrypted/authenticated DNS transport (DoT/DoH) where appropriate.**
DNSSEC would have caused this forged response to fail signature validation, since the attacker cannot forge a valid cryptographic signature for the real zone. Encrypted DNS transport also would have prevented the NFQUEUE based interception used here, since the attacker's ability to rewrite responses depended entirely on read/write access to plaintext DNS traffic in transit.

**Deploy Dynamic ARP Inspection (DAI), DHCP snooping, switch port security, and network segmentation.**
The entire attack chain in this lab depended on ARP poisoning succeeding first, DAI on a managed switch would have dropped the forged ARP replies (frames 2, 4, 22, 24, 26, 28, 30) outright, since they claimed an IP to MAC binding inconsistent with DHCP snooped records. Without successful ARP poisoning, the DNS spoofing tool would never have been positioned to intercept the victim's traffic in the first place, this is the single most effective control point in this entire chain.

**Use HTTPS certificate validation; a forged DNS answer should not produce a valid certificate for the real service.**
Had `portal.icdfa.test` been served over HTTPS with a certificate genuinely issued for that domain, the victim's browser would have rejected the analyst's self-signed or mismatched certificate, surfacing a visible warning even though DNS itself was successfully spoofed. This lab's HTTP only training page intentionally omits this layer for simplicity, but it's worth noting explicitly as a control that operates independently of DNS integrity.

**Correlate DNS, ARP, endpoint cache, switch, web proxy, and TLS evidence.**
No single data source in this investigation was sufficient alone, the DNS capture showed a suspicious IP mismatch, but confirming it as an *attack* (rather than, say, load balancer reconfiguration) required cross referencing the ARP claims (forged gateway mapping) and the immediate, automatic HTTP connection to the forged IP. This lab's Part E comparison table is itself a small scale demonstration of that correlation discipline: only by combining DNS, ARP, and connection timing evidence together could spoofing be distinguished with high confidence from legitimate DNS variation.

**Confidence level for this finding:** High. Three independent, mutually reinforcing indicators (mismatched A record, forged ARP bindings claiming the gateway's identity, and a victim connection landing on the forged IP within approximately 27ms of the response) rule out benign explanations such as caching, split horizon DNS, or CDN load balancing, none of which would also require or produce falsified ARP claims.

---

## Conclusion

The evidence gathered across Parts A through F supports a single, high confidence forensic conclusion: the DNS response observed during the controlled event was a forged answer injected via an ARP poisoning enabled man in the middle position, not a legitimate DNS variation, caching artifact, or split horizon configuration.

Three independent lines of evidence converge on this finding. First, the DNS layer evidence: the forged response returned `192.168.70.1` where the verified legitimate baseline had returned `192.168.71.2`, a direct IP substitution inconsistent with normal caching behaviour, since both records shared the same query name, type, and TTL convention with no legitimate explanation for the differing answer. Second, the link layer evidence: the forged DNS response's Ethernet source MAC belonged to the analyst's interface rather than the genuine resolver's, and the ARP table showed the gateway's IP falsely and repeatedly bound to that same analyst MAC, a finding that cannot be explained by any benign DNS mechanism, since it requires active falsification of the local network's address resolution state. Third, behavioural evidence: the victim's subsequent HTTP connection landed on the forged IP within roughly 27 milliseconds of receiving the forged answer, and received a 200 OK response from the attacker's own web server rather than the authorized training host, demonstrating that the forged answer was not merely delivered but actively consumed and acted upon.

These three findings are mutually reinforcing and none is individually explainable by legitimate DNS behaviour (multiple authoritative answers, CDN load balancing, or normal cache expiry all leave ARP tables and Ethernet layer origins untouched), which is why this report assigns a **high confidence level** to the spoofing determination.

Restoration was verified rather than assumed: `iptables -L` after cleanup showed only the same pre existing, unrelated rules present before the lab began; ARP tables were flushed on all hosts; every lab spawned process (`arp.py`, `dns_spoof.py`, `dnsmasq`, the temporary HTTP server) was confirmed terminated; and all lab only network namespaces and interfaces were deleted, returning the host to its original network configuration.

The detection and defensive recommendations above, particularly Dynamic ARP Inspection and DNSSEC validation, target the two structural weaknesses this simulation exploited directly: the ability to forge ARP bindings, and the absence of any cryptographic guarantee on DNS response authenticity. All evidence files, hashes, and command outputs referenced throughout this report are preserved under `~/SBT-DF203-Lab8/{evidence,reports}` and are available in the accompanying submission package.
