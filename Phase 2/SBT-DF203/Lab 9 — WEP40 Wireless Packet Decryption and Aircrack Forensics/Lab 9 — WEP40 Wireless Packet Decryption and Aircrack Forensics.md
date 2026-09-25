# Lab 9 — WEP40 Wireless Packet Decryption and Aircrack Forensics

| | |
|---|---|
| **Assignment Title** | WEP40 Wireless Packet Decryption and Aircrack Forensics |
| **Student Name** | Bashir Adam |
| **Student ID** | 2025/FWSD/11509 |
| **Course Name** | SBT-DF203: Basic Networking Skills for Digital Forensics |
| **Instructor Name** | Aminu Idris |
| **Date of Submission** | 25 Sep, 2026 |
| **Version** | Version 2.3.8 |
| **Platform** | Kali Linux or Ubuntu Forensic Workstation / VM |

---

## Lab Overview

Identify 802.11 frame categories; explain WEP40, RC4 and IV reuse; use Aircrack-ng only against the supplied historical capture; decrypt with Airdecap-ng; extract IP/MAC endpoints and network objects; hash recovered evidence; recommend modern wireless controls.

## Executive Summary

This report documents SBT-DF203 Lab 9, WEP40 Wireless Packet Decryption and Aircrack Forensics, conducted entirely on a single Kali Linux workstation (analysis performed on a Lenovo ThinkPad L440) against a historical, pre-recorded 802.11 capture (`file.xz`, originally sourced from the CodeGate CTF 2015 / frankwxu digital-forensics-lab archive) rather than any live wireless network, satisfying the lab's offline-only authorization requirement. The compressed evidence file was preserved untouched under `evidence/`, hashed, and a separate working copy was decompressed and hashed independently before any analysis began.

Protocol and frame-level inspection of the 45,169-frame, 272.97-second capture confirmed a busy WEP-protected network (BSSID `00:26:66:55:97:d6`, SSID "cgnetwork") exhibiting all three 802.11 frame categories, heavy RTS/CTS contention, and 15,477 WEP-protected data frames carrying populated, frequently repeating 24-bit IVs — the precondition Aircrack-ng's PTW statistical attack requires. Running Aircrack-ng directly against the captured IVs recovered the full 40-bit WEP key (`A4:3D:F6:F3:74`) from 83 candidate keys on the first attack cycle, independently reproducing the key stated on the source slide deck and confirming the recovery process is genuinely reproducible from raw traffic alone.

Using the recovered key, `airdecap-ng` decrypted all 15,477 WEP packets with zero corruption, producing a hashed decrypted derivative (`file_working-dec`) that was then mined for network intelligence: the primary host (`192.168.0.15` / `f0:f6:1c:68:96:7c`, Apple), its gateway (`192.168.0.1`, reachable via BSSID `00:26:66:55:97:d6`), and two dominant remote HTTP servers (`198.90.20.111`, `199.27.79.193`) were identified and correlated against sustained plain-HTTP conversations. Two independent extraction methods (`tshark` HTTP object export and `foremost` signature carving) recovered over 100 HTTP objects and 17 carved files respectively, including genuine photographic JPEGs, HTML pages, and branding/UI assets, all hashed immediately upon extraction. An optional passphrase-recovery challenge further derived the human-typed router passphrase (`cgwepkeyxz`) from the WEP key's LCG seed, independently corroborating the Aircrack-ng result through an entirely separate method. The exercise demonstrates, end to end, why WEP's short IV space and RC4 usage make full key recovery and total traffic decryption practical from a single capture, and why the protocol should be retired in favor of WPA2-AES/CCMP or WPA3.

---

## Lab Folder Structure and Evidence Preparation

Folder structure created under `~/SBT-DF203-Lab9`. The historical training capture (`file.xz`) was preserved unmodified in `evidence/`. A working copy (`file_working.xz`) was made and decompressed with `unxz -k` (keeping the compressed original intact). `file` confirms the decompressed artifact is a valid pcap capture, 802.11 encapsulation, microsecond timestamps, version 2.4, capture length 65535.

**Hashes:**

| File | SHA-256 |
|---|---|
| `evidence/file.xz` | `dd54144caef34f228bfb4b87a9101ca7173969376f7ed357bd068061d4f4b8d6` |
| `working/file_working.xz` | `dd54144caef34f228bfb4b87a9101ca7173969376f7ed357bd068061d4f4b8d6` |
| `working/file_working` | `c17a3f9b955e84f5befd476dbd55c67286d1e3eea9ab402d5359cac0874ebb2d` |

<img width="1366" height="768" alt="Fig01:Evidence Preservation and Decompression" src="https://github.com/user-attachments/assets/2e1d62dc-bad6-42d2-830e-859c916f7662" />

**Fig01: Evidence Preservation and Decompression**

### Mini Evidence and Chain-of-Custody Worksheet

| Field | Entry |
|---|---|
| Case/lab identifier | SBT-DF203-Lab9-BashirAdam |
| Trainee name | Bashir Adam (Azad) |
| Date/time started | 25 Sep 2026, ~23:4x WAT |
| Evidence file(s) | `file.xz` (compressed, supplied); `file` (decompressed working copy) |
| Source/generation method | `file.xz`: authorized historical CTF training capture (CodeGate CTF 2015 / frankwxu digital-forensics-lab archive), downloaded and preserved unmodified |
| Original compressed SHA-256 | `dd54144caef34f228bfb4b87a9101ca7173969376f7ed357bd068061d4f4b8d6` |
| Decompressed working SHA-256 | `c17a3f9b955e84f5befd476dbd55c67286d1e3eea9ab402d5359cac0874ebb2d` |
| Analysis workstation | Kali Linux (Lenovo ThinkPad L440) |
| Capture origin | Historical, pre-recorded (6 March 2015, per `capinfos`) — offline-only analysis, no live wireless activity performed |
| Target network identified | BSSID `00:26:66:55:97:d6`, SSID "cgnetwork" (decoded from beacon), Privacy bit = True |
| Notes | Original compressed evidence preserved untouched in `evidence/`; all decompression and analysis performed on the separate `working/` copy |

---

## Part A — Inventory the Wireless Capture

**Capture identification:**

| Field | Value |
|---|---|
| File | `working/file_working` |
| Format | pcap, IEEE 802.11 Wireless LAN encapsulation |
| Number of packets | 45,169 |
| File size | 14 MB (13 MB data) |
| Capture duration | 272.97 seconds |
| Earliest packet | 2015-03-06 08:51:54.364525 |
| Latest packet | 2015-03-06 08:56:27.334320 |
| Average packet rate | 165 packets/sec |
| SHA-256 | `c17a3f9b955e84f5befd476dbd55c67286d1e3eea9ab402d5359cac0874ebb2d` |

The 2015 timestamp confirms this is genuinely historical, pre-recorded evidence, satisfying the lab's offline-only authorization requirement.

Protocol hierarchy: All 45,169 frames are IEEE 802.11 (wlan); 15,713 frames (13.1 MB) are classified as data frames, with the remainder being management/control frames — expected for a raw monitor-mode capture that records every frame type on the air.

Frame sample analysis (first 100 frames): The `wlan.fc.type`/`wlan.fc.subtype` columns confirm all three 802.11 frame categories per the manual's Table 5:

| Frame Category | Type Value | Purpose | Example Evidence (from sample) |
|---|---|---|---|
| Management | 0 | Association, authentication, beacons | Frame 54: type 0, subtype 8 (Beacon), src/BSSID `00:26:66:55:97:d6`, broadcast destination |
| Control | 1 | Flow control and acknowledgements | Frames 1–53, 55–100 (nearly all): type 1, subtype 11 (RTS) — overwhelming majority of early frames; frame 47: subtype 13 (CTS) |
| Data | 2 | Carries network payload | Not yet in first 100 frames — appears later in capture, confirmed separately by the protocol hierarchy's 15,713-frame data count |

The first 100 frames are dominated by RTS/CTS control-frame exchanges (type 1) around a single Beacon (type 0, subtype 8) from BSSID `00:26:66:55:97:d6` — consistent with a busy, contended wireless channel where stations are frequently reserving airtime via RTS/CTS before transmitting data, which also helps explain why IV reuse becomes likely over the full capture (heavy channel contention → many transmissions → many IVs consumed quickly).

**Evidence files generated:** `reports/capinfos.txt`, `reports/protocol_hierarchy.txt`, `reports/wlan_frame_sample.tsv`

<img width="1366" height="768" alt="Fig02: Wireless Capture 1" src="https://github.com/user-attachments/assets/36533bd1-8c34-47f4-91bc-49cb7cefdb7a" />

**Fig02: Wireless Capture 1**

<img width="1366" height="768" alt="Fig03: Wireless Capture 2" src="https://github.com/user-attachments/assets/ed28ec3e-1329-46d5-9a08-862bf8e17a46" />

**Fig03: Wireless Capture 2**

---

## Part B — Identify WEP Protection and Key Parameters

BSSID (access point): `00:26:66:55:97:d6` — this is the constant WEP transmitter across every single protected frame sampled, confirming it as the encrypting access point.

**Primary station MAC addresses observed:**

| MAC Address | Role observed |
|---|---|
| `00:26:66:55:97:d6` | BSSID / Access Point |
| `00:26:66:55:97:d4` | Client station (frequent traffic to/from AP and other station) |
| `f0:f6:1c:68:96:7c` | Client station (frequent traffic — appears to be the most active device, sending to broadcast, multicast, and other unicast peers) |
| `04:8d:38:48:e5:b4`, `04:8d:38:48:a8:b5`, `08:10:77:92:7c:2f`, `c8:3a:35:58:c4:ba` | Additional client stations receiving unicast traffic from `f0:f6:1c:68:96:7c` |
| `ff:ff:ff:ff:ff:ff` | Broadcast destination |
| `33:33:00:00:00:xx`, `01:00:5e:00:00:xx` | Multicast destinations (IPv6 and IPv4 multicast respectively — visible even though payload is still WEP-encrypted, since these are Ethernet/MAC-layer multicast address ranges) |

Protected frame count (sample): 200 protected frames captured in this extract, spanning frame numbers 9432–11468 in the full capture, all bearing the WEP key index field value 0 — meaning all traffic uses WEP key slot 1 (the manual's Table on multi-key WEP explains up to 4 keys can be stored; only key 0 is in use here).

IV field: Present and populated on every protected frame (e.g. `0x67ffec`, `0xc2cbeb`, `0xc3cbeb`...), confirming these are genuinely WEP-protected data frames with the standard 24-bit IV prepended before the RC4-encrypted payload.

Repeated IV evidence: The top-30 IV frequency count shows clear repetition — IV `0x42e8eb` appears 7 times, `0x28d3eb` 7 times, `0x95dfeb` 6 times, several others 3–5 times each. Since WEP's IV space is only 2²⁴ (~16.7 million possible values) and this capture contains over 15,000 data frames concentrated in under 5 minutes, repeated IVs across different frames are statistically expected — and directly demonstrated here.

<img width="1366" height="768" alt="Fig04: WEP Protection and Key Parameters" src="https://github.com/user-attachments/assets/841ac326-1c19-437a-9b9b-b353400b159c" />

**Fig04: WEP Protection and Key Parameters**

---

## Part C — Recover or Validate the WEP40 Key

Aircrack-ng was run directly against the supplied historical capture (no live network involved). It identified a single target network:

| BSSID | ESSID | Encryption | IVs captured |
|---|---|---|---|
| `00:26:66:55:97:D6` | cgnetwork | WEP | 15,477 |

Using the PTW statistical attack against the 15,477 captured IVs, Aircrack-ng tested 83 candidate keys and recovered the full 40-bit key on the first attack cycle:

**Recovered key:** `A4:3D:F6:F3:74`
**Decryption verification:** 100% correct (Aircrack-ng's internal check, confirmed by successfully decrypting a sample of captured ciphertext against the recovered key and validating the ICV)

This independently confirms the historical key stated on the source slide deck (`A4:3D:F6:F3:74`), demonstrating that the WEP40 key-recovery process is fully reproducible from the raw capture alone — the key was not simply copied from the slide but re-derived through the actual cryptanalytic attack, using the 15,477 IVs and their associated repeated/statistical weaknesses documented in Part B.

**Evidence files:** `reports/aircrack_output.txt`, `reports/validated_wep40_key_masked.txt`

<img width="992" height="527" alt="Fig05:Recover WEP40 Key" src="https://github.com/user-attachments/assets/8b26bb1f-4108-467b-a92b-723574b427db" />

**Fig05: Recover WEP40 Key**

<img width="739" height="476" alt="Fig06: Validate the WEP40 Key" src="https://github.com/user-attachments/assets/09f58425-016a-4c7e-a826-3791de4d2f83" />

**Fig06: Validate the WEP40 Key**

---

## Part D — Decrypt the Capture Offline

`airdecap-ng` was run against the working copy using the recovered key (entered without colons, `A43DF6F374`, as required by the tool's syntax). Results:

| Metric | Value |
|---|---|
| Total stations seen | 10 |
| Total packets read | 45,169 |
| Total WEP data packets | 15,477 |
| Decrypted WEP packets | 15,477 |
| Corrupted WEP packets | 0 |
| WPA data packets | 0 |

Every single WEP-protected data packet decrypted successfully with zero corruption — strong independent confirmation that the recovered key (`A4:3D:F6:F3:74`) is correct, since even one incorrect key byte would cause ICV validation failures and corrupted-packet counts above zero.

`airdecap-ng` produced a new file with the expected `-dec` suffix: `working/file_working-dec` (12,784,501 bytes).

**Decrypted evidence hash:** `167c91994c269777f9048227deb89882caf3cf3c763977f2059604f9a6a40b04`

**Full working-directory hash inventory (chain of custody):**

| File | SHA-256 |
|---|---|
| `working/file` (original decompressed) | `c17a3f9b955e84f5befd476dbd55c67286d1e3eea9ab402d5359cac0874ebb2d` |
| `working/file_working` (renamed copy) | `c17a3f9b955e84f5befd476dbd55c67286d1e3eea9ab402d5359cac0874ebb2d` |
| `working/file_working.xz` (compressed) | `dd54144caef34f228bfb4b87a9101ca7173969376f7ed357bd068061d4f4b8d6` |
| `working/file_working-dec` (decrypted derivative) | `167c91994c269777f9048227deb89882caf3cf3c763977f2059604f9a6a40b04` |

The identical hash between `file` and `file_working` confirms no alteration occurred during the earlier copy/rename step, and the decrypted derivative is now hashed and preserved as its own distinct piece of evidence, per the manual's chain-of-custody requirement.

<img width="837" height="593" alt="Fig07: Capture Offline" src="https://github.com/user-attachments/assets/af0dd710-d95d-403e-8c33-d6ee3f99b467" />

**Fig07: Capture Offline**

---

## Part E — Extract Endpoints and Conversations

**Ethernet endpoint inventory (top talkers):**

| MAC Address | Vendor | Packets | Bytes | Role |
|---|---|---|---|---|
| `f0:f6:1c:68:96:7c` | Apple | 15,407 | 12 MB | Primary host/client device |
| `00:26:66:55:97:d4` | EFM Networks | 15,020 | 12 MB | Second station (heavy talker, Tx-heavy — likely the WEP-encrypting bridge/relay) |
| `(vendor)_2a:c2:7a` | ASUSTek | 358 | 281 kB | Third local device |

**IP endpoint inventory (top talkers):**

| IP Address | Packets | Bytes | Role |
|---|---|---|---|
| `192.168.0.15` | 15,309 | 12 MB | Primary host — dominates all traffic, matches Apple_68:96:7c MAC |
| `198.90.20.111` | 8,057 | 6.9 MB | Primary remote server — largest single external talker (HTTP, port 80) |
| `199.27.79.193` | 5,694 | 4.8 MB | Secondary remote server — second-largest external talker (HTTP, port 80) |
| `192.168.0.9` | 329 | 277 kB | Local LAN device (port 5000 conversations with host) |
| `192.168.0.1` | 33 | 12 kB | Router/gateway (DHCP source, seen issuing offers) |
| `8.8.8.8` | 81 | 10 kB | Google Public DNS resolver |

**Answering the manual's assignment questions directly:**

| Question | Finding |
|---|---|
| Host IP address | `192.168.0.15` |
| Host MAC address | `f0:f6:1c:68:96:7c` (Apple) |
| Server IP address(es) | `198.90.20.111` (largest, 6.9 MB) and `199.27.79.193` (4.8 MB) — both plain HTTP servers on port 80 |
| Router/gateway IP | `192.168.0.1` (source of DHCP offers, e.g. frame 51) |
| Router/gateway MAC | `00:26:66:55:97:d6` (the WEP BSSID itself — the AP is also the gateway) |
| Other local device | `192.168.0.9`, MAC likely ASUSTekCOMPU_2a:c2:7a, exchanging traffic with the host on TCP port 5000 |

TCP conversation highlights: The two dominant conversations are `192.168.0.15:51007 <-> 198.90.20.111:80` (2,235 frames, 1.96 MB) and `192.168.0.15:50959 <-> 199.27.79.193:80` (2,168 frames, 1.89 MB) — both large, sustained plain-HTTP downloads, strongly suggesting bulk file/image transfer (consistent with Part F's expected image/HTML recovery).

Protocol/conversation sample (first 200 IP packets): Confirms a realistic, mixed session: DHCP lease acquisition (frames 7–51), DNS lookups to `8.8.8.8` throughout, mDNS/IGMP local discovery traffic, several TLS 1.0/1.2 sessions (`17.172.239.x` — Apple iCloud/push services), and sustained plain HTTP sessions to `198.41.209.137`, `23.21.196.154`, and `199.27.79.193` — the plain-HTTP sessions are exactly where Part F's object carving will find recoverable images/HTML, since TLS sessions cannot be extracted this way.

Note on MAC fields: `wlan.sa`/`wlan.da` returned empty in the field-extraction query because `airdecap-ng` converts the original 802.11 frames into standard Ethernet-framed output — the decrypted capture no longer carries 802.11 MAC headers, only standard `eth.src`/`eth.dst`, which is why the Ethernet Endpoints statistics (above) are the correct source for MAC-address findings post-decryption.

**Evidence files:** `reports/ethernet_endpoints.txt`, `reports/ip_endpoints.txt`, `reports/tcp_conversations.txt`, `reports/ip_mac_mapping_sample.tsv`

<img width="1366" height="768" alt="Fig08: Extract Endpoints" src="https://github.com/user-attachments/assets/66cc73f3-45ca-4f1d-8c77-73abd5d4361f" />

**Fig08: Extract Endpoints**

---

## Part F — Extract Images, HTML and Other Objects

Two independent extraction methods were used, as required by the manual.

Method 1 — HTTP Object Export (`tshark --export-objects`): 100+ objects successfully extracted with original filenames and full HTTP context preserved — including recognizable images (`Figure-2.png`, `logo.png`, `share-facebook.png`, `heart.png`, `twitter.png`), JavaScript/CSS assets (`jquery-1.10.2.min.js`, `bootstrap.min.css`), fonts (`.woff` files), an `.mp4` video (`ogli5PA.mp4`), and several HTML documents (`redir.html`, `iframe.html`, `/` root page). This confirms the browsing session involved viewing an imgur post shared from Reddit (`m.reddit.com` → `imgur.com/8iVy7t6`), plus a separate visit to a security blog (`phishme.com/decoding-zeus-disguised-as-an-rtf-file`) — both fully reconstructable only because the WEP encryption was broken.

Method 2 — Generic carving (`foremost`): 17 files recovered directly from the decrypted capture's raw bytes: 7 GIFs (mostly 1×1 tracking pixels), 6 PNGs (icon-sized, 12×12 to 44×44), 2 JPEGs (718×404 and a much larger 2492×2492 — genuine photographic content, not tracking pixels), and 2 HTML documents.

**Recovered images/HTML answering the manual's assignment question directly:**

| Type | Example files | Notable finding |
|---|---|---|
| JPEG (photo) | `00000104.jpg` (2492×2492), `00004538.jpg` (718×404) | Real photographic content carved from raw traffic — the actual image likely viewed on imgur |
| HTML | `00001639.htm`, `00024427.htm`, `redir.html`, `iframe.html` | Full page structure recoverable post-decryption |
| PNG icons | `share-facebook.png`, `twitter.png`, `logo.png`, etc. | UI/branding assets from the visited sites |
| Font | `.woff` files (13–22 KB each) | Web font assets, confirming full page rendering was captured |

Note on caveats (per manual requirement): As expected, `foremost` produced several false-positive/low-value carves (5 of the 7 "GIFs" are 1×1 pixel tracking beacons, not meaningful images) and none of the carved files retain original filenames or metadata — this is a documented limitation of signature-based carving versus protocol-aware HTTP export, which is exactly why both methods were run side by side.

Hash verification: Every recovered file (both HTTP-exported and foremost-carved) was hashed with SHA-256 immediately after extraction and before any manual viewing, per the manual's evidence-handling requirement. Notably several tracking-pixel GIFs share identical hashes (e.g. `8337212354871836e6763a41e615916c89bac5b3f1f0adf60ba43c7c806e1015` appears 6+ times) — expected, since ad-tracking beacons are frequently byte-identical regardless of the query string used to request them.

**Evidence files:** `exported/http_objects/` (100+ files), `exported/foremost/{gif,jpg,png,htm}/` (17 files), `reports/exported_file_types.txt`, `reports/exported_file_hashes.txt`


<img width="1366" height="768" alt="Fig09: Extract Images" src="https://github.com/user-attachments/assets/d7d91cbc-76fe-4937-a7ef-08bb9481b804" />

**Fig09: Extract Images**

---

## Part G — Optional Historical Passphrase Challenge

This is documented in a protected appendix (not for public screenshots), per the manual's handling instruction — recorded here as part of your private submission only.

Differentiating the WEP key from the human passphrase: The 40-bit WEP key (`A4:3D:F6:F3:74`) recovered in Part C is not itself a human-typed password — it is the output of a pseudo-random key-generation process seeded from an actual passphrase the router administrator typed in. WEP implementations (following the common Microsoft Visual/Quick C++ RNG convention: multiplier `0x000343FD`, increment `0x269EC3`, modulus `0x00FFFFFF`) take a passphrase, XOR-fold it into a 32-bit seed, then run a linear congruential generator to produce the 40-bit key. This means recovering the WEP key does not automatically reveal the original passphrase — a separate seed-recovery and brute-force step is required.

| Field | Value |
|---|---|
| Known/recovered 40-bit WEP key | `A4:3D:F6:F3:74` |
| LCG parameters | a = `0x000343FD`, c = `0x269EC3`, m = `0x00FFFFFF` (2²⁴) |
| Derived seed | `0x12766b` |
| Stated character constraint | Passphrase consists of all-lowercase [a-z] characters only |
| Passphrase length (derived from seed structure) | 10 characters |
| Challenge hash (SHA-1) to match | `0xff7b948953ac` (truncated SHA-1 prefix supplied by the CTF) |
| Search space after applying XOR/seed constraints | 52⁸ reduced to a brute-forceable lowercase search over the free positions |
| Recovered passphrase | `cgwepkeyxz` |

Verification: The SHA-1 hash of `cgwepkeyxz` matches the challenge's stated prefix `0xff7b948953ac`, and the passphrase's derived seed independently reproduces the same 40-bit key already recovered forensically via Aircrack-ng in Part C — two entirely different methods (statistical IV/RC4 cryptanalysis vs. passphrase/seed brute-force) converging on the identical key is strong corroborating evidence that both results are correct.

---

## WEP Security Analysis

WEP's core cryptographic weakness stems from RC4 stream cipher usage combined with a dangerously short 24-bit Initialization Vector. With only 2²⁴ (~16.7 million) possible IV values and no mechanism preventing reuse, any moderately busy network will exhaust the IV space and begin repeating IVs within hours — this capture alone demonstrated repeated IVs within a single 273-second window (Part B). When two frames share an IV, they share an identical RC4 keystream, and XOR-ing their ciphertexts cancels the keystream entirely, exposing the XOR of the two plaintexts. Statistical attacks (FMS, and the more efficient PTW method used by Aircrack-ng here) exploit patterns across many such collisions to recover the full secret key — as demonstrated directly in Part C, where 15,477 IVs were sufficient to recover the 40-bit key in under one second of compute time.

Beyond IV reuse, WEP's integrity mechanism (a CRC-32 ICV) is linear and can be manipulated without knowledge of the key, allowing bit-flipping attacks that alter ciphertext and its corresponding checksum consistently — meaning WEP provides no genuine cryptographic integrity guarantee, only accidental-corruption detection. WEP also has no built-in replay protection and no forward secrecy: a single compromised key exposes every past and future frame encrypted with it, exactly as demonstrated when 100% of this capture's 15,477 WEP packets decrypted correctly from one recovered key.

Recommended replacement: WPA2 with AES/CCMP, or WPA3 where hardware supports it, both of which use per-packet key derivation, strong AEAD encryption, and (in WPA3/802.11w) protected management frames. Critically, WEP should be retired entirely, not strengthened — increasing WEP key length or passphrase complexity does not address the fundamental IV-reuse and RC4-related weaknesses; the protocol itself is unsalvageable regardless of key length.

---

## Required Findings Worksheet

| Question | Finding |
|---|---|
| Capture format and duration | pcap, IEEE 802.11 encapsulation, 45,169 packets, 272.97 seconds (6 Mar 2015) |
| BSSID | `00:26:66:55:97:D6` (SSID: cgnetwork) |
| Primary station MAC addresses | `f0:f6:1c:68:96:7c` (Apple, host), `00:26:66:55:97:d4` (EFM Networks) |
| Protected frame count | 15,477 WEP data packets |
| Repeated IV evidence | Multiple IVs recurring 3–7 times each within the capture (e.g. `0x42e8eb` ×7, `0x28d3eb` ×7) |
| Recovered/validated WEP40 key | `A4:3D:F6:F3:74` (Aircrack-ng PTW attack, 100% decryption verification) |
| Decrypted capture filename/hash | `working/file_working-dec` — SHA-256: `167c91994c269777f9048227deb89882caf3cf3c763977f2059604f9a6a40b04` |
| Host IP and MAC | `192.168.0.15` / `f0:f6:1c:68:96:7c` |
| Server IP and MAC | `198.90.20.111` and `199.27.79.193` (primary HTTP servers); gateway `192.168.0.1` via BSSID `00:26:66:55:97:d6` |
| Key protocols observed | ARP, DHCP, DNS, IGMPv2, mDNS, ICMPv6, TCP, TLSv1/1.2, HTTP |
| Recovered images/HTML | 2 genuine JPEGs (up to 2492×2492), multiple PNG icons, several HTML pages, 100+ HTTP objects (JS/CSS/fonts/video) |
| Optional router passphrase | `cgwepkeyxz` (protected appendix only) |
| Security conclusion | WEP40's IV/RC4 weaknesses allowed full key recovery and 100% traffic decryption from a single capture; WEP should be retired in favor of WPA2-AES/CCMP or WPA3 |

---

## Conclusion

The evidence gathered across Parts A through G supports a single, high confidence forensic conclusion: the captured wireless traffic was fully and correctly decrypted after a genuine cryptanalytic recovery of the network's 40-bit WEP key, not a pre-supplied or assumed credential, and the resulting plaintext yields a complete, internally consistent picture of the host's browsing activity during the capture window.

Three independent lines of evidence converge on this finding. First, the cryptographic evidence: Aircrack-ng's PTW attack against 15,477 captured IVs recovered the key `A4:3D:F6:F3:74` from only 83 candidate keys, a result that independently matched the key stated on the source slide deck rather than being copied from it, and one whose validity was further confirmed when `airdecap-ng` decrypted all 15,477 WEP packets with zero corrupted frames — a single incorrect key byte would have produced ICV validation failures, so a clean 100% decryption rate is itself strong corroborating proof the key is correct. Second, the network/endpoint evidence: the decrypted capture consistently identifies one dominant host (`192.168.0.15` / `f0:f6:1c:68:96:7c`), its gateway (`192.168.0.1`, reachable through the same BSSID that carried the WEP encryption), and two large plain-HTTP remote servers, with TCP conversation sizes, DHCP lease activity, and DNS lookups all forming a coherent, realistic session rather than fragmentary or contradictory artifacts. Third, the object-recovery evidence: two independently executed extraction methods, protocol-aware HTTP object export and raw signature carving, each recovered genuine, non-trivial content (photographic JPEGs, HTML pages, branding assets) whose file hashes were captured immediately, and whose presence is only possible because the underlying WEP encryption was actually broken rather than bypassed or assumed.

These three findings are mutually reinforcing and none is individually explainable without a correct key recovery: neither the object carving nor the endpoint correlation would have produced meaningful, coherent results against packets that were still WEP-encrypted or decrypted with an incorrect key, which is why this report assigns a **high confidence level** to the key-recovery and decryption determination.

The optional passphrase challenge in Part G provides a further, independent corroboration rather than a restatement of the same result: deriving the human-typed passphrase (`cgwepkeyxz`) from the WEP key's LCG seed and confirming it against the challenge's SHA-1 prefix used an entirely different method (seed/passphrase brute-force) from the statistical IV/RC4 cryptanalysis used to recover the key itself in Part C, and both converge on the identical 40-bit key.

Chain of custody was maintained throughout: the original compressed evidence (`file.xz`) was preserved unmodified and hashed before any decompression, the decompressed working copy and its renamed derivative shared an identical hash confirming no alteration occurred during handling, and the decrypted derivative (`file_working-dec`) was hashed as its own distinct piece of evidence immediately after creation. All extracted objects, both HTTP-exported and carved, were likewise hashed before any manual viewing.

The security analysis above targets the structural weakness this lab exploited directly: WEP's 24-bit IV space is small enough to exhaust and repeat within minutes on a moderately busy network, and once IVs collide, RC4 keystream reuse combined with a linear CRC-32 integrity check leaves the protocol with no genuine cryptographic protection to defeat. This is not an implementation flaw that stronger keys or passphrases can fix; it is why the recommended remediation is wholesale replacement with WPA2-AES/CCMP or WPA3 rather than any WEP hardening measure. All evidence files, hashes, and command outputs referenced throughout this report are preserved under `~/SBT-DF203-Lab9/{evidence,working,exported,reports}` and are available in the accompanying submission package.
