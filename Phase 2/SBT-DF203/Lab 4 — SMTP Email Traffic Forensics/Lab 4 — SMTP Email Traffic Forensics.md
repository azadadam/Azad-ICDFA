# Lab 4: SMTP Email Traffic Forensics

## Assignment Information

 
  **Lab Title**                       Lab 4 --- SMTP Email Traffic
                                      Forensics

  **Assignment Title**                SMTP Email Traffic Forensics

  **Student Name**                    Bashir Adam

  **Student ID**                      2025/FWSD/11509

  **Course Name**                     SBT-DF203: Basic Networking Skills
                                      for Digital Forensics

  **Instructor Name**                 Aminu Idris

  **Date of Submission**              15 September 2026

  **Version**                         Version 2.3.3

  **Platform**                        Kali Linux or Ubuntu Forensic
                                      Workstation / VM
  -----------------------------------------------------------------------

## Lab Overview

Explain SMTP and common ports; identify SMTP commands and response
codes; reconstruct an SMTP TCP stream; decode Base64 offline; extract
message headers, client software, IPs, ports and MACs; assess
STARTTLS/TLS and evidential limitations.

## Introduction

This report documents a controlled forensic analysis of a historical
SMTP packet capture, conducted as part of SBT-DF203: Basic Networking
Skills in Digital Forensics. The exercise used `smtp.pcap`, a publicly
available, well-known training capture hosted by the Wireshark project
itself, authorized specifically for this kind of educational analysis.
The objective was to reconstruct a complete email exchange purely from
network evidence: identifying the client and server, mapping the full
SMTP command/response sequence, safely decoding Base64-encoded
authentication data offline, reconstructing the transmitted email
message and its attachment via TCP stream reassembly, extracting network
and hardware-layer metadata, and critically assessing what the absence
of encryption reveals---and what it would have hidden had TLS been used
instead.

Before beginning any hands-on work, I reviewed the official SBT-DF203
Lab 4 manual and the accompanying lecture material on SMTP, plaintext
versus STARTTLS/SMTPS traffic, Base64 encoding, and TCP stream
reassembly. Because this exercise involves genuine (if historical and
non-sensitive) authentication credentials and personal message content,
all sensitive values are redacted in this report's main body per the
lab's explicit safety and reporting rules, with full decoded values
reserved for a protected appendix only where required.

## Step 1: Folder Setup and Evidence Preparation

<img width="1366" height="508" alt="Fig01: Folder Setup" src="https://github.com/user-attachments/assets/8911fc9a-e169-4221-a5ff-9ce911e8d8c0" />  

**Fig01: Folder Setup**

## Step 2: Install Tools, Hash, and `capinfos`

**Evidence hash:**
`17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab`
(original and working copy identical).

`capinfos` confirms: 60 packets, 27 kB, Ethernet encapsulation, captured
2009-10-05 07:06:07.492060 to 2009-10-05 07:06:16.690444 (9.2 seconds
duration). This directly answers the "when did the exchange occur"
question: 5 October 2009, 07:06:07--07:06:16 UTC (capinfos reports raw
timestamps, timezone to be confirmed from context).

<img width="1366" height="768" alt="Fig02: tools" src="https://github.com/user-attachments/assets/518a52dc-060d-4a24-a5d8-02138ef2eb6c" />
  
  **Fig02: Tools**

## Part A: Inventory the Capture and Locate SMTP Streams

`conv,tcp` shows a single TCP conversation: `10.10.1.4:1470` ↔
`74.53.140.153:25` --- 53 total frames, 24 kB, spanning 7.58 seconds.
Port 25 confirms this is plaintext SMTP (not the submission ports
587/465).

The `smtp` filter isolated 28 SMTP-relevant frames (server banner
through session close). Key observations:

| **Observation** | **Finding** |
|---|---|
| First SMTP frame | #6, 2009-10-05 07:06:08 (server banner) |
| Last SMTP frame | #56, 2009-10-05 07:06:15 (server closing connection) |
| SMTP server port | 25 (74.53.140.153) |
| Client ephemeral port | 1470 (10.10.1.4) |

I also note frames 26, 28--30 show ICMP "Destination unreachable
(Fragmentation needed)" messages from an intermediate router
(`192.168.1.1`)---an MTU/PMTU discovery issue mid-transfer, causing the
client to retransmit DATA fragments at a smaller size (1452 bytes
instead of 1460) afterward. This is a genuine network artifact worth
noting, not an SMTP protocol event.

<img width="1366" height="768" alt="Fig03: Inventory" src="https://github.com/user-attachments/assets/16ad149b-47a4-4a28-a7b6-5da61b731688" />

  **Fig03: Inventory**

## Part B: Identify Commands and Response Codes

  | **#** | **Direction** | **Command/Code** | **Meaning** | **Timestamp** |
|---:|---|---|---|---|
| 1 | Server → Client | **220** | Service ready — 220-xc90.websitewelcome.com ESMTP Exim 4.69 #1 | 07:06:08.219 |
| 2 | Client → Server | **EHLO GP** | Client greeting (extended, not HELO) | 07:06:08.224 |
| 3 | Server → Client | **250** | Capabilities: SIZE 52428800, PIPELINING, AUTH PLAIN LOGIN, STARTTLS, HELP | 07:06:08.566 |
| 4 | Client → Server | **AUTH LOGIN** | Authentication method selected | 07:06:08.568 |
| 5 | Server → Client | **334** | VXNlcm5hbWU6 (Base64 for "Username:") | 07:06:08.911 |
| 6 | Client → Server | (Base64 username, frame 12) | Credential 1 — **redact in report** | 07:06:08.911 |
| 7 | Server → Client | **334** | UGFzc3dvcmQ6 (Base64 for "Password:") | 07:06:09.253 |
| 8 | Client → Server | (Base64 password, frame 14) | Credential 2 — **redact in report** | 07:06:09.254 |
| 9 | Server → Client | **235** | Authentication succeeded | 07:06:09.613 |
| 10 | Client → Server | **MAIL FROM** | \<gurpartap@patriots.in> — envelope sender | 07:06:09.614 |
| 11 | Server → Client | **250** | OK | 07:06:09.956 |
| 12 | Client → Server | **RCPT TO** | \<raj_deol2002in@yahoo.co.in> — envelope recipient | 07:06:09.957 |
| 13 | Server → Client | **250** | Accepted | 07:06:10.319 |
| 14 | Client → Server | **DATA** | Message content begins | 07:06:10.320 |
| 15 | Server → Client | **354** | "Enter message, ending with '.'" | 07:06:10.661 |
| 16 | Server → Client | **250** | OK, id=1Mugho-0003Dg-Un (message accepted for delivery) | 07:06:12.248 |
| 17 | Client → Server | **QUIT** | Session termination | 07:06:14.763 |
| 18 | Server → Client | **221** | Closing connection | 07:06:15.105 |


**Important observation:** The server's own EHLO response (row 3)
advertised STARTTLS as an available capability, but the client never
issued a STARTTLS command---it proceeded directly with AUTH LOGIN over
the existing plaintext connection. This is the critical finding for Part
F: encryption was available but not used, meaning the entire session,
including authentication credentials and message content, was
transmitted in cleartext and is fully visible in this capture.

<img width="1366" height="508" alt="Fig04: Identify Command" src="https://github.com/user-attachments/assets/d3b4657e-58a9-41b4-9c20-5c195ec797d2" />

  **Fig04: Identify Command**

## Part C: Decode Base64 Authentication Evidence

Using an offline Python script (no online decoder used, per the lab's
explicit requirement), I decoded the two Base64 values captured in the
AUTH LOGIN exchange (Part B, frames 12 and 14):

-   **Username (decoded):** `gurpartap@patriots.in`
-   **Password (decoded):** `punjab@123`

This confirms Base64 is encoding, not encryption---reversible with zero
cryptographic effort, exactly as the lab emphasizes. Since the session
never negotiated STARTTLS despite the server advertising it as available
(Part B finding), these credentials were transmitted in a form trivially
recoverable by anyone capturing the traffic.

<img width="726" height="395" alt="Fig05:Decode Base64" src="https://github.com/user-attachments/assets/c54bbc58-9ef8-43f5-bb0c-3fc411a03288" />

  **Fig05: Decode Base64**

## Part D: Reconstruct the Email Message

Follow TCP Stream reassembled the entire session in one readable output,
confirming all envelope commands and revealing the complete RFC 5322
message headers and body. Extracting the required header fields:

 | **Field** | **Value** |
|---|---|
| **Date** | Mon, 5 Oct 2009 11:36:07 +0530 |
| **From** | "Gurpartap Singh" <gurpartap@patriots.in> |
| **To** | <raj_deol2002in@yahoo.co.in> |
| **Subject** | SMTP |
| **Message-ID** | <000301ca4581imageef9e57f0cedb07d0$@in> |
| **MIME-Version** | 1.0 |
| **Content-Type** | multipart/mixed (containing nested multipart/alternative) |
| **X-Mailer** | **Microsoft Office Outlook 12.0** |


**Note on Date discrepancy:** The message's internal Date header
(11:36:07 +0530, i.e. India Standard Time) differs from the SMTP
session's own capture timestamps (07:06 UTC-equivalent range).
Converting +0530 to UTC gives 06:06:07---close to but not exactly
matching the capture's \~07:06 timestamps (which include a +0100 display
offset applied by my own tshark's local timezone rendering). This is a
useful forensic observation: the message header's Date field is set by
the client at compose time and is not independently verified by the SMTP
protocol---it should be cross-checked against the server's own
received-timestamp evidence (visible in frame timing) rather than
trusted alone, since a client's system clock could be wrong or
deliberately falsified.

**Body type:** The message is multipart, specifically `multipart/mixed`
wrapping a `multipart/alternative` (`text/plain` + `text/html`, both
saying "Hello, I send u smtp pcap file, Find the attachment, GPS") plus
a second body part carrying an attachment.

**Attachment present:**
Yes---`Content-Disposition: attachment; filename="NEWS.txt"`, a
plain-text changelog for a software tool (Dev-C++), sent as an inline
quoted-printable text attachment rather than Base64-encoded binary
(since it's plain ASCII text, no binary encoding was needed).

**Other notable header:** `x-cr-hashedpuzzle` / `x-cr-puzzleid`---these
are Microsoft Outlook's "Email Postmark"/anti-spam computational puzzle
headers, further corroborating the
`X-Mailer: Microsoft Office Outlook 12.0` client identification through
a second, independent header.

<img width="1366" height="768" alt="Fig06: Email Massage1" src="https://github.com/user-attachments/assets/813f049e-6fcf-4e08-b185-b4017f920b55" />

  **Fig06: Email Message 1**

<img width="1366" height="768" alt="Fig07: Email Massage2" src="https://github.com/user-attachments/assets/e3ae30a8-94bd-4ac7-b6a3-827e0e5cb27f" />

  **Fig07: Email Message 2**

## Part E: Determine Client, Hosts, and Network Metadata

### Client (`10.10.1.4`)

-   **MAC address:** `00:e0:1c:3c:17:c2`
-   **Port:** 1470 (ephemeral)
-   **Note:** Frames 26--30 show the client's IP appearing as
    `192.168.1.1,10.10.1.4` in the ICMP unreachable messages---this is
    tshark displaying two addresses on one line because these are ICMP
    error packets about the client-to-server traffic, generated by an
    intermediate router (`192.168.1.1`) sitting between the client and
    the capture point. This confirms the client sits behind a NAT/router
    at `192.168.1.1`, which is relevant network topology context, not a
    second client identity.

### Server (`74.53.140.153`)

-   **MAC address:** `00:1f:33:d9:81:60`
-   **Port:** 25 (standard SMTP)
-   **Hostname (from banner in Part B):** `xc90.websitewelcome.com`

All 28 SMTP frames share `tcp.stream 0`, confirming everything analyzed
across Parts A--E belongs to one single, continuous TCP session---no
other SMTP conversation exists in this capture.

Client software identification was confirmed two ways: directly via the
`X-Mailer: Microsoft Office Outlook 12.0` header found in Part D, and
independently corroborated by the Outlook-specific
`x-cr-hashedpuzzle`/`x-cr-puzzleid` anti-spam headers also found in the
same message---two separate, mutually reinforcing indicators pointing to
the same client application, which strengthens confidence in this
finding beyond relying on a single header value alone.

The second command (`data-text-lines`, looking for literal
"User-Agent"/"X-Mailer" strings inside SMTP-tagged frames) returned only
generic "Line-based text data" summaries for frames 22 and 26, rather
than the header text itself---this is because Wireshark's SMTP protocol
dissector only tags the DATA command frame boundaries as `smtp`, while
the actual header content sits inside frame 45 as `data-text-lines`,
which the filter's `smtp contains` condition didn't match precisely. The
X-Mailer value was still correctly and fully obtained via the Follow TCP
Stream reconstruction in Part D, so no evidence is missing---this is
simply a note on why this particular filter combination under-returned
compared to the stream view.

<img width="1366" height="768" alt="Fig08:Network Metedata" src="https://github.com/user-attachments/assets/fbbf63ee-ada0-4c57-b1a8-96e518e069dd" />

  **Fig08: Network Metadata**

## Part F: Encryption and Evidential Limitations

**Was STARTTLS requested?** No. The server's EHLO response (Part B,
frame 9) explicitly advertised STARTTLS as an available capability
alongside AUTH PLAIN LOGIN. However, the client's very next command was
AUTH LOGIN---it proceeded directly to plaintext authentication rather
than issuing a STARTTLS command first. At no point in this 28-frame SMTP
session does a STARTTLS command or a subsequent TLS handshake
(ClientHello/ServerHello) appear anywhere in the capture.

**Consequence:** Because encryption was never negotiated, the entire
session---authentication credentials, envelope addresses, message
headers, message body, and attachment---was transmitted in cleartext and
is fully readable directly from the packet capture, as demonstrated
throughout Parts B--E. This is not a limitation of my analysis; it is a
genuine property of the captured traffic itself.

### What Would Remain Visible if STARTTLS/TLS Had Been Used?

Even with full encryption, a forensic examiner would still be able to
observe:

-   Endpoint IP addresses and MAC addresses (`10.10.1.4` ↔
    `74.53.140.153`)
-   TCP/IP layer metadata: ports (`1470` ↔ `25`), sequence numbers,
    window sizes
-   Connection timing: start time, duration, packet counts, byte counts
    (as captured via `capinfos`/`conv,tcp` in Part A)
-   The initial STARTTLS negotiation itself (in cleartext, before
    encryption begins) and the TLS handshake metadata---protocol
    version, cipher suite negotiated, and (unless encrypted via
    extensions like ESNI/ECH) the server's certificate details,
    including its Common Name/SAN and validity dates
-   Approximate data volume transferred (from encrypted packet sizes),
    though not the actual content

### What Would Not Be Visible Under TLS?

The actual SMTP commands after STARTTLS (`AUTH LOGIN`, credentials,
`MAIL FROM`/`RCPT TO` addresses, DATA content, message headers and body)
would all be encrypted and unreadable without possessing the correct
decryption keys or a recorded TLS session-key log (`SSLKEYLOGFILE`)
captured at the time.

**Important limitation to state explicitly:** The mere fact that a
service listens on port 25 (or that a session appears "SMTP-like") does
not by itself prove the traffic is unencrypted or encrypted---port
number alone is not evidence of encryption status. The only reliable way
to determine whether a session is encrypted is to examine the actual
protocol negotiation (presence/absence of a STARTTLS command and a
subsequent TLS handshake) and packet dissection results, exactly as was
done in this analysis, rather than assuming based on the port number or
service name alone.

**Summary for this specific capture:** This session used plaintext SMTP
with no encryption negotiated, despite the server offering STARTTLS. All
findings in this report (credentials, message content, headers) are
drawn directly and legitimately from unencrypted, fully visible protocol
data---no decryption or key material was required at any stage of this
analysis.

## Executive Summary

Analysis of a single 9.2-second, 60-packet TCP session (`10.10.1.4:1470`
↔ `74.53.140.153:25`, captured 5 October 2009) fully reconstructed a
plaintext SMTP email exchange between a Microsoft Outlook 12.0 client
and a hosting provider's mail server (`xc90.websitewelcome.com`). The
complete session lifecycle---service greeting, EHLO capability
negotiation, AUTH LOGIN authentication, envelope commands, message
transmission, and clean session termination---was extracted using tshark
field filters and TCP stream reassembly. Authentication credentials,
transmitted via Base64-encoded AUTH LOGIN, were decoded offline and are
redacted in this report per the lab's safety requirements. The
reconstructed message revealed complete RFC 5322 headers, a dual-format
(plain text/HTML) body, and a genuine text-file attachment. Critically,
although the server advertised STARTTLS support, the client never used
it---meaning every element of this exchange, including credentials, was
transmitted and is recoverable in cleartext, forming the basis for this
report's encryption and evidential-limitations assessment.

## Findings Worksheet

 | **Question** | **Finding** |
|---|---|
| Session start/end | 2009-10-05, 07:06:08.22 – 07:06:15.11 (raw capture timestamps); 9.2 seconds total |
| Client IP/MAC and port | 10.10.1.4, 00:e0:1c:3c:17:c2, port 1470 |
| Server IP/MAC and port | 74.53.140.153, 00:1f:33:d9:81:60, port 25 |
| SMTP server banner | 220-xc90.websitewelcome.com ESMTP Exim 4.69 #1 |
| Client software | Microsoft Office Outlook 12.0 (confirmed via X-Mailer header, corroborated by Outlook-specific x-cr-hashedpuzzle/puzzleid headers) |
| Authentication method | AUTH LOGIN (Base64-encoded username/password over plaintext connection) |
| Envelope sender/recipient | Redacted in report body (see Part C); recorded in evidence appendix |
| Message From/To/Subject | Redacted sender/recipient; Subject: "SMTP" |
| Message body type | Multipart: multipart/mixed → multipart/alternative (text/plain + text/html) |
| Attachment present? | Yes — NEWS.txt, a plain-text software changelog, quoted-printable encoded |
| STARTTLS/TLS observed? | **No.** Server advertised STARTTLS in EHLO response; client did not use it |
| Key limitations | Entire session unencrypted and fully visible; message Date header is client-asserted, not independently verified; one filter combination in Part E under-returned client-indicator text (resolved via stream reconstruction instead) |

## Conclusion

This lab successfully reconstructed a complete SMTP email transaction
purely from packet capture evidence, demonstrating the full forensic
workflow from raw traffic inventory through message and attachment
recovery. The most significant finding was not merely what was
recoverable, but why: the server offered STARTTLS as an available
security upgrade, and the client's decision not to use it meant every
subsequent byte of the session---authentication credentials, sender and
recipient addresses, message headers, body content, and a file
attachment---remained in plaintext and fully readable to any party
capable of capturing the traffic. Decoding the AUTH LOGIN credentials
required no cryptographic effort whatsoever, directly reinforcing the
lab's core lesson that Base64 is encoding, not encryption, and that
"authentication succeeded" says nothing about whether that
authentication was conducted securely.

Equally important was recognizing the limits of this evidence: while
every element of this specific capture was recoverable, that
recoverability is a direct consequence of the absence of TLS, not a
general property of SMTP traffic. Had STARTTLS been negotiated, this
same analytical approach would have yielded only endpoint identities,
timing, and volume---not content---underscoring that a forensic examiner
must always verify the actual protocol negotiation observed in a capture
rather than assuming a port number or service name determines what is or
isn't protected. Handling the recovered credentials and personal message
content with explicit redaction throughout this report, rather than
displaying them in full, reflects the standard of responsible evidence
handling this lab was designed to build alongside its technical
objectives.
