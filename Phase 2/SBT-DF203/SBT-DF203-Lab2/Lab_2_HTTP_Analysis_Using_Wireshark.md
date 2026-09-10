# Lab 2 — HTTP Analysis Using Wireshark: Embedded Image Traffic

| | |
|---|---|
| **Assignment Title** | Basic Networking Skills for Digital Forensics |
| **Student Name** | Bashir Adam |
| **Student ID** | 2025/FWSD/11509 |
| **Course Name** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Instructor Name** | Aminu Idris |
| **Date of Submission** | 9 Sep, 2026 |
| **Version** | Version 2.3.1 |
| **Platform** | Kali Linux / Ubuntu Forensic Workstation (VM) |

---

## Lab Overview

Explain browser-generated multiple HTTP requests; capture HTML and image transfers; analyse TCP reassembly; compare IP/TCP/HTTP size relationships; export HTTP objects; verify recovered-image integrity; explain cache and curl-versus-browser behaviour.

## Introduction

This report documents a practical network forensics exercise conducted as part of **SBT-DF203: Basic Networking Skills for Digital Forensics**. The exercise required setting up a controlled, self-hosted web environment — an Apache2 server on a local Kali Linux machine — to serve a simple webpage containing an embedded image, then capturing and analyzing the resulting HTTP traffic using Wireshark and tshark. The purpose was to build practical skill in a scenario highly relevant to real digital investigations: reconstructing what happened during a plaintext network transaction purely from a packet capture, without relying on the original web server or files being available afterward.

Before beginning any hands-on work, I reviewed the official SBT-DF203 Lab 2 manual and the accompanying Module 2 lecture material on HTTP, Wireshark, and digital forensics, covering how browsers generate multiple HTTP requests per page, how large HTTP responses are split across TCP segments, and how Wireshark's Export Objects feature can recover complete files from raw packet data. All activity in this lab was performed exclusively on `127.0.0.1` (loopback) within my own authorized virtual environment, using an image I own and am authorized to use, in line with the lab's legal, ethical, and safety requirements. No third-party systems, production networks, or public networks were involved at any point.

This report walks through evidence preparation, browser traffic capture (including two failed attempts caused by HTTP caching, and the fix that resolved them), proof that a single webpage generates multiple distinct object requests, TCP segmentation and reassembly analysis, object extraction and hash-based integrity verification, and a direct comparison between automated (curl) and browser-driven request behavior — concluding with documented limitations and a summary of forensic findings.

---

## Setup — Folder Structure & Tool Installation

I created the required lab folder structure with subfolders for evidence, working copies, exported objects, reports, screenshots, and scripts. I then confirmed/installed the required tools — Apache2, curl, Wireshark, tshark, and ImageMagick — were all present or freshly installed, and Apache2 was enabled and started as a system service.

> 📸 **Fig01 — Folder Creation**

I placed my authorized personal image (`Azad.png`, renamed to `lab_photo.jpg` for this exercise — noted honestly, since the file is actually a PNG despite the `.jpg` extension, which we'll verify with `file`/`identify` in Part A) into Apache's web root, and created `image.html` containing a heading, analyst name, and an `<img>` tag referencing the photo. `sha256sum` recorded baseline hashes for both source objects:

| File | SHA-256 |
|---|---|
| `image.html` | `454ac5b6370ca6dd7333221a9ccf8eaa24d0a0e96bf10014741a154244ad5784` |
| `lab_photo.jpg` | `309a7249050df7fc1021d75ff48090bbc1abd61fbde4bee9b2faa1dbd70be230` |

> 📸 **Fig02 — Object & Hashes**

---

## Part A — Verify the Webpage and Eliminate Cache Effects

`file` and `identify` confirmed the source image's true type: **PNG image data, 896×1195, 8-bit/color RGBA**, despite being named `lab_photo.jpg`. This is an important, honest observation: a file's extension does not determine its actual format — the byte content does. `ls -lh` showed `image.html` at 148 bytes and `lab_photo.jpg` (really a PNG) at 1.4M.

`curl -I` against both objects confirmed Apache serves them with `HTTP/1.1 200 OK`. Notably, Apache's `Content-Type` header for the image reports `image/jpeg` — this is because Apache determines Content-Type primarily from the file extension (`.jpg`) via its MIME-type mapping, not by inspecting the actual file bytes. This is a genuinely useful forensic/networking finding: it means the HTTP layer's stated content type can be wrong or misleading if a file has been renamed, and a forensic examiner analyzing HTTP traffic should verify a transferred object's real type (e.g. with `file` after export) rather than trusting the `Content-Type` header alone. `Content-Length: 1391039` matches the file's actual 1.4M size exactly, confirming Apache is at least reporting an accurate size regardless of the mislabeled type.

> 📸 **Fig03 — Eliminate Cache Effects**

Opening `http://127.0.0.1/image.html` in a browser confirmed the page renders correctly, displaying the "SBT-DF203 Image Traffic" heading, "Analyst: Bashir Adam," and the embedded photo — proving Apache is correctly serving both objects and the browser successfully requests and displays each one.

> 📸 **Fig04 — The Image**

---

## Part B — Capture Browser-Generated HTTP Traffic

I captured browser-generated HTTP traffic on the loopback interface using:

```bash
sudo tshark -i lo -f 'tcp port 80' -w /tmp/image_traffic.pcapng
```

(writing to `/tmp` first due to an AppArmor permission restriction preventing tshark from writing directly into my home directory evidence folder even as root — a worthwhile note on Kali's sandboxing of capture tools). While the capture was running, I opened a private/incognito browser window and visited `http://127.0.0.1/image.html`, waited for the page and image to fully load, then stopped the capture with `Ctrl+C`, which reported **42 packets captured**.

I moved the capture into my evidence folder and corrected ownership, then created a working copy and hashed both files to confirm the copy is identical to the original:

**SHA-256 (both original and working copy):**
`17fed76ac7210720f07bf8359ec1046daeb396699385753e7bf2cf4b32dd25b0`

The matching hash confirms the working copy is byte-for-byte identical to the preserved original, meaning any subsequent analysis performed on the working copy is provably equivalent to analyzing the original evidence.

> 📸 **Fig05 — Traffic**

---

## Part C — Prove Two Objects Were Requested

Filtering for `http.request` showed **9 total HTTP GET requests**, all on the same TCP stream (stream 1) and the same source port (58410) — meaning all requests reused a single persistent TCP connection (HTTP keep-alive), rather than opening a new connection per request.

- **Frame 8** (22:19:14.719): `GET /image.html` — the initial page request.
- **Frame 15** (22:19:14.740, ~20ms later): `GET /lab_photo.jpg` — the browser correctly parsed the HTML and automatically requested the embedded image, confirming the core learning objective of this lab: one webpage triggers multiple object requests.
- **Frames 18, 21, 24, 27, 30, 33, 36** (spaced roughly 1–5 seconds apart over the next ~13 seconds): seven additional, unexpected `GET /image.html` requests, each also returning `200 text/html`, 150 bytes.

Checking the corresponding responses: the image request (frame 15) returned **HTTP 304 Not Modified**, not 200 — meaning the browser sent a conditional GET (using cached ETag/Last-Modified headers) and the server confirmed the cached copy was still valid, so no image body was retransmitted. This is notable because it happened on the very first request in what was intended to be a cache-free private window — the most likely explanation is that the private window's disk cache was not fully isolated from a prior normal-mode visit to the same URL earlier in this session (browser cache isolation in private mode varies by browser and can still reuse disk-level cached responses for static assets in some configurations), rather than a true "cold" first load.

The seven repeated `image.html` requests are unusual and not part of the expected page-load flow — a single page visit should not repeatedly re-request its own HTML five to nine times over 13 seconds. I'm documenting this honestly rather than removing it: the most likely causes are a browser feature such as automatic page-reload/prefetch, a background extension polling the tab, or the page being manually refreshed multiple times during the capture window. Since each repeat returned 150 bytes (the same content-length as the original HTML, meaning the HTML itself was not re-cached/served as 304), this behavior did not affect the correctness of the core image-transfer evidence I need for Parts D and E, but it is a documented anomaly worth explaining in the report rather than silently omitting.

> 📸 **Fig06 — The Simple Traffic**

---

## Part D — TCP Segmentation and Reassembly

Filtering `tcp.stream==0 && tcp.len>0` extracted every TCP segment carrying data on the connection. The frames from 12 through 56 (excluding the small HTML/request frames 4, 6, 11) are the segments that together make up the image response (frame 56 also carries the final HTTP response headers, since `tcp.len=15181` combines the tail of image data with the trailing bytes). Most segments carry **65483 bytes** of TCP payload (`tcp.len`), which is the maximum a single segment can carry given a 65535-byte IP packet minus a 32-byte TCP header on this loopback interface — loopback typically uses a much larger MTU than a real network link (often 64KB or larger), which is why these segments are dramatically larger than the ~1460-byte segments you'd see on a standard Ethernet (1500 MTU) capture.

Summing the `tcp.len` values for all data-carrying segments in this stream accounts for the full image transfer: the TCP Conversations summary (`conv,tcp`) confirms the server→client direction carried **1,394 kB across 36 frames**, closely matching the HTTP `Content-Length` of 1,391,039 bytes (the small difference is TCP/IP framing overhead counted in the conversation total). This is the Reassembled TCP Segments relationship the lab asks for: one single HTTP object (the 1.4MB image) was too large to fit in one TCP segment, so it was split across roughly 25 segments and reassembled by Wireshark/tshark into the complete HTTP response body before the `image/jpeg` Content-Type and full length could be reported in Part C.

**Why segment sizes differ from the lab's example (128k):** the lab notes that the exact segment sizes may vary from the reference slides due to interface offloading, OS buffer sizes, MTU, and capture location. In this case, the loopback interface's very large effective MTU (allowing ~65KB segments) is the dominant factor — a real network interface (typically 1500-byte MTU) would have split this same 1.4MB image into roughly 950+ much smaller segments instead of ~25 large ones, since loopback traffic never actually goes through a physical network link with standard Ethernet framing limits.

The TCP Conversations summary also shows a second, separate connection (port 59308, only 3 frames, 214 bytes) — a minor additional connection the browser opened, likely for a favicon request or similar background browser behavior, consistent with the lab's own guidance to document rather than delete such incidental traffic.

> 📸 **Fig07 — The TCP Traffic**

---

## Part E — Export the Embedded Image

```bash
tshark --export-objects http
```

extracted three objects from the capture: `image.html` (158 bytes, exported twice due to the two separate GET requests for it, saved as `image.html` and `image(1).html`), and the image itself, saved as `lab_photo.jpg%3fnocache=1` — the exported filename preserves the URL-encoded query string I added (`%3f` = `?`), confirming exactly which request the object was extracted from.

`file` confirmed the exported image is genuinely **PNG image data, 896×1195, 8-bit/color RGBA** — matching the source file's true type exactly, and consistent with Wireshark's own protocol column earlier labeling frame 56 as `HTTP 200 OK (PNG)`, correctly identifying the real format even though the HTTP Content-Type header claimed `image/jpeg`. This is strong independent confirmation of the Part A finding: Wireshark inspects the actual bytes, not just the misleading filename/header.

**Hash comparison — the critical integrity check:**

| File | SHA-256 |
|---|---|
| Original source (`/var/www/html/lab_photo.jpg`) | `309a7249050df7fc1021d75ff48090bbc1abd61fbde4bee9b2faa1dbd70be230` |
| Exported from capture (`lab_photo.jpg%3fnocache=1`) | `309a7249050df7fc1021d75ff48090bbc1abd61fbde4bee9b2faa1dbd70be230` |

The hashes match exactly. Per the lab's own integrity interpretation guidance, a different exported filename (due to the URL-encoded query string) is not a problem — what matters is that size, type, and hash all match, which they do here perfectly. This proves the image was recovered byte-for-byte identical to the original source file purely from the network capture, using only the TCP segments reassembled in Part D. This is the central forensic conclusion of the entire lab: a file transferred in plaintext HTTP can be completely and verifiably reconstructed from packet capture evidence alone.

The two exported `image.html` copies also share an identical hash to each other (`ff83a2a...`), consistent with the two `GET /image.html` requests both returning the exact same, unchanged HTML content.

> 📸 **Fig08 — The Embedded Image**

---

## Part F — curl vs Browser Comparison

I captured a fresh 20-second window on the loopback interface while running:

```bash
curl -v http://127.0.0.1/image.html
```

requesting only the HTML page. curl's verbose output confirmed the request/response: `GET /image.html HTTP/1.1` → `HTTP/1.1 200 OK`, `Content-Type: text/html`, `Content-Length: 158`.

Filtering the resulting capture for `http.request` showed exactly **one** HTTP request: `/image.html` — and critically, no second request for `lab_photo.jpg` at all.

This is the key difference between curl and a browser: curl is a simple HTTP client that retrieves exactly the URL it is told to fetch and nothing more — it has no HTML parser and no concept of a webpage's structure. It downloads the raw bytes of `image.html` and stops. A web browser, by contrast, actively parses the HTML content after receiving it, discovers the `<img src="...">` tag inside, and automatically issues a second, separate HTTP request for that referenced resource — exactly what I captured in Parts B/C (the browser's two GET requests: `/image.html` then `/lab_photo.jpg?nocache=1`). curl has no equivalent automatic behavior unless the referenced URL is explicitly and separately requested (e.g. `curl http://127.0.0.1/lab_photo.jpg` as its own command).

**Forensic significance:** this distinction matters when analyzing network captures, since the tool used to generate traffic fundamentally changes what evidence appears in a capture. A single curl request in a log or capture cannot be assumed to represent "a user viewing a webpage" the way a full browser session can — a forensic analyst must correlate the number and pattern of requests with the type of client generating them (identifiable via the `User-Agent` header, which curl's own request showed as `curl/8.21.0`, clearly distinguishing it from a browser's User-Agent string) before drawing conclusions about what content a user or system actually rendered and viewed.

> 📸 **Fig09 — The Comparison**

---

## Executive Summary and Scope

This report documents a controlled, self-hosted HTTP traffic analysis exercise conducted entirely on a local Kali Linux workstation, using Apache2 to serve a webpage with an embedded image, Wireshark/tshark to capture and analyze browser-generated traffic, and cryptographic hashing to verify the integrity of a recovered network object. The scope covered: preparing and hashing source evidence objects; capturing genuine browser traffic across three iterative attempts (the first two of which returned cached 304 responses, requiring a cache-busting fix); proving that a single webpage generates multiple HTTP requests; analyzing TCP segmentation and reassembly of a 1.4MB image transferred over ~25 TCP segments; exporting the image directly from the packet capture and verifying it against the source via SHA-256; and comparing automated (curl) versus browser-driven request behavior. All activity was confined to `127.0.0.1` (loopback), with no third-party systems or networks involved.

### Evidence Acquisition and Integrity Hashes

| Object | SHA-256 |
|---|---|
| Source `image.html` (final version) | `454ac5b6370ca6dd7333221a9ccf8eaa24d0a0e96bf10014741a154244ad5784` *(pre-cache-fix version; regenerate if needed after nocache edit)* |
| Source `lab_photo.jpg` (actually PNG) | `309a7249050df7fc1021d75ff48090bbc1abd61fbde4bee9b2faa1dbd70be230` |
| Final capture: `evidence/image_traffic.pcapng` | `888b9b26ed492043bd50a04f00bfc94bbc685b2e3c97b324ea46b1a49fa3df02` |
| Working copy: `working/image_traffic_working.pcapng` | `888b9b26ed492043bd50a04f00bfc94bbc685b2e3c97b324ea46b1a49fa3df02` (identical — verified copy) |
| `curl_only.pcapng` | (recorded via same hashing method, see reports folder) |
| Exported image (from capture) | `309a7249050df7fc1021d75ff48090bbc1abd61fbde4bee9b2faa1dbd70be230` (identical to source) |

Two earlier capture attempts were made and superseded before the final successful capture, due to HTTP 304 caching preventing full image transfer — documented transparently in the findings below rather than omitted.

### HTTP Request/Response Inventory

| # | Time | Method | URI | Response | Type | Length |
|---|---|---|---|---|---|---|
| 1 | 22:30:05.131 | GET | `/image.html` | 200 | text/html | 157 |
| 2 | 22:30:05.150 | GET | `/lab_photo.jpg?nocache=1` | 200 | image/jpeg (header) / PNG (actual) | 1,391,039 |
| 3 | 22:30:06.877 | GET | `/image.html` (repeat) | 200 | text/html | 157 |

All three requests occurred on a single persistent TCP connection (stream 0, port 59298), confirming HTTP keep-alive. A second, minor connection (port 59308, 3 frames) was also observed and is documented as incidental background browser traffic.

### TCP Segmentation and Reassembly Analysis

The 1,391,039-byte image response was carried across approximately 25 TCP data segments, the majority at 65,483 bytes of payload each — the maximum supported by the loopback interface's large effective MTU. Summing the server→client payload bytes across the stream (per the `conv,tcp` summary: 1,394 kB across 36 frames) closely matches the HTTP Content-Length, accounting for TCP/IP framing overhead. Wireshark/tshark's reassembly engine combined these segments into a single logical HTTP response body before reporting the object's type and size in Part C — directly demonstrating that one HTTP object can span, and require reassembly from, many individual TCP segments.

Segment sizes here are substantially larger than the ~1460-byte segments typical of a real Ethernet-based capture (1500-byte MTU), because loopback traffic bypasses physical network framing limits entirely. This was documented as the primary reason this capture's segmentation pattern differs from a reference example based on a standard network interface.

### Object Extraction Method

The image was extracted directly from the packet capture using `tshark --export-objects http`, which reconstructs and writes out complete HTTP response bodies found in a capture file — no interaction with the live web server was required at extraction time, only the previously captured evidence. The exported file, `lab_photo.jpg%3fnocache=1` (its exported name preserving the URL-encoded query string from the original request), was confirmed via `file` to be a genuine, complete, unencoded PNG image.

### Hash-Based Integrity Conclusion

The exported image's SHA-256 hash (`309a7249...be230`) is identical to the original source file's hash. Per the lab's integrity interpretation guidance, this proves byte-for-byte, lossless recovery of the transferred object purely from network capture evidence — the differing exported filename (due to URL encoding) does not affect this conclusion, since file identity is established by content hash, not name. This is the single most important forensic result in this lab: it demonstrates that a plaintext HTTP file transfer, once captured, can be fully and verifiably reconstructed after the fact, which is directly relevant to real-world investigations involving unencrypted network traffic (e.g. malware delivery over HTTP, unauthorized file exfiltration, or evidence of file access).

### curl versus Browser Explanation

curl issued exactly one HTTP request (`GET /image.html`) and stopped — it has no HTML parsing capability and therefore never discovered or requested the embedded image. A browser, by contrast, parses the returned HTML, locates the `<img>` tag, and automatically issues a second, independent request for the referenced image — exactly as observed in the browser capture (Parts B/C). This is not a bug or inconsistency but a fundamental architectural difference: curl is a raw HTTP transfer tool, while a browser is a full HTML rendering engine that treats a webpage as a graph of resources to be fully resolved and displayed. Forensically, this means the number and pattern of requests in a capture can itself be evidence of what kind of client (script/tool vs. real browser/user) generated the traffic — reinforced by curl's distinct `User-Agent: curl/8.21.0` string, clearly separable from a browser's own User-Agent.

### Limitations and Recommendations

- Two initial capture attempts failed to transfer the actual image body, returning HTTP 304 Not Modified instead of 200, because the unchanged source file produced identical caching headers (ETag/Last-Modified) on every request regardless of private-browsing mode or manual cache-clearing. This was resolved using a cache-busting query string (`?nocache=1`), a standard, well-documented technique — but it highlights a real limitation of relying on private/incognito mode alone to guarantee a fresh HTTP request, and is recommended as a documented fallback technique for future similar labs.
- Unexpected repeated `GET /image.html` requests occurred in every capture attempt (ranging from 1 to 7 extra repeats) — the exact cause (browser auto-refresh, extension, or manual reload) was not definitively identified and is noted as an open observation rather than a resolved root cause.
- The source image's file extension (`.jpg`) did not match its true format (PNG), causing Apache's Content-Type header to incorrectly report `image/jpeg`. This was independently caught by both `file`/`identify` (Part A) and Wireshark's own protocol detection (Part D/E, correctly labeling the object as PNG despite the misleading header) — reinforcing that HTTP headers describing content type should never be trusted uncritically in forensic analysis without verifying the actual file bytes.
- This exercise used loopback traffic exclusively, meaning segmentation behavior (very large TCP segments) is not representative of a real network capture; a follow-up exercise across an actual Ethernet or Wi-Fi link would show markedly different, smaller segment sizes and a higher segment count for the same file size.
- AppArmor restricted tshark from writing capture files directly into the home directory even when run as root — worked around by capturing to `/tmp` and moving the file afterward, a minor but real environment-specific hurdle documented for reproducibility.

---

## Conclusion

This lab successfully demonstrated the complete lifecycle of an HTTP object transfer, from source preparation through packet capture, protocol analysis, TCP reassembly, and cryptographically verified recovery. Despite two initial capture attempts being invalidated by HTTP caching, transparently documenting and resolving that obstacle rather than concealing it proved to be as valuable a forensic exercise as the successful capture itself, since real investigations frequently involve exactly this kind of troubleshooting before usable evidence is obtained. The final result conclusively proved that a single webpage generates multiple, separately observable HTTP requests, that a large object can be split across many TCP segments and correctly reassembled, and that a file transferred entirely in plaintext HTTP can be extracted from a packet capture and proven identical to its source using SHA-256 — the foundational skill this lab was designed to build.
