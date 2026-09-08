# Lab 1 — HTTP Analysis Using Wireshark: Text Traffic  
   
## Assignment Information  
   
- **Assignment Title:** Basic Networking Skills for Digital Forensics  
- **Student Name:** Bashir Adam  
- **Student ID:** 2025/FWSD/11509  
- **Course Name:** SBT-DF203 Basic Networking Skills for Digital Forensics  
- **Instructor Name:** Aminu Idris  
- **Date of Submission:** 8 Sep, 2026  
- **Version:** 2.3.0  
- **Platform:** Kali Linux or Ubuntu Forensic Workstation / VM  
   
---  
   
# Lab Overview  
   
You are a junior network forensic analyst asked to document a short plaintext HTTP session. You will create a local webpage containing your name and registration number, capture the traffic, reconstruct the TCP conversation, identify the HTTP request and response, and explain how each protocol layer contributes evidence.  
   
---  
   
# Introduction  
   
This practical exercise focused on the analysis of plaintext HTTP network traffic using Wireshark/TShark in an authorized Kali Linux environment. The objective was to understand how HTTP communication is established, transmitted, and terminated at the network level, while also applying basic digital forensic evidence-handling procedures.  
   
To generate the required traffic, a local Apache web server was configured to host a simple HTML page containing the student's name and registration number. The HTTP communication between the client and the local web server was captured on the loopback interface and preserved as a PCAP evidence file. The captured traffic was then analyzed to identify the TCP three-way handshake, HTTP GET request, HTTP 200 OK response, TCP data transfer, encapsulation layers, and connection termination. The original evidence and working copy were also verified using SHA-256 hashing to demonstrate that the evidence remained unchanged during analysis.  
   
---  
   
# Section 1: Environment Setup & Workstation Configuration  
   
## Directory Structure Creation  
   
To maintain forensic integrity and strict chain-of-custody standards, a dedicated directory structure was configured prior to initiating any traffic generation or packet capture. The baseline directories isolate original raw evidence, working copies, exported objects, reports, screenshots, and custom scripts.  
   
**Figure 01:** Directory Structure <img width="754" height="398" alt="Fig01-directory" src="https://github.com/user-attachments/assets/b8e54960-145c-4e59-97fa-ca61e2630c4c" />
  
   
---  
   
# Part A — Verify the Web Service and Generate Text HTTP Traffic  
   
I created `basic.html` containing my full name **Adam Bashir** and registration number **2025/FWSD/11509**, then hosted it locally using Apache on **127.0.0.1:80**. Verified the page with `curl`, which returned **HTTP/1.1 200 OK**, **Content-Type: text/html**, and **Content-Length: 135 bytes**. The verbose HTTP request and response were saved to `reports/curl_verbose.txt`.  
   
**Figure 02:** Enable Apache <img width="933" height="526" alt="Fig02-enable apache" src="https://github.com/user-attachments/assets/9e7cd2ae-36af-43c1-86ef-64ffaf18e659" />

  
   
A test client request was initiated using:  
   
```bash  
curl -v http://127.0.0.1/basic.html  
```  
   
The client initiated a connection from ephemeral source port **60716** to target port **80**. The web server returned an **HTTP/1.1 200 OK** status header with a **Content-Length of 131 bytes**, serving the HTML payload containing the analyst identity markers (Adam Bashir and 2025/FWSD/11509). Output was piped to `reports/curl_verbose.txt` for audit tracking.  
   
**Figure 03:** Web Service Verification <img width="695" height="491" alt="Fig03- webservice" src="https://github.com/user-attachments/assets/adca892f-90ce-4436-9cac-fc9b40e4f78e" />
 
   
---  
   
# Part B — Capture and Preserve the Session  
   
Captured the authorized local HTTP session on the loopback interface `lo` using TShark, producing `evidence/basic.pcapng` (1.8 KB). A working copy was created as `working/basic_working.pcapng`.  
   
Both files produced the same SHA-256 hash:  
   
```text  
6740f70ace58fb96c17a6155375d7229a230be956457b1dab55865734eb2ffa7  
```  
   
This confirms that the working copy matches the original evidence.  
   
**Figure 04:** Capture Session <img width="1366" height="768" alt="Fig04- captere session" src="https://github.com/user-attachments/assets/7403b262-91be-42aa-9b0d-9dfeacfac2fe" />

  
   
---  
   
# Part C — Analyze the TCP Three-Way Handshake  
   
Analyzed the captured TCP session and identified the complete three-way handshake between **127.0.0.1:42846** and **127.0.0.1:80**.  
   
- Frame 1 contained the **SYN** with sequence number 0.  
- Frame 2 contained the **SYN-ACK** with sequence number 0 and acknowledgement number 1.  
- Frame 3 contained the final **ACK** with sequence number 1 and acknowledgement number 1.  
   
The handshake occurred at approximately **22:49:45.636** on **8 September 2026**, successfully establishing the TCP connection before the HTTP request was transmitted.  
   
| Frame | Flags | Source → Destination | Seq | ACK |  
|------|------|------|------:|------:|  
| 1 | SYN | 127.0.0.1:42846 → 127.0.0.1:80 | 0 | 0 |  
| 2 | SYN-ACK | 127.0.0.1:80 → 127.0.0.1:42846 | 0 | 1 |  
| 3 | ACK | 127.0.0.1:42846 → 127.0.0.1:80 | 1 | 1 |  
   
**Figure 05:** TCP Three-Way Handshake <img width="1366" height="768" alt="Fig05- the three tcp" src="https://github.com/user-attachments/assets/f9c09ed5-b632-47a8-ae4e-24aae1a7cae3" />
  
   
---  
   
# Part D — Examine the HTTP Request and Response  
   
Frame 4 shows the client **127.0.0.1:42846** sending a **GET** request for `/basic.html` to **127.0.0.1:80** using `curl/8.21.0`.  
   
Frame 6 shows the server responding with:  
   
```http  
HTTP/1.1 200 OK  
```  
   
Using:  
   
```text  
Apache/2.4.68 (Debian)  
```  
   
The response content type was **text/html** with a content length of **135 bytes**.  
   
**Figure 06:** HTTP Request and Response <img width="1366" height="768" alt="Fig06- httprequest" src="https://github.com/user-attachments/assets/eb2eb30d-7900-43cc-9784-302d86c714a7" />
  
   
---  
   
# Part E — Inspect Encapsulation and Connection Closure  
   
The captured TCP stream was **Stream 0**, between **127.0.0.1:42846** and **127.0.0.1:80**.  
   
Following the stream reconstructed the complete plaintext HTTP exchange, including:  
   
- `GET /basic.html`  
- `HTTP/1.1 200 OK`  
- HTML response content  
   
The connection terminated normally using **FIN/ACK** packets in **Frames 8 and 9**, confirming an orderly TCP session closure.  
   
**Figure 07:** Connection Closure <img width="1366" height="768" alt="Fig07- connectin closue" src="https://github.com/user-attachments/assets/e7ba4ee5-e742-476f-a461-e1a1e5e5b9ae" />
  
   
---  
   
# Part F — Encapsulation and Loopback Analysis  
   
The HTTP traffic was encapsulated through:  
   
```text  
HTTP → TCP → IP  
```  
   
Frame 4 contained the **83-byte TCP HTTP request** with a total frame length of **149 bytes**.  
   
Frame 6 contained the **386-byte TCP HTTP response** with a total frame length of **452 bytes**.  
   
The capture used the local loopback interface, so the traffic remained within the host and did not represent a normal physical Ethernet transmission.  
   
**Figures:**  
   
- <img width="1366" height="768" alt="Fig08- loopback" src="https://github.com/user-attachments/assets/9c923688-04ef-41d8-b48e-8121088919f1" />
  
- <img width="1366" height="211" alt="Fig09-loopback2" src="https://github.com/user-attachments/assets/cb4254e8-a5c1-42d2-86d1-36cced992e35" />
  
- <img width="1366" height="768" alt="Fig10-loopback3" src="https://github.com/user-attachments/assets/09693a62-87f5-4e17-9ff1-37862c6aaa23" />
  
   
---  
   
# Conclusion  
   
The practical was successfully completed and demonstrated the process of capturing and analyzing plaintext HTTP traffic from a digital forensic perspective. The captured PCAP file provided sufficient evidence to reconstruct the communication between the client at **127.0.0.1:42846** and the Apache web server at **127.0.0.1:80**.  
   
The analysis successfully identified the TCP three-way handshake consisting of the SYN, SYN-ACK, and ACK packets, followed by the HTTP **GET /basic.html** request and the server's **HTTP/1.1 200 OK** response. Following the TCP stream also revealed the complete plaintext HTTP conversation, including the HTML content transmitted by the server. The encapsulation analysis demonstrated the movement of the HTTP data through TCP and IP, while the FIN/ACK packets confirmed that the TCP connection was closed normally.  
   
From an evidence-handling perspective, the original capture was preserved and a working copy was created for analysis. Both files produced the same SHA-256 hash:  
   
```text  
6740f70ace58fb96c17a6155375d7229a230be956457b1dab55865734eb2ffa7  
```  
   
confirming that the working copy matched the original evidence. Overall, the exercise provided practical experience in network traffic capture, protocol analysis, evidence preservation, and forensic reconstruction of plaintext HTTP communication.  
