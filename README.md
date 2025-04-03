
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/coreyhallbtrt/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what 
looks like the user “labuser” downloaded a tor installer, did something that resulted in many 
tor-related files being copied to the desktop at 2025-04-01T11:02:45.5169141Z and the creation of a 
file called “tor-shopping-list.txt” on the desktop. These events began at: 
2025-04-01T10:21:48.5892232Z 

**Query used to locate events:**

```kql
DeviceFileEvents 
| where DeviceName == "threat-hunt-lab" 
| where InitiatingProcessAccountName == "labuser" 
| where FileName contains "tor" 
| where Timestamp >= datetime(2025-04-01T10:21:48.5892232Z) 
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = 
InitiatingProcessAccountName
```
<![image](https://github.com/user-attachments/assets/11c2e686-b946-437d-bd8d-f5897e9c4ec9)>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceprocessEvents table for any ProccessCommandLine that contained the string 
"tor-browser-windows-x86_64-portable-14.0.8.exe". Based on logs returned, On April 1, 2025, at 
6:23:58 AM, on the device “threat-hunt-lab” under the account “labuser,” a ProcessCreated event was 
logged indicating that “tor-browser-windows-x86_64-portable-14.0.8.exe” (SHA256: 
ae202c167bda5afd8c47b5a027f04fbb6ef16dc41a47a372ff69fe872e7029a8) was executed from 
“C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.8.exe” using the command 
line “tor-browser-windows-x86_64-portable-14.0.8.exe /S.” 

**Query used to locate event:**

```kql

DeviceProcessEvents 
| where DeviceName == "threat-hunt-lab" 
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.8.exe" 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, 
SHA256, ProcessCommandLine 
```
<![image](https://github.com/user-attachments/assets/c9e0a407-79c1-4aaa-98eb-dfd87d24a444)>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “labuser” actually opened the 
tor browser. There was evidence that they did open it at 2025-04-01T10:24:36.6498099Z 

**Query used to locate events:**

```kql
DeviceProcessEvents 
| where DeviceName == "threat-hunt-lab" 
| where FileName has_any 
("torbrowser-install-win64.exe","torbrowser-install-win32.exe","tor.exe","Start Tor Browser.exe","tor-browser-windows-x86_64-portable-<version>.exe","Tor Browser.ex")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, 
SHA256, ProcessCommandLine 
| order by Timestamp desc 
```
<![image](https://github.com/user-attachments/assets/95d9513a-c37a-46a9-a8ad-132af5d47cb4)>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a 
connection using any of the known tor port at 2025-04-01T10:51:28.5400542Z On the device 
“threat-hunt-lab,” under the account “labuser,” a ConnectionSuccess event occurred when 
“firefox.exe” located at “c:\users\labuser\desktop\tor browser\browser\firefox.exe” connected to 
127.0.0.1 on port 9151. There was a couple of connections to sites over port 443. 

**Query used to locate events:**

```kql
DeviceNetworkEvents 
| where DeviceName == "threat-hunt-lab" 
| where InitiatingProcessAccountName == "labuser" 
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151, 80, 443) 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, 
RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath 
| order by Timestamp desc 
```
<![image](https://github.com/user-attachments/assets/d86270f5-b3c2-4b7f-9f73-f57da543e66c)>

---

## Chronological Event Timeline 

Timeline Report 

● April 1, 2025, 06:23:58 AM 
A ProcessCreated event was logged on the device “threat-hunt-lab” under the account 
“labuser.” The event indicates that the file tor-browser-windows-x86_64-portable-14.0.8.exe 
was executed (SHA256: 
ae202c167bda5afd8c47b5a027f04fbb6ef16dc41a47a372ff69fe872e7029a8) from the 
Downloads folder using the command line switch /S. 

● April 1, 2025, 10:21:48 AM 
The first file events related to Tor were recorded. A search in the DeviceFileEvents table 
revealed that files containing “tor” began to appear. During this period, it appears the Tor 
installer was downloaded and multiple Tor-related files were copied to the desktop. 

● April 1, 2025, 10:24:36 AM 
A subsequent event in the DeviceProcessEvents table showed that the user “labuser” 
actually opened the Tor browser. This confirms that the installation was followed by an active 
launch of the application. 

● April 1, 2025, 10:51:28 AM 
In the DeviceNetworkEvents table, a ConnectionSuccess event was recorded where the 
file firefox.exe (located at c:\users\labuser\desktop\tor 
browser\browser\firefox.exe) connected to the IP address 127.0.0.1 on port 9151. 
There were also additional connections noted over port 443, suggesting that Tor-related 
network activity was taking place. 

● April 1, 2025, 11:02:45 AM 
Additional file events were noted, including the creation of a file named tor-shopping-list.txt 
on the desktop. This reinforces the observation that several Tor-related files were being 
handled or copied around during this session. 

---

## Summary

On April 1, 2025, the user “labuser” on the “threat-hunt-lab” device initiated a series of Tor-related 
activities. The timeline shows that the Tor browser executable was first silently executed early in the 
morning. This was followed by the download and copying of Tor-related files (including an installer 
and a “tor-shopping-list.txt” file) to the desktop. Shortly after, the Tor browser was launched, and 
network connections consistent with Tor usage (notably on port 9151 and port 443) were established. 
Collectively, these events suggest that the user not only installed but also actively used the Tor 
browser during that period. 

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
