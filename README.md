# Threat-Hunting-Scenario-Tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JanGuiao/Threat-Hunting-Scenario-Tor/blob/main/Threat%20Hunting%20Scenario.md)

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “j4n” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at this time, 2026-04-22T16:46:49.6565332Z. These events began at: (2026-04-22T16:37:04.7709546Z)

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "j4n-vm"
| where InitiatingProcessAccountName == "j4n"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-22T16:37:04.7709546Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1445" height="591" alt="Screenshot 2026-04-22 141014" src="https://github.com/user-attachments/assets/dabe291b-3d0d-4210-a061-a4ef2978614a" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.10.exe". Based on the logs returned, at 2026-04-22T16:38:13.4331429Z, the computer named j4n-vm created (started running) a file called tor-browser-windows-x86_64-portable-15.0.10.exe, which was located in the user’s Downloads folder, triggered a silent installation, and the file has a unique SHA256 hash identifying it.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "j4n-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.10.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1372" height="312" alt="image" src="https://github.com/user-attachments/assets/9e380da8-a5d7-4eb4-8616-1c71ae2e42b0" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “employee” actually opened the tor browser. There was evidence that they did open it at 2026-04-22T16:38:36.8016516Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "j4n-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1315" height="510" alt="image" src="https://github.com/user-attachments/assets/cdfc220a-315d-4791-853d-2999fdff6eec" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2026-04-22T16:39:11.5789883Z, the computer named j4n-vm successfully made a network connection to the remote IP address 5.255.123.158 on port 9001, accessing the URL https://www.mdjhxwzijgjkuvzyqwg.com. This connection was initiated by the user j4n through the process tor.exe, which was running from the Tor Browser installation folder on the desktop.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "j4n-vm"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1603" height="452" alt="image" src="https://github.com/user-attachments/assets/daa5a17d-9fa9-4479-8637-0c3382050319" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-04-22T16:37:04.7709546Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.10.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\j4n\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-04-22T16:38:13.4331429Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-15.0.10.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.10.exe /S`
- **File Path:** `C:\Users\j4n\Downloads\tor-browser-windows-x86_64-portable-15.0.10.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-04-22T16:38:36.8016516Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\j4n\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-04-22T16:39:11.5789883Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\j4n\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-04-22T16:39:11.5789883Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-04-22T16:46:49.6565332Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\j4n\Desktop\tor-shopping-list.txt`

---

## Summary

The user "j4n" on the "j4n-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

<img width="1741" height="152" alt="image" src="https://github.com/user-attachments/assets/aabb170a-22da-4279-803d-e3c96df333dc" />


---

## Response Taken

TOR usage was confirmed on the endpoint `j4n-vm` by the user `j4n`. The device was isolated, and the user's direct manager was notified.

---
