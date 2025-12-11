# 🧩 Assisted Lab: Performing Root Cause Analysis (CySA+)

## 📌 Overview

This project documents a full **root cause analysis (RCA)** of a simulated security breach in the Structureality Inc. environment.  
As a **Cybersecurity Analyst**, I used centralized logging, host forensics, network analysis, and firewall logs to:

- Trace **audit policy tampering** on a domain controller (DC10)
- Attribute malicious activity to a specific insider (Dylan from HR)
- Reconstruct the **end-to-end attack path**, from phishing to credential theft to misuse of admin privileges
- Produce actionable **lessons learned** and **mitigation recommendations**

The lab is designed to align with **CompTIA CySA+** objectives and to demonstrate practical incident investigation skills.

---

## 🏗️ Lab Environment

**Primary Systems**

- **KALI**
  - Role: CySA analyst workstation
  - OS: Kali Linux
  - Tools: Firefox, terminal, ping, SSH, web access to Wazuh & OPNSense

- **DC10**
  - Role: Domain Controller
  - OS: Windows Server 2019
  - Segment: `vLAN_SERVERS`
  - Functions: AD services, security auditing, critical infrastructure

- **MS10**
  - Role: Legacy server used in the attack path
  - OS: Windows Server 2016
  - Segment: `vLAN_SERVERS`
  - Tools: Event Viewer, Wireshark, PowerShell, proxy script, PCAP storage

- **PC10**
  - Role: User workstation (Jaime)
  - OS: Windows Server 2019 (used as a client)
  - Segment: `vLAN_CLIENTS`
  - Tools: Mozilla Thunderbird, Firefox, Command Prompt

- **ROUTER-BORDER**
  - Role: Perimeter firewall
  - Platform: OPNSense
  - Function: Logs north–south traffic, GUI accessible from Kali

- **WAZUH**
  - Role: Centralized SIEM / threat detection platform
  - OS: Ubuntu Server
  - Agents: Installed on DC10 and PC10

---

## 🎯 Learning Objectives (CySA+ Mapping)

This lab reinforces the following **CompTIA CySA+** objectives:

- **1.1** – System & network architecture concepts in security operations  
- **1.2** – Analyze indicators of potentially malicious activity  
- **1.3** – Use appropriate tools/techniques to determine malicious activity  
- **1.4** – Threat intelligence & threat hunting concepts  
- **3.2** – Perform incident response activities  
- **3.3** – Preparation & post-incident activity in the incident lifecycle  

---

## 🔍 High-Level Workflow

1. **Start from the SOC Alert**  
   - Wazuh rule `60112`: audit policy changes on **DC10**.
2. **Confirm Host Impact on DC10**  
   - Check audit policies and Security log using `auditpol` and Event Viewer.
3. **Pivot to MS10 (suspected origin of RDP)**  
   - Use Security logs to identify who initiated the RDP session to DC10.
4. **Investigate PC10 (user compromise)**  
   - Analyze email, downloaded scripts, and browser proxy settings.
5. **Correlate with Perimeter Firewall (ROUTER-BORDER)**  
   - Validate outbound connections to the **Juice Shop** host.
6. **Finalize Evidence on MS10**  
   - Examine proxy script and `juiceshop.pcapng` in Wireshark to recover stolen credentials.
7. **Document Root Cause, Impact, and Recommendations**  

---

## 🧪 Detailed Investigation Steps

### 1️⃣ Initial Alert Triage in Wazuh (KALI)

- Logged into **Wazuh** dashboard as `admin`.
- Navigated to **Security events** and set time range to:
  - **Start:** `Mar 31, 2023 @ 00:00:00.000`  
  - **End:** `Apr 1, 2023 @ 00:00:00.000`
- Filtered on **Rule ID `60112`** (Audit Policy Change):
  - Identified multiple alerts on **DC10**.
  - Observed:
    - `data.win.eventdata.auditPolicyChanges` → `Success removed` / `Failure removed`
    - `data.win.eventdata.subjectUserName` → **`jaime`**
- Extracted key data:
  - Multiple policy change events
  - Example **EventRecordID**: `17542`
- Next, filtered Wazuh events by **search term `jaime`**:
  - Found **Rule ID `92653`**: RDP logon to DC10
  - Confirmed the connection type as **Remote Desktop Connection (RDP)**
  - Noted approximate time: **`17:55:26`**

**Conclusion:**  
Someone using **Jaime’s account** connected via RDP to **DC10** just before audit policies were disabled — a strong indicator of privileged misuse.

---

### 2️⃣ Investigating the Breach on DC10

- Logged into **DC10** as `Structureality\Administrator`.
- Ran:

  ```cmd
  auditpol /get /category:*
Confirmed audit policies were set to “No Auditing” (or effectively disabled where they mattered).

Opened Event Viewer → Windows Logs → Security:

Used Find to locate EventRecordID 17542.

Event ID 4719: audit policy change.

Time near 17:56:05 (just after the RDP event).

Searched for EventRecordID 17464:

Confirmed RDP logon corresponding to Wazuh alert.

Logon Type 10 → RemoteInteractive (Remote Desktop).

Conclusion:
Jaime’s account (via RDP from MS10) was used to connect to DC10 and then disable auditing — an intentional anti-forensic move.

3️⃣ Expanding the Investigation to MS10
Logged into MS10 as administrator.

Opened Event Viewer → Security.

Searched around 5:55 PM, then filtered for jaime.

Found Event ID 4648 – logon using explicit credentials.

The Account Name initiating RDP: dylan (from HR).

Located logon event for dylan:

Event ID 4624 (successful logon)

Confirmed logon type = 2 (Interactive) → Dylan logged directly onto MS10 at the console.

Time of Dylan logging into MS10: 05:48:14

Conclusion:
Dylan physically accessed MS10, logged in locally, then used Jaime’s credentials to RDP into DC10 and disable auditing.

4️⃣ Continuing the Investigation from PC10 (Jaime’s Workstation)
Logged into PC10 as jaime.

Checked event logs & malware scanner — no direct malware findings.

Opened Mozilla Thunderbird:

Found a phishing email: “Grab you free juice!”

Link text System Update pointed to a URL containing:

IP: 10.1.24.142

File: proxyset.bat

From Command Prompt:

cmd
Copy code
ping 10.1.24.142
Host no longer reachable (attack infrastructure torn down or offline).

Searched for downloaded file:

cmd
Copy code
cd c:\ && dir /s proxyset.bat
Located: c:\Users\jaime\Downloads\proxyset.bat

Viewed script:

cmd
Copy code
type c:\Users\jaime\Downloads\proxyset.bat
Script modified Firefox proxy settings to point to MS10 (10.1.16.2).

Validated browser proxy configuration:

Opened Firefox → Settings → Network Settings → Settings…

Confirmed Manual proxy configuration reflecting the script changes.

Conclusion:
Jaime received a social engineering email, downloaded and executed proxyset.bat, which silently redirected Firefox traffic through MS10 as a proxy.

5️⃣ Correlating with ROUTER-BORDER (Firewall / OPNSense)
From Kali, resolved Juice Shop host:

bash
Copy code
ping juiceshop.com -c 1
Resolved IP: 203.0.113.228

Opened OPNSense GUI at 10.1.128.253 as root / Pa$$w0rd.

Navigated to:
Firewall → Log Files → Live View

Applied filters:

dst contains 203.0.113.228

src = 10.1.24.101 (PC10) → no results

src = 10.1.16.2 (MS10) → multiple results

Opened detailed log entry:

Verified communication from MS10 → 203.0.113.228

Plaintext HTTP traffic (non-encrypted, standard web port).

Conclusion:
Jaime’s browser, configured to use MS10 as proxy, reached the Juice Shop site via MS10, and that traffic crossed the firewall as plaintext HTTP.

6️⃣ Concluding the Investigation on MS10 (Wireshark & Credential Theft)
On MS10, searched for proxy-related files:

cmd
Copy code
cd c:\ && dir /s proxy*
Found c:\HR\proxy.ps1:

A PowerShell script to configure MS10 as a proxy server.

Searched for packet captures:

cmd
Copy code
dir /s *.pcapng
Found: c:\Users\dylan\Documents\juiceshop.pcapng

Opened Wireshark on MS10:

Loaded juiceshop.pcapng.

Applied display filter:

text
Copy code
http.request.method == "POST"
Selected HTTP POST /rest/user/login to the Juice Shop application.

In Packet Bytes (ASCII) view, extracted credentials:

Username / Email: jaime@structureality.com

Password: Pa$$w0rd

These credentials match Jaime’s domain credentials, allowing Dylan to:

Use Jaime’s account to RDP into DC10

Disable auditing and perform further malicious actions.

📅 Incident Timeline (Reconstructed)
Times approximate; some systems log in local time (Pacific), firewall logs in UTC.

~17:48 – Dylan logs in interactively to MS10 (Logon Type 2).

Phishing Phase – Jaime receives scam email on PC10, downloads and runs proxyset.bat.

Proxy Setup – Firefox on PC10 is configured to send traffic via MS10 (10.1.16.2).

~17:54 – Jaime visits juiceshop.com → traffic flows:
PC10 → MS10 (proxy) → Juice Shop (HTTP plaintext).

Credential Theft – Dylan captures juiceshop.pcapng on MS10 using Wireshark and extracts Jaime’s credentials.

~17:55:26 – Dylan initiates RDP to DC10 from MS10 using Jaime’s account (Logon Type 10).

~17:56:05 – Audit policies on DC10 are modified (Success/Failure removed) by account jaime.

Post-event – Wazuh raises alerts:

Rule 60112: audit policy changes

Rule 92653: RDP logon event

🧠 Root Cause & Impact
Root Cause

Social engineering + plaintext interception:

Jaime fell for a phishing email, executed an untrusted script that:

Repointed Firefox to use a rogue proxy (MS10).

Dylan, with physical and logical access to MS10:

Ran a proxy server (PowerShell script).

Captured HTTP traffic with Wireshark, including Jaime’s login to a trusted site (Juice Shop) using corporate credentials.

Reused those credentials to access DC10 as Jaime and disable auditing.

Impact

Audit logging disabled on DC10, creating a blind spot for further malicious activity.

Privileged account compromise (Jaime’s account used as an admin pivot).

Potential for:

Unauthorized changes to AD / domain settings.

Unlogged lateral movement or data access.

Insider threat element:

Attack executed by Dylan (HR) using a combination of physical access, phishing, and network interception.

🛡️ Recommended Mitigations
Security Awareness & Phishing Training

Continuous training to help users recognize phishing/scam emails.

Emphasize: “Don’t run scripts or installers from email links.”

Application Control / Allowlisting

Only allow approved scripts & executables to run (e.g., AppLocker, WDAC).

Block batch scripts and PowerShell scripts from non-admin locations by default.

Proxy & Network Configuration Hardening

Centralize browser/proxy config via GPO / MDM.

Prevent users from modifying proxy settings or using unauthorized proxies.

Least Privilege & Access Control

No non-admin interactive logons to server systems (like MS10).

Restrict data center access strictly to infrastructure teams.

Require privileged accounts (like Jaime’s) to be used only from hardened admin workstations, not from general servers.

Secure Remote Access Practices

Limit or ban direct RDP to domain controllers.

Use jump hosts / bastion systems with strong auditing and MFA.

TLS Everywhere

Enforce HTTPS only for internal and external web traffic where possible.

Terminate plaintext HTTP at secure reverse proxies, inspect, and log.

Enhanced Logging & Alerting

Alert on:

Audit policy changes.

Direct RDP logons to DCs.

New or modified proxy settings on user endpoints.

Forward logs to SIEM (Wazuh) with integrity monitoring (e.g., file integrity, config drift).

Post-Incident Actions

Reset Jaime’s credentials and any shared secrets.

Review changes made on DC10 during the logging “gap.”

Conduct HR/legal review of Dylan’s actions.

🧰 Tools & Techniques Used
Wazuh

Security events, correlation rules (60112, 92653)

Time-bound pivoting and alert-based investigation

Windows Event Viewer (DC10, MS10, PC10)

Security log analysis (4624, 4648, 4719)

EventRecordID correlation with SIEM data

Command-Line Tools

auditpol (DC10) – audit policy status

ping, dir, type (PC10, MS10)

PowerShell script discovery (proxy.ps1)

Email & Browser

Mozilla Thunderbird – phishing email review

Firefox – proxy behavior and misconfiguration verification

OPNSense (ROUTER-BORDER)

Live firewall logs

Source/destination-based filtering for juiceshop.com traffic

Wireshark (MS10)

PCAP analysis (juiceshop.pcapng)

HTTP POST filtering

Credential reconstruction from plaintext HTTP payload
