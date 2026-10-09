# Cerber Ransomware Investigation – Splunk BOTS v1

> 🇮🇹 Riassunto in italiano: [in fondo alla pagina](#riassunto-in-italiano)

**Author:** Vincenzo Carotenuto · [GitHub](https://github.com/vincenzocarotenuto) · [LinkedIn](https://www.linkedin.com/in/vincenzo-carotenuto/)
**Tools:** Splunk Enterprise, SPL, VirusTotal
**Dataset:** [Splunk Boss of the SOC v1](https://github.com/splunk/botsv1) (attack-only version)
**Related project:** [Web Defacement Investigation – BOTS v1](https://github.com/vincenzocarotenuto/splunk-bots-v1-web-defacement)

---

## 1. Executive Summary

On 24 August 2016, an employee workstation at Wayne Enterprises was infected by the **Cerber ransomware**. The investigation reconstructed the full infection chain from log data alone.

The user `bob.smith` connected a **USB flash drive** and opened a Word document containing a **malicious macro**. The macro generated an obfuscated VBScript that waited about four and a half minutes, downloaded the ransomware disguised as a `.jpg` image, and executed it. The malware disguised itself as a Windows component, obtained administrator privileges, **deleted the Windows shadow copies** and disabled system recovery, then **encrypted at least 970 files on the company file share** and left ransom notes in 641 folders.

**Root cause:** a malicious document from an untrusted USB device, opened by a user with macros allowed, on a workstation able to reach the Internet freely and with write access to a shared company folder.
**Impact:** files encrypted on the workstation and on the shared folder `fileshare` of the domain controller `we9041srv`; local recovery options destroyed.

---

## 2. Scenario & Lab Environment

**Boss of the SOC (BOTS) v1** is a public dataset released by Splunk with real log data from a fictional company, Wayne Enterprises. This report covers **Scenario 2: the Cerber ransomware infection**.

The lab is the same used for the [web defacement investigation](https://github.com/vincenzocarotenuto/splunk-bots-v1-web-defacement): Splunk Enterprise on a Windows laptop, the attack-only BOTS v1 dataset and current versions of the FortiGate, Stream, Sysmon and Windows add-ons. Setup issues and sourcetype renaming are documented there.

> **Note on time:** timestamps are shown as displayed by Splunk in the analyst's local time zone (UTC+2).

**Assets involved**

| Host | IP | Role |
|---|---|---|
| `we8105desk` | 192.168.250.100 | Workstation of `WAYNECORPINC\bob.smith` (patient zero) |
| `we9041srv` | 192.168.250.20 | Domain controller, internal DNS and file server (`fileshare`) |

---

## 3. Data Sources

| Sourcetype / source | Content | Used for |
|---|---|---|
| `suricata` | IDS alerts | Initial detection, identifying the infected host |
| `XmlWinEventLog` (Sysmon) | Process creation (EventCode 1), network connections (EventCode 3), hashes | Process tree, command lines, hashes, host and user |
| `WinEventLog` (Security, EventCode 5145) | File share access on the server | Encrypted files and ransom notes on the network share |
| `WinRegistry` | Registry changes | USB device identification |
| `stream:http` | HTTP traffic | Payload download |
| `stream:dns` | DNS queries | Download domain, geolocation lookup, ransom domain |
| `stream:smb` | SMB traffic | Volume of file share activity |

---

## 4. Investigation

### 4.1 Detection – Which host is infected?

The investigation started from the ransomware family name:

```spl
index=botsv1 sourcetype=suricata cerber
| stats count by src_ip, dest_ip, alert.signature
| sort -count
```

| src_ip | dest_ip | signature |
|---|---|---|
| 192.168.250.100 | 192.168.250.20 | ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup |
| 192.168.250.100 | 85.93.0.0 | ETPRO TROJAN Ransomware/Cerber Checkin 2 |
| 85.93.4.54, 85.93.43.236 | 192.168.250.100 | ETPRO TROJAN Ransomware/Cerber Checkin Error ICMP Response |

- **192.168.250.100** is the infected host.
- The check-in is sent to a **whole network range** (85.93.0.0) over UDP, a known Cerber behaviour that makes blocking a single IP useless. Some hosts answer with ICMP errors.
- The onion domain lookup goes to 192.168.250.20, the internal DNS server.

```spl
index=botsv1 sourcetype=XmlWinEventLog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 SourceIp=192.168.250.100
| stats count by host, User
```

The host is **`we8105desk`**, used by **`WAYNECORPINC\bob.smith`** (other accounts are Windows service accounts).

### 4.2 Initial Access – USB drive and malicious document

Process creation on the workstation, in chronological order:

```spl
index=botsv1 sourcetype=XmlWinEventLog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=we8105desk User="*bob.smith"
| stats count, min(_time) as first_seen by Image, ParentImage
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| sort first_seen
```

Zooming on the critical window with full command lines:

```spl
index=botsv1 sourcetype=XmlWinEventLog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=we8105desk earliest="08/24/2016:18:40:00" latest="08/24/2016:18:50:00"
| table _time Image CommandLine
| sort _time
```

At **18:43:12** Word opened:

```
WINWORD.EXE /n /f "D:\Miranda_Tate_unveiled.dotm"
```

- `.dotm` is a **macro-enabled Word template**.
- The file is on drive **D:**, not in the user profile or an email attachment folder.
- The name is a social engineering lure (a Batman character, "unveiled").

**Where did drive D: come from?**

```spl
index=botsv1 sourcetype=WinRegistry host=we8105desk friendlyname
| table _time key_path registry_value_name registry_value_data
```

At **18:42:17** the registry recorded a USB storage device (`USBSTOR`, "Generic Flash Disk") with volume name **`MIRANDA_PRI`**. The document was opened **55 seconds later**: the initial access vector was a **USB drive**.

### 4.3 Execution – Macro, VBScript and payload

Process tree:

```
WINWORD.EXE  (Miranda_Tate_unveiled.dotm)                18:43:12
 └─ cmd.exe  (writes %APPDATA%\%RANDOM%.vbs line by line) 18:43:21
     └─ wscript.exe  20429.vbs                            18:43:21
         └─ cmd.exe /C START 121214.tmp                   18:48:21
             └─ 121214.tmp
                 ├─ osk.exe  (copy of itself)             18:48:41
                 └─ cmd.exe  taskkill + ping + del        18:48:41
```

**Word spawning `cmd.exe` and `wscript.exe`** is the signature of a malicious macro.

The macro builds the script with a `for ... do echo` loop, so the `.vbs` file only exists once written on disk. The VBScript is **obfuscated**:
- random upper/lower case (`fuNCtioN`, `WSCRiPt.sLEeP`) and junk variables (`EYnt=45`);
- object names and URLs **XOR-encrypted** and decoded at runtime;
- a **270-second sleep** (`MA((-176+446))`) before acting, a sandbox evasion technique that explains the gap between 18:43:21 and 18:48:21;
- the dropped file name is built from the **seconds of the system clock** (`121214.tmp`), so it changes at every infection;
- a **fallback URL**: if the first download fails, a second one is tried.

**Payload download**

```spl
index=botsv1 sourcetype=stream:http src_ip=192.168.250.100 earliest="08/24/2016:18:47:00" latest="08/24/2016:18:49:00"
| table _time dest_ip site uri http_method status
| sort _time
```

| _time | dest_ip | site | uri | status |
|---|---|---|---|---|
| 18:48:13 | 37.187.37.150 | solidaritedeproximite.org | `/mhtr.jpg` | 404 |
| 18:48:14 | 92.222.104.182 | 92.222.104.182 | `/mhtr.jpg` | 206 |

The first domain (possibly a compromised legitimate site) returned 404; the script then used its **fallback IP** and succeeded. The `.jpg` extension is fake: the content is the XOR-encrypted executable, decoded by the script and saved as `121214.tmp`.

**Masquerading and self-deletion**

```spl
index=botsv1 sourcetype=XmlWinEventLog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=we8105desk (Image="*121214.tmp" OR Image="*osk.exe" OR Image="*AdapterTroubleshooter.exe")
| stats values(Hashes) as Hashes by Image
```

- `121214.tmp` and `osk.exe` have the **same hashes**: the malware copied itself to `%APPDATA%\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`, using the name of the Windows On-Screen Keyboard, then deleted the original (`taskkill ... & ping -n 1 127.0.0.1 & del ...`).
- MD5 `EE0828A4E4C195D97313BFC7D4B531F1`: **56/71** detections on VirusTotal (checked on 09/10/2026).

### 4.4 Privilege Escalation and Defense Evasion

At **18:49:02–18:49:03** `consent.exe` (the **UAC prompt**) appears several times, and `AdapterTroubleshooter.exe` is started from a random folder `C:\Windows\SysWOW64\QqJXZrBKCk72XzRgZs\`. This file has **0/60** detections: it is a legitimate Microsoft binary used out of context. This is consistent with a **UAC bypass via DLL hijacking** (hypothesis, not verified). Right after, the malware runs commands that require administrator rights.

### 4.5 Impact – Inhibiting recovery

```
wmic.exe shadowcopy delete
vssadmin.exe delete shadows /all /quiet
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
```

At **18:49:23–18:49:24** the malware **deleted all Volume Shadow Copies** (with two different tools) and **disabled Windows Recovery**, removing any built-in way to restore files without paying.

### 4.6 Discovery and Command & Control

```spl
index=botsv1 sourcetype=stream:dns src_ip=192.168.250.100 earliest="08/24/2016:18:42:00" query!="*.in-addr.arpa" query!="*waynecorpinc.local"
| stats count, min(_time) as first_seen by query
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| sort first_seen
```

| first_seen | query | Meaning |
|---|---|---|
| 18:48:12 | `solidaritedeproximite.org` | Payload download domain |
| 18:49:24 | `ipinfo.io` | Public IP / geolocation of the victim |
| 19:15:12 | `cerberhhyed5frqa.xmfir0.win` | Tor gateway to the ransom payment page |

Without the filters, hundreds of reverse lookups for `85.93.0.x` appear at 18:49:27, matching the UDP check-in sweep detected by Suricata. The remaining queries (NetBIOS names, `wpad`, `isatap`, Microsoft domains) are normal Windows traffic.

### 4.7 Impact – Encryption of the network share

```spl
index=botsv1 sourcetype=stream:smb src_ip=192.168.250.100
| stats count by dest_ip
| sort -count
```

**39,204** SMB events from the workstation to **192.168.250.20**.

```spl
index=botsv1 sourcetype=WinEventLog EventCode=5145 192.168.250.100
| stats count by host, Share_Name
```

The server is **`we9041srv`** (also hosting `SYSVOL` and `NETLOGON`, so a **domain controller**). The share **`fileshare`** received **16,902** accesses.

```spl
index=botsv1 sourcetype=WinEventLog EventCode=5145 192.168.250.100 Share_Name="*fileshare"
| eval extension=lower(mvindex(split(Relative_Target_Name, "."), -1))
| stats dc(Relative_Target_Name) as unique_files by extension
| sort -unique_files
```

- **970** distinct files with the **`.cerber`** extension (encrypted files).
- Targeted file types include PDF (257), images, Word, Excel and PowerPoint documents.

```spl
index=botsv1 sourcetype=WinEventLog EventCode=5145 192.168.250.100 Share_Name="*fileshare"
| eval file_name=mvindex(split(Relative_Target_Name, "\\"), -1)
| search file_name="*.vbs" OR file_name="*.url"
| stats count, dc(Relative_Target_Name) as folders by file_name
```

Ransom notes **`# DECRYPT MY FILES #`** (`.html`, `.txt`, `.url`, `.vbs`) were written in **641 folders**. The `#` prefix puts them at the top of every folder listing.

At **19:15:11** the malware displayed the ransom demand (Internet Explorer, Notepad and a VBScript voice message), resolved the payment domain and deleted itself at **19:15:29**.

---

## 5. Attack Timeline

| Time (24 Aug 2016) | Phase | Event |
|---|---|---|
| 18:42:17 | Initial Access | USB drive `MIRANDA_PRI` connected to we8105desk |
| 18:43:12 | Execution | `D:\Miranda_Tate_unveiled.dotm` opened in Word |
| 18:43:21 | Execution | Macro writes and runs obfuscated `20429.vbs` |
| 18:43–18:48 | Defense Evasion | 270-second sleep (sandbox evasion) |
| 18:48:13 | Command & Control | `mhtr.jpg` download: 404 from domain, success from fallback IP |
| 18:48:21 | Execution | `121214.tmp` executed |
| 18:48:41 | Defense Evasion | Copy to `osk.exe`, original deleted |
| 18:49:02 | Privilege Escalation | UAC prompt, AdapterTroubleshooter.exe (possible UAC bypass) |
| 18:49:23 | Impact | Shadow copies deleted, Windows Recovery disabled |
| 18:49:24 | Discovery | `ipinfo.io` lookup |
| 18:49:27 | Command & Control | UDP check-in to 85.93.0.0 range |
| 18:49–19:15 (estimated) | Impact | Encryption of local files and `\\we9041srv\fileshare` |
| 19:15:11 | Impact | Ransom note displayed, `cerberhhyed5frqa.xmfir0.win` resolved |
| 19:15:29 | Defense Evasion | Malware self-deletion |

---

## 6. Indicators of Compromise (IOCs)

| Type | Value | Description |
|---|---|---|
| USB device | Volume name `MIRANDA_PRI` (Generic Flash Disk) | Delivery device |
| File | `Miranda_Tate_unveiled.dotm` | Malicious macro document |
| File | `%APPDATA%\20429.vbs` | Obfuscated downloader script (name is random) |
| Domain | `solidaritedeproximite.org` (37.187.37.150) | Payload hosting (404 at time of infection) |
| IP | `92.222.104.182` | Fallback payload hosting |
| URL path | `/mhtr.jpg` | XOR-encrypted payload disguised as an image |
| File | `121214.tmp`, `osk.exe` in `%APPDATA%\{35ACA89F-933F-6A5D-2776-A3589FB99832}\` | Cerber ransomware |
| MD5 | `EE0828A4E4C195D97313BFC7D4B531F1` | Cerber ransomware |
| SHA256 | `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` | Cerber ransomware |
| Network | UDP to `85.93.0.0` range | Cerber check-in |
| Domain | `cerberhhyed5frqa.xmfir0.win` | Ransom payment gateway |
| File | `# DECRYPT MY FILES #.html/.txt/.url/.vbs` | Ransom notes |
| Extension | `.cerber` | Encrypted files |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1091 – Replication Through Removable Media | USB drive `MIRANDA_PRI` |
| Execution | T1204.002 – User Execution: Malicious File | User opened the `.dotm` document |
| Execution | T1059.005 – Visual Basic | Macro and `20429.vbs` |
| Execution | T1059.003 – Windows Command Shell | `cmd.exe` spawned by Word and by the malware |
| Defense Evasion | T1027 – Obfuscated Files or Information | Obfuscated VBScript, XOR-encrypted strings and payload |
| Defense Evasion | T1497.003 – Time Based Evasion | 270-second sleep |
| Defense Evasion | T1036 – Masquerading | `osk.exe` name, `.jpg` extension for an executable |
| Defense Evasion | T1070.004 – File Deletion | Self-deletion of `121214.tmp` and `osk.exe` |
| Privilege Escalation | T1548.002 – Bypass User Account Control | AdapterTroubleshooter.exe out of context (hypothesis) |
| Command and Control | T1105 – Ingress Tool Transfer | Download of `mhtr.jpg` |
| Discovery | T1614 – System Location Discovery | `ipinfo.io` lookup |
| Impact | T1490 – Inhibit System Recovery | vssadmin, wmic, bcdedit |
| Impact | T1486 – Data Encrypted for Impact | 970+ `.cerber` files on the file share |

---

## 8. Root Cause & Recommendations

| Root cause | Recommendation |
|---|---|
| Unknown USB storage device allowed on a corporate workstation | Block or control removable storage (device control policies) |
| Macros executed from a document on external media | Block macros from untrusted sources/locations via Group Policy |
| User clicked through social engineering and approved UAC | Security awareness training (USB drops, macro warnings, UAC prompts); standard users without local admin rights |
| Workstation could download from raw IP addresses on the Internet | Web proxy with category and reputation filtering; block direct-to-IP downloads |
| User had write access to a large shared folder | Least privilege on file shares; monitor mass file modifications |
| Recovery relied on local shadow copies | Offline/immutable backups of file servers, regularly tested |
| No alert on Office spawning scripts or on shadow copy deletion | SIEM detection rules (see below) |

**Detection example 1** – Office application spawning a shell or script engine:

```spl
index=botsv1 sourcetype=XmlWinEventLog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*POWERPNT.EXE")
  (Image="*cmd.exe" OR Image="*wscript.exe" OR Image="*cscript.exe" OR Image="*powershell.exe")
| table _time host User ParentImage Image CommandLine
```

**Detection example 2** – Shadow copy deletion and recovery tampering:

```spl
index=botsv1 sourcetype=XmlWinEventLog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((Image="*vssadmin.exe" CommandLine="*delete shadows*") OR (Image="*wmic.exe" CommandLine="*shadowcopy delete*") OR (Image="*bcdedit.exe" CommandLine="*recoveryenabled no*"))
| table _time host User ParentImage Image CommandLine
```

---

## 9. Limitations & Lessons Learned

**Limitations**
- The **attack-only** dataset contains only malicious events, so they are easier to find than in a real environment.
- The encryption window (18:49–19:15) is **estimated** from the process sequence, not measured on file events.
- The UAC bypass through `AdapterTroubleshooter.exe` is a hypothesis: the DLLs it loaded were not analysed.
- `solidaritedeproximite.org` being a compromised legitimate site is a hypothesis based on its name.
- The VBScript logic was read from its structure; the payload was not executed or reverse engineered.

**Lessons learned**
- **Parent → child process relationships** (Word → cmd → wscript) reveal an infection faster than any single log line.
- **Hashes beat file names**: `121214.tmp` and `osk.exe` are the same file.
- A **clean VirusTotal result** does not mean benign activity: path, parent process and timing matter.
- Filtering noise is half of the job: hundreds of reverse DNS lookups and Windows background traffic hid three meaningful domains.
- Server-side events (EventCode 5145) measure the **business impact** that workstation logs alone cannot show.

---

## Riassunto in italiano

Indagine su un'infezione ransomware ricostruita con il dataset **Splunk BOTS v1** (Wayne Enterprises). Usando solo i log in Splunk ho ricostruito l'intera catena: una **chiavetta USB** con un documento Word malevolo, una **macro** che genera uno script VBScript offuscato, l'attesa per eludere le sandbox, il download del ransomware **Cerber** camuffato da immagine, il **bypass dell'UAC**, la cancellazione delle copie shadow e la **cifratura di oltre 970 file** sulla cartella condivisa aziendale, con note di riscatto in 641 cartelle. Il report include query SPL, timeline, IOC, mappatura MITRE ATT&CK, raccomandazioni e regole di detection.
