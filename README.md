# Threat Hunt: PHP2Shell, The Hartwell Breach

**Date:** November 2026
**Analyst:** Ayaan Sheikh
**Result:** 18 / 18 flags (1750 / 1750)

## Tools Used

- Azure Log Analytics (LAW-HuntPractice) / Microsoft Sentinel
- KQL
- Logs: Apache access and error logs, enriched HTTP logs, Sysmon for Linux, auditd
- Target: debian13 (192.168.1.120), a WordPress server on Debian 13

## Scenario

Hartwell Medical Group runs a WordPress site for patient scheduling. On 23 October 2026 the SOC got alerts showing the `www-data` account (the account Apache runs as) writing files into the web folder. That account should never be running commands or writing files there. My job was to find out who did it, how they got in, what they did, and whether they spread to other machines.

## What Happened

An attacker at **192.168.1.100** scanned the site with **Nmap**, then exploited a bug in PHP's **session upload progress** feature to drop a webshell called **health-check.php**. They sent commands to it through a hidden HTTP header, looked around the server, stole the WordPress database login and user password hashes, and tried to shut off the security tools. That failed because they didn't have root. They set up a **cron job** to keep access and never moved to another machine.

## How I Hunted

- Every Hartwell table has an `OriginalTime` column with the real event time, so I filtered every query on it. The attack window was 23 Oct 2026, 04:00 to 16:00 UTC.
- I started with counts and summaries to find what stood out, then filtered down to the attacker to read the actual events.

---

## Section 1: First Contact

### Flags 1 and 2: The Scanner and Reconnaissance Tool

I was looking for an outside IP sending far more traffic than the staff IPs (192.168.1.50 and .80). I counted requests by IP and user agent.

```kql
HartwellApache_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| summarize Hits = count(), Paths = dcount(URI) by SourceIP, UserAgent
| sort by Hits desc
```

<img width="931" height="832" alt="Screenshot 2026-11-11 170327" src="https://github.com/user-attachments/assets/a247a87f-1133-434a-8710-8eb3652b0b2a" />


192.168.1.100 kept showing up with a different user agent each time (Android, iPhone, Windows, Mac), which a normal visitor wouldn't do. One of its user agents gave away the tool: `Nmap Scripting Engine`. The other busy IP, 192.168.1.120, is the server itself.

- **Flag 1:** `192.168.1.100`
- **Flag 2:** `Nmap`

---

## Section 2: The Exploit

### Flag 3: Error Trail

Exploits usually leave errors behind, so I checked the Apache error log for the attacker IP.

```kql
HartwellApacheError_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where ClientIP == "192.168.1.100"
| where Message has "session"
| project OriginalTime, Level, Module, Message
| sort by OriginalTime asc
```
width="660" height="601" alt="Screenshot 2026-11-11 171430" src="https://github.com/user-attachments/assets/b58a1d20-b374-48f5-b0f3-f3636d6a370c" />


The messages were cut off, so I grouped them to see each unique message in full.

```kql
HartwellApacheError_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where ClientIP == "192.168.1.100"
| summarize Count = count() by Message
```

<img width="660" height="601" alt="Screenshot 2026-11-11 171430" src="https://github.com/user-attachments/assets/2251bbcd-836e-42e2-97cd-ac3586bf3499" />


Three PHP session warnings repeated 25 times each ("Session ID is too long," "Failed to read session data," "Failed to write session data"). These come from PHP's session upload progress feature, which is the bug this exploit targets (CVE-2026-109618 / CVE-2026-109619).

- **Flag 3:** `session.upload_progress`

### Flag 4: Exploit Delivery


Since the bug is in the upload feature, I expected the exploit to look like a file upload. I compared request methods and content types.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| summarize Requests = count() by id_orig_h, method, content_type
| sort by Requests desc
```

<img width="707" height="558" alt="Screenshot 2026-11-11 171805" src="https://github.com/user-attachments/assets/c0c46f07-136d-48d7-ac6e-76e84ade44df" />


Normal browsing is GET. The attacker sent POST requests with `multipart/form-data`, one with the boundary `----0x4148php2shell`. PHP only runs the upload progress code on real file uploads, so the attacker had to fake one to reach the bug.

- **Flag 4:** `POST, multipart/form-data`

### Flag 5: The Payload

The error summary above also showed PHP errors from `/var/www/html/health-check.php` running code with `eval()`, with pieces like "DB_NAME" and "SELECT" in them. That's the webshell. The name is meant to look like a normal health check page.

- **Flag 5:** `health-check.php`

---

## Section 3: Remote Control

### Flag 6: The Operator

A webshell runs inside the web server, so its commands run as the web server's account. Apache runs as www-data, which has no admin rights. That becomes important in Section 6.

- **Flag 6:** `www-data`

### Flags 7 and 8: Hidden Trigger and Encoded Orders

There was nothing like `?cmd=` in the URLs, so the commands were hidden somewhere else. The HTTP table had columns for a custom header called `X-HMG-Debug`, so I compared its raw and decoded values.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where isnotempty(x_hmg_debug_raw)
| project OriginalTime, x_hmg_debug_raw, x_hmg_debug_decoded
| sort by OriginalTime asc
| take 10
```

<img width="755" height="670" alt="Screenshot 2026-11-11 173017" src="https://github.com/user-attachments/assets/28043641-20ae-4f88-b46f-cc141df7b0f9" />


Every command came in through the `X-HMG-Debug` header. Apache's normal access log doesn't record custom headers, so this only shows up in the enriched HTTP log.

The raw values end in `=`, a sign of Base64. Base64 decoding `ZmxmZ3J6KCJ2cSIpOw==` gives `flfgrz("vq");`, and ROT13 turns that into `system("id");`. So the attacker applied ROT13 first, then Base64. Every value starts with `ZmxmZ3J6` because every command starts with `system(`.

- **Flag 7:** `X-HMG-Debug`
- **Flag 8:** `ROT13, Base64`

---

## Section 4: Mapping the Territory

The decoded column is basically the attacker's full command history, so I pulled all of it in order.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where isnotempty(x_hmg_debug_decoded)
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

<img width="928" height="902" alt="Screenshot 2026-11-11 173447" src="https://github.com/user-attachments/assets/b44c3eb5-9651-4d90-9c23-6a84f8bb96d3" />


It starts at 14:01 UTC with basic checks (`id`, `whoami`, `uname -a`, `hostname`) and moves into network discovery, security tool checks, and the config file.

### Flag 9: Network Mapping

I filtered for networking commands.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has_any ("arp", "neigh", "route", "netstat", "ping", "ifconfig", "ip ", "ss ", "hosts", "nmap")
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

<img width="820" height="651" alt="Screenshot 2026-11-11 173525" src="https://github.com/user-attachments/assets/c2e9e6a9-5359-4b73-aab8-eac0a4fa8ad0" />


`ip a` / `ip addr show` shows what network the server is on, `ip neigh` shows nearby machines, and `ss -tlnp` shows what's listening.

- **Flag 9:** `ip addr, ss, ip neigh`

### Flag 10: Monitoring Awareness

In the full command list, at 14:02:57 the attacker ran `dpkg -l | grep -iE 'splunk|sysmon|auditd|wazuh|ossec'` to check for security tools. Only Sysmon, auditd and Splunk are installed on this server.

- **Flag 10:** `sysmon, auditd, splunk`

---

## Section 5: Credential Harvest

### Flag 11: The Config File

The full command list shows the attacker reading `/var/www/html/wp-config.php` several times with grep and head. That's where WordPress keeps its database login.

- **Flag 11:** `wp-config.php`

### Flag 12: The Database Dump

Next I looked at what they did with that login.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has "mysql"
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

<img width="813" height="516" alt="Screenshot 2026-11-11 180841" src="https://github.com/user-attachments/assets/79e5aeda-dea6-4a29-b58a-25409bbbb212" />


They logged into MySQL as `wpuser` (with the password `wp_lab_2026` typed right on the command line) and ran `SELECT user_login,user_pass FROM wp_users`. `wp_users` is the user table and `user_pass` holds the password hashes. The last query dumped the whole table into base64.

- **Flag 12:** `wp_users, user_pass`

---

## Section 6: Fighting the Watchers

### Flags 13 and 14: Targets for Silence and Success or Failure

After finding the security tools, I expected the attacker to try turning them off.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has_any ("systemctl", "service ", "kill", "stop")
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

<img width="796" height="432" alt="Screenshot 2026-11-11 174359" src="https://github.com/user-attachments/assets/471fef47-496d-45b6-a99b-6ff3cd15d48c" />


They listed running services, ran `systemctl stop` on sysmon and SplunkForwarder, then checked all three with `systemctl is-active sysmon auditd SplunkForwarder`.

It didn't work. The commands ran as www-data, and stopping system services needs root. The proof is that the logs kept recording everything they did afterward.

- **Flag 13:** `sysmon, auditd, SplunkForwarder`
- **Flag 14:** No. The www-data account does not have root privileges, so it lacked permission to stop the services with systemctl and all monitoring kept running.

---

## Section 7: Digging In

### Flags 15 and 16: The Scheduled Callback and Hidden Implant

On Linux, the usual way to keep running something on a schedule is cron, so I searched for cron and common hiding spots.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has_any ("/dev/shm", "cron", "chmod")
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

<img width="943" height="666" alt="Screenshot 2026-11-11 174710" src="https://github.com/user-attachments/assets/d23a073b-d3ff-4e6b-9966-4d4d415ee630" />


At 14:15 they copied a file to `/dev/shm/.cache-helper` and made it executable. At 14:16 they added a cron job to run it every 5 minutes.

`/dev/shm` lives in memory, not on disk, so the file disappears on reboot and won't show up in a disk image. The dot in the name hides it from a normal `ls`. The file was just a copy of `/usr/bin/sleep`, so they were probably testing that the cron job works.

- **Flag 15:** `cron job`
- **Flag 16:** `/dev/shm/.cache-helper`

---

## Section 8: Damage Assessment

### Flag 17: Data Out

The attacker already had a webshell that sends back command output, so I checked whether they used it to pull data out.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has "base64"
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

<img width="782" height="670" alt="Screenshot 2026-11-11 180854" src="https://github.com/user-attachments/assets/790799c5-2c42-4799-942d-592eee660542" />


They ran `base64 /var/www/html/wp-config.php` and `SELECT * FROM wp_users | base64`. The webshell sent the encoded output back in its web response, so no separate channel was needed.

- **Flag 17:** The attacker base64 encoded the wp-config.php contents and database records and pulled them back out in the HTTP responses of the existing health-check.php webshell, so no separate exfiltration channel was used.

### Flag 18: Lateral Movement Check

A coworker thought the attacker moved to other machines. Going through the full command list, they looked at nearby machines with `ip neigh` but never used ssh, scp, nc, or anything else to connect to one.

- **Flag 18:** No, the logs only show local discovery like ip neigh with no ssh, scp, nc or connections to other hosts, so all activity stayed on 192.168.1.120.

---

## Timeline (UTC, 23 Oct 2026)

| Time | What happened |
|---|---|
| Morning | Nmap scan from 192.168.1.100 |
| 08:18 | Exploit attempts start (PHP session warnings) |
| 14:01 | First webshell command (`id`) |
| 14:02 | Network discovery and security tool check |
| 14:03 to 14:09 | Read wp-config.php and dumped wp_users |
| 14:12 | More network discovery (`ip addr show`, `ip neigh`) |
| 14:13 to 14:14 | Tried to stop the security tools (failed) |
| 14:14 to 14:15 | Base64 exfiltration of wp-config.php and wp_users |
| 14:15 to 14:16 | Staged `/dev/shm/.cache-helper` and added the cron job |

## MITRE ATT&CK

| Technique | Evidence |
|---|---|
| T1595 / T1595.002 Active Scanning | Nmap scan |
| T1190 Exploit Public-Facing Application | session.upload_progress exploit |
| T1505.003 Web Shell | health-check.php |
| T1059.004 Unix Shell | Commands run as www-data |
| T1027 Obfuscated Files or Information | ROT13 + Base64 commands |
| T1016 System Network Configuration Discovery | ip addr, ss, ip neigh |
| T1518.001 Security Software Discovery | dpkg check for security tools |
| T1555 Credentials from Password Stores | wp-config.php and wp_users |
| T1562.001 Disable or Modify Tools | systemctl stop (failed) |
| T1053.003 Cron | Cron job every 5 minutes |
| T1036.005 Match Legitimate Name or Location | health-check.php, .cache-helper |
| T1041 Exfiltration Over C2 Channel | Base64 data sent back through the webshell |
| T1021 Remote Services | Checked, not found |

## IOCs

- IP: `192.168.1.100`
- Webshell: `/var/www/html/health-check.php`
- Implant: `/dev/shm/.cache-helper`
- Header: `X-HMG-Debug`
- Encoded command prefix: `ZmxmZ3J6`

## Recommendations

- Block 192.168.1.100
- Remove the webshell, the implant, and the www-data cron job
- Patch PHP or turn off `session.upload_progress` until it's patched
- Change the database password and WordPress keys, and reset all WordPress user passwords
- Alert on the X-HMG-Debug header, www-data running shell commands, and new files in /dev/shm

## What I Learned

- The normal Apache log missed the most important part. The commands were hidden in a header and only showed up in the enriched HTTP log.
- Running Apache as a low-privilege account stopped the attacker from turning off monitoring, which is why the full attack was visible.
- It's worth testing claims instead of assuming them. The lateral movement theory didn't hold up.
