# Threat Hunt Report: PHP2Shell, The Hartwell Breach

**Date:** November 2026
**Analyst:** Ayaan Sheikh
**Difficulty:** Easy | **Result:** 18 / 18 flags

## Platforms and Tools Used

- **Platform:** Azure Log Analytics workspace (LAW-HuntPractice), Microsoft Sentinel
- **Target host:** debian13 (192.168.1.120), Debian 13 running WordPress 7.1.3, Apache 2.4.69, PHP 8.4.4
- **Log sources:** Apache access log, Apache error log, Sysmon for Linux, auditd, enriched HTTP log (from packet capture), syslog, auth.log
- **Languages & Tools:** Kusto Query Language (KQL), Python (to check the encoding order)

## Scenario Summary

Hartwell Medical Group runs a public WordPress site for patient scheduling. On 23 October 2026, the on-call SOC analyst got a cluster of auditd alerts showing the `www-data` account writing files into the Apache webroot. That account runs the Apache worker processes and should never spawn shells, run discovery commands, or write files outside the WordPress uploads folder.

My job was to figure out who did this, how they got in, what they did once inside, what they took, and whether they spread to other machines.

**What I found:** an attacker at 192.168.1.100 scanned the site with Nmap, exploited PHP's session upload progress feature to drop a webshell called `health-check.php`, and controlled it through a hidden HTTP header with encoded commands. They explored the server, stole the WordPress database password and every user's password hash, tried and failed to shut off the monitoring tools, and set up a cron job to keep access. They never moved to another machine.

**Attack window:** 23 Oct 2026, 04:00 to 16:00 UTC

## How I Approached the Hunt

The hunt is split into 8 sections that follow the attack from start to finish. My general method was:

1. **Filter first.** Every query is limited to the attack window. All Hartwell tables have an `OriginalTime` column with the real event time. `TimeGenerated` is just when the log was ingested, so I always filtered on `OriginalTime`.
2. **Start broad, then narrow.** I'd count or summarize first to find what stands out, then filter down to the attacker and look at the actual events.
3. **Pivot between tables.** The access log shows who connected, the error log shows what broke, the enriched HTTP log shows what was hidden in the requests, and Sysmon shows what ran on the host.
4. **Use what I already found.** Once I had the attacker IP, the webshell name, and the hidden header, most of the later flags came from one table of decoded commands.

### Getting set up (the part that took the longest)

My first queries all failed with `Failed to resolve table or column expression named 'HartwellApache_CL'`, and the table name was underlined red. The query was fine. I was just in the wrong place. I listed every table I could see and none of the Hartwell tables were there:

```kql
union withsource=TableName *
| where TimeGenerated > ago(30d)
| summarize Rows=count() by TableName
| order by TableName asc
```

The fix was opening `LAW-HuntPractice` from inside the `Cyber-Range-2-Admin-SOC` resource group in the Azure portal, then switching the query editor from **Simple mode** to **KQL mode**. After that the starter query returned data.

---

## 🔎 Flag Analysis & Findings

### Section 1: First Contact (Reconnaissance)

#### 🏁 Flag 1 – The Scanner

**Goal:** Find the external IP that generated far more traffic than the staff baseline.

**My approach:** The brief says staff connect from 192.168.1.50 and 192.168.1.80. A scanner hits a lot of pages fast, so I counted requests per IP in the Apache access log. I also grouped by user agent and counted distinct paths, because scanners usually request many different URLs.

```kql
HartwellApache_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| summarize Hits = count(), Paths = dcount(URI) by SourceIP, UserAgent
| sort by Hits desc
```

**What I found:** 192.168.1.100 showed up over and over with a different user agent each time: Android, iPhone, iPad, Windows, Mac, Linux, Firefox, Chrome. A real person uses one browser, so cycling through that many is someone trying to look like normal traffic. The other big IP, 192.168.1.120, is the web server itself, so it isn't external. The staff IPs barely appeared. The environment topology also listed 192.168.1.100 as the only "external workstation."

**Answer:** `192.168.1.100`

![Flags 1 and 2: request counts by IP and user agent](screenshots/flag01-02-scanner-and-nmap.png)

#### 🏁 Flag 2 – Reconnaissance Tool

**Goal:** Identify the scanning tool the attacker used.

**My approach:** Scanning tools usually write their own name into the user agent string, while browsers say things like "Chrome" or "Safari." Since I already had every user agent for 192.168.1.100 from the Flag 1 query, I went through those rows looking for one that wasn't a browser.

**What I found:** One user agent gave it away: `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)` with 93 hits. The Nmap Scripting Engine can probe web servers for versions and known weaknesses, which fits "identifying the web stack."

**Answer:** `Nmap`

---

### Section 2: The Exploit (Initial Access)

#### 🏁 Flag 3 – Error Trail

**Goal:** Find which PHP feature generated the warnings during exploitation.

**My approach:** Failed exploit attempts usually leave errors behind, so I moved to the Apache error log and filtered to the attacker IP. My first attempt projected each row, but the messages were cut off and I couldn't read the important part. So I switched to summarizing by message, which shows each unique message once with a count.

```kql
HartwellApacheError_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where ClientIP == "192.168.1.100"
| summarize Count = count() by Message
```

**What I found:** Three PHP warnings repeated exactly 25 times each, all starting with "PHP Request Startup":

- Session ID is too long or contains illegal characters
- Failed to read session data: files
- Failed to write session data (files)

PHP only touches session data at request startup like this when a request includes an upload progress field. So the attacker was sending crafted values into the session through PHP's session upload progress feature. The case brief also says the exploit was a bug in PHP's `session.upload_progress` handler, so this lined up.

**Answer:** `session.upload_progress`

![Flag 3: unique error messages from the attacker IP](screenshots/flag03-error-messages.png)

**Something extra I noticed:** the same results had PHP parse errors from `/var/www/html/health-check.php` running code through `eval()`, with pieces like "inet", "DB_NAME", "splunk" and "SELECT" in them. That looked like a webshell leaking the attacker's commands, so I wrote it down for later.

#### 🏁 Flag 4 – Exploit Delivery

**Goal:** Find the HTTP method and content type that separates exploit traffic from normal browsing.

**My approach:** The upload progress feature only works on file uploads, so I expected the exploit to look like a file upload. I used the enriched HTTP log because it has the `content_type` field, and compared the attacker's request types.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| summarize Requests = count() by id_orig_h, method, content_type
| sort by Requests desc
```

**What I found:** Most traffic was GET with no content type, which is normal browsing. The attacker also sent several POST requests with `multipart/form-data`, the content type used for file uploads. One of them even had the boundary `----0x4148php2shell`, which is basically the attacker signing their work.

**Why this content type:** PHP only runs the upload progress code when it sees a real file upload, and that only happens with multipart/form-data. A normal form post never touches that code, so the attacker had to fake a file upload to hit the bug.

**Answer:** `POST, multipart/form-data`

![Flag 4: HTTP method and content type](screenshots/flag04-post-multipart.png)

#### 🏁 Flag 5 – The Payload

**Goal:** Find the new file that appeared in the web root after the exploit.

**My approach:** I already had a strong lead from Flag 3: the parse errors pointed to `/var/www/html/health-check.php`, and `/var/www/html` is the web root. To confirm it was the attacker's file, I checked who requested it and when it was first seen.

```kql
HartwellApache_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where URI has "health-check.php"
| summarize FirstSeen = min(OriginalTime), Hits = count() by SourceIP
| sort by FirstSeen asc
```

**What I found:** `health-check.php` is the webshell. The name was chosen to sound like a normal monitoring page so an admin looking at the folder wouldn't think twice about it.

**Answer:** `health-check.php`

![Flag 5: first requests to health-check.php](screenshots/flag05-webshell.png)

---

### Section 3: Remote Control (Execution)

#### 🏁 Flag 6 – The Operator

**Goal:** Find which Linux account the webshell ran commands as.

**My approach:** A webshell runs inside the web server, so its commands run as whatever account the web server uses. The brief says Apache runs as `www-data`. I confirmed it by looking at process creation events in Sysmon for that user.

```kql
HartwellSysmon_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where RuleName == "ProcessCreate" and User has "www-data"
| project OriginalTime, Image, CommandLine, ParentImage, User
| sort by OriginalTime asc
```

**What I found:** Commands like `id`, `whoami` and `uname` running as `www-data`, which should never happen on a normal web server. This mattered later, because www-data is a low privilege account.

**Answer:** `www-data`

![Flag 6: processes run as www-data](screenshots/flag06-www-data.png)

#### 🏁 Flag 7 – Hidden Trigger

**Goal:** Find the custom HTTP header the webshell used to receive commands.

**My approach:** A basic webshell takes commands in the URL, like `?cmd=whoami`, and those would show up plainly in the access log. I didn't see anything like that, so the commands had to be hidden somewhere else. Going through the data dictionary, the enriched HTTP log had two unusual columns: `x_hmg_debug_raw` ("Raw X-HMG-Debug header value (encoded)") and `x_hmg_debug_decoded` ("Decoded X-HMG-Debug command"). I pulled the rows where that header had a value.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where isnotempty(x_hmg_debug_raw)
| project OriginalTime, x_hmg_debug_raw, x_hmg_debug_decoded
| sort by OriginalTime asc
```

**What I found:** Every webshell command came in through a header called `X-HMG-Debug`. The name sounds like a harmless debug setting. Apache's access log doesn't record custom headers, so in the normal logs this just looks like ordinary requests to health-check.php. It only shows up in the HTTP log built from packet capture.

**Answer:** `X-HMG-Debug`

#### 🏁 Flag 8 – Encoded Orders

**Goal:** Identify the two encoding methods used on the commands, and the order they were applied in.

**My approach:** Using the same query as Flag 7, I compared the raw header value with the decoded command. The raw values like `ZmxmZ3J6KCJ2cSIpOw==` end in `=`, which is a classic sign of Base64. I decoded a few in Python to see what was underneath.

**What I found:** Base64 decoding `ZmxmZ3J6KCJ2cSIpOw==` gave `flfgrz("vq");`, which still wasn't readable. Each letter looked shifted, and shifting by 13 (ROT13) turned it into `system("id");`, matching the decoded column. `whoami` worked the same way.

So the attacker applied **ROT13 first, then Base64**, and the webshell reverses it. PHP has built-in functions for both (`str_rot13` and `base64_encode`), which is probably why they were chosen.

Detection idea: every command starts with `system(`, so every encoded header starts with the same string, `ZmxmZ3J6`. That's an easy thing to alert on.

**Answer:** `ROT13, Base64`

![Flag 8: raw vs decoded header values](screenshots/flag08-encoded-headers.png)

---

### Section 4: Mapping the Territory (Discovery)

At this point I realized the `x_hmg_debug_decoded` column was basically the attacker's full command history. So for the rest of the hunt, my main query was every decoded command in time order:

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where isnotempty(x_hmg_debug_decoded)
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

This returned 45 commands. The first one, `system("id");`, ran at 14:01:23 UTC.

![Decoded webshell commands](screenshots/flag10-12-webshell-commands.png)

#### 🏁 Flag 9 – Network Mapping

**Goal:** Identify the three network discovery commands.

**My approach:** In the full command list I spotted `ip a` and `ss -tlnp` early on, but I was only seeing the first 19 of 45 rows. Rather than scroll through everything, I filtered for common Linux networking commands.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has_any ("arp", "neigh", "route", "netstat", "ping", "ifconfig", "ip ", "ss ", "hosts", "nmap")
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

**What I found:** Four commands that answer three questions an attacker asks after getting in:

| Question | Command |
|---|---|
| What network am I on? | `ip a` / `ip addr show` (same command, short and long form) |
| Who else is around? | `ip neigh` |
| What services are listening? | `ss -tlnp` |

**Answer:** `ip addr, ss, ip neigh`

![Flag 9: network discovery commands](screenshots/flag09-network-discovery.png)

#### 🏁 Flag 10 – Monitoring Awareness

**Goal:** Find which security tools the attacker discovered on the host.

**My approach:** In the full command list (Section 4 query), I looked for anything that checked installed software or running processes.

**What I found:** At 14:02:57 UTC:

```
dpkg -l 2>/dev/null | grep -iE 'splunk|sysmon|auditd|wazuh|ossec' | head -10
```

The attacker searched the installed packages for five security tools. The question asks what they **found**, not what they searched for. The brief says this server runs Sysmon for Linux, auditd, and a Splunk Universal Forwarder. Wazuh and OSSEC aren't installed.

**Answer:** `sysmon, auditd, splunk`

---

### Section 5: Credential Harvest (Credential Access)

#### 🏁 Flag 11 – The Config File

**Goal:** Find which config file the attacker read to get database credentials.

**My approach:** WordPress stores its database login in `wp-config.php`. I checked the full command list (Section 4 query) for anything touching it.

**What I found:** Between 14:03 and 14:08 UTC the attacker read `/var/www/html/wp-config.php` several different ways: `grep -E 'DB_|TABLE_PREFIX'`, `ls -la`, `head -5`, `grep DB_`, and `grep -i AUTH`. That file has the database name, username, password, and the WordPress auth keys.

**Answer:** `wp-config.php`

#### 🏁 Flag 12 – The Database Dump

**Goal:** Name the table they dumped and the column holding the password hashes.

**My approach:** Once an attacker has the database password, the next step is querying the database. I looked for `mysql` commands in the same command list.

**What I found:** Right after reading the config, they logged in with the stolen credentials and ran:

```
mysql -u wpuser wordpress -e "SELECT user_login,user_pass FROM wp_users"
```

`wp_users` is the WordPress users table, and `user_pass` holds the password hashes. They also ran a second query for usernames, emails, and signup dates.

**Answer:** `wp_users, user_pass`

---

### Section 6: Fighting the Watchers (Defense Evasion)

#### 🏁 Flag 13 – Targets for Silence

**Goal:** Find the three monitoring services the attacker tried to stop with systemctl.

**My approach:** After finding the monitoring tools in Flag 10, I expected the attacker to try turning them off. Service names can differ from tool names (Splunk's service is `SplunkForwarder`), so I needed the exact commands.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has_any ("systemctl", "service ", "kill", "stop")
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

**What I found:**

| Time (UTC) | Command |
|---|---|
| 14:13:21 | `systemctl list-units --type=service --state=running` (list what's running) |
| 14:14:01 | `systemctl stop sysmon` |
| 14:14:07 | `systemctl stop SplunkForwarder` |
| 14:14:14 | `systemctl is-active sysmon auditd SplunkForwarder` (check if it worked) |

**Answer:** `sysmon, auditd, SplunkForwarder`

![Flag 13: systemctl stop attempts](screenshots/flag13-systemctl-stop.png)

#### 🏁 Flag 14 – Success or Failure

**Goal:** Decide whether the attacker managed to disable any monitoring, and why.

**My approach:** I thought about who ran the commands. Everything ran as `www-data` (Flag 6). Stopping a system service on Debian needs root, and www-data is a normal low privilege account with no sudo.

Then I checked whether the logs agreed. If Sysmon and auditd had really stopped at 14:14, there would be a gap in the logs afterward. Instead, the activity kept getting logged, including the implant being staged at 14:15:49 and the cron job at 14:16:00 (Flags 15 and 16). So the monitoring never stopped.

**Answer:** No. The www-data account does not have root privileges, so it lacked permission to stop the services with systemctl and all monitoring kept running.

**Note:** My first answer had the same idea in different words and was marked wrong. Spelling out "root privileges" and "permission" got it accepted.

---

### Section 7: Digging In (Persistence)

#### 🏁 Flag 15 – The Scheduled Callback

**Goal:** Identify the persistence mechanism.

**My approach:** The question mentions "scheduling recurring execution." On Linux that almost always means cron. I searched the decoded commands for cron activity and for common hiding places for files.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has_any ("/dev/shm", "cron", "chmod")
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

**What I found:** At 14:16:00 UTC the attacker added a crontab entry: `*/5 * * * * /dev/shm/.cache-helper 300`. That runs the file every 5 minutes, so even if someone deletes the webshell, the attacker's program keeps running.

**Answer:** `cron job`

![Flags 15 and 16: implant copy and crontab entry](screenshots/flag15-16-cron-implant.png)

#### 🏁 Flag 16 – Hidden Implant

**Goal:** Find the full path of the implant and explain why the location matters.

**My approach:** Same query as Flag 15. The cron job pointed to the file, and the command right before it showed how the file got there.

**What I found:** At 14:15:49 UTC:

```
cp /usr/bin/sleep /dev/shm/.cache-helper && chmod +x /dev/shm/.cache-helper
```

Why the location matters:

- `/dev/shm` is stored in **RAM, not on disk**. If the server reboots or gets shut down for investigation, the file disappears, and a disk image taken afterward won't have it.
- The dot at the start of `.cache-helper` hides it from a normal `ls`.
- "cache-helper" sounds like something that belongs on a server.

Something interesting: the "implant" is just a copy of `/usr/bin/sleep`, a harmless built-in program. It looks like the attacker was testing that the cron persistence works before swapping in a real payload.

**Answer:** `/dev/shm/.cache-helper`

---

### Section 8: Damage Assessment (Synthesis)

#### 🏁 Flag 17 – Data Out

**Goal:** Describe how the stolen data left the server.

**My approach:** I thought about what channel the attacker already had. They didn't need a new one, since the webshell already sends them the output of every command. I searched the decoded commands for encoding that would make data easy to copy out.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where x_hmg_debug_decoded has "base64"
| project OriginalTime, x_hmg_debug_decoded
| sort by OriginalTime asc
```

**What I found:** The attacker base64-encoded the stolen data and had the webshell print it back in its HTTP response. They didn't upload anything anywhere or open a new connection. It all went out through the same web traffic they were already using, which is harder to notice.

**Answer:** The attacker base64 encoded the wp-config.php contents and database records and pulled them back out in the HTTP responses of the existing health-check.php webshell, so no separate exfiltration channel was used.

![Flag 17: base64 exfiltration commands](screenshots/flag17-base64-exfil.png)

#### 🏁 Flag 18 – Lateral Movement Check

**Goal:** Test a colleague's claim that the attacker moved to other systems on 192.168.1.0/24.

**My approach:** Instead of assuming the claim was true, I tested it. Moving to another machine on Linux usually means tools like ssh, scp, rsync, or netcat. I searched every decoded command for them.

```kql
HartwellHTTPEnriched_CL
| where OriginalTime between (datetime("2026-10-23 04:00") .. datetime("2026-10-23 16:00"))
| where isnotempty(x_hmg_debug_decoded)
| where x_hmg_debug_decoded has_any ("ssh", "scp", "rsync", "nc ")
| project OriginalTime, x_hmg_debug_decoded
```

**What I found:** Nothing. The attacker looked at the neighbor table with `ip neigh` but never connected to another machine. All their activity stayed on 192.168.1.120.

**Answer:** No, the logs only show local discovery like ip neigh with no ssh, scp, nc or connections to other hosts, so all activity stayed on 192.168.1.120.

![Flag 18: no lateral movement commands found](screenshots/flag18-no-lateral-movement.png)

---

## 🕒 Attack Timeline (UTC, 23 Oct 2026)

| Time | Activity |
|---|---|
| Morning | Nmap scan and user agent rotation from 192.168.1.100 |
| 08:18 onward | Session upload progress exploit attempts (PHP session warnings in the error log) |
| Before 14:01 | Webshell `health-check.php` dropped in `/var/www/html` |
| 14:01:23 | First webshell command: `id` |
| 14:01 to 14:02 | System and user discovery (`whoami`, `uname -a`, `hostname`, `os-release`) |
| 14:02:18 to 14:02:28 | Network discovery (`ip a`, `ss -tlnp`) |
| 14:02:39 to 14:02:54 | `/etc/passwd`, `ps aux`, attempted `/etc/shadow` read |
| 14:02:57 | Checked for Splunk, Sysmon, auditd, Wazuh, OSSEC |
| 14:03 to 14:08 | Read wp-config.php, dumped `wp_users` (usernames and password hashes) |
| 14:12:49 to 14:12:57 | More network discovery (`ip addr show`, `ip neigh`) |
| 14:14:01 to 14:14:14 | Tried to stop sysmon and SplunkForwarder, checked status (failed) |
| 14:15:49 | Staged `/dev/shm/.cache-helper` |
| 14:16:00 | Added cron job running the implant every 5 minutes |

## 🧠 Summary Table

| Flag | Description | Value |
|---|---|---|
| 1 | Scanner IP | 192.168.1.100 |
| 2 | Recon tool | Nmap |
| 3 | Exploited PHP feature | session.upload_progress |
| 4 | Exploit signature | POST, multipart/form-data |
| 5 | Webshell | health-check.php |
| 6 | Execution account | www-data |
| 7 | Webshell trigger header | X-HMG-Debug |
| 8 | Command encoding | ROT13, then Base64 |
| 9 | Network discovery | ip addr, ss, ip neigh |
| 10 | Monitoring found | sysmon, auditd, splunk |
| 11 | Credential file | wp-config.php |
| 12 | Data dumped | wp_users, user_pass |
| 13 | Services targeted | sysmon, auditd, SplunkForwarder |
| 14 | Evasion outcome | Failed (no root) |
| 15 | Persistence | Cron job |
| 16 | Implant path | /dev/shm/.cache-helper |
| 17 | Exfiltration | Base64 in webshell HTTP responses |
| 18 | Lateral movement | None found |

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Reconnaissance | T1595 Active Scanning / T1595.002 Vulnerability Scanning | Nmap NSE and rotating user agents |
| Initial Access | T1190 Exploit Public-Facing Application | session.upload_progress exploit |
| Persistence | T1505.003 Web Shell | health-check.php |
| Execution | T1059.004 Unix Shell | `system()` commands as www-data |
| Defense Evasion | T1027 Obfuscated Files or Information | ROT13 + Base64 in X-HMG-Debug |
| Discovery | T1016 System Network Configuration Discovery | ip addr, ss, ip neigh |
| Discovery | T1518.001 Security Software Discovery | dpkg grep for monitoring tools |
| Credential Access | T1555 Credentials from Password Stores | wp-config.php, wp_users dump |
| Defense Evasion | T1562.001 Disable or Modify Tools | systemctl stop (failed) |
| Persistence | T1053.003 Cron | `*/5` crontab running the implant |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Base64 data returned through the webshell |

## 🧾 Indicators of Compromise

| Type | Value |
|---|---|
| IP | 192.168.1.100 |
| File | /var/www/html/health-check.php |
| File | /dev/shm/.cache-helper |
| HTTP header | X-HMG-Debug |
| Multipart boundary | ----0x4148php2shell |
| User agent | Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html) |
| Encoded prefix | ZmxmZ3J6 (Base64 of ROT13 `system(`) |
| Cron entry | `*/5 * * * * /dev/shm/.cache-helper 300` |

## 🛡️ Recommended Response Actions

- Block 192.168.1.100 at the firewall
- Remove `health-check.php`, delete `/dev/shm/.cache-helper`, and clear the www-data crontab
- Patch PHP for the session.upload_progress vulnerability, or turn off `session.upload_progress.enabled` until it's patched
- Rotate the WordPress database password and the auth keys and salts in wp-config.php
- Force a password reset for every WordPress user, since their hashes were dumped
- Add detections for the `X-HMG-Debug` header or any header value starting with `ZmxmZ3J6`, www-data spawning shells, and new files in `/dev/shm`
- Since this is a healthcare organization, treat it as a possible data breach and involve whoever handles breach notification

## 📘 Lessons Learned

- **Standard access logs miss a lot.** The webshell's commands were hidden in a custom header, so they only showed up in the HTTP log built from packet capture, not in Apache's access log.
- **Least privilege worked.** Because Apache runs as www-data, the attacker couldn't shut off the monitoring, and that's why I could see everything they did afterward.
- **Test claims, don't assume them.** The lateral movement theory sounded believable, but the logs didn't support it.
- **Summarize before you scroll.** Switching from listing every row to `summarize count() by Message` turned 75+ cut-off error lines into a handful of clear patterns.
- **Setup matters.** Most of my time early on went to "Failed to resolve table" errors from being in the wrong workspace. Checking the resource group and using KQL mode fixed it.
