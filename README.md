# RDP Brute Force Detection Lab

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing  
**Detection Severity:** Level 10 — Critical  
**Time to Credential Compromise:** 4 seconds  
**Outcome:** Detected ✅ | Credential compromised ✅ | Detection gap found ✅

---

## Why I built this

The question I wanted to answer was simple: if someone hammered my Windows Server with repeated RDP login attempts, would my SIEM actually catch it — or would it just sit there silently while an attacker found the right password?

I didn't want to assume detection worked. I wanted to prove it, or find out where it broke.

So I set up a controlled brute force attack from my Kali machine against my Windows Server 2019 endpoint, watched what Wazuh logged in real time, and investigated every alert like a Tier-1 SOC analyst would at 2am when something fires.

What I found was more interesting than a clean detection story. The SIEM caught it — but only after the attacker already had the password. And the network IDS (Suricata) didn't catch it at all. Those gaps matter more than the detection itself.

---

## Lab environment

| Machine | Role | IP |
|---|---|---|
| Ubuntu 24.04 + Wazuh Manager | SIEM — receives and correlates all alerts | 10.0.2.4 |
| Windows Server 2019 + Wazuh Agent + Sysmon | Target endpoint | 10.0.2.6 |
| Kali Linux + Wazuh Agent | Attack machine | 10.0.2.5 |

All three VMs run on a VirtualBox NAT Network (`10.0.2.0/24`). They can reach each other but are isolated from my actual home network.

**One thing worth flagging:** Kali is enrolled as a Wazuh agent in this lab. In a real SOC environment, the attacker's machine would never be monitored by the defender's SIEM. This is a known lab constraint — I've documented it here rather than hiding it.

**Timezone note:** Kali ran on EDT (UTC-4). Wazuh Manager ran on UTC. Every Kali timestamp + 4 hours = Wazuh log timestamp. This caused a genuine investigation confusion I'll explain in the findings.

---

## What I set out to test

1. Would Wazuh detect repeated RDP authentication failures in real time?
2. Would a successful credential compromise generate a different alert from the failures?
3. Would Suricata (network IDS) catch what Wazuh (host-based SIEM) caught — or would one layer miss what the other found?
4. What does the evidence actually look like inside the raw logs, not just on the dashboard?

---

## How I did it

### Before touching anything — lab verification

First thing I did was confirm the lab was actually working before simulating any attack. A common mistake is running the attack, seeing no alerts, and assuming detection failed — when really an agent was disconnected or a port was closed.

```bash
# Check all Wazuh agents are active
sudo /var/ossec/bin/agent_control -l
```

Output confirmed Ubuntu (server), Kali, and Windows-agent all showing **Active**.

Then I checked whether RDP was actually reachable from Kali:

```bash
nmap -p 3389 10.0.2.6
```

First result: `3389/tcp filtered`. Windows Firewall was silently dropping RDP packets before they even reached the service. Hydra attacking a filtered port would generate zero Windows logs and zero Wazuh alerts — and I would have had no idea why.

Fixed it on Windows Server:

```powershell
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
net localgroup "Remote Desktop Users" "Administrator" /add
```

After fix: `3389/tcp open`. Now we're actually talking to the service.

### Building the wordlist

I created a 16-password wordlist on Kali with the correct Administrator password placed at position 8 — not first, not last. The goal was to generate a realistic pattern of failures before Hydra found the valid credential.

```bash
cat ~/rdp_wordlist.txt
```

![Attack setup — wordlist and Hydra command](Screenshots/02_attack_setup.png)

### First attack — and what went wrong

```bash
hydra -t 4 -V -f -l Administrator -P ~/rdp_wordlist.txt rdp://10.0.2.6
```

This run hit repeated `freerdp: The connection failed to establish` errors. The Administrator account existed but wasn't enabled for Remote Desktop sessions yet. Hydra identified the password as probably valid but couldn't confirm it.

Here's what made this interesting: those NLA-layer failures left **no trace in Windows event logs**. No Event ID 4625. No failed logon entries. No Wazuh alerts. An attacker whose tool hits NLA errors walks away without leaving a single authentication failure in the SIEM.

That's a real detection gap — and I only found it because the first run failed.

### Second attack — confirmed compromise in 4 seconds

After adding Administrator to the Remote Desktop Users group, I ran the attack again:

```bash
hydra -t 4 -V -f -l Administrator -P ~/rdp_wordlist.txt rdp://10.0.2.6
```

Result at `07:44:43` Kali time (`11:44:43` UTC):

```
[3389][rdp] host: 10.0.2.6   login: Administrator   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-06-24 07:44:43
```

4 seconds. That's how long it took to go from first attempt to confirmed valid credential against an Administrator account with no lockout policy.

### Investigating what Wazuh captured

I went to the Wazuh alert archive — not the live log, because the attack happened the previous day and `alerts.log` had already rotated:

```bash
sudo grep -A 5 "60204" /var/ossec/logs/alerts/2026/Jun/ossec-alerts-23.log | head -20
sudo grep -A 8 "92657" /var/ossec/logs/alerts/2026/Jun/ossec-alerts-23.log | head -30
```

![Wazuh dashboard showing attack alerts](Screenshots/03_wazuh_dashboard.png)

![Rule 60204 — brute force correlation alert](Screenshots/04_rule_60204_raw_log.png)

![Rule 92657 — successful logon detection](Screenshots/05_rule_92657_logon.png)

![Event timeline — chronological alert sequence](Screenshots/06_event_timeline.png)

---

## What the logs actually showed

### The full attack sequence (UTC)

| Time (UTC) | Event ID | Rule | Level | What happened |
|---|---|---|---|---|
| 11:44:39.822 | 4625 | 60122 | 5 | Logon failure #1 from 10.0.2.5 |
| 11:44:39.836 | 4625 | 60122 | 5 | Logon failure #2 |
| 11:44:39.869 | 4625 | 60122 | 5 | Logon failure #3 |
| 11:44:40.018 | 4625 | 60122 | 5 | Logon failure #4 |
| 11:44:40.020 | 4625 | 60122 | 5 | Logon failure #5 |
| 11:44:41.976 | 4625 | 60122 | 5 | Logon failure #6 |
| 11:44:42.098 | 4625 | 60122 | 5 | Logon failure #7 |
| 11:44:42.135 | 4624 | 92657 | 6 |  Administrator logged in from kali (10.0.2.5) |
| 11:44:42.135 | 4672 | 67028 | 3 | Full admin privileges assigned to new session |
| 11:44:42.195 | 4625 | 60204 | 10 |  Multiple Windows Logon Failures — BRUTE FORCE |
| 11:44:42.562 | 4005 | 60602 | 9 | Windows logon process unexpectedly terminated |

### Detection numbers

| What we measured | Count |
|---|---|
| Individual logon failure alerts (Rule 60122) | 26 |
| Brute force correlation alerts (Rule 60204) | 3 |
| Successful remote logon alerts (Rule 92657) | 5 |
| Total attacker events indexed from 10.0.2.5 | 114 |
| Suricata alerts during the entire attack | **0** |

---

## Findings

### Finding 1 — The SIEM caught it, but 60 milliseconds too late

Rule 60204 (Multiple Windows Logon Failures, level 10 critical) fired at `11:44:42.195`.

The successful login happened at `11:44:42.135`.

The brute force alert fired **60 milliseconds after the attacker already had valid credentials.**

Detection worked — but it was reactive, not preventive. The alert tells you someone broke in. It doesn't stop them from breaking in. That's why account lockout policies and MFA matter alongside detection rules. Detection without prevention just means you know you got hit.

### Finding 2 — The first attack left no trace at all

During the first Hydra run, NLA (Network Level Authentication) rejected connections before credentials were even exchanged. No Event ID 4625. No Wazuh alert. Zero entries in the SIEM.

An attacker who only hits NLA errors walks away clean. From the SIEM's perspective, nothing happened. This is a real blind spot in host-based detection — it only sees what Windows logs, and Windows doesn't log NLA-layer rejections as authentication failures.

### Finding 3 — Suricata heard nothing

Suricata was running. Confirmed active. Generated zero alerts.

![Suricata running but silent during the attack](![](Screenshots/07_suricata_silence.png.png)

RDP traffic is encrypted at the network layer. Suricata sees the packets but cannot read the credential payload inside them. Hydra's rapid connection attempts also look like normal RDP connection setup at the packet level — without a volume-based rule tuned specifically for this pattern, Suricata stays silent.

This is not a bug. It's a coverage gap by design. Host-based detection (Wazuh reading Windows event logs) caught what network-based detection (Suricata inspecting packets) could not. You need both layers because each catches things the other misses.

### Finding 4 — The logon type tells a second story

The successful logon shows `logonType: 3` — network authentication. Not `logonType: 10` which would be a full interactive RDP desktop session.

Hydra validated the credential but never opened a desktop. A real attacker would follow this with a proper RDP client to actually sit at the machine — and that would generate a Type 10 event. The absence of Type 10 here means credential theft was confirmed but active session was not established. In production, a Tier-1 analyst escalates the moment they see Type 3 from an unknown workstation named "kali" hitting a privileged account at 7am.

### Finding 5 — Timezone mismatch almost buried the evidence

Kali's clock was on EDT. Wazuh Manager was on UTC. Four-hour gap.

When I first searched Wazuh for the attack at `07:44`, I found nothing. Because in Wazuh's world, that attack happened at `11:44`. An analyst who doesn't know about timezone misalignment looks at the wrong window and writes "no evidence of attack" in the incident report.

The fix is simple — align all machines to UTC. But finding this the hard way during investigation made it a lesson I won't forget.

### Finding 6 — Sysmon added a third evidence layer

Three instances of `smss.exe` spawned at level 12 severity during the attack. `smss.exe` is the Windows Session Manager — it creates a new instance for every RDP session. Three spawns in 4 seconds means Hydra's parallel threads were each partially establishing RDP sessions before disconnecting.

Sysmon caught process-level evidence that the Security event log alone would have under-reported. This is why Sysmon matters in endpoint detection — it sees what the OS-level logs miss.

---

## What I'd do differently (and what comes next)

**The immediate gap to fix:** No account lockout policy. An attacker with a wordlist and patience can try thousands of passwords against this server with zero consequences. Locking the account after 5 failed attempts and alerting on Event ID 4740 (account lockout) would stop the attack at attempt 5 — not attempt 11.

**The next detection to build:** A custom Wazuh active response rule that automatically blocks the source IP the moment Rule 60204 fires. Detection without automated response means a human has to be watching the dashboard 24/7 to act on the alert.

**For Suricata:** Write a custom rule that counts RDP connection attempts from a single source IP within a 10-second window and fires when the count exceeds 5. That would catch what the encrypted payload inspection cannot.

**For investigation:** Before closing any brute force alert, always check:
1. Did any Logon Type 10 (full RDP session) follow the Type 3 network logon?
2. What processes spawned after authentication? (Sysmon Event ID 1)
3. Is the source IP a known asset? Is it authorised for RDP access to this server?
4. Escalate to Tier-2 if a full session was established — potential lateral movement investigation required.

---
Repository structure

rdp-brute-force-detection-lab/
├── README.md                        ← You are here
├── Screenshots/
│   ├── 01_lab_architecture.png      ← VirtualBox — all VMs running
│   ├── 02_attack_setup.png          ← Hydra command + wordlist
│   ← 03_wazuh_dashboard.png        ← Security Events dashboard
│   ├── 04_rule_60204_raw_log.png    ← Brute force correlation alert raw log
│   ├── 05_rule_92657_logon.png      ← Successful logon detection
│   ├── 06_event_timeline.png        ← Chronological alert sequence
│   └── 07_suricata_silence.png      ← Detection gap evidence
└── evidence/
    └── alert_timeline.txt           ← Raw grep output from ossec-alerts-23.log


## MITRE ATT&CK mapping

| Technique | ID | What was observed |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | 16-entry wordlist against RDP port 3389 |
| Valid Accounts | T1078 | Administrator credentials successfully validated via NTLM |
| Remote Services: RDP | T1021.001 | Port 3389 used as the attack vector |

---

## Tools used

- **Hydra v9.6** — password brute force tool (attack simulation)
- **Wazuh 4.x** — SIEM and alert correlation engine
- **Suricata** — network IDS/IDP (detection gap validation)
- **Sysmon** — Windows endpoint process monitoring
- **Nmap** — pre-attack port verification
- **VirtualBox** — lab virtualisation

---

*Project 3 of 10 — SOC Home Lab Detection Series
