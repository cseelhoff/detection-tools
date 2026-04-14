# Detection Tools

A comprehensive endpoint detection and response (EDR) toolkit for Windows and Linux environments. Remotely collects system state snapshots from target hosts via PSRemoting (Windows) and SSH (Linux), stores them in a PostgreSQL database, provides tooling to diff snapshots over time to detect changes, and includes a YAML-playbook-driven response framework for executing remediation actions at scale.

## Problem

In defensive cyber operations (DCO) / hunt missions, operators need to:

1. **Baseline and monitor endpoint state** — Know what's running, what's persisting, who's logged in, and what network connections exist across every machine in the environment.
2. **Detect changes over time** — Compare snapshots to spot new autoruns entries, new processes, new user accounts, or new network connections that could indicate compromise.
3. **Identify persistence mechanisms** — Autoruns (services, scheduled tasks, drivers, etc.) are a primary way attackers maintain access. Cataloging them across every host and flagging unique/rare ones surfaces anomalies.
4. **Assess security posture** — Inventory Defender exclusions, ASR rules, audit policies, credential protection settings, firewall rules, and security product health — detect weakening or misconfiguration.
5. **Respond quickly** — Once threats are identified, operators need to kill processes, remove files, disable accounts, rotate credentials, adjust firewall rules, and remove persistence entries across multiple hosts rapidly.

Commercial EDR tools may not be available in all environments (air-gapped networks, exercise environments, etc.), so a lightweight, script-based approach is needed.

## Solution

This toolkit automates the full cycle:

1. **Collect** — PSRemote into Windows hosts and SSH into Linux hosts, gather comprehensive system state (~60 data categories per host), and save as JSON.
2. **Store** — Import collected JSON snapshots into a PostgreSQL database with a relational schema, enabling SQL-based analysis.
3. **Analyze** — Use SQL queries/views to diff snapshots, count autorun frequency across hosts, and surface outliers.
4. **Respond** — Use the response toolkit (`respond.ps1`) to execute response actions from YAML-driven playbooks with full audit logging, dry-run mode, and safe credential rotation.

## Data Collected Per Host

### Windows (collect-snapshots.ps1)

| Category | Details |
|---|---|
| **Computer Info** | Hostname, domain, manufacturer, model, OS version, last boot time |
| **Disk Volumes** | Drive letters, types, sizes, file systems |
| **Network Adapters** | MAC addresses, status, physical media type, DNS settings |
| **IP Addresses** | All addresses with prefix length, address family, type |
| **DNS Servers** | Per-interface DNS server addresses |
| **DNS Search Suffixes** | Per-interface suffix search lists |
| **DNS Cache** | Cached DNS entries (C2/recon detection) |
| **ARP Cache** | IP-to-MAC mappings and state |
| **Routes** | Routing table with destination, next hop, metric |
| **TCP Connections** | Local/remote address:port, owning process, state |
| **UDP Endpoints** | Local/remote address:port, owning process |
| **Processes** | Name, user, PID, parent PID, command line, executable path |
| **Local Users** | Name, enabled, last logon, password last set, SID |
| **Local Groups** | Name, SID |
| **Group Membership** | User SID to Group SID mappings |
| **SMB Shares** | Name, path, scope |
| **Security Products** | AV/Firewall/AntiSpyware from SecurityCenter2 WMI with product state decoding |
| **Defender Status** | Real-time protection, behavior monitor, signatures, tamper protection, running mode |
| **EDR Services** | Known EDR service detection (CrowdStrike, Carbon Black, SentinelOne, Tanium, etc.) |
| **Firewall Profiles** | Per-profile enabled state, default actions, logging config |
| **Firewall Rules** | All enabled rules with direction, action, profile |
| **Logged-On Users** | Console, RDP, and disconnected sessions (query user) |
| **WinRM Sessions** | Active PSRemoting shells with owner and client IP |
| **SSH Sessions** | OpenSSH sshd process connections |
| **Security Policy** | secedit export: System Access, Registry Values, Privilege Rights |
| **Audit Policies** | auditpol: all advanced audit subcategories and inclusion settings |
| **Domain Controller** | Auto-detection (DomainRole ≥ 4) with AD queries when true |
| **Domain Users** | Name, UPN, enabled, logon, password info, MemberOf, SID (DC only) |
| **Domain Service Accounts** | MSAs and gMSAs (DC only) |
| **Domain Groups** | Name, scope, category, SID (DC only) |
| **Domain Computers** | Name, DNS, OS, last logon, IPv4, SID (DC only) |
| **Domain Group Memberships** | All group→member mappings (DC only) |
| **GPOs** | All GPOs with full XML reports (DC only) |
| **Autoruns** | Entry location, signer, image path, hashes (MD5/SHA1/SHA256), launch string |
| **User Executables** | Executables (.exe, .bat, .ps1, .msi, etc.) under user profile directories |
| **NTFS File Inventory** | MFT-based fast scan of all files on the system drive (WizTree-style) |
| **Registry Watchlist** | ~65 security-critical keys: Defender exclusions, UAC, LSASS protection, WDigest, CredSSP, RDP, WinRM, SMB signing, event log config, PS logging, proxy, audit policy |
| **Environment Variables** | All environment variables |
| **Installed Applications** | All software from Uninstall registry with version, publisher, install date |
| **Scheduled Tasks** | Non-Microsoft tasks with actions, run-as, state |
| **Third-Party Services** | Non-Microsoft services with binary path, company, start account |
| **Third-Party Drivers** | Non-Microsoft kernel drivers (BYOVD detection baseline) |
| **Named Pipes** | All named pipes (C2 framework detection baseline) |
| **Credential Guard Status** | VBS, Credential Guard configured/running (WMI) |
| **ASR Rules** | Attack Surface Reduction rules, status, and exclusions |
| **LAPS Detection** | LAPS DLL and policy presence |
| **AppLocker Policy** | Effective AppLocker policy as XML |
| **WEF Config** | Windows Event Forwarding subscription manager |
| **PS Session Configs** | WinRM plugin SDDLs (who can remote in) |
| **AMSI Providers** | Registered AMSI provider CLSIDs resolved to DLL paths |
| **Certificates** | Certs with private keys, EKU, template (AD CS abuse surface) |
| **Cloud Environment** | AWS/Azure/GCP detection |
| **Cached Credentials** | cmdkey /list output |
| **AutoLogon** | Winlogon auto-logon credentials |
| **AlwaysInstallElevated** | HKLM + HKCU elevation policy |
| **Point-and-Print** | PrintNightmare policy settings |
| **.NET Versions** | Framework versions (AMSI support assessment) |
| **Sysmon Config** | Hashing algorithm, options |
| **WSL Distributions** | Installed WSL distros |
| **Container Detection** | Running inside a container check |
| **SAM/SYSTEM Backups** | Backup file presence and size |
| **Unattend Files** | Sysprep/unattend credential file presence |
| **Printers** | Installed printers with driver info |
| **Token Privileges** | Current token privileges (SeDebug, SeImpersonate, etc.) |
| **Installed Hotfixes** | All patches with KB, description, install date |
| **Saved RDP Connections** | Saved RDP server history with username hints |
| **PuTTY Sessions** | Saved PuTTY/SSH session configurations |
| **PowerShell History** | Last 200 lines per user (credential leak detection) |
| **Recent Events** | Last 100 logons (4624), 50 failed logons (4625), 50 process creation (4688), 50 ScriptBlock (4104) |
| **DPAPI Keys** | Master key and credential file inventory |
| **WiFi Profiles** | Saved wireless network names |
| **Mapped Drives** | Network drive mappings |
| **Hosts File** | DNS override entries |
| **Service Binary ACLs** | SDDL for every service executable (offline priv-esc analysis) |
| **Task Binary ACLs** | SDDL for scheduled task executables |
| **PATH Directory ACLs** | SDDL for each PATH directory (hijacking analysis) |
| **Named Pipe ACLs** | SDDL for named pipes (impersonation analysis) |
| **Share ACLs** | SMB share permissions |
| **Home Directory ACLs** | SDDL for user home directories |

### Linux (linux-collector.py)

| Category | Details |
|---|---|
| **System UUID** | DMI product UUID |
| **Computer Info** | Hostname, FQDN, domain, OS, kernel, CPU, memory, manufacturer, model |
| **Disk Volumes** | lsblk or df output with filesystem type, size, mount points |
| **Network Adapters** | Interface name, MAC, state, MTU, flags |
| **IP Addresses** | All addresses with prefix, family, scope |
| **DNS Config** | resolv.conf nameservers and search domains |
| **ARP Cache** | IP-to-MAC mappings |
| **Routes** | Full routing table |
| **TCP/UDP Connections** | All connections with owning process |
| **Processes** | PID, PPID, user, status, CPU/mem, command line, exe path (/proc) |
| **Users** | /etc/passwd + /etc/shadow (password status, fingerprint for change detection, aging) + lastlog |
| **Groups** | /etc/group with members |
| **Members** | Full user-to-group mapping (supplementary + primary) |
| **Shares** | NFS exports + Samba shares |
| **Security Products** | ClamAV, CrowdStrike, Carbon Black, SentinelOne, Tanium, Wazuh, OSSEC, Elastic, Sophos, McAfee, Trend Micro, Cylance detection |
| **Logged-In Users** | who, SSH connections, loginctl sessions |
| **Audit Config** | auditctl rules, auditd.conf, auditd status |
| **PAM Config** | All /etc/pam.d files + /etc/login.defs |
| **Persistence** | systemd services/timers, cron (system + user + periodic), at jobs, rc.local, init.d, profile.d, ld.so.preload, XDG autostart |
| **SSH Authorized Keys** | All users' authorized_keys |
| **SSH Config** | sshd_config hardening settings, host keys, agent sockets, TCP wrappers |
| **Kernel Modules** | lsmod output |
| **Installed Packages** | dpkg/rpm/pacman/apk |
| **User Executables** | Executable files under /home + /root |
| **File Inventory** | find -printf on all local mounts |
| **Sudoers** | /etc/sudoers + sudoers.d |
| **SUID/SGID Binaries** | All setuid/setgid files with permissions |
| **File Capabilities** | getcap -r / (cap_setuid, cap_sys_admin, etc.) |
| **Docker Containers** | docker ps -a |
| **Firewall Rules** | iptables, nftables, firewalld, ufw |
| **SELinux/AppArmor** | Security module status |
| **Hosts File** | /etc/hosts entries |
| **Environment Variables** | All env vars |
| **Kernel Hardening** | ASLR, kptr_restrict, ptrace_scope, dmesg_restrict, symlink/hardlink protection, seccomp, lockdown, BPF, userns, virtualization |
| **Container Info** | Container detection (Docker/Podman/K8s), runtime tools, socket writability, K8s tokens |
| **Cloud Environment** | AWS/Azure/GCP detection + credential file inventory |
| **Writable Critical Paths** | Writable PATH dirs, /etc/passwd, network-scripts, ld.so.conf paths |
| **Deleted Executables** | Running processes with deleted binaries (strong IOC) |
| **Fstab** | Mount options (nosuid/noexec/nodev gap detection) |
| **D-Bus Services** | busctl service inventory |
| **Unix Sockets** | Listening Unix sockets with owning process |
| **Privileged Groups** | Members of sudo/wheel/docker/lxd/disk/shadow + UID 0 users |
| **Kerberos Config** | krb5.conf, keytab files, cached AD hashes |
| **Attack Tools** | Offensive tool presence (nmap, gcc, gdb, john, hashcat, hydra, etc.) |
| **Sensitive Process Env** | /proc/*/environ scan for PASSWORD/SECRET/TOKEN vars across all processes |
| **inetd/xinetd Services** | Legacy service entries |
| **R-Commands Trust** | /etc/hosts.equiv and .rhosts files |
| **Terminal Sessions** | Active tmux/screen sessions |
| **Sudo Version** | CVE matching (Baron Samedit, etc.) |
| **Shell History** | Last 200 lines per user (credential leak detection) |
| **SSH Private Keys** | Private key file locations with permissions |
| **Interesting Hidden Files** | .env, .netrc, .pgpass, .my.cnf, .git-credentials, .kube/config, etc. |
| **Process Binary Permissions** | stat on every running process binary (offline writable-binary analysis) |
| **Systemd Unit Permissions** | Permissions on .service files (writable = persistence hijack) |
| **Cron Script Permissions** | Permissions on cron-referenced scripts |
| **ld.so.conf Permissions** | Library search path permissions (shared library injection) |

## Prerequisites

- **PowerShell 5.1+** with PSRemoting enabled on Windows target hosts
- **Sysinternals Autorunsc.exe** — placed in the working directory (automatically downloaded if missing)
- **Python 3.6+** on Linux targets (no dependencies beyond stdlib)
- **SSH access** to Linux targets (key-based or password)
- **PostgreSQL** database server (for storage/analysis)
- **Npgsql.dll** — .NET PostgreSQL driver (GAC-installed or local path)
- **sops + age** (optional, recommended) — for encrypted credential storage ([install sops](https://github.com/getsops/sops), [install age](https://github.com/FiloSottile/age))
- **Python 3 + Flask + Flask-SQLAlchemy** (optional, for the web UI)

## Configuration

### Inventory & Credentials

The toolkit uses a **YAML inventory file** that replaces the old `targetHosts.txt` with per-host credential support, group-based inheritance, and optional encryption for unattended scheduled runs.

**File resolution order** (scripts auto-discover):
1. `inventory.sops.yml` — SOPS-encrypted (preferred for production)
2. `inventory.yml` — plaintext (warns)
3. `targetHosts.txt` — legacy fallback (single-credential, prompts interactively)

#### Quick Start — Interactive (no setup)

Just list hostnames in `targetHosts.txt` and run. You'll be prompted for credentials:

```
dc01.domain.mil
web01.domain.mil
dbserver.domain.mil
```

When hosts have no stored credentials, the toolkit asks:

```
  ┌─────────────────────────────────────────────────┐
  │  Credentials needed for 3 host(s)               │
  └─────────────────────────────────────────────────┘
    - dc01.domain.mil
    - web01.domain.mil
    - dbserver.domain.mil

  Options:
    [1] Enter ONE set of credentials for ALL 3 hosts
    [2] Enter credentials individually per host
    [3] Skip these hosts
  Choice (1/2/3): 1

  Platform for these hosts:
    [1] Windows (WinRM/PSRemoting)
    [2] Linux (SSH with password)
    [3] Linux (SSH with key)
  Choice (1/2/3): 1
```

After successful collection, you're asked:
```
  Save these credentials for future unattended use? (y/N): y
  Saved credentials for 3 host(s) to inventory.yml
```

**Credentials that fail to connect are never saved.**

#### Inventory YAML — Per-Host Credentials

Create `inventory.yml` for multi-credential environments:

```yaml
credentials:
  domain-admin:
    type: winrm
    username: admin@domain.mil
    password: MyPassword123
  linux-root-key:
    type: ssh-key
    username: root
    key_file: ~/.ssh/id_ed25519
  linux-svc:
    type: ssh-password
    username: svc-account
    password: LinuxPass456

groups:
  windows-servers:
    credential: domain-admin
    platform: windows
  linux-servers:
    credential: linux-root-key
    platform: linux

hosts:
  dc01.domain.mil:
    group: windows-servers
  web01.domain.mil:
    group: windows-servers
  dbserver.domain.mil:
    group: linux-servers
  appserver.domain.mil:
    group: linux-servers
    credential: linux-svc          # override group default
  newhost.domain.mil:
    platform: linux                # no credential — prompts at runtime
```

**Credential inheritance**: host-level `credential` overrides group-level, which overrides interactive prompt.

**Auth types**:

| `type` | Platform | How it connects |
|---|---|---|
| `winrm` | Windows | PSCredential → `New-PSSession -ComputerName` |
| `ssh-password` | Linux | SSH with password |
| `ssh-key` | Linux | SSH with `-i key_file` |

#### Encrypted Credentials (SOPS + age) — Unattended Runs

For scheduled/automated collection without human interaction, encrypt the inventory with SOPS + age:

```bash
# 1. Install age and sops (one-time)
#    https://github.com/FiloSottile/age/releases
#    https://github.com/getsops/sops/releases

# 2. Generate an age key pair (one-time per operator/machine)
age-keygen -o age-key.txt
#   → Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# 3. Write your inventory in plaintext, then encrypt
sops --encrypt --age age1ql3z7hjy54pw... inventory.yml > inventory.sops.yml

# 4. Delete the plaintext version
rm inventory.yml

# 5. For scheduled runs, set the env var pointing to your age key:
export SOPS_AGE_KEY_FILE=./age-key.txt
```

The encrypted file is **safe to commit to git** — SOPS only encrypts values, leaving keys visible for review and diffs.

**Multiple operators**: List multiple age public keys as recipients when encrypting — any operator with their private key can decrypt.

**Never commit `age-key.txt`** — add it to `.gitignore`.

### config.json (Database)

```json
{
    "npgsqlPath": "C:\\path\\to\\Npgsql.dll",
    "connectionString": "Host=localhost;Username=postgres;Password=yourpassword;Database=postgres"
}
```

## Usage — Step by Step

### Step 1: Collect Snapshots

**Windows hosts:**
```powershell
.\collect-snapshots.ps1
```
Loads inventory → resolves per-host credentials → PSRemotes into each host (up to 10 concurrent) → deploys autorunsc.exe → collects all data → saves `system-info_<hostname>.json`.

Hosts without stored credentials are prompted interactively with the option to save for future use.

**Linux hosts:**
```bash
./collect-snapshots-linux.sh
```
Loads inventory → resolves per-host SSH credentials/keys → SSHes into each host → pipes `linux-collector.py` → saves `system-info_<hostname>.json`.

**Legacy mode** (still works):
```bash
SSH_USER=root SSH_KEY=~/.ssh/id_rsa ./collect-snapshots-linux.sh
```

### Step 2: Import to Database

```powershell
.\import-to-psql.ps1
```
Auto-creates tables from `table_definitions.json`, imports all JSON snapshots.

### Step 3: Analyze

Use the provided SQL files:
- **`WITH.sql`** — Diff latest vs. oldest autorunsc entries (new/removed persistence)
- **`CREATE VIEW system_snapshots_view AS.sql`** — Latest snapshot per system
- **`sql.sql`** — Autorun frequency analysis (rare = suspicious)
- **`schema-migration.sql`** — Maintenance scripts

Or run the **offline security analyzer** (PEASS-ng-style) directly against snapshot JSON files:

```bash
# Analyze all snapshots in current directory
python analyze-snapshots.py

# Analyze a specific host
python analyze-snapshots.py system-info_host1.domain.mil.json

# Disable colors (for logging/piping)
python analyze-snapshots.py --no-color

# Quick summary of all hosts
python analyze-snapshots.py --summary
```

This performs ~95% of the checks that winPEAS/linPEAS do (security products, Defender exclusions, ASR rules, credential protection, UAC, privilege escalation vectors, audit policies, logging gaps, firewall, persistence, ACL analysis, credential exposure, etc.) — entirely offline from the JSON snapshots, with colored output and MITRE ATT&CK technique IDs.

### Step 4: Respond

Create a YAML playbook and execute:

```powershell
# Dry run — preview actions without executing
.\respond.ps1 -PlaybookPath .\playbook.yml -WhatIf

# Execute with confirmation prompts
.\respond.ps1 -PlaybookPath .\playbook.yml

# Execute without prompts (scripted/automated)
.\respond.ps1 -PlaybookPath .\playbook.yml -Force
```

See `playbook-sample.yml` for a complete example covering all action types.

**Supported Response Actions:**

| Action | Windows | Linux | Description |
|---|---|---|---|
| `kill-process` | ✅ | ✅ | Kill by PID, name, or path |
| `disable-local-user` | ✅ | — | Disable local user account |
| `disable-domain-user` | ✅ | — | Disable AD user account |
| `disable-user` | — | ✅ | Lock user + set shell to nologin |
| `force-logoff` | ✅ | ✅ | Disconnect user sessions |
| `reset-local-password` | ✅ | — | Rotate local password (auto-generated, saved encrypted) |
| `reset-domain-password` | ✅ | — | Rotate AD password (auto-generated, must-change-at-logon) |
| `reset-password` | — | ✅ | Rotate Linux user password |
| `delete-file` | ✅ | ✅ | Delete a file |
| `quarantine-file` | ✅ | ✅ | Move to quarantine dir with hash rename |
| `collect-file` | ✅ | ✅ | Copy file to operator machine |
| `delete-scheduled-task` | ✅ | — | Remove a scheduled task |
| `disable-service` | ✅ | ✅ | Disable (and optionally stop) a service |
| `remove-persistence` | ✅ | — | Remove autorun via autorunsc |
| `remove-cron` | — | ✅ | Remove a cron entry |
| `remove-authorized-key` | — | ✅ | Remove an SSH authorized key |
| `registry-delete` | ✅ | — | Delete registry key or value |
| `registry-set` | ✅ | — | Set registry value |
| `firewall-block` | ✅ | ✅ | Block IP/port |
| `firewall-remove-rule` | ✅ | — | Remove a firewall rule |
| `firewall-unblock` | — | ✅ | Remove iptables block |
| `isolate-host` | ✅ | ✅ | Network isolation (allow management only) |
| `unisolate-host` | ✅ | ✅ | Remove network isolation |
| `set-audit-policy` | ✅ | — | Configure audit subcategory |
| `enable-ps-logging` | ✅ | — | Enable ScriptBlock + Module + Transcription logging |
| `set-event-log-size` | ✅ | — | Set event log maximum size |
| `block-hash` | ✅ | — | Block file hash via Defender |
| `set-sysctl` | — | ✅ | Set kernel parameter persistently |
| `enable-auditd-rule` | — | ✅ | Add auditd rule |
| `run-script` | ✅ | ✅ | Execute arbitrary script/command |

**Response features:**
- Full JSON-lines audit log (operator, timestamp, host, action, target, pre-state, result, duration)
- `-WhatIf` dry-run mode
- Confirmation prompts for destructive actions (skip with `-Force`)
- Credential rotation with secure encrypted output (never in playbook)
- Pre-action state capture for rollback reference

### Optional: Web UI

```bash
pip install flask flask-sqlalchemy psycopg2
python webserver.py
```

## AD Enumeration

`ad_query.ps1` enumerates Active Directory users and computers with group memberships via LDAP.

## Database Schema

The database uses a **serial ID schema** where `systemsnapshots` has an auto-incrementing `snapshotid` primary key. All child tables reference snapshots via a `snapshotid` foreign key. Table definitions are driven by `table_definitions.json` and auto-created by `import-to-psql.ps1`.

**Relational tables** (flat/tabular data imported to PostgreSQL):
`computerinfo`, `diskvolumes`, `netadapters`, `ipaddresses`, `dnsservers`, `dnssearchsuffixes`, `arpcache`, `routes`, `tcpconnections`, `udpconnections`, `processes`, `users`, `groups`, `members`, `shares`, `autorunsc`, `userexecutables`, `securityproducts`, `edrservices`, `firewallrules`, `loggedonusers`, `installedapps`, `scheduledtasks`, `thirdpartyservices`, `thirdpartydrivers`, `namedpipes`, `certificates`, `installedhotfixes`, `mappeddrives`, `servicebinaryacls`, `namedpipeacls`

**JSON-only fields** (complex/nested data stored in snapshot JSON, not normalized):
Registry snapshot, GPOs (XML), AppLocker policy (XML), ASR rules, security options, audit policies, Defender status, environment variables, recent events, DPAPI keys, PS history, credential guard status, Sysmon config, cloud environment, file inventory, and more.

## File Reference

| File | Purpose |
|---|---|
| **Core Pipeline — Windows** | |
| `collect-snapshots.ps1` | Collect system snapshots from Windows hosts via PSRemoting |
| `import-to-psql.ps1` | Import JSON snapshots into PostgreSQL |
| `config.json` | Database connection and Npgsql path configuration |
| `table_definitions.json` | Table column definitions for auto-creating DB schema |
| **Core Pipeline — Linux** | |
| `linux-collector.py` | Python agent that collects Linux system state (piped via SSH) |
| `collect-snapshots-linux.sh` | Bash orchestrator for parallel SSH collection |
| **Inventory & Credentials** | |
| `Invoke-Inventory.ps1` | Shared PowerShell module for inventory loading + credential resolution |
| `inventory-sample.yml` | Annotated sample inventory with credentials, groups, hosts |
| `inventory.yml` / `inventory.sops.yml` | Your inventory file (plaintext or SOPS-encrypted) |
| `targetHosts.txt` | Legacy host list (fallback if no inventory.yml) |
| **Response Toolkit** | |
| `respond.ps1` | YAML-playbook-driven response framework (Windows + Linux) |
| `playbook-sample.yml` | Annotated sample playbook covering all action types |
| **Legacy Response** | |
| `clear.ps1` | Original CSV-driven response script |
| `clear.csv` | CSV-driven list of remediation actions |
| **Analysis** | |
| `analyze-snapshots.py` | Offline PEASS-ng-style security analyzer (reads JSON snapshots) |
| `sql.sql` | Autorun frequency analysis query |
| `WITH.sql` | Snapshot diff query — new/removed autoruns |
| `CREATE VIEW system_snapshots_view AS.sql` | Latest snapshot per system |
| `schema-migration.sql` | Migration & maintenance SQL |
| **Schema** | |
| `publicddl.sql` | Reference DDL for the database schema |
| **Setup / Utilities** | |
| `ad_query.ps1` | AD user/computer enumeration with group membership |
| `dns_enumeration.ps1` | DNS enumeration utility |
| `powershell-scriptblock-logging.ps1` | Enable PowerShell ScriptBlock logging |
| `procs_only.ps1` | Quick single-host process snapshot |
| `webserver.py` | Flask web UI for browsing snapshot data |