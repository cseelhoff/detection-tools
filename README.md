# Detection Tools

A PowerShell-based endpoint detection and response (EDR) toolkit for Windows domain environments. Remotely collects system state snapshots from target hosts via PSRemoting, stores them in a PostgreSQL database, and provides tooling to diff snapshots over time to detect changes — with a focus on identifying persistence mechanisms, suspicious processes, and unauthorized accounts.

## Problem

In defensive cyber operations (DCO) / hunt missions on Windows domain networks, operators need to:

1. **Baseline and monitor endpoint state** — Know what's running, what's persisting, who's logged in, and what network connections exist across every machine in the environment.
2. **Detect changes over time** — Compare snapshots to spot new autoruns entries, new processes, new user accounts, or new network connections that could indicate compromise.
3. **Identify persistence mechanisms** — Autoruns (services, scheduled tasks, drivers, etc.) are a primary way attackers maintain access. Cataloging them across every host and flagging unique/rare ones surfaces anomalies.
4. **Respond quickly** — Once threats are identified, operators need to kill processes, remove files, disable accounts, and remove persistence entries across multiple hosts rapidly.

Commercial EDR tools may not be available in all environments (air-gapped networks, exercise environments, etc.), so a lightweight, script-based approach is needed.

## Solution

This toolkit automates the full cycle:

1. **Collect** — PSRemote into target hosts, gather comprehensive system state (processes, autoruns, network, users, etc.), and save as JSON.
2. **Store** — Import collected JSON snapshots into a PostgreSQL database with a relational schema, enabling SQL-based analysis.
3. **Analyze** — Use SQL queries/views to diff snapshots, count autorun frequency across hosts, and surface outliers.
4. **Respond** — Use the remediation script (`clear.ps1`) to execute response actions (kill processes, delete files, disable users, remove persistence) across endpoints from a CSV-driven action list.

## Data Collected Per Host

Each snapshot captures:

| Category | Details |
|---|---|
| **Computer Info** | Hostname, domain, manufacturer, model, OS version, last boot time |
| **Disk Volumes** | Drive letters, types, sizes, file systems |
| **Network Adapters** | MAC addresses, status, physical media type, DNS settings |
| **IP Addresses** | All addresses with prefix length, address family, type |
| **DNS Servers** | Per-interface DNS server addresses |
| **DNS Search Suffixes** | Per-interface suffix search lists |
| **ARP Cache** | IP-to-MAC mappings and state |
| **Routes** | Routing table with destination, next hop, metric |
| **TCP Connections** | Local/remote address:port, owning process, state |
| **UDP Endpoints** | Local/remote address:port, owning process |
| **Processes** | Name, user, PID, parent PID, command line, executable path |
| **Local Users** | Name, enabled, last logon, password last set, SID |
| **Local Groups** | Name, SID |
| **Group Membership** | User SID to Group SID mappings |
| **SMB Shares** | Name, path, scope |
| **Autoruns** | Entry location, signer, image path, hashes (MD5/SHA1/SHA256), launch string |
| **User Executables** | Executables (.exe, .bat, .ps1, .msi, etc.) found under user profile directories |

## Prerequisites

- **PowerShell 5.1+** with PSRemoting enabled on target hosts
- **Domain credentials** with admin access to target hosts
- **Sysinternals Autorunsc.exe** — placed in the working directory (automatically deployed to targets)
- **PostgreSQL** database server
- **Npgsql.dll** — .NET PostgreSQL driver (GAC-installed or local path)
- **Python 3 + Flask + Flask-SQLAlchemy** (optional, for the web UI)

## Configuration

### config.json

Create a `config.json` in the project root:

```json
{
    "npgsqlPath": "C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\Npgsql\\v4.0_4.1.14.0__5d8b90d52f46fda7\\Npgsql.dll",
    "connectionString": "Host=localhost;Username=postgres;Password=yourpassword;Database=postgres"
}
```

- `npgsqlPath` — Path to the Npgsql.dll assembly
- `connectionString` — PostgreSQL connection string

### targetHosts.txt

List target hostnames, one per line:

```
host1.domain.mil
host2.domain.mil
host3.domain.mil
```

## Usage — Step by Step

### Step 1: Initial Setup (One-Time)

**If operating from a non-domain-joined workstation**, run `trusted-host-setup.ps1` first to configure WinRM trusted hosts and test connectivity to the domain controller.

**Enable PowerShell ScriptBlock Logging** (optional, for auditing) by running `powershell-scriptblock-logging.ps1` on target hosts.

### Step 2: Collect Snapshots from Target Hosts

```powershell
.\collect-snapshots.ps1
```

This script:
1. Reads target hostnames from `targetHosts.txt`
2. Prompts for domain credentials
3. PSRemotes into each host (up to 10 concurrent jobs)
4. Copies `autorunsc.exe` to each target if not already present
5. Collects all system state data (see table above)
6. Saves results as `system-info_<hostname>.json` files locally

### Step 3: Create Database and Import Data

```powershell
.\import-to-psql.ps1
```

This script:
1. Reads `config.json` for the database connection and Npgsql path
2. Connects to PostgreSQL
3. Auto-creates the `SystemSnapshots` table and all data tables (from `table_definitions.json`) if they don't exist
4. Reads each `system-info_<hostname>.json` file
5. Inserts a snapshot record and all associated data into the database

### Step 4: Analyze with SQL

Use the provided SQL files for analysis:

- **`WITH.sql`** — CTE query to diff the latest vs. oldest autorunsc entries per system, surfacing new or removed persistence
- **`CREATE VIEW system_snapshots_view AS.sql`** — View to get the latest snapshot per system
- **`sql.sql`** — Query to count autorun frequency across hosts (rare autoruns = suspicious)
- **`schema-migration.sql`** — One-time schema migration and maintenance scripts (deduplicate autoruns, purge old snapshots)

### Step 5: Respond / Remediate

Edit `clear.csv` with response actions:

```csv
host,creds,action,target,result
dc.domain.mil,domain creds,Disable-DomainUser,malicious.user,
host1.domain.mil,domain creds,Stop-ProcessForce,1234,
host1.domain.mil,domain creds,Remove-File,C:\path\to\malware.exe,
```

Then run:

```powershell
.\clear.ps1
```

Supported actions:
| Action | Description |
|---|---|
| `Stop-ProcessForce` | Kill a process by ID |
| `Remove-File` | Delete a file from the endpoint |
| `remove-persistence` | Remove an autoruns entry using autorunsc |
| `disable-localuser` | Disable a local user account |
| `Disable-DomainUser` | Disable a domain user account via AD |

### Optional: Web UI

```bash
pip install flask flask-sqlalchemy psycopg2
python webserver.py
```

A basic Flask web interface for browsing systems and filtering snapshots. Runs on `http://localhost:5000`.

## AD Enumeration

`ad_query.ps1` is a standalone script to enumerate Active Directory users and computers with their group memberships. It:
- Connects to a domain controller via LDAP with explicit credentials
- Pulls users and computers with key attributes (name, SamAccountName, UPN, last logon, group membership)
- Exports to `AD_Users_With_Groups.json` and displays in GridView

## Database Schema

The database uses a **serial ID schema** where `systemsnapshots` has an auto-incrementing `snapshotid` primary key. All child tables (autorunsc, computerinfo, processes, etc.) reference snapshots via a `snapshotid` foreign key. The canonical DDL is in `publicddl.sql`.

Key tables:
- **`systemsnapshots`** — One row per collection run per host (`snapshotid`, `systemuuid`, `snapshottime`)
- **`autorunsc`** — Autoruns entries per snapshot
- **`computerinfo`** — Host identity and OS info per snapshot
- **`processes`**, **`tcpconnections`**, **`udpconnections`** — Runtime state per snapshot
- **`users`**, **`groups`**, **`members`** — Local account info per snapshot
- **`unique_autorunsc_signer_path_cmdline`** — Deduplicated autoruns for frequency analysis

## File Reference

| File | Purpose |
|---|---|
| **Core Pipeline** | |
| `collect-snapshots.ps1` | Collect system snapshots from remote hosts via PSRemoting |
| `import-to-psql.ps1` | Import JSON snapshots into PostgreSQL |
| `config.json` | Database connection and Npgsql path configuration |
| `table_definitions.json` | Table column definitions used for auto-creating DB schema |
| `targetHosts.txt` | List of target hostnames |
| **Response** | |
| `clear.ps1` | Execute response actions on endpoints from CSV |
| `clear.csv` | CSV-driven list of remediation actions |
| `clear.json` | Example JSON format for remediation actions |
| **Analysis SQL** | |
| `sql.sql` | Autorun frequency analysis query |
| `WITH.sql` | Snapshot diff query — surfaces new/removed autoruns between snapshots |
| `CREATE VIEW system_snapshots_view AS.sql` | View to get latest snapshot per system |
| `schema-migration.sql` | One-time migration & maintenance SQL |
| **Schema DDL** | |
| `publicddl.sql` | Canonical DDL for the database schema |
| **Setup / Utilities** | |
| `ad_query.ps1` | Standalone AD user/computer enumeration with group membership |
| `trusted-host-setup.ps1` | WinRM trusted hosts setup for non-domain workstations |
| `powershell-scriptblock-logging.ps1` | Enable PowerShell ScriptBlock logging |
| `procs_only.ps1` | Quick single-host process snapshot (lightweight / ad-hoc use) |
| `webserver.py` | Flask web UI for browsing snapshot data |