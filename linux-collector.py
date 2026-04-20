#!/usr/bin/env python3
"""
linux-collector.py
Collects comprehensive Linux system state and outputs JSON to stdout.
Run with root/sudo for full data collection; degrades gracefully without root.
Designed to be piped through SSH: ssh user@host 'python3 -' < linux-collector.py

Requires: Python 3.6+
"""

import json
import subprocess
import os
import sys
import socket
import datetime
import re
import glob
import hashlib
from pathlib import Path

ERRORS = []


def run(cmd, timeout=60):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        ERRORS.append(f"Timeout running: {cmd}")
        return ""
    except Exception as e:
        ERRORS.append(f"Error running '{cmd}': {str(e)}")
        return ""


def run_sudo(cmd, timeout=60):
    """
    Run a command with sudo using the tty credential cache.

    The expected invocation is that the SSH controller has already primed
    sudo's tty timestamp via `sudo -v` on the same pty. Every call here uses
    `sudo -n` (non-interactive) — if the cache has expired or isn't present,
    sudo returns non-zero immediately and we fall back to running the command
    unprivileged.

    No password material is handled in this process: no env var, no stdin
    pipe, no shell echo pipeline. This eliminates:
      - password leakage via /proc/<pid>/environ (env was the old mechanism)
      - shell injection if the password contained metacharacters
      - password visibility in /proc/<pid>/cmdline during any child echo
    """
    # argv form (no shell=True) — cmd is split safely; avoids shell injection
    # from untrusted cmd content and keeps argv inspection clean.
    try:
        argv = ["sudo", "-n"] + __import__("shlex").split(cmd)
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            return proc.stdout.strip()
        # sudo -n prints "sudo: a password is required" to stderr when the
        # cache is missing. Record that so the operator knows to re-run with
        # the paramiko-based collector that primes the cache.
        if "password is required" in proc.stderr:
            ERRORS.append(f"sudo cache not primed for: {cmd}")
    except subprocess.TimeoutExpired:
        ERRORS.append(f"Timeout running sudo: {cmd}")
    except Exception as e:
        ERRORS.append(f"Error running sudo '{cmd}': {str(e)}")

    # Unprivileged fallback — graceful degradation.
    return run(f"{cmd} 2>/dev/null", timeout=timeout)


def read_file_contents(path):
    """Read a file and return its contents, or empty string on failure."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except PermissionError:
        ERRORS.append(f"Permission denied reading {path}")
        return ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# System UUID
# ---------------------------------------------------------------------------
def get_system_uuid() -> str:
    """
    Get system UUID with multiple fallbacks.
    Tries to mimic Windows Win32_ComputerSystemProduct.UUID behavior.
    """
    uuid = ""

    # 1. Preferred: Direct sysfs (fastest, no extra tools)
    uuid = read_file_contents("/sys/class/dmi/id/product_uuid")
    
    # 2. Alternative sysfs path (sometimes used)
    if not uuid:
        uuid = read_file_contents("/sys/devices/virtual/dmi/id/product_uuid")

    # 3. dmidecode (most reliable when DMI is available)
    if not uuid:
        uuid = run("dmidecode -s system-uuid 2>/dev/null")

    # 4. Fallback: systemd machine-id (very common on modern Ubuntu/Debian)
    #     This is stable per-installation and works great in containers/VMs
    if not uuid or uuid.lower() in ("", "00000000-0000-0000-0000-000000000000", "not settable"):
        uuid = read_file_contents("/etc/machine-id")
        if not uuid:
            uuid = read_file_contents("/var/lib/dbus/machine-id")

    # 5. Last resort: Generate a random UUID (consistent if you cache it)
    if not uuid or len(uuid) < 32:
        uuid = run("uuidgen 2>/dev/null") or "unknown"

    # Clean up (some sources return uppercase with/without dashes)
    uuid = uuid.replace("-", "").upper()
    if len(uuid) == 32:
        # Reformat to standard UUID style for consistency with Windows
        uuid = f"{uuid[:8]}-{uuid[8:12]}-{uuid[12:16]}-{uuid[16:20]}-{uuid[20:]}"
    
    return uuid or "unknown"

# ---------------------------------------------------------------------------
# Computer Info (equivalent of Get-ComputerInfo)
# ---------------------------------------------------------------------------
def get_computer_info():
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    domain = fqdn.replace(hostname + ".", "", 1) if fqdn != hostname and "." in fqdn else ""

    os_info = {}
    for line in read_file_contents("/etc/os-release").splitlines():
        if "=" in line:
            key, val = line.split("=", 1)
            os_info[key] = val.strip('"')

    uname = os.uname()
    manufacturer = read_file_contents("/sys/class/dmi/id/sys_vendor")
    model = read_file_contents("/sys/class/dmi/id/product_name")
    serial = read_file_contents("/sys/class/dmi/id/product_serial")
    uptime_since = run("uptime -s 2>/dev/null")
    cpu_model = ""
    for line in read_file_contents("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    mem_total = ""
    for line in read_file_contents("/proc/meminfo").splitlines():
        if line.startswith("MemTotal"):
            mem_total = line.split(":", 1)[1].strip()
            break

    return {
        "Hostname": hostname,
        "FQDN": fqdn,
        "Domain": domain,
        "Manufacturer": manufacturer,
        "Model": model,
        "SerialNumber": serial,
        "OsName": os_info.get("PRETTY_NAME", ""),
        "OsId": os_info.get("ID", ""),
        "OsVersion": os_info.get("VERSION_ID", ""),
        "KernelRelease": uname.release,
        "KernelVersion": uname.version,
        "Architecture": uname.machine,
        "CPUModel": cpu_model,
        "MemTotal": mem_total,
        "LastBootTime": uptime_since,
    }


# ---------------------------------------------------------------------------
# Disk Volumes (equivalent of Get-Volume)
# ---------------------------------------------------------------------------
def get_disk_volumes():
    output = run("lsblk -J -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,UUID,RO,MODEL 2>/dev/null")
    if output:
        try:
            return json.loads(output).get("blockdevices", [])
        except json.JSONDecodeError:
            pass

    # Fallback: parse df
    volumes = []
    for line in run("df -BK -T 2>/dev/null").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 7:
            volumes.append({
                "Filesystem": parts[0],
                "Type": parts[1],
                "SizeKB": parts[2],
                "UsedKB": parts[3],
                "AvailableKB": parts[4],
                "UsePercent": parts[5],
                "MountPoint": parts[6],
            })
    return volumes


# ---------------------------------------------------------------------------
# Network Adapters (equivalent of Get-NetAdapter)
# ---------------------------------------------------------------------------
def get_net_adapters():
    adapters = []
    output = run("ip -j link show 2>/dev/null")
    if output:
        try:
            for link in json.loads(output):
                adapters.append({
                    "Name": link.get("ifname", ""),
                    "MacAddress": link.get("address", ""),
                    "State": link.get("operstate", ""),
                    "MTU": link.get("mtu", 0),
                    "InterfaceIndex": link.get("ifindex", 0),
                    "Flags": link.get("flags", []),
                    "Type": link.get("link_type", ""),
                })
            return adapters
        except json.JSONDecodeError:
            pass

    # Fallback: parse ip link show
    current = None
    for line in run("ip link show 2>/dev/null").splitlines():
        m = re.match(r"^(\d+):\s+(\S+?)(?:@\S+)?:\s+<(.*)>\s+mtu\s+(\d+)", line)
        if m:
            if current:
                adapters.append(current)
            current = {
                "InterfaceIndex": int(m.group(1)),
                "Name": m.group(2),
                "Flags": m.group(3).split(","),
                "MTU": int(m.group(4)),
                "State": "",
                "MacAddress": "",
            }
            state_m = re.search(r"state\s+(\S+)", line)
            if state_m:
                current["State"] = state_m.group(1)
        elif current:
            mac_m = re.match(r"\s+link/\S+\s+([0-9a-f:]{17})", line)
            if mac_m:
                current["MacAddress"] = mac_m.group(1)
    if current:
        adapters.append(current)
    return adapters


# ---------------------------------------------------------------------------
# IP Addresses (equivalent of Get-NetIPAddress)
# ---------------------------------------------------------------------------
def get_ip_addresses():
    addresses = []
    output = run("ip -j addr show 2>/dev/null")
    if output:
        try:
            for iface in json.loads(output):
                for addr_info in iface.get("addr_info", []):
                    addresses.append({
                        "InterfaceIndex": iface.get("ifindex", 0),
                        "InterfaceName": iface.get("ifname", ""),
                        "IPAddress": addr_info.get("local", ""),
                        "PrefixLength": addr_info.get("prefixlen", 0),
                        "AddressFamily": addr_info.get("family", ""),
                        "Scope": addr_info.get("scope", ""),
                        "ValidLifetime": addr_info.get("valid_life_time", 0),
                    })
            return addresses
        except json.JSONDecodeError:
            pass

    # Fallback
    for line in run("ip addr show 2>/dev/null").splitlines():
        m = re.match(r"\s+inet6?\s+(\S+)", line)
        if m:
            parts = m.group(1).split("/")
            addresses.append({
                "IPAddress": parts[0],
                "PrefixLength": int(parts[1]) if len(parts) > 1 else 0,
                "AddressFamily": "inet6" if ":" in parts[0] else "inet",
            })
    return addresses


# ---------------------------------------------------------------------------
# DNS Configuration (equivalent of Get-DnsClientServerAddress + Get-DnsClient)
# ---------------------------------------------------------------------------
def get_dns_config():
    servers = []
    search_suffixes = []

    resolv = read_file_contents("/etc/resolv.conf")
    for line in resolv.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                servers.append({"ServerAddress": parts[1]})
        elif line.startswith("search") or line.startswith("domain"):
            for suffix in line.split()[1:]:
                search_suffixes.append({"Suffix": suffix})

    # If systemd-resolved is in use (127.0.0.53), get the real upstream servers
    has_stub = any(s.get("ServerAddress") == "127.0.0.53" for s in servers)
    if has_stub:
        resolvectl = run("resolvectl status 2>/dev/null")
        if not resolvectl:
            resolvectl = run("systemd-resolve --status 2>/dev/null")
        if resolvectl:
            for line in resolvectl.splitlines():
                line = line.strip()
                if "DNS Servers:" in line or "DNS Server:" in line:
                    addr = line.split(":", 1)[1].strip()
                    if addr and addr != "127.0.0.53":
                        servers.append({"ServerAddress": addr, "Source": "systemd-resolved"})
                elif "Current DNS Server:" in line:
                    addr = line.split(":", 1)[1].strip()
                    if addr and addr != "127.0.0.53":
                        servers.append({"ServerAddress": addr, "Source": "systemd-resolved-current"})

    return servers, search_suffixes


# ---------------------------------------------------------------------------
# ARP Cache (equivalent of Get-NetNeighbor)
# ---------------------------------------------------------------------------
def get_arp_cache():
    entries = []
    output = run("ip -j neigh show 2>/dev/null")
    if output:
        try:
            for n in json.loads(output):
                entries.append({
                    "IPAddress": n.get("dst", ""),
                    "LinkLayerAddress": n.get("lladdr", ""),
                    "InterfaceName": n.get("dev", ""),
                    "State": n.get("state", []),
                })
            return entries
        except json.JSONDecodeError:
            pass

    for line in run("ip neigh show 2>/dev/null").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            lladdr = ""
            state = parts[-1] if parts else ""
            for i, p in enumerate(parts):
                if p == "lladdr" and i + 1 < len(parts):
                    lladdr = parts[i + 1]
            iface = ""
            for i, p in enumerate(parts):
                if p == "dev" and i + 1 < len(parts):
                    iface = parts[i + 1]
            entries.append({
                "IPAddress": parts[0],
                "InterfaceName": iface,
                "LinkLayerAddress": lladdr,
                "State": state,
            })
    return entries


# ---------------------------------------------------------------------------
# Routes (equivalent of Get-NetRoute)
# ---------------------------------------------------------------------------
def get_routes():
    routes = []
    output = run("ip -j route show table all 2>/dev/null")
    if output:
        try:
            for r in json.loads(output):
                routes.append({
                    "Destination": r.get("dst", ""),
                    "Gateway": r.get("gateway", ""),
                    "InterfaceName": r.get("dev", ""),
                    "Protocol": r.get("protocol", ""),
                    "Scope": r.get("scope", ""),
                    "Metric": r.get("metric", 0),
                    "Table": r.get("table", ""),
                })
            return routes
        except json.JSONDecodeError:
            pass

    for line in run("ip route show 2>/dev/null").splitlines():
        parts = line.split()
        route = {"Destination": parts[0] if parts else ""}
        for i, p in enumerate(parts):
            if p == "via" and i + 1 < len(parts):
                route["Gateway"] = parts[i + 1]
            elif p == "dev" and i + 1 < len(parts):
                route["InterfaceName"] = parts[i + 1]
            elif p == "metric" and i + 1 < len(parts):
                route["Metric"] = int(parts[i + 1])
            elif p == "proto" and i + 1 < len(parts):
                route["Protocol"] = parts[i + 1]
        routes.append(route)
    return routes


# ---------------------------------------------------------------------------
# TCP / UDP connections (equivalent of Get-NetTCPConnection / Get-NetUDPEndpoint)
# ---------------------------------------------------------------------------
def _split_addr_port(addr_port):
    """Split address:port, handling IPv6 [addr]:port and bare * formats."""
    if not addr_port or addr_port == "*":
        return ("*", "")
    if addr_port.startswith("["):
        bracket_end = addr_port.rfind("]")
        addr = addr_port[1:bracket_end]
        port = addr_port[bracket_end + 2:] if bracket_end + 1 < len(addr_port) else ""
    else:
        idx = addr_port.rfind(":")
        if idx >= 0:
            addr = addr_port[:idx]
            port = addr_port[idx + 1:]
        else:
            addr = addr_port
            port = ""
    return (addr, port)


def get_tcp_connections():
    connections = []
    for line in run("ss -tnpH 2>/dev/null").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        process_name, pid = "", ""
        if len(parts) >= 6:
            pm = re.search(r'users:\(\("([^"]*)",pid=(\d+)', parts[5])
            if pm:
                process_name = pm.group(1)
                pid = pm.group(2)
        local_addr, local_port = _split_addr_port(parts[3])
        remote_addr, remote_port = _split_addr_port(parts[4])
        connections.append({
            "State": parts[0],
            "RecvQ": int(parts[1]) if parts[1].isdigit() else 0,
            "SendQ": int(parts[2]) if parts[2].isdigit() else 0,
            "LocalAddress": local_addr,
            "LocalPort": local_port,
            "RemoteAddress": remote_addr,
            "RemotePort": remote_port,
            "ProcessName": process_name,
            "ProcessId": pid,
        })
    return connections


def get_udp_connections():
    connections = []
    for line in run("ss -unpH 2>/dev/null").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        process_name, pid = "", ""
        # Process info can be at index 5 or embedded differently for UDP
        for p in parts[4:]:
            pm = re.search(r'users:\(\("([^"]*)",pid=(\d+)', p)
            if pm:
                process_name = pm.group(1)
                pid = pm.group(2)
                break
        local_addr, local_port = _split_addr_port(parts[3])
        remote_addr, remote_port = _split_addr_port(parts[4])
        connections.append({
            "State": parts[0],
            "RecvQ": int(parts[1]) if parts[1].isdigit() else 0,
            "SendQ": int(parts[2]) if parts[2].isdigit() else 0,
            "LocalAddress": local_addr,
            "LocalPort": local_port,
            "RemoteAddress": remote_addr,
            "RemotePort": remote_port,
            "ProcessName": process_name,
            "ProcessId": pid,
        })
    return connections


# ---------------------------------------------------------------------------
# Processes (equivalent of Get-Process + Win32_Process)
# ---------------------------------------------------------------------------
def get_processes():
    processes = []
    output = run(
        "ps -eo pid,ppid,uid,user,stat,%cpu,%mem,vsz,rss,tty,lstart,time,comm,args "
        "--no-headers 2>/dev/null"
    )
    for line in output.splitlines():
        # lstart is multi-word (e.g. "Mon Apr 14 12:00:00 2025"), so we must parse carefully
        # Format: PID PPID UID USER STAT %CPU %MEM VSZ RSS TTY <lstart 5 words> TIME COMM ARGS
        parts = line.split()
        if len(parts) < 15:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            uid = int(parts[2])
            user = parts[3]
            stat = parts[4]
            cpu_pct = parts[5]
            mem_pct = parts[6]
            vsz = int(parts[7])
            rss = int(parts[8])
            tty = parts[9]
            # lstart is exactly 5 words: day_of_week month day time year
            start_time = " ".join(parts[10:15])
            cpu_time = parts[15]
            comm = parts[16]
            cmdline = " ".join(parts[17:]) if len(parts) > 17 else comm
        except (ValueError, IndexError):
            continue

        exe_path = ""
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            pass

        processes.append({
            "ProcessId": pid,
            "ParentProcessId": ppid,
            "UID": uid,
            "UserName": user,
            "Status": stat,
            "CPUPercent": cpu_pct,
            "MemPercent": mem_pct,
            "VSZ": vsz,
            "RSS": rss,
            "TTY": tty,
            "StartTime": start_time,
            "CPUTime": cpu_time,
            "ProcessName": comm,
            "CommandLine": cmdline,
            "ExecutablePath": exe_path,
        })
    return processes


# ---------------------------------------------------------------------------
# Users (equivalent of Get-LocalUser)
# ---------------------------------------------------------------------------
def get_users():
    users = []
    shadow = {}
    lastlog = {}

    # Parse /etc/shadow for password status (requires root/sudo)
    shadow_content = read_file_contents("/etc/shadow")
    if not shadow_content:
        shadow_content = run_sudo("cat /etc/shadow")
    for line in shadow_content.splitlines():
        parts = line.split(":")
        if len(parts) >= 9:
            pw = parts[1]
            # Derive a one-way fingerprint of the password hash for change detection.
            # SHA-256(shadow_hash) — can't be reversed to recover the original hash,
            # but is deterministic so it changes when the password changes.
            pw_fingerprint = ""
            if pw and pw not in ("!", "!!", "*", ""):
                pw_fingerprint = hashlib.sha256(pw.encode("utf-8")).hexdigest()
            shadow[parts[0]] = {
                "PasswordLocked": pw.startswith("!") or pw.startswith("*") or pw == "!!",
                "PasswordStatus": "locked" if (pw.startswith("!") or pw.startswith("*")) else (
                    "no-password" if pw == "" else "set"
                ),
                "PasswordFingerprint": pw_fingerprint,
                "LastPasswordChangeDays": parts[2],
                "MinAgeDays": parts[3],
                "MaxAgeDays": parts[4],
                "WarnDays": parts[5],
                "InactiveDays": parts[6],
                "ExpireDateDays": parts[7],
            }

    # Parse lastlog
    for line in run("lastlog 2>/dev/null").splitlines()[1:]:
        parts = line.split(None, 1)
        if len(parts) >= 2 and "Never logged in" not in parts[1]:
            lastlog[parts[0]] = parts[1].strip()
        elif len(parts) >= 1:
            lastlog[parts[0]] = "Never logged in"

    # Parse /etc/passwd
    for line in read_file_contents("/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username = parts[0]
        shell = parts[6]
        user_info = {
            "Name": username,
            "UID": int(parts[2]),
            "GID": int(parts[3]),
            "GECOS": parts[4],
            "HomeDirectory": parts[5],
            "Shell": shell,
            "InteractiveLogin": shell not in (
                "/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
            ),
            "LastLogon": lastlog.get(username, ""),
        }
        if username in shadow:
            user_info.update({
                "PasswordLocked": shadow[username]["PasswordLocked"],
                "PasswordStatus": shadow[username]["PasswordStatus"],
                "PasswordFingerprint": shadow[username]["PasswordFingerprint"],
                "LastPasswordChangeDays": shadow[username]["LastPasswordChangeDays"],
                "ExpireDateDays": shadow[username]["ExpireDateDays"],
            })
        users.append(user_info)
    return users


# ---------------------------------------------------------------------------
# Groups + Members (equivalent of Get-LocalGroup / Get-LocalGroupMember)
# ---------------------------------------------------------------------------
def get_groups():
    groups = []
    for line in read_file_contents("/etc/group").splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            groups.append({
                "Name": parts[0],
                "GID": int(parts[2]),
                "Members": [m for m in parts[3].split(",") if m],
            })
    return groups


def get_members():
    """User-to-group membership (supplementary + primary)."""
    members = []

    group_by_gid = {}
    for line in read_file_contents("/etc/group").splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            group_name = parts[0]
            gid = parts[2]
            group_by_gid[gid] = group_name
            for member in parts[3].split(","):
                if member.strip():
                    members.append({
                        "UserName": member.strip(),
                        "GroupName": group_name,
                        "GroupGID": int(gid),
                        "PrimaryGroup": False,
                    })

    # Primary group from /etc/passwd
    for line in read_file_contents("/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            members.append({
                "UserName": parts[0],
                "GroupName": group_by_gid.get(parts[3], parts[3]),
                "GroupGID": int(parts[3]),
                "PrimaryGroup": True,
            })
    return members


# ---------------------------------------------------------------------------
# Shares (NFS exports + Samba)
# ---------------------------------------------------------------------------
def get_shares():
    shares = []

    # NFS exports
    for line in read_file_contents("/etc/exports").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            shares.append({
                "Type": "NFS",
                "Path": parts[0] if parts else "",
                "Options": " ".join(parts[1:]) if len(parts) > 1 else "",
            })

    # Samba shares
    smb_content = read_file_contents("/etc/samba/smb.conf")
    current_share = None
    for line in smb_content.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            if name.lower() != "global":
                current_share = {"Type": "SMB", "Name": name, "Path": ""}
                shares.append(current_share)
            else:
                current_share = None
        elif current_share and "=" in line and not line.startswith("#") and not line.startswith(";"):
            key, val = line.split("=", 1)
            if key.strip().lower() == "path":
                current_share["Path"] = val.strip()

    return shares


# ---------------------------------------------------------------------------
# Persistence Mechanisms (Linux equivalent of Autoruns)
# ---------------------------------------------------------------------------
def get_persistence():
    persistence = []

    # 1. Systemd services
    for line in run(
        "systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null"
    ).splitlines():
        parts = line.split()
        if len(parts) >= 2:
            persistence.append({
                "Type": "systemd-service",
                "Name": parts[0],
                "State": parts[1],
            })

    # 2. Systemd timers
    for line in run(
        "systemctl list-unit-files --type=timer --no-pager --no-legend 2>/dev/null"
    ).splitlines():
        parts = line.split()
        if len(parts) >= 2:
            persistence.append({
                "Type": "systemd-timer",
                "Name": parts[0],
                "State": parts[1],
            })

    # 3. System cron
    for cron_file in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
        if not os.path.isfile(cron_file):
            continue
        for line in read_file_contents(cron_file).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                persistence.append({
                    "Type": "cron-system",
                    "Source": cron_file,
                    "Entry": line,
                })

    # 4. Per-user crontabs
    for cron_dir in ["/var/spool/cron/crontabs", "/var/spool/cron"]:
        if not os.path.isdir(cron_dir):
            continue
        try:
            entries = os.listdir(cron_dir)
        except PermissionError:
            continue
        for entry in entries:
            cron_path = os.path.join(cron_dir, entry)
            if not os.path.isfile(cron_path):
                continue
            for line in read_file_contents(cron_path).splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    persistence.append({
                        "Type": "cron-user",
                        "User": entry,
                        "Source": cron_path,
                        "Entry": line,
                    })

    # 5. Cron periodic directories
    for cron_dir in [
        "/etc/cron.hourly", "/etc/cron.daily",
        "/etc/cron.weekly", "/etc/cron.monthly",
    ]:
        if not os.path.isdir(cron_dir):
            continue
        for item in os.listdir(cron_dir):
            full_path = os.path.join(cron_dir, item)
            if os.path.isfile(full_path):
                persistence.append({
                    "Type": "cron-directory",
                    "Source": cron_dir,
                    "Name": item,
                    "Path": full_path,
                })

    # 6. At jobs
    for line in run("atq 2>/dev/null").splitlines():
        if line.strip():
            persistence.append({"Type": "at-job", "Entry": line.strip()})

    # 7. rc.local
    for line in read_file_contents("/etc/rc.local").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("exit"):
            persistence.append({
                "Type": "rc-local",
                "Source": "/etc/rc.local",
                "Entry": line,
            })

    # 8. Init.d scripts
    if os.path.isdir("/etc/init.d"):
        for script in os.listdir("/etc/init.d"):
            full_path = os.path.join("/etc/init.d", script)
            if os.path.isfile(full_path):
                persistence.append({
                    "Type": "init.d",
                    "Name": script,
                    "Path": full_path,
                })

    # 9. /etc/profile.d scripts
    if os.path.isdir("/etc/profile.d"):
        for script in os.listdir("/etc/profile.d"):
            full_path = os.path.join("/etc/profile.d", script)
            if os.path.isfile(full_path):
                persistence.append({
                    "Type": "profile-script",
                    "Source": "/etc/profile.d",
                    "Name": script,
                    "Path": full_path,
                })

    # 10. LD_PRELOAD / ld.so.preload
    for line in read_file_contents("/etc/ld.so.preload").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            persistence.append({
                "Type": "ld-preload",
                "Source": "/etc/ld.so.preload",
                "Path": line,
            })

    # 11. XDG autostart (desktop environments)
    for autostart_dir in ["/etc/xdg/autostart"] + glob.glob("/home/*/.config/autostart"):
        if not os.path.isdir(autostart_dir):
            continue
        for entry_file in os.listdir(autostart_dir):
            if entry_file.endswith(".desktop"):
                persistence.append({
                    "Type": "xdg-autostart",
                    "Source": autostart_dir,
                    "Name": entry_file,
                    "Path": os.path.join(autostart_dir, entry_file),
                })

    return persistence


# ---------------------------------------------------------------------------
# SSH Authorized Keys
# ---------------------------------------------------------------------------
def get_ssh_authorized_keys():
    keys = []
    for line in read_file_contents("/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) < 6:
            continue
        username = parts[0]
        home = parts[5]
        auth_keys_path = os.path.join(home, ".ssh", "authorized_keys")
        content = read_file_contents(auth_keys_path)
        if not content:
            continue
        for key_line in content.splitlines():
            key_line = key_line.strip()
            if not key_line or key_line.startswith("#"):
                continue
            key_parts = key_line.split(None, 2)
            keys.append({
                "User": username,
                "KeyType": key_parts[0] if key_parts else "",
                "KeyFingerprint": key_parts[1][:44] + "..." if len(key_parts) > 1 and len(key_parts[1]) > 44 else (key_parts[1] if len(key_parts) > 1 else ""),
                "Comment": key_parts[2] if len(key_parts) > 2 else "",
            })
    return keys


# ---------------------------------------------------------------------------
# Kernel Modules (lsmod)
# ---------------------------------------------------------------------------
def get_kernel_modules():
    modules = []
    for line in run("lsmod 2>/dev/null").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            modules.append({
                "Name": parts[0],
                "Size": int(parts[1]) if parts[1].isdigit() else 0,
                "UsedByCount": parts[2],
                "UsedBy": parts[3].rstrip(",") if len(parts) > 3 else "",
            })
    return modules


# ---------------------------------------------------------------------------
# Installed Packages
# ---------------------------------------------------------------------------
def get_installed_packages():
    packages = []

    # Debian/Ubuntu (dpkg)
    output = run(
        r"dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' 2>/dev/null"
    )
    if output:
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and "installed" in parts[2]:
                packages.append({
                    "Name": parts[0],
                    "Version": parts[1],
                    "Manager": "dpkg",
                })
        return packages

    # RHEL/CentOS/Fedora (rpm)
    output = run(
        r"rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME:date}\n' 2>/dev/null"
    )
    if output:
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                packages.append({
                    "Name": parts[0],
                    "Version": parts[1],
                    "InstallTime": parts[2] if len(parts) > 2 else "",
                    "Manager": "rpm",
                })
        return packages

    # Arch (pacman)
    output = run("pacman -Q 2>/dev/null")
    if output:
        for line in output.splitlines():
            parts = line.split(None, 1)
            if len(parts) >= 2:
                packages.append({
                    "Name": parts[0],
                    "Version": parts[1],
                    "Manager": "pacman",
                })
        return packages

    # Alpine (apk)
    output = run("apk list --installed 2>/dev/null")
    if output:
        for line in output.splitlines():
            # Format: name-version-rrelease arch {origin} (license) [installed]
            m = re.match(r"^(\S+?)-(\d\S*)\s", line)
            if m:
                packages.append({
                    "Name": m.group(1),
                    "Version": m.group(2),
                    "Manager": "apk",
                })
        return packages

    return packages


# ---------------------------------------------------------------------------
# User Executables in /home (equivalent of scanning user profile directories)
# ---------------------------------------------------------------------------
def get_user_executables():
    executables = []
    extensions = {".sh", ".py", ".pl", ".rb", ".exe", ".elf", ".bin", ".jar", ".ps1", ".bat"}
    skip_dirs = {".cache", ".local/share/Trash", "node_modules", ".git", "__pycache__", ".npm"}

    search_roots = ["/home", "/root"]
    for search_root in search_roots:
        if not os.path.isdir(search_root):
            continue
        # Manual walk with depth limit + skip dirs to keep scan bounded
        dir_stack = [search_root]
        while dir_stack:
            current = dir_stack.pop()
            try:
                for entry in os.scandir(current):
                    if entry.is_symlink():
                        continue
                    if entry.is_dir():
                        if entry.name not in skip_dirs:
                            dir_stack.append(entry.path)
                    elif entry.is_file():
                        _, ext = os.path.splitext(entry.name)
                        try:
                            st = entry.stat()
                            is_exec = bool(st.st_mode & 0o111)
                            if is_exec or ext.lower() in extensions:
                                executables.append({
                                    "Path": entry.path,
                                    "Size": st.st_size,
                                    "IsExecutable": is_exec,
                                    "Extension": ext,
                                })
                        except Exception:
                            pass
            except PermissionError:
                pass
            except Exception:
                pass
    return executables


# ---------------------------------------------------------------------------
# File Inventory (fast full-filesystem scan)
# Uses 'find' with -printf for a single-pass inode-order scan.
# On ext4/xfs this reads inode tables sequentially — typically completes
# in under 30 seconds even for millions of files.
# ---------------------------------------------------------------------------
def get_file_inventory():
    files = []
    errors = []

    # Get mounted local filesystems (skip network, pseudo, snap, tmpfs)
    skip_fstypes = {"tmpfs", "devtmpfs", "sysfs", "proc", "cgroup", "cgroup2",
                    "securityfs", "debugfs", "tracefs", "configfs", "fusectl",
                    "hugetlbfs", "mqueue", "pstore", "binfmt_misc", "autofs",
                    "nfs", "nfs4", "cifs", "smbfs", "fuse.sshfs", "squashfs",
                    "overlay", "devpts", "rpc_pipefs", "nfsd"}
    mount_points = []
    for line in read_file_contents("/proc/mounts").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            fstype = parts[2]
            mountpoint = parts[1]
            if fstype not in skip_fstypes and mountpoint.startswith("/"):
                mount_points.append(mountpoint)

    if not mount_points:
        mount_points = ["/"]

    for mp in mount_points:
        # -xdev: stay on same filesystem; -printf for minimal stat overhead
        # Format: size_bytes \t type(f/d/l) \t permissions \t full_path
        output = run(
            f"find {mp} -xdev -printf '%s\\t%y\\t%M\\t%p\\n' 2>/dev/null",
            timeout=120,
        )
        if not output:
            errors.append(f"find returned empty for {mp}")
            continue
        for line in output.splitlines():
            parts = line.split("\t", 3)
            if len(parts) < 4:
                continue
            size_str, ftype, perms, path = parts
            if ftype == "d":  # skip directories to keep payload smaller
                continue
            try:
                size = int(size_str)
            except ValueError:
                size = 0
            files.append({
                "Path": path,
                "Size": size,
                "Type": ftype,  # f=file, l=symlink, etc.
                "Permissions": perms,
                "MountPoint": mp,
            })

    return files, errors


# ---------------------------------------------------------------------------
# Sudoers Configuration
# ---------------------------------------------------------------------------
def get_sudoers():
    entries = []

    # List sudoers.d files — may need sudo if directory isn't readable
    sudoers_d_files = glob.glob("/etc/sudoers.d/*")
    if not sudoers_d_files and os.path.isdir("/etc/sudoers.d"):
        ls_output = run_sudo("ls /etc/sudoers.d")
        if ls_output:
            sudoers_d_files = [f"/etc/sudoers.d/{f}" for f in ls_output.splitlines() if f.strip()]

    for sudoers_file in ["/etc/sudoers"] + sudoers_d_files:
        content = read_file_contents(sudoers_file)
        if not content:
            content = run_sudo(f"cat {sudoers_file}")
        if not content:
            continue
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("Defaults"):
                entries.append({"Source": sudoers_file, "Entry": line})
    return entries


# ---------------------------------------------------------------------------
# SUID / SGID Binaries
# ---------------------------------------------------------------------------
def get_suid_binaries():
    binaries = []
    output = run(
        "find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /opt "
        "-type f \\( -perm -4000 -o -perm -2000 \\) "
        "-exec stat --format='%n\\t%a\\t%U\\t%G\\t%s' {} \\; 2>/dev/null",
        timeout=120,
    )
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 5:
            binaries.append({
                "Path": parts[0],
                "Permissions": parts[1],
                "Owner": parts[2],
                "Group": parts[3],
                "Size": int(parts[4]) if parts[4].isdigit() else 0,
            })
    return binaries


# ---------------------------------------------------------------------------
# Docker Containers
# ---------------------------------------------------------------------------
def get_docker_containers():
    containers = []
    output = run("docker ps -a --no-trunc --format '{{json .}}' 2>/dev/null")
    if output:
        for line in output.splitlines():
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return containers


# ---------------------------------------------------------------------------
# Firewall Rules (iptables / nftables / firewalld)
# ---------------------------------------------------------------------------
def get_firewall_rules():
    rules = {}

    iptables = run_sudo("iptables -L -n -v --line-numbers")
    if iptables:
        rules["iptables"] = iptables

    ip6tables = run_sudo("ip6tables -L -n -v --line-numbers")
    if ip6tables:
        rules["ip6tables"] = ip6tables

    nft = run_sudo("nft list ruleset")
    if nft:
        rules["nftables"] = nft

    firewalld = run_sudo("firewall-cmd --list-all-zones")
    if firewalld:
        rules["firewalld"] = firewalld

    ufw = run_sudo("ufw status verbose")
    if ufw:
        rules["ufw"] = ufw

    return rules


# ---------------------------------------------------------------------------
# SELinux / AppArmor Status
# ---------------------------------------------------------------------------
def get_security_modules():
    status = {}

    selinux = run("getenforce 2>/dev/null")
    if selinux:
        status["SELinux"] = {
            "Mode": selinux,
            "Details": run("sestatus 2>/dev/null"),
        }

    apparmor = run("aa-status 2>/dev/null")
    if apparmor:
        status["AppArmor"] = apparmor

    return status


# ---------------------------------------------------------------------------
# /etc/hosts
# ---------------------------------------------------------------------------
def get_hosts_file():
    entries = []
    for line in read_file_contents("/etc/hosts").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2:
                entries.append({
                    "IPAddress": parts[0],
                    "Hostnames": parts[1:],
                })
    return entries


# ---------------------------------------------------------------------------
# AV / EDR / Security Software Status
# ---------------------------------------------------------------------------
def get_security_products():
    products = []

    # ClamAV
    clamd_status = run("systemctl is-active clamav-daemon 2>/dev/null || systemctl is-active clamd 2>/dev/null")
    if clamd_status:
        version = run("clamscan --version 2>/dev/null")
        products.append({
            "Name": "ClamAV",
            "Type": "AntiVirus",
            "ServiceStatus": clamd_status.strip(),
            "Version": version,
        })

    # Common EDR/AV agents - check for running services
    edr_services = [
        ("falcon-sensor", "CrowdStrike Falcon"),
        ("cbagentd", "Carbon Black Agent"),
        ("sentinelone", "SentinelOne"),
        ("SentinelAgent", "SentinelOne Agent"),
        ("taniumclient", "Tanium Client"),
        ("qualys-cloud-agent", "Qualys Cloud Agent"),
        ("nessus", "Nessus Agent"),
        ("osqueryd", "osquery"),
        ("wazuh-agent", "Wazuh Agent"),
        ("ossec", "OSSEC HIDS"),
        ("filebeat", "Elastic Filebeat"),
        ("auditbeat", "Elastic Auditbeat"),
        ("endgame", "Elastic Endgame"),
        ("elastic-agent", "Elastic Agent"),
        ("elastic-endpoint", "Elastic Endpoint"),
        ("sophos", "Sophos"),
        ("savd", "Sophos AV Daemon"),
        ("McAfeeTP", "McAfee Threat Prevention"),
        ("isectd", "McAfee Agent"),
        ("ds_agent", "Trend Micro Deep Security"),
        ("cylancesvc", "Cylance"),
    ]
    for svc_name, display_name in edr_services:
        status = run(f"systemctl is-active {svc_name} 2>/dev/null").strip()
        if status and status != "":
            enabled = run(f"systemctl is-enabled {svc_name} 2>/dev/null").strip()
            products.append({
                "Name": display_name,
                "Type": "EDR/Agent",
                "ServiceName": svc_name,
                "ServiceStatus": status,
                "Enabled": enabled,
            })

    # Also check running processes for known agent binaries
    edr_process_names = [
        "falcon-sensor", "cbagentd", "sentinelagent", "taniumclient",
        "qualys-cloud-agent", "osqueryd", "wazuh-agentd", "ossec-agentd",
        "auditbeat", "filebeat", "elastic-agent", "elastic-endpoint",
    ]
    ps_output = run("ps -eo comm --no-headers 2>/dev/null")
    running_procs = set(ps_output.splitlines()) if ps_output else set()
    for proc_name in edr_process_names:
        if proc_name in running_procs:
            # Only add if not already found via systemd
            already_found = any(p.get("ServiceName") == proc_name for p in products)
            if not already_found:
                products.append({
                    "Name": proc_name,
                    "Type": "EDR/Agent",
                    "DetectedVia": "running-process",
                    "ServiceStatus": "running",
                })

    return products


# ---------------------------------------------------------------------------
# Logged-in Users / Active Sessions (console, SSH, screen, tmux)
# ---------------------------------------------------------------------------
def get_logged_in_users():
    sessions = []

    # 'who' gives console + SSH + pts sessions
    for line in run("who -u 2>/dev/null").splitlines():
        parts = line.split()
        if len(parts) >= 5:
            sessions.append({
                "UserName": parts[0],
                "Terminal": parts[1],
                "LoginTime": " ".join(parts[2:4]),
                "Idle": parts[4] if len(parts) > 4 else "",
                "PID": parts[5] if len(parts) > 5 else "",
                "Source": parts[6].strip("()") if len(parts) > 6 else "local",
            })

    # SSH sessions with more detail from ss
    ssh_sessions = []
    for line in run("ss -tnpH sport = :22 2>/dev/null").splitlines():
        parts = line.split()
        if len(parts) >= 5 and "ESTAB" in parts[0]:
            remote_addr, remote_port = _split_addr_port(parts[4])
            ssh_sessions.append({
                "RemoteAddress": remote_addr,
                "RemotePort": remote_port,
            })

    # loginctl sessions (systemd-logind)
    logind_sessions = []
    for line in run("loginctl list-sessions --no-pager --no-legend 2>/dev/null").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            session_id = parts[0]
            # Get session details
            detail = run(f"loginctl show-session {session_id} --no-pager 2>/dev/null")
            session_info = {"SessionId": session_id}
            for detail_line in detail.splitlines():
                if "=" in detail_line:
                    k, v = detail_line.split("=", 1)
                    if k in ("Name", "Type", "Class", "State", "Remote", "RemoteHost", "Service", "TTY", "Leader"):
                        session_info[k] = v
            logind_sessions.append(session_info)

    return {
        "ActiveSessions": sessions,
        "SSHConnections": ssh_sessions,
        "LogindSessions": logind_sessions,
    }


# ---------------------------------------------------------------------------
# Audit Configuration (auditd rules + status)
# ---------------------------------------------------------------------------
def get_audit_config():
    config = {}

    # auditd status
    auditd_status = run("auditctl -s 2>/dev/null")
    if auditd_status:
        config["AuditdStatus"] = auditd_status

    # Current audit rules
    audit_rules = run("auditctl -l 2>/dev/null")
    if audit_rules:
        config["AuditRules"] = audit_rules.splitlines()

    # Audit config file
    audit_conf = read_file_contents("/etc/audit/auditd.conf")
    if audit_conf:
        config["AuditdConfig"] = {}
        for line in audit_conf.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                config["AuditdConfig"][k.strip()] = v.strip()

    return config


# ---------------------------------------------------------------------------
# PAM Configuration (security-relevant authentication settings)
# ---------------------------------------------------------------------------
def get_pam_config():
    pam_files = {}
    pam_dir = "/etc/pam.d"
    if os.path.isdir(pam_dir):
        for entry in os.listdir(pam_dir):
            full_path = os.path.join(pam_dir, entry)
            if os.path.isfile(full_path):
                content = read_file_contents(full_path)
                if content:
                    # Only store non-comment lines
                    active_lines = [
                        l.strip() for l in content.splitlines()
                        if l.strip() and not l.strip().startswith("#")
                    ]
                    if active_lines:
                        pam_files[entry] = active_lines

    # login.defs (password aging defaults, UID/GID ranges)
    login_defs = {}
    for line in read_file_contents("/etc/login.defs").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split(None, 1)
            if len(parts) == 2:
                login_defs[parts[0]] = parts[1]

    return {
        "PamFiles": pam_files,
        "LoginDefs": login_defs,
    }


# ---------------------------------------------------------------------------
# Kernel Hardening Sysctls
# ---------------------------------------------------------------------------
def get_kernel_hardening():
    sysctls = {
        "randomize_va_space": "/proc/sys/kernel/randomize_va_space",
        "kptr_restrict": "/proc/sys/kernel/kptr_restrict",
        "dmesg_restrict": "/proc/sys/kernel/dmesg_restrict",
        "ptrace_scope": "/proc/sys/kernel/yama/ptrace_scope",
        "protected_symlinks": "/proc/sys/fs/protected_symlinks",
        "protected_hardlinks": "/proc/sys/fs/protected_hardlinks",
        "perf_event_paranoid": "/proc/sys/kernel/perf_event_paranoid",
        "mmap_min_addr": "/proc/sys/vm/mmap_min_addr",
        "unprivileged_userns_clone": "/proc/sys/kernel/unprivileged_userns_clone",
        "unprivileged_bpf_disabled": "/proc/sys/kernel/unprivileged_bpf_disabled",
    }
    result = {}
    for name, path in sysctls.items():
        val = read_file_contents(path)
        if val:
            result[name] = val.strip()

    # Seccomp
    for line in read_file_contents("/proc/self/status").splitlines():
        if line.startswith("Seccomp"):
            result["seccomp"] = line.split(":", 1)[1].strip()

    # Kernel lockdown
    lockdown = read_file_contents("/sys/kernel/security/lockdown")
    if lockdown:
        result["lockdown"] = lockdown.strip()

    # Virtualization detection
    virt = run("systemd-detect-virt 2>/dev/null")
    if virt:
        result["virtualization"] = virt.strip()

    return result


# ---------------------------------------------------------------------------
# Container Detection (detailed)
# ---------------------------------------------------------------------------
def get_container_info():
    info = {
        "inside_container": False,
        "container_type": "",
        "container_tools": [],
        "docker_sockets": [],
        "k8s_service_account": False,
    }

    # Detect container type
    if os.path.exists("/.dockerenv"):
        info["inside_container"] = True
        info["container_type"] = "docker"
    elif os.path.exists("/run/.containerenv"):
        info["inside_container"] = True
        info["container_type"] = "podman"
    container_env = read_file_contents("/run/systemd/container")
    if container_env:
        info["inside_container"] = True
        info["container_type"] = container_env.strip()
    if os.path.exists("/proc/vz"):
        info["inside_container"] = True
        info["container_type"] = "openvz"

    # Container tools present
    tools = ["docker", "lxc", "rkt", "podman", "runc", "ctr", "containerd",
             "crio", "nerdctl", "kubectl", "crictl", "docker-compose"]
    for tool in tools:
        if run(f"command -v {tool} 2>/dev/null"):
            info["container_tools"].append(tool)

    # Docker sockets
    for sock in ["/var/run/docker.sock", "/run/docker.sock",
                 "/var/run/containerd/containerd.sock"]:
        if os.path.exists(sock):
            writable = os.access(sock, os.W_OK)
            info["docker_sockets"].append({"Path": sock, "Writable": writable})

    # Kubernetes service account
    k8s_token = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if os.path.exists(k8s_token):
        info["k8s_service_account"] = True

    return info


# ---------------------------------------------------------------------------
# Cloud Environment Detection
# ---------------------------------------------------------------------------
def get_cloud_environment():
    cloud = {"provider": "", "detected_via": ""}

    # Check env vars first (fast)
    for key in os.environ:
        if key.startswith("AWS_"):
            cloud["provider"] = "aws"
            cloud["detected_via"] = "env_var"
            break
        if key.startswith("GOOGLE_") or key.startswith("GCE_"):
            cloud["provider"] = "gcp"
            cloud["detected_via"] = "env_var"
            break
        if key.startswith("AZURE_") or key == "MSI_ENDPOINT":
            cloud["provider"] = "azure"
            cloud["detected_via"] = "env_var"
            break

    # Check known directories
    if not cloud["provider"]:
        if os.path.isdir("/var/log/amazon") or os.path.exists("/etc/amazon"):
            cloud["provider"] = "aws"
            cloud["detected_via"] = "filesystem"
        elif os.path.isdir("/var/log/waagent") or os.path.exists("/etc/waagent.conf"):
            cloud["provider"] = "azure"
            cloud["detected_via"] = "filesystem"
        elif os.path.isdir("/etc/google_cloud") or os.path.exists("/usr/share/google"):
            cloud["provider"] = "gcp"
            cloud["detected_via"] = "filesystem"

    # Cloud credential files
    cred_files = []
    cred_paths = [
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.aws/config"),
        os.path.expanduser("~/.config/gcloud/credentials.db"),
        os.path.expanduser("~/.config/gcloud/access_tokens.db"),
        os.path.expanduser("~/.azure/accessTokens.json"),
        os.path.expanduser("~/.azure/azureProfile.json"),
    ]
    for p in cred_paths:
        if os.path.exists(p):
            try:
                st = os.stat(p)
                cred_files.append({"Path": p, "Size": st.st_size})
            except Exception:
                cred_files.append({"Path": p})
    cloud["credential_files"] = cred_files

    return cloud


# ---------------------------------------------------------------------------
# SSH Configuration & Keys
# ---------------------------------------------------------------------------
def get_ssh_config():
    config = {}

    # sshd_config settings
    sshd_settings = {}
    important_keys = [
        "PermitRootLogin", "PasswordAuthentication", "PermitEmptyPasswords",
        "PubkeyAuthentication", "AllowAgentForwarding", "X11Forwarding",
        "MaxAuthTries", "AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups",
        "UsePAM", "ChallengeResponseAuthentication", "AuthorizedKeysFile",
    ]
    sshd_content = read_file_contents("/etc/ssh/sshd_config")
    for line in sshd_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for key in important_keys:
            if line.lower().startswith(key.lower()):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    sshd_settings[parts[0]] = parts[1]
    config["SshdSettings"] = sshd_settings

    # SSH host keys
    host_keys = []
    for f in glob.glob("/etc/ssh/ssh_host_*_key.pub"):
        content = read_file_contents(f)
        if content:
            host_keys.append({"File": f, "Key": content.strip()})
    config["HostKeys"] = host_keys

    # SSH agent sockets
    agent_socks = []
    for pattern in ["/run/user/*/ssh-agent.*", "/tmp/ssh-*/agent.*"]:
        for sock in glob.glob(pattern):
            try:
                st = os.stat(sock)
                agent_socks.append({"Path": sock, "UID": st.st_uid})
            except Exception:
                pass
    config["AgentSockets"] = agent_socks

    # TCP wrappers
    config["HostsAllow"] = read_file_contents("/etc/hosts.allow")
    config["HostsDeny"] = read_file_contents("/etc/hosts.deny")

    return config


# ---------------------------------------------------------------------------
# File Capabilities
# ---------------------------------------------------------------------------
def get_file_capabilities():
    caps = []
    output = run("getcap -r / 2>/dev/null", timeout=120)
    for line in output.splitlines():
        parts = line.rsplit(" ", 1)
        if len(parts) == 2:
            caps.append({"Path": parts[0].strip(), "Capabilities": parts[1].strip()})
    return caps


# ---------------------------------------------------------------------------
# Writable Critical Paths
# ---------------------------------------------------------------------------
def get_writable_critical_paths():
    results = []

    # Writable dirs in PATH
    path_dirs = os.environ.get("PATH", "").split(":")
    for d in path_dirs:
        if d and os.path.isdir(d) and os.access(d, os.W_OK):
            results.append({"Type": "PATH_dir", "Path": d})

    # Writable /etc/passwd
    if os.access("/etc/passwd", os.W_OK):
        results.append({"Type": "etc_passwd", "Path": "/etc/passwd"})

    # Writable /etc/shadow
    if os.access("/etc/shadow", os.W_OK):
        results.append({"Type": "etc_shadow", "Path": "/etc/shadow"})

    # Writable network-scripts (RHEL)
    ns_dir = "/etc/sysconfig/network-scripts"
    if os.path.isdir(ns_dir) and os.access(ns_dir, os.W_OK):
        results.append({"Type": "network_scripts", "Path": ns_dir})

    # ld.so.conf writable paths
    for conf in ["/etc/ld.so.conf"] + glob.glob("/etc/ld.so.conf.d/*"):
        content = read_file_contents(conf)
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and os.path.isdir(line):
                if os.access(line, os.W_OK):
                    results.append({"Type": "ld_so_path", "Path": line, "ConfigFile": conf})

    return results


# ---------------------------------------------------------------------------
# Deleted-but-Running Executables
# ---------------------------------------------------------------------------
def get_deleted_executables():
    deleted = []
    for pid_dir in glob.glob("/proc/[0-9]*"):
        try:
            exe = os.readlink(os.path.join(pid_dir, "exe"))
            if "(deleted)" in exe:
                pid = os.path.basename(pid_dir)
                cmdline = read_file_contents(os.path.join(pid_dir, "cmdline")).replace("\x00", " ")
                deleted.append({
                    "PID": pid,
                    "DeletedExe": exe,
                    "CommandLine": cmdline.strip(),
                })
        except Exception:
            pass
    return deleted


# ---------------------------------------------------------------------------
# Fstab Mount Options
# ---------------------------------------------------------------------------
def get_fstab():
    entries = []
    for line in read_file_contents("/etc/fstab").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 4:
                entries.append({
                    "Device": parts[0],
                    "MountPoint": parts[1],
                    "FsType": parts[2],
                    "Options": parts[3],
                })
    return entries


# ---------------------------------------------------------------------------
# D-Bus Services
# ---------------------------------------------------------------------------
def get_dbus_services():
    services = []
    output = run("busctl list --no-pager --no-legend 2>/dev/null")
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            services.append({
                "Name": parts[0],
                "PID": parts[1],
                "Process": parts[2],
                "User": parts[3],
                "Session": parts[4] if len(parts) > 4 else "",
            })
    return services


# ---------------------------------------------------------------------------
# Unix Sockets
# ---------------------------------------------------------------------------
def get_unix_sockets():
    sockets = []
    output = run("ss -xlpH 2>/dev/null")
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            path = parts[4] if not parts[4].startswith("*") else ""
            proc_match = ""
            for p in parts[5:]:
                import re as _re
                m = _re.search(r'users:\(\("([^"]*)",pid=(\d+)', p)
                if m:
                    proc_match = f"{m.group(1)}({m.group(2)})"
                    break
            sockets.append({
                "State": parts[0],
                "Path": path,
                "Process": proc_match,
            })
    return sockets


# ---------------------------------------------------------------------------
# Privileged Group Members
# ---------------------------------------------------------------------------
def get_privileged_groups():
    result = {}
    for grp in ["sudo", "wheel", "adm", "docker", "lxd", "lxc", "root",
                "shadow", "disk", "video", "staff", "kmem"]:
        output = run(f"getent group {grp} 2>/dev/null")
        if output:
            parts = output.split(":")
            if len(parts) >= 4 and parts[3].strip():
                result[grp] = parts[3].strip().split(",")
    # UID 0 users
    uid0 = []
    for line in read_file_contents("/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid0.append(parts[0])
    result["uid0_users"] = uid0
    return result


# ---------------------------------------------------------------------------
# Kerberos Configuration
# ---------------------------------------------------------------------------
def get_kerberos_config():
    config = {}
    krb5_conf = read_file_contents("/etc/krb5.conf")
    if krb5_conf:
        config["krb5_conf"] = krb5_conf

    # Keytab files
    keytabs = []
    for pattern in ["/etc/krb5.keytab", "/etc/*.keytab", "/tmp/krb5*"]:
        for f in glob.glob(pattern):
            try:
                st = os.stat(f)
                keytabs.append({"Path": f, "Size": st.st_size, "Mode": oct(st.st_mode)})
            except Exception:
                pass
    config["keytab_files"] = keytabs

    # Cached AD hashes
    ad_caches = []
    for f in ["/var/lib/samba/private/secrets.tdb", "/var/lib/samba/passdb.tdb",
              "/var/opt/quest/vas/authcache/vas_auth.vdb"]:
        if os.path.exists(f):
            ad_caches.append(f)
    for f in glob.glob("/var/lib/sss/db/cache_*"):
        ad_caches.append(f)
    config["ad_hash_caches"] = ad_caches

    return config


# ---------------------------------------------------------------------------
# Attack Tools Present
# ---------------------------------------------------------------------------
def get_attack_tools():
    tools_found = []
    check_tools = [
        "nmap", "gcc", "g++", "gdb", "python", "python3", "perl", "ruby",
        "curl", "wget", "nc", "ncat", "socat", "tcpdump", "tshark", "dumpcap",
        "strace", "ltrace", "gcore", "john", "hashcat", "hydra", "sqlmap",
        "msfconsole", "msfvenom", "responder", "impacket-smbserver",
        "gobuster", "nikto", "wfuzz", "ffuf", "burpsuite",
    ]
    for tool in check_tools:
        path = run(f"command -v {tool} 2>/dev/null")
        if path:
            tools_found.append({"Name": tool, "Path": path.strip()})
    return tools_found


# ---------------------------------------------------------------------------
# Process Environment Variables (all /proc/*/environ)
# ---------------------------------------------------------------------------
def get_all_process_env_vars():
    """Scan /proc/*/environ for sensitive env vars across all processes."""
    sensitive_patterns = [
        "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
        "AWS_ACCESS", "AWS_SECRET", "PRIVATE_KEY", "CREDENTIAL",
        "DB_PASS", "DATABASE_URL", "CONN_STR", "CONNECTION_STRING",
    ]
    findings = []
    for pid_dir in glob.glob("/proc/[0-9]*"):
        environ_path = os.path.join(pid_dir, "environ")
        content = read_file_contents(environ_path)
        if not content:
            continue
        pid = os.path.basename(pid_dir)
        for var in content.split("\x00"):
            if "=" not in var:
                continue
            key = var.split("=", 1)[0].upper()
            for pattern in sensitive_patterns:
                if pattern in key:
                    findings.append({
                        "PID": pid,
                        "Variable": var.split("=", 1)[0],
                        # Don't include the value for security - just flag existence
                    })
                    break
    return findings


# ---------------------------------------------------------------------------
# inetd / xinetd legacy services
# ---------------------------------------------------------------------------
def get_inetd_services():
    entries = []
    for line in read_file_contents("/etc/inetd.conf").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append({"Source": "/etc/inetd.conf", "Entry": line})
    xinetd_dir = "/etc/xinetd.d"
    if os.path.isdir(xinetd_dir):
        for f in os.listdir(xinetd_dir):
            fp = os.path.join(xinetd_dir, f)
            if os.path.isfile(fp):
                entries.append({"Source": fp, "Entry": read_file_contents(fp)})
    return entries


# ---------------------------------------------------------------------------
# R-commands trust files
# ---------------------------------------------------------------------------
def get_rcommands_trust():
    trust_files = {}
    for f in ["/etc/hosts.equiv"]:
        content = read_file_contents(f)
        if content:
            trust_files[f] = content
    for rhosts in glob.glob("/home/*/.rhosts") + glob.glob("/root/.rhosts"):
        content = read_file_contents(rhosts)
        if content:
            trust_files[rhosts] = content
    return trust_files


# ---------------------------------------------------------------------------
# Tmux / Screen Sessions
# ---------------------------------------------------------------------------
def get_terminal_sessions():
    sessions = []
    tmux = run("tmux ls 2>/dev/null")
    if tmux:
        for line in tmux.splitlines():
            sessions.append({"Type": "tmux", "Session": line.strip()})
    screen = run("screen -ls 2>/dev/null")
    if screen:
        for line in screen.splitlines():
            if ".S." in line or "Attached" in line or "Detached" in line:
                sessions.append({"Type": "screen", "Session": line.strip()})
    return sessions


# ---------------------------------------------------------------------------
# Sudo Version (for CVE matching)
# ---------------------------------------------------------------------------
def get_sudo_version():
    return run("sudo -V 2>/dev/null | head -1")


# ---------------------------------------------------------------------------
# Shell History (last 200 lines per user, for credential leak detection)
# ---------------------------------------------------------------------------
def get_shell_history():
    histories = []
    for line in read_file_contents("/etc/passwd").splitlines():
        parts = line.split(":")
        if len(parts) < 6:
            continue
        username = parts[0]
        home = parts[5]
        for hist_file in [".bash_history", ".zsh_history", ".sh_history"]:
            hist_path = os.path.join(home, hist_file)
            content = read_file_contents(hist_path)
            if not content:
                continue
            lines = content.splitlines()
            histories.append({
                "User": username,
                "File": hist_path,
                "TotalLines": len(lines),
                "Last200": lines[-200:] if len(lines) > 200 else lines,
            })
    return histories


# ---------------------------------------------------------------------------
# SSH Private Key Locations
# ---------------------------------------------------------------------------
def get_ssh_private_keys():
    keys = []
    output = run(
        "find /home /root /etc /opt -maxdepth 4 "
        "\\( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' "
        "-o -name '*.pem' -o -name '*.key' \\) "
        "-type f 2>/dev/null",
        timeout=30,
    )
    for line in output.splitlines():
        path = line.strip()
        if not path:
            continue
        try:
            st = os.stat(path)
            keys.append({
                "Path": path,
                "Size": st.st_size,
                "Mode": oct(st.st_mode),
                "Owner": st.st_uid,
            })
        except Exception:
            keys.append({"Path": path})
    return keys


# ---------------------------------------------------------------------------
# Interesting Hidden Files (.env, .netrc, .pgpass, .my.cnf, etc.)
# ---------------------------------------------------------------------------
def get_interesting_hidden_files():
    patterns = [
        ".env", ".netrc", ".pgpass", ".my.cnf", ".s3cfg",
        ".git-credentials", ".docker/config.json", ".kube/config",
        ".npmrc", ".pypirc", ".composer/auth.json",
    ]
    found = []
    search_roots = ["/home", "/root", "/opt", "/var/www", "/srv"]
    for root_dir in search_roots:
        if not os.path.isdir(root_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Limit depth to 5
            depth = dirpath.replace(root_dir, "").count(os.sep)
            if depth > 5:
                dirnames.clear()
                continue
            # Skip noise dirs
            for skip in [".cache", "node_modules", ".git", "__pycache__", ".npm"]:
                if skip in dirnames:
                    dirnames.remove(skip)
            for fname in filenames:
                for pattern in patterns:
                    if fname == pattern or dirpath.endswith(os.path.dirname(pattern)) and fname == os.path.basename(pattern):
                        full = os.path.join(dirpath, fname)
                        try:
                            st = os.stat(full)
                            found.append({
                                "Path": full,
                                "Size": st.st_size,
                                "Mode": oct(st.st_mode),
                            })
                        except Exception:
                            found.append({"Path": full})
    return found


# ---------------------------------------------------------------------------
# Process Binary Permissions (for offline writability analysis)
# ---------------------------------------------------------------------------
def get_process_binary_permissions():
    """Stat the binary of every running process — enables offline writable-binary detection."""
    bins = {}
    for pid_dir in glob.glob("/proc/[0-9]*"):
        try:
            exe = os.readlink(os.path.join(pid_dir, "exe"))
            if "(deleted)" in exe or exe in bins:
                continue
            st = os.stat(exe)
            bins[exe] = {
                "Path": exe,
                "Mode": oct(st.st_mode),
                "UID": st.st_uid,
                "GID": st.st_gid,
                "Size": st.st_size,
            }
        except Exception:
            pass
    return list(bins.values())


# ---------------------------------------------------------------------------
# Systemd Unit File Permissions
# ---------------------------------------------------------------------------
def get_systemd_unit_permissions():
    """Permissions on systemd .service files — writable = persistence hijack."""
    units = []
    output = run(
        "systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null"
    )
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        unit_name = parts[0]
        # Find the unit file path
        unit_path = run(f"systemctl show {unit_name} -p FragmentPath --no-pager 2>/dev/null")
        if "=" in unit_path:
            path = unit_path.split("=", 1)[1].strip()
            if path and os.path.exists(path):
                try:
                    st = os.stat(path)
                    units.append({
                        "Unit": unit_name,
                        "Path": path,
                        "Mode": oct(st.st_mode),
                        "UID": st.st_uid,
                        "GID": st.st_gid,
                    })
                except Exception:
                    pass
    return units


# ---------------------------------------------------------------------------
# Cron Script Permissions
# ---------------------------------------------------------------------------
def get_cron_script_permissions():
    """Permissions on scripts referenced by cron — writable = escalation."""
    scripts = []
    seen = set()
    # Cron directories
    for cron_dir in ["/etc/cron.hourly", "/etc/cron.daily",
                     "/etc/cron.weekly", "/etc/cron.monthly"]:
        if not os.path.isdir(cron_dir):
            continue
        for item in os.listdir(cron_dir):
            full = os.path.join(cron_dir, item)
            if full in seen or not os.path.isfile(full):
                continue
            seen.add(full)
            try:
                st = os.stat(full)
                scripts.append({
                    "Path": full,
                    "Mode": oct(st.st_mode),
                    "UID": st.st_uid,
                    "GID": st.st_gid,
                })
            except Exception:
                pass
    # System crontab entries — extract paths
    for cron_file in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
        content = read_file_contents(cron_file)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Try to extract command path (after the 5 time fields + user field)
            parts = line.split()
            if len(parts) >= 7:
                cmd = parts[6].split()[0] if parts[6] else ""
                if cmd.startswith("/") and cmd not in seen and os.path.exists(cmd):
                    seen.add(cmd)
                    try:
                        st = os.stat(cmd)
                        scripts.append({
                            "Path": cmd,
                            "Source": cron_file,
                            "Mode": oct(st.st_mode),
                            "UID": st.st_uid,
                            "GID": st.st_gid,
                        })
                    except Exception:
                        pass
    return scripts


# ---------------------------------------------------------------------------
# ld.so.conf Parsed Paths with Permissions
# ---------------------------------------------------------------------------
def get_ld_so_conf_permissions():
    """Parsed ld.so.conf paths with stat — writable = shared library injection."""
    paths = []
    seen = set()
    for conf in ["/etc/ld.so.conf"] + glob.glob("/etc/ld.so.conf.d/*"):
        content = read_file_contents(conf)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("include"):
                continue
            if line in seen:
                continue
            seen.add(line)
            if os.path.isdir(line):
                try:
                    st = os.stat(line)
                    paths.append({
                        "Path": line,
                        "ConfigFile": conf,
                        "Mode": oct(st.st_mode),
                        "UID": st.st_uid,
                        "GID": st.st_gid,
                    })
                except Exception:
                    pass
    return paths


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    dns_servers, dns_search_suffixes = get_dns_config()
    file_inventory, file_inventory_errors = get_file_inventory()

    snapshot = {
        "SystemUUID": get_system_uuid(),
        "SnapshotTime": datetime.datetime.now().isoformat(),
        "ComputerInfo": get_computer_info(),
        "DiskVolumes": get_disk_volumes(),
        "NetAdapters": get_net_adapters(),
        "IpAddresses": get_ip_addresses(),
        "DnsServers": dns_servers,
        "DnsSearchSuffixes": dns_search_suffixes,
        "ArpCache": get_arp_cache(),
        "Routes": get_routes(),
        "TcpConnections": get_tcp_connections(),
        "UdpConnections": get_udp_connections(),
        "Processes": get_processes(),
        "Users": get_users(),
        "Groups": get_groups(),
        "Members": get_members(),
        "Shares": get_shares(),
        "SecurityProducts": get_security_products(),
        "LoggedInUsers": get_logged_in_users(),
        "AuditConfig": get_audit_config(),
        "PamConfig": get_pam_config(),
        "Persistence": get_persistence(),
        "SshAuthorizedKeys": get_ssh_authorized_keys(),
        "KernelModules": get_kernel_modules(),
        "InstalledPackages": get_installed_packages(),
        "UserExecutables": get_user_executables(),
        "FileInventory": file_inventory,
        "FileInventoryErrors": file_inventory_errors,
        "SudoersConfig": get_sudoers(),
        "SetuidBinaries": get_suid_binaries(),
        "DockerContainers": get_docker_containers(),
        "FirewallRules": get_firewall_rules(),
        "SecurityModules": get_security_modules(),
        "HostsFile": get_hosts_file(),
        "EnvironmentVariables": dict(os.environ),
        "KernelHardening": get_kernel_hardening(),
        "ContainerInfo": get_container_info(),
        "CloudEnvironment": get_cloud_environment(),
        "SshConfig": get_ssh_config(),
        "FileCapabilities": get_file_capabilities(),
        "WritableCriticalPaths": get_writable_critical_paths(),
        "DeletedExecutables": get_deleted_executables(),
        "Fstab": get_fstab(),
        "DbusServices": get_dbus_services(),
        "UnixSockets": get_unix_sockets(),
        "PrivilegedGroups": get_privileged_groups(),
        "KerberosConfig": get_kerberos_config(),
        "AttackTools": get_attack_tools(),
        "SensitiveProcessEnvVars": get_all_process_env_vars(),
        "InetdServices": get_inetd_services(),
        "RcommandsTrust": get_rcommands_trust(),
        "TerminalSessions": get_terminal_sessions(),
        "SudoVersion": get_sudo_version(),
        "ShellHistory": get_shell_history(),
        "SshPrivateKeys": get_ssh_private_keys(),
        "InterestingHiddenFiles": get_interesting_hidden_files(),
        "ProcessBinaryPermissions": get_process_binary_permissions(),
        "SystemdUnitPermissions": get_systemd_unit_permissions(),
        "CronScriptPermissions": get_cron_script_permissions(),
        "LdSoConfPermissions": get_ld_so_conf_permissions(),
        "CollectionErrors": ERRORS,
    }

    json.dump(snapshot, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
