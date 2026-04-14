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
def get_system_uuid():
    uuid = read_file_contents("/sys/class/dmi/id/product_uuid")
    if not uuid:
        uuid = run("dmidecode -s system-uuid 2>/dev/null")
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

    # Parse /etc/shadow for password status
    for line in read_file_contents("/etc/shadow").splitlines():
        parts = line.split(":")
        if len(parts) >= 9:
            pw = parts[1]
            shadow[parts[0]] = {
                "PasswordLocked": pw.startswith("!") or pw.startswith("*") or pw == "!!",
                "PasswordStatus": "locked" if (pw.startswith("!") or pw.startswith("*")) else (
                    "no-password" if pw == "" else "set"
                ),
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
        for entry in os.listdir(cron_dir):
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
# Sudoers Configuration
# ---------------------------------------------------------------------------
def get_sudoers():
    entries = []

    for sudoers_file in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
        if not os.path.isfile(sudoers_file):
            continue
        content = read_file_contents(sudoers_file)
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

    iptables = run("iptables -L -n -v --line-numbers 2>/dev/null")
    if iptables:
        rules["iptables"] = iptables

    ip6tables = run("ip6tables -L -n -v --line-numbers 2>/dev/null")
    if ip6tables:
        rules["ip6tables"] = ip6tables

    nft = run("nft list ruleset 2>/dev/null")
    if nft:
        rules["nftables"] = nft

    firewalld = run("firewall-cmd --list-all-zones 2>/dev/null")
    if firewalld:
        rules["firewalld"] = firewalld

    ufw = run("ufw status verbose 2>/dev/null")
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
# Main
# ---------------------------------------------------------------------------
def main():
    dns_servers, dns_search_suffixes = get_dns_config()

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
        "SudoersConfig": get_sudoers(),
        "SetuidBinaries": get_suid_binaries(),
        "DockerContainers": get_docker_containers(),
        "FirewallRules": get_firewall_rules(),
        "SecurityModules": get_security_modules(),
        "HostsFile": get_hosts_file(),
        "CollectionErrors": ERRORS,
    }

    json.dump(snapshot, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
