#!/usr/bin/env python3
"""
analyze-snapshots.py — Offline PEASS-ng-style security analysis of collected snapshots.

Reads system-info_*.json snapshot files (produced by collect-snapshots.ps1 or
linux-collector.py) and performs comprehensive security posture analysis with
colored output, emulating winPEAS and linPEAS.

Usage:
    python analyze-snapshots.py                          # analyze all snapshots in cwd
    python analyze-snapshots.py system-info_host1.json   # analyze specific snapshot
    python analyze-snapshots.py --no-color               # disable colors
    python analyze-snapshots.py --summary                # one-line-per-host summary only
"""

import json
import sys
import os
import glob
import re

# ============================================================================
# ANSI Colors
# ============================================================================
USE_COLOR = True

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)

def RED(t):      return _c("91", t)
def YELLOW(t):   return _c("93", t)
def GREEN(t):    return _c("92", t)
def BLUE(t):     return _c("94", t)
def MAGENTA(t):  return _c("95", t)
def CYAN(t):     return _c("96", t)
def GRAY(t):     return _c("90", t)
def BOLD(t):     return _c("1", t)
def REDBG(t):    return _c("41;97", t)

# Counters for summary
_counts = {"good": 0, "bad": 0, "warn": 0, "crit": 0, "info": 0}

def _reset_counts():
    for k in _counts:
        _counts[k] = 0

def banner():
    print(MAGENTA(r"""
    ╔══════════════════════════════════════════════════════════╗
    ║     Offline Snapshot Analyzer — PEASS-ng Style          ║
    ║     Defensive Security Posture Assessment               ║
    ╚══════════════════════════════════════════════════════════╝
    """))

def section(title, mitre=""):
    m = f" [{mitre}]" if mitre else ""
    print(f"\n{'='*70}")
    print(MAGENTA(BOLD(f"  ══════════════ {title}{m} ══════════════")))
    print(f"{'='*70}")

def subsection(title, mitre=""):
    m = f" [{mitre}]" if mitre else ""
    print(CYAN(f"\n  ╔══════════╣ {title}{m}"))

def good(msg):
    _counts["good"] += 1
    print(GREEN(f"    [+] {msg}"))

def bad(msg):
    _counts["bad"] += 1
    print(RED(f"    [-] {msg}"))

def warn(msg):
    _counts["warn"] += 1
    print(YELLOW(f"    [!] {msg}"))

def info(msg):
    _counts["info"] += 1
    print(BLUE(f"    [i] {msg}"))

def detail(msg):
    print(f"        {msg}")

def crit(msg):
    _counts["crit"] += 1
    print(REDBG(f"  !! CRITICAL: {msg} !!"))

# ============================================================================
# Helpers
# ============================================================================
def get(data, *keys, default=None):
    obj = data
    for k in keys:
        if isinstance(obj, dict):
            obj = obj.get(k, default)
        elif isinstance(obj, list) and isinstance(k, int) and k < len(obj):
            obj = obj[k]
        else:
            return default
        if obj is None:
            return default
    return obj

def first(val):
    """If val is a list, return first element, else return val."""
    if isinstance(val, list):
        return val[0] if val else {}
    return val or {}

def is_windows(snap):
    ci = first(snap.get("ComputerInfo"))
    return "Windows" in str(ci.get("OsName", "")) or ci.get("CsName") is not None

def regval(snap, path, name=None):
    """Look up value from RegistrySnapshot."""
    for entry in (snap.get("RegistrySnapshot") or []):
        if not isinstance(entry, dict):
            continue
        if path.lower().rstrip("\\") in entry.get("Path", "").lower().rstrip("\\"):
            vals = entry.get("Values", {})
            if name is None:
                return vals
            v = vals.get(name)
            if v is not None:
                return v.get("Value") if isinstance(v, dict) else v
    return None

def sddl_grants_write(sddl, danger_sids=None):
    """Rough check if an SDDL grants write to common low-priv SIDs."""
    if not sddl:
        return False
    if danger_sids is None:
        danger_sids = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"]  # Everyone, AuthUsers, Users
    write_flags = ["WD", "WO", "GA", "GW", "FA", "WDAC"]
    for sid in danger_sids:
        if sid in sddl:
            for wf in write_flags:
                if wf in sddl:
                    return True
    return False

# ============================================================================
# WINDOWS ANALYSIS
# ============================================================================
def analyze_windows(snap):
    # ---- System Info ----
    section("System Information", "T1082")
    subsection("Basic System Info")
    ci = first(snap.get("ComputerInfo"))
    for k in ["CsName", "CsDNSHostName", "CsDomain", "CsManufacturer", "CsModel",
              "OsName", "OsVersion", "OsLastBootUpTime"]:
        detail(f"{k}: {ci.get(k, 'N/A')}")

    subsection("Installed Hotfixes")
    hf = snap.get("InstalledHotfixes") or []
    if not hf:
        warn("No hotfix data — vulnerability assessment limited")
    else:
        info(f"{len(hf)} hotfixes installed")
        try:
            for h in sorted(hf, key=lambda x: str(x.get("InstalledOn", "")), reverse=True)[:5]:
                detail(f"{h.get('HotFixID')} — {h.get('Description', '')} — {h.get('InstalledOn', '')}")
        except Exception:
            pass

    # ---- Security Products ----
    section("Security Products & Defender", "T1562.001")

    subsection("Registered Security Products (SecurityCenter2)")
    for p in (snap.get("SecurityProducts") or []):
        parts = []
        if p.get("Enabled") is True:
            parts.append(GREEN("Enabled"))
        elif p.get("Enabled") is False:
            parts.append(RED("Disabled"))
        if p.get("DefinitionsUpToDate") is False:
            parts.append(RED("Defs outdated"))
        detail(f"{p.get('Type','?')}: {p.get('DisplayName','?')} — {' | '.join(parts)}")

    subsection("Windows Defender Status")
    ds = first(snap.get("DefenderStatus"))
    if ds:
        for k, exp in [("RealTimeProtectionEnabled", True), ("AntivirusEnabled", True),
                        ("BehaviorMonitorEnabled", True), ("OnAccessProtectionEnabled", True),
                        ("AMServiceEnabled", True)]:
            val = ds.get(k)
            (good if val == exp else bad)(f"{k}: {val}")
        mode = ds.get("AMRunningMode")
        if mode and (str(mode).lower() == "passive" or str(mode) == "2"):
            warn(f"Defender in PASSIVE mode")
        # Exclusions
        excl_found = False
        for excl_type in ["Paths", "Extensions", "Processes", "IpAddresses"]:
            path = f"HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\{excl_type}"
            vals = regval(snap, path)
            if vals and isinstance(vals, dict):
                for name in vals:
                    if name not in ("(Default)", "PSPath", "PSParentPath", "PSChildName", "PSProvider"):
                        bad(f"Defender exclusion ({excl_type}): {name}")
                        excl_found = True
        if not excl_found:
            good("No Defender exclusions")
    else:
        warn("No Defender data")

    subsection("ASR Rules")
    asr = first(snap.get("ASRRules"))
    asr_names = {
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from LSASS",
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block Office child processes",
        "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office executable content creation",
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable email content",
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block obfuscated scripts",
        "d1e49aac-8f56-4280-b9ba-993a6d77406c": "Block PSExec/WMI process creation",
        "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block WMI persistence",
        "c1db55ab-c21a-4637-bb3f-a12568109d35": "Advanced ransomware protection",
        "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block vulnerable signed drivers",
    }
    state_map = {"0": "Disabled", "1": "Block", "2": "Audit", "6": "Warn"}
    if not asr or not asr.get("Enabled") or str(asr.get("Enabled")) == "0":
        bad("ASR rules NOT enabled")
    else:
        good("ASR enabled")
        rules = asr.get("Rules") or {}
        for guid, val in rules.items():
            if guid.startswith("PS"):
                continue
            name = asr_names.get(guid.lower(), guid)
            sv = str(val.get("Value") if isinstance(val, dict) else val)
            state = state_map.get(sv, sv)
            fn = good if state == "Block" else (warn if state == "Audit" else bad)
            fn(f"{name}: {state}")

    subsection("AMSI Providers")
    amsi = snap.get("AMSIProviders") or []
    if not amsi:
        warn("No AMSI providers — script scanning may be disabled")
    else:
        for p in amsi:
            good(f"AMSI: {p.get('DllPath', '?')} ({p.get('CLSID', '')})")

    subsection("EDR Services")
    for svc in (snap.get("EDRServices") or []):
        fn = good if str(svc.get("Status", "")).lower() == "running" else bad
        fn(f"{svc.get('DisplayName', svc.get('ServiceName', '?'))}: {svc.get('Status')}")

    # ---- Credential Protection ----
    section("Credential Protection", "T1003")

    subsection("Credential Guard / VBS")
    cg = first(snap.get("CredentialGuardStatus"))
    if cg:
        vbs = cg.get("VirtualizationBasedSecurityStatus")
        running = cg.get("SecurityServicesRunning") or []
        (good if vbs == 2 else bad)(f"VBS status: {vbs}")
        (good if 1 in running else bad)(f"Credential Guard: {'Running' if 1 in running else 'NOT running'}")
    else:
        warn("No Credential Guard data")

    subsection("LSA Protection (RunAsPPL)")
    ppl = regval(snap, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL")
    if ppl and str(ppl) in ("1", "2"):
        good(f"RunAsPPL = {ppl} — LSASS protected")
    else:
        bad("RunAsPPL not set — LSASS is dumpable")

    subsection("WDigest")
    wd = regval(snap, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential")
    if wd and str(wd) == "1":
        crit("WDigest UseLogonCredential=1 — PLAINTEXT PASSWORDS IN MEMORY")
    elif wd and str(wd) == "0":
        good("WDigest disabled")
    else:
        info("UseLogonCredential not set (default disabled on Win≥8.1)")

    subsection("AutoLogon Credentials")
    al = first(snap.get("AutoLogon"))
    if al and al.get("DefaultPassword"):
        crit(f"AutoLogon PASSWORD for '{al.get('DefaultUserName')}' — cleartext in registry!")
    elif al and str(al.get("AutoAdminLogon")) == "1":
        warn(f"AutoAdminLogon enabled for '{al.get('DefaultUserName')}'")
    else:
        good("No AutoLogon credentials")

    subsection("LAPS")
    laps = first(snap.get("LAPSInstalled"))
    if laps and laps.get("DllExists"):
        good("LAPS installed")
    else:
        bad("LAPS NOT installed — local admin passwords may be shared")

    subsection("Cached Credentials (cmdkey)")
    cc = snap.get("CachedCredentials")
    if cc and isinstance(cc, str) and "No stored credentials" not in cc:
        warn("Stored credentials found via cmdkey")
    elif cc and isinstance(cc, list):
        targets = [l for l in cc if "Target:" in str(l)]
        if targets:
            warn(f"{len(targets)} stored credential(s)")

    subsection("DPAPI Keys")
    dk = snap.get("DPAPIKeys") or []
    cred_files = [d for d in dk if "Credentials" in str(d.get("Path", ""))]
    if cred_files:
        warn(f"{len(cred_files)} DPAPI credential file(s)")

    # ---- UAC & Privilege Escalation ----
    section("UAC & Privilege Escalation", "T1548.002")

    subsection("UAC Configuration")
    uac_vals = regval(snap, "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
    if uac_vals and isinstance(uac_vals, dict):
        for k, v in uac_vals.items():
            val = v.get("Value") if isinstance(v, dict) else v
            if k == "EnableLUA":
                (crit if str(val) == "0" else good)(f"EnableLUA = {val}")
            elif k == "ConsentPromptBehaviorAdmin":
                (bad if str(val) == "0" else good)(f"ConsentPromptBehaviorAdmin = {val}")
            elif k == "LocalAccountTokenFilterPolicy":
                if str(val) == "1":
                    bad("LocalAccountTokenFilterPolicy=1 — pass-the-hash enabled")

    subsection("AlwaysInstallElevated")
    aie = first(snap.get("AlwaysInstallElevated"))
    if aie and str(aie.get("HKLM")) == "1" and str(aie.get("HKCU")) == "1":
        crit("AlwaysInstallElevated BOTH set — any user → SYSTEM via MSI!")
    else:
        good("AlwaysInstallElevated not exploitable")

    subsection("Token Privileges")
    dangerous_privs = {"SeImpersonatePrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege",
                       "SeTakeOwnershipPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
                       "SeTcbPrivilege", "SeCreateTokenPrivilege", "SeAssignPrimaryTokenPrivilege"}
    for priv in (snap.get("TokenPrivileges") or []):
        name = priv.get("Privilege Name", priv.get("PrivilegeName", ""))
        state = str(priv.get("State", priv.get("Attributes", "")))
        if name in dangerous_privs:
            fn = bad if "enabled" in state.lower() else warn
            fn(f"{name}: {state}")

    subsection("Service Binary ACLs (writable = privesc)")
    sb_acls = snap.get("ServiceBinaryAcls") or []
    flagged = sum(1 for s in sb_acls if sddl_grants_write(s.get("SDDL", "")))
    if flagged:
        bad(f"{flagged} service binary(ies) may be writable by low-priv users")
    elif sb_acls:
        good(f"Checked {len(sb_acls)} service binaries — none writable")

    subsection("PATH Directory ACLs")
    for p in (snap.get("PathDirAcls") or []):
        if sddl_grants_write(p.get("SDDL", "")):
            bad(f"Writable PATH dir: {p.get('Path')}")

    # ---- Audit & Logging ----
    section("Audit & Logging", "T1562.002")

    subsection("Audit Policies")
    critical_subcats = ["Logon", "Process Creation", "Special Logon",
                        "Security Group Management", "User Account Management"]
    for pol in (snap.get("AuditPolicies") or []):
        subcat = pol.get("Subcategory", "")
        setting = pol.get("Inclusion Setting", "")
        if subcat in critical_subcats:
            fn = bad if "No Auditing" in setting else (good if "Success and Failure" in setting else warn)
            fn(f"{subcat}: {setting}")

    subsection("PowerShell Logging")
    sb = regval(snap, "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "EnableScriptBlockLogging")
    (good if sb and str(sb) == "1" else bad)("ScriptBlock Logging: " + ("Enabled" if sb and str(sb) == "1" else "NOT enabled"))
    ml = regval(snap, "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", "EnableModuleLogging")
    (good if ml and str(ml) == "1" else bad)("Module Logging: " + ("Enabled" if ml and str(ml) == "1" else "NOT enabled"))

    subsection("Sysmon")
    sc = first(snap.get("SysmonConfig"))
    edr_has_sysmon = any(s.get("ServiceName", "").lower().startswith("sysmon") for s in (snap.get("EDRServices") or []))
    if sc or edr_has_sysmon:
        good("Sysmon detected")
    else:
        bad("Sysmon NOT detected")

    subsection("WEF")
    if snap.get("WEFConfig"):
        good("Windows Event Forwarding configured")
    else:
        warn("No WEF — logs not forwarded")

    # ---- Network ----
    section("Network & Remote Access", "T1021")

    subsection("Firewall Profiles")
    for p in (snap.get("FirewallProfiles") or []):
        fn = good if p.get("Enabled") in (True, "True") else bad
        fn(f"{p.get('Name')} profile: {'Enabled' if p.get('Enabled') in (True, 'True') else 'DISABLED'}")

    subsection("RDP")
    rdp = regval(snap, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections")
    if rdp is not None and str(rdp) == "0":
        warn("RDP ENABLED")
    nla = regval(snap, "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "UserAuthentication")
    if nla is not None and str(nla) == "0":
        bad("NLA DISABLED for RDP")

    subsection("SMB Signing")
    sr = regval(snap, "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters", "RequireSecuritySignature")
    cr = regval(snap, "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", "RequireSecuritySignature")
    (good if sr and str(sr) == "1" else bad)(f"SMB Server signing: {'Required' if sr and str(sr) == '1' else 'NOT required'}")
    (good if cr and str(cr) == "1" else bad)(f"SMB Client signing: {'Required' if cr and str(cr) == '1' else 'NOT required'}")

    subsection("Named Pipes (C2 indicators)")
    c2_pats = [r"msagent_", r"MSSE-", r"postex_", r"status_", r"lsadump", r"cachedump",
               r"wceservice", r"\\isapi_", r"demoagent"]
    for p in (snap.get("NamedPipes") or []):
        name = p.get("Name", "") if isinstance(p, dict) else str(p)
        for pat in c2_pats:
            if re.search(pat, name, re.I):
                bad(f"Suspicious pipe: {name}")
                break

    subsection("Connections to external IPs")
    for c in (snap.get("TcpConnections") or []):
        if c.get("State") != "Established":
            continue
        ra = c.get("RemoteAddress", "")
        if ra and not ra.startswith(("10.", "192.168.", "172.", "0.0.0.0", "127.", "::", "::1")):
            detail(f"{c.get('LocalAddress')}:{c.get('LocalPort')} → {ra}:{c.get('RemotePort')} (PID {c.get('OwningProcess')})")

    subsection("Hosts File")
    hf = snap.get("HostsFileContent")
    if hf and str(hf).strip():
        warn("Custom hosts file entries")

    # ---- Persistence ----
    section("Persistence", "T1547")

    subsection("Autoruns (unsigned/unverified)")
    ar = snap.get("Autorunsc") or []
    unsigned = [a for a in ar if "(Verified)" not in str(a.get("Signer", ""))]
    if unsigned:
        warn(f"{len(unsigned)} unsigned autorun(s):")
        for a in unsigned[:15]:
            detail(f"{RED(str(a.get('Signer','Not signed')))} | {a.get('Entry','?')} | {a.get('Image Path','?')}")
    elif ar:
        good(f"All {len(ar)} autoruns verified-signed")

    subsection("Non-Microsoft Scheduled Tasks")
    for t in (snap.get("ScheduledTasks") or [])[:15]:
        detail(f"{t.get('TaskName')} | {t.get('Actions','?')} | RunAs: {t.get('RunAs','?')}")

    subsection("Third-Party Services")
    svcs = snap.get("ThirdPartyServices") or []
    running = [s for s in svcs if s.get("State") == "Running"]
    info(f"{len(running)} running non-MS services")
    for s in running[:10]:
        as_system = "SYSTEM" in str(s.get("StartName", "")).upper()
        detail(f"{s.get('Name')} | {s.get('Company')} | {YELLOW(s.get('StartName','?')) if as_system else s.get('StartName','?')}")

    subsection("Third-Party Kernel Drivers (BYOVD)")
    drivers = snap.get("ThirdPartyDrivers") or []
    if drivers:
        warn(f"{len(drivers)} non-Microsoft kernel drivers")
        for d in drivers[:10]:
            detail(f"{d.get('Name')} | {d.get('Company')} | {d.get('Path')}")

    # ---- Users ----
    section("Users & Sessions", "T1087")
    subsection("Local Users")
    for u in (snap.get("Users") or []):
        en = u.get("Enabled")
        if en in (True, "True"):
            detail(f"{u.get('Name')}: {GREEN('Enabled')} | PwSet: {u.get('PasswordLastSet')}")

    subsection("Logged-On Users")
    for u in (snap.get("LoggedOnUsers") or []):
        detail(f"{u.get('UserName')} | {u.get('SessionName')} | {u.get('State')} | {u.get('LogonTime')}")

    subsection("WinRM/SSH Sessions")
    for s in (snap.get("WinRMSessions") or []):
        if isinstance(s, dict):
            detail(f"WinRM: {s.get('Owner')} from {s.get('ClientIP')}")
    for s in (snap.get("SSHSessions") or []):
        detail(f"SSH: {s.get('UserName')} from {s.get('RemoteAddress')}")

    if snap.get("IsDomainController"):
        subsection("Domain Controller Summary")
        du = snap.get("DomainUsers") or []
        info(f"{len(du)} domain users")
        pw_never = [u for u in du if u.get("PasswordNeverExpires") is True]
        if pw_never:
            warn(f"{len(pw_never)} users with PasswordNeverExpires")

    # ---- Apps ----
    section("Applications & Software", "T1518")
    subsection(".NET Versions (AMSI bypass risk)")
    for v in (snap.get("DotNetVersions") or []):
        ver = v.get("Version", "")
        if ver.startswith(("2.", "3.0", "3.5")):
            warn(f".NET {v.get('PSChildName')} v{ver} — no AMSI")
    subsection("WSL")
    wsl = snap.get("WSLDistributions") or []
    if wsl:
        warn(f"{len(wsl)} WSL distro(s)")
    subsection("AppLocker")
    (good if snap.get("AppLockerPolicy") else warn)("AppLocker: " + ("Configured" if snap.get("AppLockerPolicy") else "NOT configured"))
    subsection("PrintNightmare PointAndPrint")
    pp = first(snap.get("PointAndPrint"))
    if pp and str(pp.get("RestrictDriverInstallationToAdministrators")) == "0":
        bad("RestrictDriverInstallationToAdministrators=0 — PrintNightmare vulnerable")
    if pp and str(pp.get("NoWarningNoElevationOnInstall")) == "1":
        bad("NoWarningNoElevationOnInstall=1 — PrintNightmare exploitable")

    # ---- Credential Exposure ----
    section("Credential Exposure", "T1552")
    subsection("Saved RDP Connections")
    rdp_saved = snap.get("SavedRdpConnections") or []
    if rdp_saved:
        warn(f"{len(rdp_saved)} saved RDP connection(s)")
    subsection("PuTTY Sessions")
    putty = snap.get("PuttySessions") or []
    if putty:
        warn(f"{len(putty)} PuTTY session(s)")
    subsection("SAM/SYSTEM Backups")
    sam = snap.get("SAMBackups") or []
    for s in sam:
        bad(f"Accessible: {s.get('Path')} ({s.get('Size')} bytes)")
    if not sam:
        good("No SAM/SYSTEM backups found")
    subsection("Unattend Files")
    ua = snap.get("UnattendFiles") or []
    for f in ua:
        bad(f"Unattend: {f}")
    subsection("Certificates with Private Keys")
    certs = [c for c in (snap.get("Certificates") or []) if c.get("HasPrivateKey")]
    if certs:
        warn(f"{len(certs)} cert(s) with private keys")
        for c in certs[:5]:
            auth = " [CLIENT AUTH]" if "Client Authentication" in str(c.get("EKU", "")) else ""
            detail(f"{c.get('Subject')} | Exp: {c.get('NotAfter')}{RED(auth) if auth else ''}")
    subsection("PowerShell History (credential leaks)")
    pw_pat = re.compile(r"(password|passwd|secret|token|apikey|convertto-securestring)", re.I)
    for h in (snap.get("PSHistory") or []):
        flagged = [l for l in (h.get("Lines") or []) if pw_pat.search(str(l))]
        if flagged:
            warn(f"User '{h.get('User')}': {len(flagged)} sensitive history lines")
            for fl in flagged[:3]:
                detail(RED(str(fl).strip()[:200]))
    subsection("Cloud Credentials")
    ce = first(snap.get("CloudEnvironment"))
    if ce:
        for cloud in ["AWS", "Azure", "GCP"]:
            if ce.get(cloud):
                info(f"Cloud: {cloud}")
    subsection("Sensitive Environment Variables")
    ev = snap.get("EnvironmentVariables") or {}
    sens = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL|PRIVATE_KEY)", re.I)
    items = ev.items() if isinstance(ev, dict) else [(e.get("Name",""), e.get("Value","")) for e in ev] if isinstance(ev, list) else []
    for k, _ in items:
        if sens.search(str(k)):
            bad(f"Sensitive env var: {k}=***")

# ============================================================================
# LINUX ANALYSIS
# ============================================================================
def analyze_linux(snap):
    # ---- System ----
    section("System Information", "T1082")
    subsection("Basic Info")
    ci = first(snap.get("ComputerInfo"))
    for k in ["Hostname", "FQDN", "OsName", "KernelRelease", "Architecture", "LastBootTime", "MemTotal"]:
        if ci.get(k):
            detail(f"{k}: {ci[k]}")
    sv = snap.get("SudoVersion", "")
    if sv:
        detail(f"Sudo: {sv}")
        if "1.8" in sv or ("1.9.5" in sv and "p1" not in sv):
            bad("Sudo may be vulnerable to CVE-2021-3156")

    subsection("Kernel Hardening")
    kh = snap.get("KernelHardening") or {}
    checks = [("randomize_va_space", "2", "ASLR"), ("kptr_restrict", "1", "Kernel pointer hiding"),
              ("dmesg_restrict", "1", "dmesg restricted"), ("ptrace_scope", "1", "Ptrace restricted"),
              ("protected_symlinks", "1", "Symlink protection"), ("protected_hardlinks", "1", "Hardlink protection")]
    for key, exp, desc in checks:
        val = kh.get(key)
        if val is None:
            info(f"{desc}: N/A")
        elif int(val) >= int(exp):
            good(f"{desc}: {val}")
        else:
            bad(f"{desc}: {RED(str(val))} (should be ≥{exp})")
    if kh.get("virtualization") and kh["virtualization"] != "none":
        info(f"Virtualization: {kh['virtualization']}")

    # ---- Security ----
    section("Security Modules & Products", "T1518.001")
    subsection("SELinux / AppArmor")
    sm = snap.get("SecurityModules") or {}
    sel = sm.get("SELinux")
    if sel:
        mode = sel.get("Mode", "") if isinstance(sel, dict) else str(sel)
        fn = good if "enforcing" in str(mode).lower() else (warn if "permissive" in str(mode).lower() else bad)
        fn(f"SELinux: {mode}")
    aa = sm.get("AppArmor")
    if aa:
        good("AppArmor: Active")
    if not sel and not aa:
        bad("No mandatory access control (SELinux/AppArmor)")

    subsection("Security Products / EDR")
    sp = snap.get("SecurityProducts") or []
    if not sp:
        warn("No security products detected")
    for p in sp:
        fn = good if p.get("ServiceStatus") == "active" else bad
        fn(f"{p.get('Name', '?')}: {p.get('ServiceStatus', '?')}")

    # ---- Users ----
    section("Users & Authentication", "T1087")
    subsection("Interactive Users")
    for u in (snap.get("Users") or []):
        if u.get("InteractiveLogin"):
            flag = RED if u.get("UID") == 0 and u.get("Name") != "root" else lambda x: x
            status = u.get("PasswordStatus", "")
            if status == "no-password":
                bad(f"{u.get('Name')} (UID {u.get('UID')}): NO PASSWORD")
            else:
                detail(f"{flag(u.get('Name','?'))} | UID:{u.get('UID')} | Shell:{u.get('Shell')} | PW:{status}")

    subsection("Privileged Groups")
    pg = snap.get("PrivilegedGroups") or {}
    uid0 = pg.get("uid0_users", [])
    if len(uid0) > 1:
        bad(f"Multiple UID 0 users: {', '.join(uid0)}")
    for grp in ["docker", "lxd", "lxc", "disk"]:
        members = pg.get(grp, [])
        if members:
            bad(f"Group '{grp}' (root-equivalent): {', '.join(members)}")
    for grp in ["sudo", "wheel"]:
        members = pg.get(grp, [])
        if members:
            warn(f"Group '{grp}': {', '.join(members)}")

    subsection("Sudoers (NOPASSWD)")
    for entry in (snap.get("SudoersConfig") or []):
        line = entry.get("Entry", "") if isinstance(entry, dict) else str(entry)
        if "NOPASSWD" in line:
            bad(f"NOPASSWD: {line}")

    subsection("SSH Server Config")
    settings = (snap.get("SshConfig") or {}).get("SshdSettings") or {}
    for key, bad_vals in [("PermitRootLogin", ["yes"]), ("PasswordAuthentication", ["yes"]),
                          ("PermitEmptyPasswords", ["yes"])]:
        val = settings.get(key, "").lower()
        if val in bad_vals:
            bad(f"{key}: {RED(val)}")
        elif val:
            good(f"{key}: {val}")

    subsection("SSH Authorized Keys")
    keys = snap.get("SshAuthorizedKeys") or []
    if keys:
        info(f"{len(keys)} authorized key(s)")

    subsection("PAM / Password Policy")
    pc = snap.get("PamConfig") or {}
    ld = pc.get("LoginDefs") or {}
    enc = ld.get("ENCRYPT_METHOD")
    if enc:
        fn = good if enc.upper() in ("SHA512", "YESCRYPT") else warn
        fn(f"ENCRYPT_METHOD: {enc}")
    max_days = ld.get("PASS_MAX_DAYS")
    if max_days and int(max_days) > 365:
        warn(f"PASS_MAX_DAYS = {max_days}")

    # ---- Persistence ----
    section("Persistence", "T1547")
    subsection("Persistence Summary")
    pers = snap.get("Persistence") or []
    types = {}
    for p in pers:
        t = p.get("Type", "?")
        types[t] = types.get(t, 0) + 1
    for t, c in sorted(types.items()):
        info(f"{t}: {c}")
    user_crons = [p for p in pers if p.get("Type") == "cron-user"]
    if user_crons:
        warn(f"{len(user_crons)} user crontab entries")

    subsection("Cron Script Permissions")
    for s in (snap.get("CronScriptPermissions") or []):
        mode = s.get("Mode", "")
        if mode:
            try:
                mode_int = int(mode, 8)
                if mode_int & 0o002:
                    bad(f"World-writable cron script: {s.get('Path')}")
            except (ValueError, TypeError):
                pass

    # ---- Processes ----
    section("Processes & Services", "T1057")
    subsection("Summary")
    procs = snap.get("Processes") or []
    info(f"{len(procs)} processes")

    subsection("Deleted Executables Still Running")
    de = snap.get("DeletedExecutables") or []
    if de:
        for d in de:
            crit(f"PID {d.get('PID')}: {d.get('DeletedExe')}")
    else:
        good("No deleted executables running")

    subsection("Attack Tools Present")
    offensive = {"nmap", "john", "hashcat", "hydra", "sqlmap", "msfconsole", "msfvenom",
                 "responder", "gobuster", "nikto", "wfuzz", "ffuf"}
    compilers = {"gcc", "g++", "gdb", "make"}
    for t in (snap.get("AttackTools") or []):
        name = t.get("Name", "")
        if name in offensive:
            bad(f"Offensive tool: {name} at {t.get('Path')}")
        elif name in compilers:
            warn(f"Compiler: {name}")

    # ---- File Permissions ----
    section("File Permissions & Capabilities", "T1548")
    subsection("SUID/SGID (dangerous)")
    dangerous = {"nmap", "vim", "find", "bash", "sh", "python", "python3", "perl",
                 "php", "env", "awk", "less", "dd", "docker", "pkexec", "systemctl"}
    for b in (snap.get("SetuidBinaries") or []):
        if os.path.basename(b.get("Path", "")) in dangerous:
            bad(f"Dangerous SUID: {b.get('Path')}")

    subsection("File Capabilities")
    dangerous_caps = ["cap_setuid", "cap_sys_admin", "cap_dac_override", "cap_sys_ptrace"]
    for c in (snap.get("FileCapabilities") or []):
        for dc in dangerous_caps:
            if dc in str(c.get("Capabilities", "")).lower():
                bad(f"{c.get('Path')}: {RED(c.get('Capabilities'))}")
                break

    subsection("Writable Critical Paths")
    for p in (snap.get("WritableCriticalPaths") or []):
        pt = p.get("Type", "")
        if pt == "etc_passwd":
            crit("/etc/passwd is WRITABLE!")
        elif pt == "etc_shadow":
            crit("/etc/shadow is WRITABLE!")
        elif pt == "PATH_dir":
            bad(f"Writable PATH dir: {p.get('Path')}")
        elif pt == "ld_so_path":
            bad(f"Writable lib path: {p.get('Path')}")

    subsection("Process Binary Permissions")
    for p in (snap.get("ProcessBinaryPermissions") or []):
        mode = p.get("Mode", "")
        try:
            if int(mode, 8) & 0o002:
                bad(f"World-writable process binary: {p.get('Path')}")
        except (ValueError, TypeError):
            pass

    subsection("Systemd Unit Permissions")
    for s in (snap.get("SystemdUnitPermissions") or []):
        mode = s.get("Mode", "")
        try:
            if int(mode, 8) & 0o002:
                bad(f"World-writable unit: {s.get('Path')}")
        except (ValueError, TypeError):
            pass

    # ---- Network ----
    section("Network", "T1016")
    subsection("Listening Services")
    tcp = snap.get("TcpConnections") or []
    listening = [c for c in tcp if "LISTEN" in str(c.get("State", "")).upper() or "LISTEN" in str(c.get("State", ""))]
    info(f"{len(listening)} listening TCP services")
    for c in listening[:15]:
        detail(f"{c.get('LocalAddress')}:{c.get('LocalPort')} ({c.get('ProcessName', c.get('ProcessId', '?'))})")

    subsection("Firewall")
    fw = snap.get("FirewallRules") or {}
    if not fw:
        bad("No firewall rules configured")
    else:
        for name in fw:
            good(f"{name}: active")

    subsection("Hosts File (custom)")
    for h in (snap.get("HostsFile") or []):
        ip = h.get("IPAddress", "")
        if ip not in ("127.0.0.1", "::1"):
            detail(f"{ip} → {', '.join(h.get('Hostnames', []))}")

    # ---- Container & Cloud ----
    section("Container & Cloud", "T1613")
    ci = snap.get("ContainerInfo") or {}
    if ci.get("inside_container"):
        warn(f"Inside a {ci.get('container_type', '?')} container")
    for s in (ci.get("docker_sockets") or []):
        if s.get("Writable"):
            crit(f"Writable Docker socket: {s.get('Path')}")
    ce = snap.get("CloudEnvironment") or {}
    if ce.get("provider"):
        info(f"Cloud: {ce['provider']}")
    for c in (ce.get("credential_files") or []):
        bad(f"Cloud creds: {c.get('Path')}")

    # ---- Credential Exposure ----
    section("Credential Exposure", "T1552")
    subsection("Shell History")
    pw_pat = re.compile(r"(password|passwd|secret|token|mysql.*-p|curl.*-u)", re.I)
    for h in (snap.get("ShellHistory") or []):
        flagged = [l for l in (h.get("Last200") or []) if pw_pat.search(str(l))]
        if flagged:
            warn(f"User '{h.get('User')}': {len(flagged)} sensitive lines")

    subsection("SSH Private Keys")
    pk = snap.get("SshPrivateKeys") or []
    if pk:
        warn(f"{len(pk)} private key file(s)")
        for k in pk[:5]:
            detail(f"{k.get('Path')} | Mode: {k.get('Mode')}")

    subsection("Interesting Hidden Files")
    for f in (snap.get("InterestingHiddenFiles") or [])[:10]:
        warn(f"{f.get('Path')} ({f.get('Size', '?')} bytes)")

    subsection("Kerberos")
    kc = snap.get("KerberosConfig") or {}
    for k in (kc.get("keytab_files") or []):
        bad(f"Keytab: {k.get('Path')}")
    for c in (kc.get("ad_hash_caches") or []):
        bad(f"AD cache: {c}")

    subsection("Sensitive Process Env Vars")
    se = snap.get("SensitiveProcessEnvVars") or []
    if se:
        warn(f"{len(se)} processes with sensitive env vars")

    # ---- Audit ----
    section("Audit & Logging", "T1562.002")
    ac = snap.get("AuditConfig") or {}
    rules = ac.get("AuditRules") or []
    if rules:
        good(f"auditd: {len(rules)} rules")
    else:
        bad("No audit rules configured")

    # ---- Misc ----
    section("Miscellaneous", "T1082")
    subsection("fstab Mount Options")
    for entry in (snap.get("Fstab") or []):
        mp = entry.get("MountPoint", "")
        opts = entry.get("Options", "")
        if mp in ("/tmp", "/var/tmp", "/dev/shm"):
            missing = []
            if "nosuid" not in opts:
                missing.append("nosuid")
            if "noexec" not in opts:
                missing.append("noexec")
            if missing:
                warn(f"{mp}: missing {', '.join(missing)}")

    subsection("inetd/xinetd")
    inet = snap.get("InetdServices") or []
    if inet:
        bad(f"{len(inet)} legacy inetd services")

    subsection("R-Commands Trust")
    rt = snap.get("RcommandsTrust") or {}
    for path in rt:
        bad(f"Trust file: {path}")

    subsection("Terminal Sessions")
    ts = snap.get("TerminalSessions") or []
    if ts:
        info(f"{len(ts)} tmux/screen sessions")

# ============================================================================
# MAIN
# ============================================================================
def analyze_snapshot(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            snap = json.load(f)
    except Exception as e:
        print(RED(f"Error loading {filepath}: {e}"))
        return

    hostname = os.path.basename(filepath).replace("system-info_", "").replace(".json", "")
    snap_time = snap.get("SnapshotTime", "unknown")
    _reset_counts()

    print(f"\n{'#'*70}")
    print(BOLD(CYAN(f"  HOST: {hostname}")))
    print(BOLD(CYAN(f"  Snapshot: {snap_time}")))
    print(f"{'#'*70}")

    if is_windows(snap):
        info("Platform: Windows")
        analyze_windows(snap)
    else:
        info("Platform: Linux")
        analyze_linux(snap)

    # Summary
    print(f"\n{'='*70}")
    print(BOLD("  SUMMARY"))
    print(f"{'='*70}")
    print(f"    {RED(str(_counts['crit']))} critical  |  {RED(str(_counts['bad']))} bad  |  "
          f"{YELLOW(str(_counts['warn']))} warnings  |  {GREEN(str(_counts['good']))} good  |  "
          f"{BLUE(str(_counts['info']))} info")
    print(f"{'='*70}\n")


def main():
    global USE_COLOR
    flags = [a for a in sys.argv[1:] if a.startswith("-")]
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--no-color" in flags:
        USE_COLOR = False
    summary_only = "--summary" in flags

    banner()

    files = args if args else sorted(glob.glob("system-info_*.json"))
    if not files:
        print(RED("No system-info_*.json files found."))
        print("Usage: python analyze-snapshots.py [file1.json ...]")
        sys.exit(1)

    print(f"Found {len(files)} snapshot(s)\n")

    if summary_only:
        for f in files:
            try:
                snap = json.load(open(f, encoding="utf-8", errors="replace"))
                hostname = os.path.basename(f).replace("system-info_", "").replace(".json", "")
                platform = "Windows" if is_windows(snap) else "Linux"
                print(f"  {hostname} ({platform}) — {snap.get('SnapshotTime', '?')}")
            except Exception as e:
                print(RED(f"  {f}: {e}"))
    else:
        for f in files:
            if os.path.isfile(f):
                analyze_snapshot(f)
            else:
                print(RED(f"File not found: {f}"))


if __name__ == "__main__":
    main()
