#!/usr/bin/env python3
"""
ssh-collect-windows.py — Run windows-collector.ps1 on a remote Windows host via SSH.
Uploads the collector script, executes it, and downloads the JSON result.

Usage:
    python ssh-collect-windows.py <host> <user> <password> <collector_script> <output_file>
    python ssh-collect-windows.py 172.17.192.126 localadmin "Pass123" windows-collector.ps1 system-info_172.17.192.126.json
"""
import sys
import os
import json
import subprocess


def collect_via_paramiko(host, user, password, collector_script, output_file):
    """Use paramiko to upload, execute, and download results."""
    try:
        import paramiko
    except ImportError:
        print("Installing paramiko...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'paramiko', '-q'])
        import paramiko

    print(f"Connecting to {user}@{host} via paramiko...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, username=user, password=password, timeout=30)
    except Exception as e:
        print(f"SSH connection failed: {e}", file=sys.stderr)
        return False

    try:
        # Upload the collector script via SFTP
        sftp = client.open_sftp()
        remote_script = "C:/Windows/Temp/windows-collector.ps1"
        remote_output = "C:/Windows/Temp/system-info.json"

        print(f"Uploading {collector_script} -> {remote_script}")
        sftp.put(collector_script, remote_script)

        # Execute the collector
        cmd = f'powershell.exe -ExecutionPolicy Bypass -File "{remote_script}" -OutputDir "C:\\Windows\\Temp"'
        print(f"Running collector on {host}...")
        stdin, stdout, stderr = client.exec_command(cmd, timeout=600)

        # Wait for completion
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')

        if out.strip():
            print(f"Remote stdout: {out.strip()}")
        if err.strip():
            print(f"Remote stderr: {err.strip()}", file=sys.stderr)

        # Download the JSON result
        try:
            sftp.stat(remote_output)
        except FileNotFoundError:
            print(f"Remote output file not found: {remote_output}", file=sys.stderr)
            return False

        print(f"Downloading {remote_output} -> {output_file}")
        sftp.get(remote_output, output_file)

        # Clean up remote files
        try:
            sftp.remove(remote_script)
            sftp.remove(remote_output)
        except Exception:
            pass

        sftp.close()

        # Validate JSON
        try:
            with open(output_file, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)
            fields = len(data.keys()) if isinstance(data, dict) else 0
            size_kb = os.path.getsize(output_file) // 1024
            hostname = data.get('ComputerInfo', {})
            if isinstance(hostname, dict):
                hostname = hostname.get('CsName', '?')
            else:
                hostname = '?'
            print(f"OK: {host} ({hostname}) -> {output_file} ({size_kb} KB, {fields} fields)")
            return True
        except json.JSONDecodeError as e:
            print(f"WARNING: Output is not valid JSON: {e}", file=sys.stderr)
            return False

    finally:
        client.close()


if __name__ == '__main__':
    if len(sys.argv) < 6:
        print(f"Usage: {sys.argv[0]} <host> <user> <password> <collector_script> <output_file>")
        sys.exit(1)

    host = sys.argv[1]
    user = sys.argv[2]
    password = sys.argv[3]
    collector = sys.argv[4]
    output = sys.argv[5]

    success = collect_via_paramiko(host, user, password, collector, output)
    sys.exit(0 if success else 1)
