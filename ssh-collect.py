#!/usr/bin/env python3
"""
ssh-collect.py — Pipe linux-collector.py to a remote host via SSH with password auth.
Handles password authentication non-interactively.

Usage:
    python ssh-collect.py <host> <user> <password> <collector_script> <output_file>
    python ssh-collect.py 10.10.11.32 root Admin1Admin1 linux-collector.py system-info_10.10.11.32.json

Can also use SSH key:
    python ssh-collect.py <host> <user> KEY:<key_path> <collector_script> <output_file>
"""
import sys
import os
import subprocess
import json

def collect_via_ssh(host, user, auth, collector_script, output_file):
    """Run collector script on remote host via SSH, save JSON output."""
    
    # Read the collector script
    with open(collector_script, 'r') as f:
        script_content = f.read()
    
    is_key = auth.startswith('KEY:')
    
    if is_key:
        key_path = auth[4:]
        ssh_cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'ConnectTimeout=30',
            '-o', 'BatchMode=yes',
            '-i', key_path,
            f'{user}@{host}',
            'python3 -'
        ]
    else:
        # Password auth — try sshpass first, fall back to paramiko
        sshpass = None
        for p in ['sshpass', 'sshpass.exe']:
            try:
                subprocess.run([p, '-V'], capture_output=True, timeout=5)
                sshpass = p
                break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        if sshpass:
            ssh_cmd = [
                sshpass, '-p', auth,
                'ssh',
                '-o', 'StrictHostKeyChecking=accept-new',
                '-o', 'ConnectTimeout=30',
                f'{user}@{host}',
                'python3 -'
            ]
        else:
            # Use paramiko if available
            try:
                import paramiko
                return collect_via_paramiko(host, user, auth, script_content, output_file)
            except ImportError:
                # Last resort: use Python's subprocess with stdin piping
                # On Windows, ssh.exe can accept password via environment with some tricks
                # But the most reliable cross-platform way is to install paramiko
                print(f"Installing paramiko for SSH password auth...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', 'paramiko', '-q'])
                import paramiko
                return collect_via_paramiko(host, user, auth, script_content, output_file)
    
    # Run SSH command
    print(f"Connecting to {user}@{host}...")
    proc = subprocess.run(
        ssh_cmd,
        input=script_content.encode('utf-8'),
        capture_output=True,
        timeout=600  # 10 minute timeout for collection
    )
    
    if proc.returncode != 0:
        stderr = proc.stderr.decode('utf-8', errors='replace')
        print(f"SSH failed (exit {proc.returncode}): {stderr}", file=sys.stderr)
        return False
    
    # Write output
    stdout = proc.stdout.decode('utf-8', errors='replace')
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(stdout)
    
    # Validate JSON
    try:
        data = json.loads(stdout)
        fields = len(data.keys()) if isinstance(data, dict) else 0
        hostname = data.get('ComputerInfo', {}).get('Hostname', '?')
        print(f"OK: {host} ({hostname}) -> {output_file} ({len(stdout)//1024} KB, {fields} fields)")
        return True
    except json.JSONDecodeError as e:
        print(f"WARNING: Output is not valid JSON: {e}", file=sys.stderr)
        return False


def collect_via_paramiko(host, user, password, script_content, output_file):
    """Use paramiko for SSH password authentication."""
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
        stdin, stdout, stderr = client.exec_command('python3 -', timeout=600)
        stdin.write(script_content)
        stdin.channel.shutdown_write()
        
        output = stdout.read().decode('utf-8', errors='replace')
        errors = stderr.read().decode('utf-8', errors='replace')
        
        if errors:
            # Write errors to .err file
            err_file = output_file.replace('.json', '.err')
            with open(err_file, 'w') as f:
                f.write(errors)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        
        # Validate
        try:
            data = json.loads(output)
            fields = len(data.keys()) if isinstance(data, dict) else 0
            hostname = data.get('ComputerInfo', {}).get('Hostname', '?')
            print(f"OK: {host} ({hostname}) -> {output_file} ({len(output)//1024} KB, {fields} fields)")
            return True
        except json.JSONDecodeError as e:
            print(f"WARNING: Output is not valid JSON: {e}", file=sys.stderr)
            return False
    finally:
        client.close()


if __name__ == '__main__':
    if len(sys.argv) < 6:
        print(f"Usage: {sys.argv[0]} <host> <user> <password|KEY:path> <collector_script> <output_file>")
        sys.exit(1)
    
    host = sys.argv[1]
    user = sys.argv[2]
    auth = sys.argv[3]
    collector = sys.argv[4]
    output = sys.argv[5]
    
    success = collect_via_ssh(host, user, auth, collector, output)
    sys.exit(0 if success else 1)
