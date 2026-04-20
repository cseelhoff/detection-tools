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
    """
    Use paramiko for SSH password authentication.

    Sudo strategy: prime sudo's tty credential cache via `sudo -v` at the start
    of a pty-backed session, then exec the collector in the SAME pty. All
    `sudo -n <cmd>` calls inside the collector then succeed without any
    password material ever being stored on the remote host.

    Security properties:
    - Password transits only over the encrypted SSH channel, into sudo's stdin.
    - No COLLECTOR_SUDO_PASS env var (not inherited by children, not visible
      in /proc/<pid>/environ).
    - No `echo $PASS | sudo` shell pipeline (not visible in /proc/<pid>/cmdline,
      not vulnerable to shell injection via passwords containing quotes).
    - Collector script is uploaded via SFTP (not stdin), so the pty channel is
      free for the interactive sudo auth.
    """
    import paramiko
    import time
    import io

    print(f"Connecting to {user}@{host} via paramiko...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, username=user, password=password, timeout=30,
                       allow_agent=False, look_for_keys=False)
    except Exception as e:
        print(f"SSH connection failed: {e}", file=sys.stderr)
        return False

    try:
        # 1. Upload the collector script via SFTP to a private temp path.
        sftp = client.open_sftp()
        remote_script = f'/tmp/.collector_{os.getpid()}_{int(time.time())}.py'
        with sftp.file(remote_script, 'w') as f:
            f.write(script_content)
        sftp.chmod(remote_script, 0o700)
        sftp.close()

        # 2. Open a session channel with a pty. Sudo's default timestamp_type
        #    is "tty" — the credential cache is keyed to the pts device, so
        #    every process in this pty inherits authentication.
        transport = client.get_transport()
        channel = transport.open_session()
        channel.get_pty(term='dumb', width=200, height=50)
        channel.settimeout(600)

        # 3. Bash wrapper:
        #    - Disable tty echo so the password isn't reflected back to us.
        #    - Read the password from stdin into a shell variable (NOT env).
        #    - Pipe it to `sudo -S -v` to prime the credential cache. Echo
        #      is a bash builtin, so no external process carries the password
        #      in its cmdline.
        #    - Unset the shell variable and exec python3. After exec, the
        #      shell's memory is replaced — nothing left for ptrace to find.
        #    - Delete the collector script via a trap (runs even on crash).
        wrapper = (
            f"stty -echo 2>/dev/null; "
            f"trap 'rm -f {remote_script}' EXIT; "
            f"IFS= read -rs _PW || exit 90; "
            f"stty echo 2>/dev/null; "
            f"printf '%s\\n' \"$_PW\" | sudo -S -p '' -v 2>/dev/null; "
            f"_sudo_rc=$?; "
            f"_PW=; unset _PW; "
            f"if [ $_sudo_rc -ne 0 ]; then echo 'SUDO_AUTH_FAILED' >&2; fi; "
            f"exec python3 {remote_script}"
        )
        channel.exec_command(f"bash -c {_shquote(wrapper)}")

        # 4. Send the password as the first (and only) line of stdin.
        channel.sendall((password + "\n").encode("utf-8"))

        # 5. Stream stdout/stderr concurrently until the channel closes.
        out_buf = io.BytesIO()
        err_buf = io.BytesIO()
        while True:
            got_data = False
            if channel.recv_ready():
                out_buf.write(channel.recv(65536))
                got_data = True
            if channel.recv_stderr_ready():
                err_buf.write(channel.recv_stderr(65536))
                got_data = True
            if channel.exit_status_ready() and not got_data:
                # Final drain
                while channel.recv_ready():
                    out_buf.write(channel.recv(65536))
                while channel.recv_stderr_ready():
                    err_buf.write(channel.recv_stderr(65536))
                break
            if not got_data:
                time.sleep(0.05)

        exit_code = channel.recv_exit_status()
        output = out_buf.getvalue().decode("utf-8", errors="replace")
        errors = err_buf.getvalue().decode("utf-8", errors="replace")

        # 6. Pty transforms \n -> \r\n on output. Normalize back so JSON tools
        #    and downstream diffs aren't surprised by stray CRs.
        output = output.replace("\r\n", "\n")

        # 7. Trim any stray leading noise before the JSON begins. With echo
        #    disabled and sudo -p '' the password prompt is silent, so this
        #    should usually be a no-op — but defend against banners / MOTD.
        brace_idx = output.find("{")
        if brace_idx > 0:
            output = output[brace_idx:]

        if "SUDO_AUTH_FAILED" in errors:
            print(f"SUDO_AUTH_FAILED: sudo rejected the password on {host}",
                  file=sys.stderr)

        if errors.strip():
            err_file = output_file.replace(".json", ".err")
            with open(err_file, "w", encoding="utf-8") as f:
                f.write(errors)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)

        try:
            data = json.loads(output)
            fields = len(data.keys()) if isinstance(data, dict) else 0
            hostname = data.get("ComputerInfo", {}).get("Hostname", "?")
            print(f"OK: {host} ({hostname}) -> {output_file} "
                  f"({len(output)//1024} KB, {fields} fields)")
            return True
        except json.JSONDecodeError as e:
            print(f"WARNING: Output is not valid JSON: {e}", file=sys.stderr)
            print(f"  exit={exit_code}  head={output[:300]!r}", file=sys.stderr)
            return False
    finally:
        client.close()


def _shquote(s):
    """Minimal single-quote shell quoting."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


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
