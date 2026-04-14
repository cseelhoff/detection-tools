#!/bin/bash
# collect-snapshots-linux.sh
# Orchestrates remote Linux system snapshot collection via SSH.
#
# Credential resolution (in order):
#   1. inventory.sops.yml (encrypted — requires sops + age-key.txt)
#   2. inventory.yml (plaintext)
#   3. targetHosts.txt with SSH_USER / SSH_KEY env vars (legacy)
#
# Usage:
#   ./collect-snapshots-linux.sh                          # uses inventory
#   SSH_USER=root SSH_KEY=~/.ssh/id_rsa ./collect-snapshots-linux.sh  # legacy
#
# Prerequisites:
#   - SSH access to target hosts
#   - Python 3.6+ on each target
#   - Root/sudo on targets for full data collection
#   - linux-collector.py in the same directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_SCRIPT="${SCRIPT_DIR}/linux-collector.py"
OUTPUT_DIR="${SCRIPT_DIR}"
MAX_CONCURRENT="${MAX_CONCURRENT:-10}"

# -------------------------------------------------------------------------
# Inventory loader
# -------------------------------------------------------------------------
load_inventory() {
    # Try SOPS-encrypted inventory first
    if [ -f "${SCRIPT_DIR}/inventory.sops.yml" ] && command -v sops &>/dev/null; then
        echo "Loading encrypted inventory: inventory.sops.yml"
        INVENTORY_JSON=$(sops --decrypt --output-type json "${SCRIPT_DIR}/inventory.sops.yml" 2>/dev/null) || {
            echo "WARNING: sops decrypt failed, falling back..."
            INVENTORY_JSON=""
        }
    fi

    # Try plaintext inventory
    if [ -z "${INVENTORY_JSON:-}" ] && [ -f "${SCRIPT_DIR}/inventory.yml" ]; then
        echo "Loading plaintext inventory: inventory.yml"
        echo "WARNING: Inventory is NOT encrypted."
        # Convert YAML to JSON using Python
        INVENTORY_JSON=$(python3 -c "
import sys, json
try:
    import yaml
    data = yaml.safe_load(open('${SCRIPT_DIR}/inventory.yml'))
except ImportError:
    # Minimal YAML parser for our schema
    data = {'credentials': {}, 'groups': {}, 'hosts': {}}
    section = ''
    item = ''
    with open('${SCRIPT_DIR}/inventory.yml') as f:
        for line in f:
            stripped = line.rstrip()
            if not stripped or stripped.lstrip().startswith('#'):
                continue
            indent = len(line) - len(line.lstrip())
            if indent == 0 and ':' in stripped:
                section = stripped.split(':')[0].strip()
                continue
            if indent == 2 and ':' in stripped:
                item = stripped.split(':')[0].strip()
                rest = stripped.split(':', 1)[1].strip()
                if section in ('credentials', 'groups', 'hosts'):
                    data[section][item] = {}
                continue
            if indent >= 4 and ':' in stripped and item:
                key = stripped.split(':')[0].strip()
                val = stripped.split(':', 1)[1].strip()
                if section in ('credentials', 'groups', 'hosts'):
                    data[section][item][key] = val
json.dump(data, sys.stdout)
" 2>/dev/null) || INVENTORY_JSON=""
    fi

    # Fallback: legacy targetHosts.txt
    if [ -z "${INVENTORY_JSON:-}" ]; then
        TARGET_HOSTS_FILE="${SCRIPT_DIR}/targetHosts.txt"
        if [ -f "$TARGET_HOSTS_FILE" ]; then
            echo "Falling back to legacy targetHosts.txt"
            # Build a simple JSON structure
            local hosts_json="{"
            hosts_json+='"credentials":{},"groups":{},"hosts":{'
            local first=true
            while IFS= read -r line; do
                [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
                $first || hosts_json+=","
                first=false
                hosts_json+="\"${line}\":{\"platform\":\"linux\"}"
            done < "$TARGET_HOSTS_FILE"
            hosts_json+="}}"
            INVENTORY_JSON="$hosts_json"
        else
            echo "ERROR: No inventory or targetHosts.txt found"
            exit 1
        fi
    fi
}

# -------------------------------------------------------------------------
# Resolve host credentials from inventory JSON
# -------------------------------------------------------------------------
resolve_hosts() {
    # Use Python to resolve the inventory into a flat host list with credentials
    python3 -c "
import json, sys, os

inv = json.loads('''${INVENTORY_JSON}''')
credentials = inv.get('credentials', {})
groups = inv.get('groups', {})
hosts = inv.get('hosts', {})

# Default SSH settings from environment (legacy override)
default_user = os.environ.get('SSH_USER', 'root')
default_key = os.environ.get('SSH_KEY', '')

for hostname, hostdef in hosts.items():
    if not hostdef:
        hostdef = {}
    # Resolve group
    group_name = hostdef.get('group', '')
    group_def = groups.get(group_name, {}) if group_name else {}

    platform = hostdef.get('platform', group_def.get('platform', 'linux'))
    if platform != 'linux':
        continue  # Linux collector only handles linux hosts

    cred_name = hostdef.get('credential', group_def.get('credential', ''))
    cred_def = credentials.get(cred_name, {}) if cred_name else {}

    user = cred_def.get('username', default_user)
    auth_type = cred_def.get('type', 'ssh-key' if default_key else 'ssh-password')
    key_file = cred_def.get('key_file', default_key)
    password = cred_def.get('password', '')

    # Output: hostname|user|auth_type|key_file
    print(f'{hostname}|{user}|{auth_type}|{key_file}')
"
}

# -------------------------------------------------------------------------
# Validate prerequisites
# -------------------------------------------------------------------------
if [ ! -f "$COLLECTOR_SCRIPT" ]; then
    echo "ERROR: Collector script not found: $COLLECTOR_SCRIPT"
    exit 1
fi

load_inventory

# Parse resolved hosts
mapfile -t HOST_LINES < <(resolve_hosts)
TOTAL=${#HOST_LINES[@]}

if [ "$TOTAL" -eq 0 ]; then
    echo "ERROR: No Linux hosts found in inventory"
    exit 1
fi

echo "========================================="
echo " Linux Snapshot Collection"
echo "========================================="
echo " Targets:        $TOTAL hosts"
echo " Max concurrent: $MAX_CONCURRENT"
echo " Output dir:     $OUTPUT_DIR"
echo "========================================="
echo ""

# -------------------------------------------------------------------------
# Collection function (runs in background per host)
# -------------------------------------------------------------------------
collect_host() {
    local host_line="$1"
    local host user auth_type key_file
    IFS='|' read -r host user auth_type key_file <<< "$host_line"

    local output_file="${OUTPUT_DIR}/system-info_${host}.json"
    local error_file="${OUTPUT_DIR}/system-info_${host}.err"

    # Build SSH options per host
    local ssh_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 -o BatchMode=yes"
    if [ "$auth_type" = "ssh-key" ] && [ -n "$key_file" ]; then
        ssh_opts="$ssh_opts -i $key_file"
    fi

    # Pipe the collector script through SSH and capture JSON output
    if ssh $ssh_opts "${user}@${host}" 'python3 -' < "$COLLECTOR_SCRIPT" > "$output_file" 2>"$error_file"; then
        # Quick JSON validation
        if python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$output_file" 2>/dev/null; then
            echo "[OK]   ${host} -> system-info_${host}.json"
            rm -f "$error_file"
            return 0
        else
            echo "[WARN] ${host} - collection returned invalid JSON (see system-info_${host}.err)"
            return 1
        fi
    else
        echo "[FAIL] ${host} - SSH or collection failed (see system-info_${host}.err)"
        return 1
    fi
}

# -------------------------------------------------------------------------
# Parallel execution with concurrency limit
# -------------------------------------------------------------------------
declare -A PIDS=()
COMPLETED=0
FAILED=0

for ((i = 0; i < TOTAL; i++)); do
    host_line="${HOST_LINES[$i]}"
    host="${host_line%%|*}"
    echo "[$((i + 1))/$TOTAL] Starting: $host"

    collect_host "$host_line" &
    PIDS["$host"]=$!

    # Throttle if at max concurrency (wait -n requires bash 4.3+)
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_CONCURRENT" ]; do
        wait -n 2>/dev/null || true
    done
done

# Wait for all remaining background jobs
echo ""
echo "Waiting for remaining collections to finish..."
for host in "${!PIDS[@]}"; do
    if wait "${PIDS[$host]}" 2>/dev/null; then
        COMPLETED=$((COMPLETED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
echo ""
echo "========================================="
echo " Collection Complete"
echo "========================================="
echo " Succeeded: $COMPLETED"
echo " Failed:    $FAILED"
echo " Total:     $TOTAL"
echo "========================================="
echo ""
echo "Output files in: $OUTPUT_DIR/system-info_*.json"
