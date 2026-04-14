#!/bin/bash
# collect-snapshots-linux.sh
# Orchestrates remote Linux system snapshot collection via SSH.
# Equivalent of collect-snapshots.ps1 for Linux targets.
#
# Usage:
#   SSH_USER=root ./collect-snapshots-linux.sh
#   SSH_USER=admin SSH_KEY=~/.ssh/id_rsa ./collect-snapshots-linux.sh
#
# Prerequisites:
#   - SSH access to all target hosts (key-based auth recommended)
#   - Python 3.6+ on each target host
#   - Root/sudo on targets for full data collection
#   - targetHosts.txt with one hostname per line
#   - linux-collector.py in the same directory as this script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_HOSTS_FILE="${SCRIPT_DIR}/targetHosts.txt"
COLLECTOR_SCRIPT="${SCRIPT_DIR}/linux-collector.py"
OUTPUT_DIR="${SCRIPT_DIR}"

MAX_CONCURRENT="${MAX_CONCURRENT:-10}"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 -o BatchMode=yes"

if [ -n "${SSH_KEY:-}" ]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
fi

# -------------------------------------------------------------------------
# Validate prerequisites
# -------------------------------------------------------------------------
if [ ! -f "$TARGET_HOSTS_FILE" ]; then
    echo "ERROR: Target hosts file not found: $TARGET_HOSTS_FILE"
    exit 1
fi
if [ ! -f "$COLLECTOR_SCRIPT" ]; then
    echo "ERROR: Collector script not found: $COLLECTOR_SCRIPT"
    exit 1
fi

# Read targets, skip blank lines and comments
mapfile -t TARGETS < <(grep -v '^\s*$\|^\s*#' "$TARGET_HOSTS_FILE")
TOTAL=${#TARGETS[@]}

if [ "$TOTAL" -eq 0 ]; then
    echo "ERROR: No target hosts found in $TARGET_HOSTS_FILE"
    exit 1
fi

echo "========================================="
echo " Linux Snapshot Collection"
echo "========================================="
echo " Targets:        $TOTAL hosts"
echo " Max concurrent: $MAX_CONCURRENT"
echo " SSH user:       $SSH_USER"
echo " Output dir:     $OUTPUT_DIR"
echo "========================================="
echo ""

# -------------------------------------------------------------------------
# Collection function (runs in background per host)
# -------------------------------------------------------------------------
collect_host() {
    local host="$1"
    local output_file="${OUTPUT_DIR}/system-info_${host}.json"
    local error_file="${OUTPUT_DIR}/system-info_${host}.err"

    # Pipe the collector script through SSH and capture JSON output
    if ssh $SSH_OPTS "${SSH_USER}@${host}" 'python3 -' < "$COLLECTOR_SCRIPT" > "$output_file" 2>"$error_file"; then
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
    host="${TARGETS[$i]}"
    echo "[$((i + 1))/$TOTAL] Starting: $host"

    collect_host "$host" &
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
