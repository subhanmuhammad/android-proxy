#!/usr/bin/env bash
#
# Android Proxy Tool - Route app traffic to Burp Suite using iptables
# Bash port of android_proxy.py (requires a rooted device and adb in PATH).
#
set -u

DIP="127.0.0.1"
DEFAULT_PORT="8082"

# ---------------------------------------------------------------------------
# ADB helpers
# ---------------------------------------------------------------------------

require_adb() {
    if ! command -v adb >/dev/null 2>&1; then
        echo "Error: 'adb' command not found. Ensure Android SDK platform-tools are in your PATH."
        exit 1
    fi
}

check_adb_connection() {
    local output devices unauthorized offline
    output="$(adb devices)"

    # Drop the "List of devices attached" header and any blank lines.
    devices="$(echo "$output" | tail -n +2 | grep -v '^[[:space:]]*$' || true)"

    if [ -z "$devices" ]; then
        echo "Error: No Android devices or emulators found. Please connect your device and try again."
        exit 1
    fi

    unauthorized="$(echo "$devices" | grep -c 'unauthorized' || true)"
    offline="$(echo "$devices" | grep -c 'offline' || true)"

    if [ "$unauthorized" -gt 0 ]; then
        echo "Error: Device is unauthorized. Please look at your phone screen and allow USB debugging."
        exit 1
    elif [ "$offline" -gt 0 ]; then
        echo "Error: Connected device is offline. Try restarting your phone's USB debugging or the ADB server."
        exit 1
    fi
}

# Echoes a root prefix (may be empty) used to wrap device-side commands.
get_adb_shell_prefix() {
    local who su_path
    who="$(adb shell whoami 2>/dev/null)"
    if echo "$who" | grep -q 'root'; then
        echo ""
        return
    fi

    su_path="$(adb shell which su 2>/dev/null)"
    if echo "$su_path" | grep -q '/system/bin/su'; then
        echo "su -c"
    else
        echo "su root sh -c"
    fi
}

# Runs an iptables command on the device with proper privilege wrapping.
# Usage: execute_iptables_cmd "<iptables args>"
# Captures stdout+stderr into IPT_OUTPUT and return code into IPT_CODE.
execute_iptables_cmd() {
    local iptables_args="$1"
    local prefix full_cmd
    prefix="$(get_adb_shell_prefix)"

    local iptables_str="iptables ${iptables_args}"

    if [ -n "$prefix" ]; then
        # Wrap the iptables invocation in single quotes for su -c / sh -c.
        full_cmd="${prefix} '${iptables_str}'"
    else
        full_cmd="${iptables_str}"
    fi

    IPT_OUTPUT="$(adb shell "$full_cmd" 2>&1)"
    IPT_CODE=$?
}

# ---------------------------------------------------------------------------
# Package <-> UID mapping
# ---------------------------------------------------------------------------

get_uid_from_pkg() {
    local pkg="$1" line uid
    line="$(adb shell pm list packages -U | grep "$pkg" | head -n 1)"
    uid="$(echo "$line" | grep -o 'uid:[0-9]\+' | head -n 1 | cut -d: -f2)"

    if [ -z "$uid" ]; then
        echo "Error: Cannot find UID for package '$pkg'" >&2
        exit 1
    fi
    echo "$uid"
}

get_pkg_from_uid() {
    local uid="$1" line pkg
    line="$(adb shell pm list packages -U | grep "uid:${uid}\b" | head -n 1)"
    pkg="$(echo "$line" | grep -o 'package:[^ ]\+' | head -n 1 | cut -d: -f2)"

    if [ -z "$pkg" ]; then
        echo "UID: ${uid}"
    else
        echo "$pkg"
    fi
}

# ---------------------------------------------------------------------------
# Core actions
# ---------------------------------------------------------------------------

enable_proxy() {
    local pkg="$1" port="$2"
    local target_uid="" iptables_args

    if [ -n "$pkg" ]; then
        target_uid="$(get_uid_from_pkg "$pkg")"
        echo "Targeting UID: ${target_uid} for app: ${pkg}"
        iptables_args="-t nat -A OUTPUT -p tcp -m owner --uid-owner ${target_uid} -j DNAT --to-destination ${DIP}:${port}"
    else
        echo "Targeting global Android traffic (excluding port 27042)..."
        iptables_args="-t nat -A OUTPUT -p tcp ! --dport 27042 -j DNAT --to-destination ${DIP}:${port}"
    fi

    if ! adb reverse "tcp:${port}" "tcp:${port}" >/dev/null 2>&1; then
        echo "Warning: Failed to set adb reverse for port ${port}"
    fi

    execute_iptables_cmd "$iptables_args"
    if [ "$IPT_CODE" -eq 0 ]; then
        echo "Proxy active → ${DIP}:${port}"
    else
        echo "Error applying proxy rules: $(echo "$IPT_OUTPUT" | xargs)"
    fi
}

# Populates parallel arrays RULE_TARGET, RULE_PORT, RULE_DELETE.
parse_active_proxies() {
    RULE_TARGET=()
    RULE_PORT=()
    RULE_DELETE=()

    execute_iptables_cmd "-t nat -S OUTPUT"
    if [ "$IPT_CODE" -ne 0 ]; then
        echo "Failed to fetch active iptables rules."
        return 1
    fi

    local line port uid delete_args display_target
    while IFS= read -r line; do
        echo "$line" | grep -q 'DNAT --to-destination' || continue

        port="$(echo "$line" | grep -oE -- '--to-destination [0-9.]+:[0-9]+' | grep -oE '[0-9]+$')"
        [ -z "$port" ] && continue

        uid="$(echo "$line" | grep -oE -- '--uid-owner [0-9]+' | grep -oE '[0-9]+')"

        if [ -n "$uid" ]; then
            delete_args="-t nat -D OUTPUT -p tcp -m owner --uid-owner ${uid} -j DNAT --to-destination ${DIP}:${port}"
            display_target="$(get_pkg_from_uid "$uid")"
        else
            delete_args="-t nat -D OUTPUT -p tcp ! --dport 27042 -j DNAT --to-destination ${DIP}:${port}"
            display_target="Global (All Apps)"
        fi

        RULE_TARGET+=("$display_target")
        RULE_PORT+=("$port")
        RULE_DELETE+=("$delete_args")
    done <<< "$IPT_OUTPUT"

    return 0
}

list_proxies() {
    parse_active_proxies || return 1

    if [ "${#RULE_TARGET[@]}" -eq 0 ]; then
        echo "No active proxy rules found."
        return 1
    fi

    echo ""
    echo "=== Active Proxy Rules ==="
    printf "%-5s %-40s %-15s\n" "No." "Target (Package / Scope)" "Burp Proxy Port"
    printf -- '-%.0s' {1..65}; echo ""
    local i
    for i in "${!RULE_TARGET[@]}"; do
        printf "%-5s %-40s %-15s\n" "$((i + 1))" "${RULE_TARGET[$i]}" "${RULE_PORT[$i]}"
    done
    echo ""
    return 0
}

disable_proxy_interactive() {
    list_proxies || return

    local choice idx port
    read -r -p "Enter the number of the proxy rule you want to REMOVE (or 'q' to quit): " choice
    choice="$(echo "$choice" | xargs)"

    if [ -z "$choice" ] || [ "$choice" = "q" ] || [ "$choice" = "Q" ]; then
        return
    fi

    if ! echo "$choice" | grep -qE '^[0-9]+$'; then
        echo "Invalid input. Please enter a number."
        return
    fi

    idx=$((choice - 1))
    if [ "$idx" -ge 0 ] && [ "$idx" -lt "${#RULE_TARGET[@]}" ]; then
        port="${RULE_PORT[$idx]}"
        execute_iptables_cmd "${RULE_DELETE[$idx]}"
        if [ "$IPT_CODE" -eq 0 ]; then
            adb reverse --remove "tcp:${port}" >/dev/null 2>&1
            echo "Successfully removed proxy rule for Port ${port}!"
        else
            echo "Failed to remove iptables rule: $(echo "$IPT_OUTPUT" | xargs)"
        fi
    else
        echo "Invalid selection."
    fi
}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

usage() {
    cat <<'EOF'
Android Proxy Tool - Route app traffic to Burp Suite using iptables

Usage:
  android_proxy.sh (-s | -l | -r) [-u PACKAGE] [-p PORT]

Actions (mutually exclusive):
  -s, --start      Start proxy routing (uses -p/--port)
  -l, --list       List active proxy rules
  -r, --remove     Interactively list and remove a proxy rule

Options:
  -u, --package    Target specific Android package name (OMIT for global proxy)
  -p, --port       Local Burp Suite proxy port (default: 8082)
  -h, --help       Show this help message
EOF
}

main() {
    local action="" pkg="" port="$DEFAULT_PORT"

    while [ $# -gt 0 ]; do
        case "$1" in
            -s|--start)   action="start" ;;
            -l|--list)    action="list" ;;
            -r|--remove)  action="remove" ;;
            -u|--package) shift; pkg="${1:-}" ;;
            -p|--port)    shift; port="${1:-}" ;;
            -h|--help)    usage; exit 0 ;;
            *)
                echo "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    if [ -z "$action" ]; then
        usage
        exit 0
    fi

    require_adb
    check_adb_connection

    case "$action" in
        start)  enable_proxy "$pkg" "$port" ;;
        list)   list_proxies ;;
        remove) disable_proxy_interactive ;;
    esac
}

main "$@"
