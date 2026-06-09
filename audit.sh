#!/bin/bash

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
results_file="baseline-results.txt"
pass() {
    ((PASS_COUNT++))
    printf '\033[32mOK\033[0m %s\n' "$*"
}
fail() {
    ((FAIL_COUNT++))
    printf '\033[31mFAIL\033[0m %s\n' "$*"
}
warn() {
    ((WARN_COUNT++))
    printf '\033[33mWARN\033[0m %s\n' "$*"
}
require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        fail "$1 is not installed"
        return 1
    }
}
check_results_file() {
    if [[ -e "$results_file" ]]; then
        rm -f "$results_file"
    else
        touch "$results_file"
    fi
}
add_date_time(){
        echo "Hostname: $(hostname)" >> "$results_file"
        echo "Date: $(date)" >> "$results_file"
        echo "Kernel: $(uname -r)" >> "$results_file"
}
check() {
    local mask=$1
    local file=$2
    local grp=$3

    if [[ ! -e "$file" ]]; then
        warn "$file does not exist"
        return
    fi

    local p o g result="OK"

    p=$(stat -c %a "$file")
    o=$(stat -c %U "$file")
    g=$(stat -c %G "$file")

    if (( (8#$p & 8#$mask) != 0 )); then
        result="FAIL"
    fi

    [[ "$o" != "root" ]] && result="FAIL"

    if [[ "$grp" == "root" ]]; then
        [[ "$g" != "root" ]] && result="FAIL"
    else
        [[ "$g" != "root" && "$g" != "shadow" ]] && result="FAIL"
    fi

    if [[ "$result" == "OK" ]]; then
        pass "$file mode=$p owner=$o group=$g"
        echo "$result $file mode=$p owner=$o group=$g" >> "$results_file"
    else
        fail "$file mode=$p owner=$o group=$g"
    fi
}
check_sysctl_value () {
    local proc="$1"
    local expected="$2"
    local value

    value=$(sysctl -n "$proc" 2>/dev/null)

    if [[ $? -ne 0 || -z "$value" ]]; then
        fail "$proc could not be checked"
        return 1
    fi

    if [[ "$value" == "$expected" ]]; then
        pass "$proc is hardened: expected=$expected actual=$value"
    else
        fail "$proc is not hardened: expected=$expected actual=$value"
    fi
}
check_service() {
    local svc=$1
    local expected=$2
    local actual

    actual=$(systemctl is-active "$svc" 2>/dev/null)

    if [[ "$actual" == "$expected" ]]; then
        pass "$svc is $actual | AU.L2-3.3.1, CM.L2-3.4.6  "
        echo "$svc is $actual" >> "$results_file"
    else
        fail "$svc is $actual (expected $expected)"
    fi
}
check_ufw() {
    local output
    local result="OK"

    output=$(ufw status verbose 2>/dev/null)

    echo "$output" | grep -qi "^status: active" || result="FAIL"
    echo "$output" | grep -qi "Default:.*deny (incoming" || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "UFW is active and incoming traffic is denied by default | AC.L2-3.1.2, SC.L2-3.13.1 "
        echo "$output" >> "$results_file"
    else
        fail "UFW configuration requires review"
        echo "$output"
    fi
}
check_aa() {
    local output
    local result="OK"

    output=$(aa-status 2>/dev/null)

    echo "$output" | grep -qi "apparmor module is loaded" || result="FAIL"
    echo "$output" | grep -qi "0 profiles are in complain mode" || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "AppArmor is active and no profiles are in complain mode"
        echo "AppArmor is active and no profiles are in complain mode" >> "$results_file"
    else
        fail "AppArmor configuration requires review"
        echo "$output"
    fi
}
check_mdatp() {
    local output
    local result="OK"

    output=$(mdatp health --output json 2>/dev/null)

    echo "$output" | jq -e '.definitionsStatus["$type"] == "upToDate"' >/dev/null 2>&1 || result="FAIL"
    echo "$output" | jq -e '.realTimeProtectionEnabled.value == true' >/dev/null 2>&1 || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "Microsoft Defender is active and definitions are up to date | SI.L2-3.14.2, SI.L2-3.14.6 "

        echo "Definition Status: $(echo "$output" | jq -r '.definitionsStatus["$type"]')" >> "$results_file"
        echo "RealTimeProtectionEnabled: $(echo "$output" | jq -r '.realTimeProtectionEnabled.value')" >> "$results_file"

    else
        fail "Microsoft Defender configuration requires review"
        echo "$output" | jq '.definitionsStatus'
        echo "$output" | jq '.realTimeProtectionEnabled'
    fi
}
check_ssh() {
    local result="OK"

    if ! command -v sshd >/dev/null 2>&1; then
        pass "SSH service is not installed | AC.L2-3.1.12, SC.L2-3.13.8 "
        echo "SSH service is not installed" >> "$results_file"
        return
    fi

    if ! systemctl is-active ssh >/dev/null 2>&1 && \
       ! systemctl is-active sshd >/dev/null 2>&1; then
        warn "SSH service is installed but not active"
        echo "\033[33mWARNING:\033[0m SSH service is installed but not active" >> "$results_file"
        return
    fi

    grep -Eq '^PasswordAuthentication\s+no' /etc/ssh/sshd_config || result="FAIL"
    grep -Eq '^PermitRootLogin\s+no' /etc/ssh/sshd_config || result="FAIL"
    grep -Eq '^PubkeyAuthentication\s+yes' /etc/ssh/sshd_config || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "SSHD configuration is hardened | AC.L2-3.1.12"
    else
        fail "SSHD configuration requires review"
    fi
}
check_kernel(){ 
local kmd=$1 
output=$(lsmod | grep -E "$kmd") 

if [[ "$output" == "" ]]; then 
    pass "$kmd is disabled | AC.L2-3.1.2 CM.L2-3.4.6, CM.L2-3.4.7 " 
    echo "$kmd is disabled" >> "$results_file"
else 
    fail "kmd is enabled, please review" echo "$output" 
fi 
}
check_ipfwd() {
    local val num

    # Prefer numeric output; fall back to /proc if sysctl not available
    if command -v sysctl >/dev/null 2>&1; then
        val=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    else
        val=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    fi

    # normalize whitespace and strip CR
    val=$(echo "$val" | tr -d '\r' | xargs 2>/dev/null)

    if [[ -z "$val" ]]; then
        warn "Could not determine net.ipv4.ip_forward value"
        return
    fi

    # extract first numeric token if present
    num=$(echo "$val" | grep -oE '[0-9]+' | head -n1 || true)
    if [[ -z "$num" ]]; then
        # fallback to patterns like 'net.ipv4.ip_forward = 0'
        if echo "$val" | grep -qE '= *0\b'; then
            pass "IP forwarding is disabled"
            return
        fi
        warn "Unrecognized net.ipv4.ip_forward output: $val"
        return
    fi

    if (( num == 0 )); then
        pass "IP forwarding is disabled"
        echo "IP Forwarding is disabled" >> "$results_file"
    else
        fail "IP forwarding is enabled (value=$num, raw='$val')"
    fi
}
check_ports() {
    local role="${1:-probe}"
    local allowed_ports
    local bad_ports
    local loopback_ports

    case "$role" in
        probe)
            # Approved probe ports
            allowed_ports="3000 9392 6379 5432 514 22"
            ;;

        gitlab)
            # Approved GitLab VM ports
            allowed_ports="22 80 443"
            ;;

        syslog)
            # Approved syslog VM ports
            allowed_ports="22 514 6514"
            ;;

        *)
            fail "Unknown system role: $role"
            return
            ;;
    esac

    bad_ports=$(ss -H -tln | awk -v allowed="$allowed_ports" '
        BEGIN {
            split(allowed, a, " ")
            for (i in a) ok[a[i]] = 1
        }

        function is_loopback(addr) {
            if (addr ~ /^127\./) return 1
            if (addr == "::1") return 1
            if (addr ~ /^::ffff:127\./) return 1
            return 0
        }

        {
            local_addr = $4

            port = local_addr
            sub(/^.*:/, "", port)

            addr = local_addr
            sub(/:[0-9]+$/, "", addr)
            gsub(/^\[/, "", addr)
            gsub(/\]$/, "", addr)
            sub(/%.*/, "", addr)

            if (!(port in ok) && !is_loopback(addr)) {
                print local_addr
            }
        }
    ' | sort -u)

    loopback_ports=$(ss -H -tln | awk '
        {
            local_addr = $4

            addr = local_addr
            sub(/:[0-9]+$/, "", addr)
            gsub(/^\[/, "", addr)
            gsub(/\]$/, "", addr)
            sub(/%.*/, "", addr)

            if (addr ~ /^127\./ || addr == "::1" || addr ~ /^::ffff:127\./) {
                print local_addr
            }
        }
    ' | sort -u)

    if [[ -z "$bad_ports" ]]; then
        pass "Only approved externally listening ports detected for role: $role | AC.L2-3.1.2, CM.L2-3.4.6, CM.L2-3.4.7"
        echo "Only approved externally listening ports detected for role: $role" >> "$results_file"
    else
        fail "Unauthorized externally listening ports detected for role $role: $bad_ports"
        echo "Unauthorized externally listening ports detected for role $role: $bad_ports" >> "$results_file"
    fi

    if [[ -n "$loopback_ports" ]]; then
        warn "Loopback-only listening ports detected; review for awareness only"
        echo "Loopback-only listening ports detected; review for awareness only:" >> "$results_file"
        echo "$loopback_ports" >> "$results_file"
    fi
}
check_results_file
add_date_time

echo -e "\e[33m--SYSTEM BASELINE CM.L2-3.4.1--\e[0m"
echo

echo -e "\e[33m--FILE PERMISSIONS--\e[0m"
check 0177 /etc/crontab root
check 0077 /etc/cron.daily root
check 0077 /etc/cron.weekly root
check 0077 /etc/cron.monthly root
check 0077 /etc/cron.d root
check 0177 /etc/ssh/sshd_config root
check 0133 /etc/passwd root
check 0133 /etc/passwd- root
check 0133 /etc/group root
check 0133 /etc/group- root
check 0137 /etc/shadow either
check 0137 /etc/shadow- either
check 0137 /etc/gshadow either
check 0137 /etc/gshadow- either
check 0133 /etc/shells root
check 0133 /etc/apt/trusted.gpg.d root
check 0177 /etc/security/opasswd root
check 0022 /etc/apt/trusted.gpg.d root
check 0022 /etc/apt/auth.conf.d root
check 0027 /etc/apt/auth.conf.d/* root
check 0022 /usr/share/keyrings root
check 0022 /etc/apt/sources.list.d root
check 0133 /etc/apt/sources.list.d/* root

echo
echo -e "\e[33m--PROCESS HARDENING--\e[0m"
check_sysctl_value fs.protected_symlinks 1
check_sysctl_vaule "kernel.yama.ptrace_scope" 1
check_sysctl_vaule "fs.suid_dumpable" 0 

echo
echo -e "\e[33m--SERVICES--\e[0m"
check_service named.service inactive
check_service auditd active
check_service chrony active
check_service rsyslog active
check_ufw
check_mdatp
check_aa
check_ssh

echo
echo -e "\e[33m--KERNEL MODULES--\e[0m"
check_kernel cramfs
check_kernel freevxfs
check_kernel hfs
check_kernel hfsplus
check_kernel jffs2
check_kernel overlay
check_kernel squashfs
check_kernel udf
check_kernel dccp
check_kernel sctp
check_kernel tipc
check_ipfwd
check_kernel usb_storage

echo
echo -e "\e[33m--OPEN PORTS--\e[0m"
SYSTEM_ROLE="${1:-probe}"
check_ports "$SYSTEM_ROLE"

echo
echo -e "\e[33m--SUMMARY--\e[0m"
echo -e "\e[32mPASS: $PASS_COUNT\e[0m"
echo -e "\e[31mFAIL: $FAIL_COUNT\e[0m"
echo -e "\e[33mWARN: $WARN_COUNT\e[0m"

echo "Pass Count $PASS_COUNT" >> "$results_file"
echo "Warn Count $WARN_COUNT" >> "$results_file"
echo "Fail Count $FAIL_COUNT" >> "$results_file"
