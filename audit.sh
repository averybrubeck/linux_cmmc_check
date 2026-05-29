#!/bin/bash

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

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

check() {
    local mask=$1
    local file=$2
    local grp=$3

    if [[ ! -e "$file" ]]; then
        fail "$file does not exist"
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
    else
        fail "$file mode=$p owner=$o group=$g"
    fi
}

check_service() {
    local svc=$1
    local expected=$2
    local actual

    actual=$(systemctl is-active "$svc" 2>/dev/null)

    if [[ "$actual" == "$expected" ]]; then
        pass "$svc is $actual"
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
        pass "UFW is active and incoming traffic is denied by default"
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
        pass "Microsoft Defender is active and definitions are up to date"
    else
        fail "Microsoft Defender configuration requires review"
        echo "$output" | jq '.definitionsStatus'
    fi
}

check_ssh() {
    if command -v sshd >/dev/null 2>&1; then
        warn "SSH service installed - review sshd_config"
    else
        pass "SSH service not installed"
    fi
}

check_kernel() {
    local kmd=$1
    local output

    output=$(modprobe -n -v "$kmd" 2>/dev/null)

    echo "$output" | grep -Eq "install /bin/(true|false)" && {
        pass "$kmd is disabled"
        return
    }

    fail "$kmd is enabled or not properly blacklisted"
    echo "$output"
}

check_ipfwd() {
    local output
    local result="OK"

    output=$(sysctl net.ipv4.ip_forward 2>/dev/null)

    echo "$output" | grep -q "= 0" || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "IP forwarding is disabled"
    else
        fail "IP forwarding is enabled"
        echo "$output"
    fi
}

check_ports() {
    local bad_ports

    bad_ports=$(ss -H -tln | awk '{ if (match($0, /:[0-9]+$/)) { port=substr($0,RSTART+1,RLENGTH-1); if (port!="3000" && port!="9392" && port!="6379" && port!="5432") print port } }' | sort -u)

    if [[ -z "$bad_ports" ]]; then
        pass "Only approved listening ports detected"
    else
        fail "Unauthorized listening ports detected: $bad_ports"
    fi
}

echo
echo "Hostname: $(hostname)"
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo

echo -e "\e[33m--SYSTEM HARDENING--\e[0m"
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
check 0177 /etc/security/opasswd root

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

check_kernel usb_storage
check_kernel cramfs
check_kernel freevxfs
check_kernel hfs
check_kernel udf
check_kernel dccp
check_kernel sctp
check_kernel tipc

check_ipfwd

echo
echo -e "\e[33m--OPEN PORTS--\e[0m"

check_ports

echo
echo -e "\e[33m--SUMMARY--\e[0m"

echo -e "\e[32mPASS: $PASS_COUNT\e[0m"
echo -e "\e[31mFAIL: $FAIL_COUNT\e[0m"
echo -e "\e[33mWARN: $WARN_COUNT\e[0m"

