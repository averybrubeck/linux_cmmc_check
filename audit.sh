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
get_coredump_setting_lines () {
    local key="$1"

    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | awk -v key="$key" '
            BEGIN {
                in_section=0
                current_file="unknown"
            }

            /^# \/.*coredump.*\.conf/ {
                current_file=$0
                sub(/^# /, "", current_file)
                next
            }

            /^[[:space:]]*#/ { next }
            /^[[:space:]]*$/ { next }

            /^[[:space:]]*\[/ {
                section=tolower($0)
                gsub(/[[:space:]]/, "", section)
                in_section=(section == "[coredump]")
                next
            }

            in_section {
                line=$0
                sub(/^[[:space:]]*/, "", line)

                if (line ~ "^" key "[[:space:]]*=") {
                    clean=line
                    sub(/[[:space:]]*#.*/, "", clean)
                    sub(/[[:space:]]*;.*/, "", clean)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", clean)

                    value=clean
                    sub("^" key "[[:space:]]*=[[:space:]]*", "", value)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

                    print value "|" current_file "|" clean
                }
            }
        '
        return
    fi

    local files=(/etc/systemd/coredump.conf)

    if compgen -G "/etc/systemd/coredump.conf.d/*.conf" > /dev/null; then
        files+=(/etc/systemd/coredump.conf.d/*.conf)
    fi

    awk -v key="$key" '
        BEGIN { in_section=0 }

        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }

        /^[[:space:]]*\[/ {
            section=tolower($0)
            gsub(/[[:space:]]/, "", section)
            in_section=(section == "[coredump]")
            next
        }

        in_section {
            line=$0
            sub(/^[[:space:]]*/, "", line)

            if (line ~ "^" key "[[:space:]]*=") {
                clean=line
                sub(/[[:space:]]*#.*/, "", clean)
                sub(/[[:space:]]*;.*/, "", clean)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", clean)

                value=clean
                sub("^" key "[[:space:]]*=[[:space:]]*", "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

                print value "|" FILENAME "|" clean
            }
        }
    ' "${files[@]}" 2>/dev/null
}
check_coredump_setting () {
    local key="$1"
    local expected="$2"
    local lines
    local effective_line
    local effective_value
    local effective_file
    local bad_extra_lines
    local failed=0

    lines=$(get_coredump_setting_lines "$key")

    if [[ -z "$lines" ]]; then
        fail "systemd-coredump $key is not hardened: expected=$expected actual=not configured"
        echo "systemd-coredump $key is not hardened: expected=$expected actual=not configured" >> "$results_file"
        return 1
    fi

    effective_line=$(printf '%s\n' "$lines" | head -n 1)
    effective_value=$(printf '%s\n' "$effective_line" | cut -d'|' -f1)
    effective_file=$(printf '%s\n' "$effective_line" | cut -d'|' -f2)

    if [[ "$effective_value" == "$expected" ]]; then
        pass "systemd-coredump $key is hardened: expected=$expected actual=$effective_value"
        echo "systemd-coredump $key is hardened: expected=$expected actual=$effective_value from $effective_file" >> "$results_file"
    else
        fail "systemd-coredump $key is not hardened: expected=$expected actual=$effective_value"
        echo "systemd-coredump $key is not hardened: expected=$expected actual=$effective_value from $effective_file" >> "$results_file"
        failed=1
    fi

    bad_extra_lines=$(printf '%s\n' "$lines" | tail -n +2 | awk -F'|' -v expected="$expected" '$1 != expected { print $2 ": " $3 }')

    if [[ -n "$bad_extra_lines" ]]; then
        warn "Additional incorrect systemd-coredump $key values found; effective value may still be correct, but old values should be fixed or commented out"
        printf '%s\n' "$bad_extra_lines"
        {
            echo "Additional incorrect systemd-coredump $key values found:"
            printf '%s\n' "$bad_extra_lines"
        } >> "$results_file"
    fi

    return "$failed"
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
check_core_limits () {
    local bad_lines
    local failed=0
    local limit_files=(/etc/security/limits.conf)

    if compgen -G "/etc/security/limits.d/*.conf" > /dev/null; then
        limit_files+=(/etc/security/limits.d/*.conf)
    fi

    bad_lines=$(awk '
        /^[[:space:]]*#/ { next }
        NF < 4 { next }

        $3 == "core" {
            if ($4 == "unlimited" || $4 == "-1") {
                print FILENAME ": " $0
            } else if ($4 ~ /^[0-9]+$/ && $4 > 0) {
                print FILENAME ": " $0
            }
        }
    ' "${limit_files[@]}" 2>/dev/null)

    if [[ -n "$bad_lines" ]]; then
        fail "Core file size is not hardened: core limits greater than 0 found"
        printf '%s\n' "$bad_lines"
        {
            echo "Core file size is not hardened: core limits greater than 0 found"
            printf '%s\n' "$bad_lines"
        } >> "$results_file"
        failed=1
    else
        pass "Core file size is hardened: no core limits greater than 0 found"
        echo "Core file size is hardened: no core limits greater than 0 found" >> "$results_file"
    fi

    if ! dpkg-query -W -f='${Status}' systemd-coredump 2>/dev/null | grep -q "install ok installed"; then
        pass "systemd-coredump package is not installed; Storage and ProcessSizeMax checks are not required"
        echo "systemd-coredump package is not installed; Storage and ProcessSizeMax checks are not required" >> "$results_file"
        return "$failed"
    fi

    check_coredump_setting "ProcessSizeMax" "0" || failed=1
    check_coredump_setting "Storage" "none" || failed=1

    return "$failed"
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
        echo "$proc could not be checked" >> "$results_file"
        return 1
    fi

    if [[ "$value" == "$expected" ]]; then
        pass "$proc is hardened: expected=$expected actual=$value"
        echo "$proc is hardened: expected=$expected actual=$value" >> "$results_file"
    else
        fail "$proc is not hardened: expected=$expected actual=$value"
        echo "$proc is not hardened: expected=$expected actual=$value" >> "$results_file"
    fi
}
check_service() {
    local svc="$1"
    local expected="$2"
    local actual

    actual=$(systemctl is-active "$svc" 2>/dev/null || true)
    [[ -z "$actual" ]] && actual="not-found"

    if [[ "$expected" == "inactive" ]]; then
        if [[ "$actual" == "active" ]]; then
            fail "$svc is active and should not be running"
        else
            pass "$svc is not active: actual=$actual"
            echo "$svc is not active: actual=$actual" >> "$results_file"
        fi
        return
    fi

    if [[ "$actual" == "$expected" ]]; then
        pass "$svc is $actual | AU.L2-3.3.1, CM.L2-3.4.6"
        echo "$svc is $actual" >> "$results_file"
    else
        fail "$svc is $actual (expected $expected)"
    fi
}
check_package() {
    local package="$1"
    local name="$2"

    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        fail "$name is not hardened: $package is installed"
        echo "$name is not hardened: $package is installed" >> "$results_file"
    else
        pass "$name is hardened: $package is not installed"
        echo "$name is hardened: $package is not installed" >> "$results_file"
    fi
}
check_ufw() {
    local output
    local result="OK"

    output=$(ufw status verbose 2>/dev/null)

    echo "$output" | grep -qi "^status: active" || result="FAIL"
    echo "$output" | grep -qi "Default:.*deny (incoming" || result="FAIL"
    echo "$output" | grep -qi "Default:.*allow (outgoing" || result="FAIL"
    echo "$output" | grep -qi "Default:.*disabled (routed" || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "UFW is active with default deny incoming, allow outgoing, and deny routed | AC.L2-3.1.2, SC.L2-3.13.1"
        echo "$output" >> "$results_file"
    else
        fail "UFW configuration requires review"
        echo "$output"
        echo "UFW configuration requires review:" >> "$results_file"
        echo "$output" >> "$results_file"
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
check_chrony_sync() {
    local leap
 
    leap=$(chronyc tracking 2>/dev/null | grep -i 'Leap status' | awk -F: '{gsub(/^ +/,"",$2); print $2}')
 
    if [[ "$leap" == "Normal" ]]; then
        pass "Chrony is synchronized: leap status Normal | AU.L2-3.3.7"
        echo "Chrony is synchronized: leap status Normal" >> "$results_file"
    else
        fail "Chrony synchronization requires review: leap status=${leap:-unknown}"
    fi
}
check_banner() {
    local result="OK"
    local f
 
    for f in /etc/issue /etc/issue.net; do
        grep -qs 'AUTHORIZED ACCESS ONLY' "$f"                     || result="FAIL"
        grep -qs 'Controlled Unclassified Information' "$f"        || result="FAIL"
    done
 
    # motd should be empty (or whitespace only)
    if [[ -s /etc/motd ]] && grep -qE '[^[:space:]]' /etc/motd; then
        result="FAIL"
    fi
 
    if [[ "$result" == "OK" ]]; then
        pass "Login banners are configured and motd is empty | AC.L2-3.1.9"
        echo "Login banners are configured and motd is empty" >> "$results_file"
    else
        fail "Login banners require review: missing required text or motd not empty"
    fi
}
check_ssh() {
    local output result="OK"

    if ! command -v sshd >/dev/null 2>&1; then
        pass "SSH service is not installed | AC.L2-3.1.12, SC.L2-3.13.8"
        echo "SSH service is not installed" >> "$results_file"
        return
    fi

    if ! systemctl is-active ssh >/dev/null 2>&1 && \
       ! systemctl is-active sshd >/dev/null 2>&1; then
        warn "SSH service is installed but not active"
        echo "WARN: SSH service is installed but not active" >> "$results_file"
        return
    fi

    output=$(sshd -T 2>/dev/null)

    echo "$output" | grep -qE '^passwordauthentication[[:space:]]+no$' || result="FAIL"
    echo "$output" | grep -qE '^permitrootlogin[[:space:]]+no$' || result="FAIL"
    echo "$output" | grep -qE '^pubkeyauthentication[[:space:]]+yes$' || result="FAIL"
    echo "$output" | grep -qE '^clientaliveinterval[[:space:]]+120$' || result="FAIL"
    echo "$output" | grep -qE '^clientalivecountmax[[:space:]]+3$' || result="FAIL"
    echo "$output" | grep -qE '^logingracetime[[:space:]]+60$' || result="FAIL"
    echo "$output" | grep -qE '^maxauthtries[[:space:]]+4$' || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "SSHD effective configuration is hardened | AC.L2-3.1.12"
        echo "SSHD effective configuration is hardened" >> "$results_file"
    else
        fail "SSHD effective configuration requires review"
        echo "$output" | grep -E 'passwordauthentication|permitrootlogin|pubkeyauthentication|clientaliveinterval|clientalivecountmax|logingracetime|maxauthtries'
    fi
}
check_kernel() {
    local kmd="$1"
    local output

    output=$(lsmod | awk -v mod="$kmd" '$1 == mod { print }')

    if [[ -z "$output" ]]; then
        pass "$kmd is not loaded | AC.L2-3.1.2, CM.L2-3.4.6, CM.L2-3.4.7"
        echo "$kmd is not loaded" >> "$results_file"
    else
        fail "$kmd is loaded, please review"
        echo "$output"
        echo "$kmd is loaded:" >> "$results_file"
        echo "$output" >> "$results_file"
    fi
}
check_audit_immutable() {
    local status
 
    status=$(auditctl -s 2>/dev/null | grep -E '^enabled' | awk '{print $2}')
 
    if [[ "$status" == "2" ]]; then
        pass "Audit configuration is immutable until reboot: enabled=2 | AU.L2-3.3.8"
        echo "Audit configuration is immutable: enabled=2" >> "$results_file"
    else
        fail "Audit immutability requires review: enabled=${status:-unknown} (expected 2)"
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
            allowed_ports="3000 9392 6379 5432 514"
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
check_pwquality() {
    local file="/etc/security/pwquality.conf"
    local result="OK"
    local minlen minclass maxrepeat
 
    if [[ ! -e "$file" ]]; then
        fail "pwquality is not hardened: $file does not exist"
        return
    fi
 
    minlen=$(grep -E '^\s*minlen\s*=' "$file" | tail -n1 | awk -F= '{gsub(/ /,"",$2); print $2}')
    minclass=$(grep -E '^\s*minclass\s*=' "$file" | tail -n1 | awk -F= '{gsub(/ /,"",$2); print $2}')
    maxrepeat=$(grep -E '^\s*maxrepeat\s*=' "$file" | tail -n1 | awk -F= '{gsub(/ /,"",$2); print $2}')
 
    [[ "$minlen" =~ ^[0-9]+$ ]] && (( minlen >= 14 ))      || result="FAIL"
    [[ "$minclass" =~ ^[0-9]+$ ]] && (( minclass >= 4 ))   || result="FAIL"
    [[ "$maxrepeat" =~ ^[0-9]+$ ]] && (( maxrepeat <= 3 )) || result="FAIL"
 
    if [[ "$result" == "OK" ]]; then
        pass "Password complexity is hardened: minlen=$minlen minclass=$minclass maxrepeat=$maxrepeat | IA.L2-3.5.7"
        echo "Password complexity is hardened: minlen=$minlen minclass=$minclass maxrepeat=$maxrepeat" >> "$results_file"
    else
        fail "Password complexity requires review: minlen=${minlen:-unset} minclass=${minclass:-unset} maxrepeat=${maxrepeat:-unset}"
    fi
}
check_pwhistory() {
    local line val
 
    line=$(grep -E '^\s*password\s+.*pam_pwhistory\.so' /etc/pam.d/common-password 2>/dev/null | head -n1)
 
    if [[ -z "$line" ]]; then
        fail "Password history is not hardened: pam_pwhistory not present in common-password"
        return
    fi
 
    val=$(echo "$line" | grep -oE 'remember=[0-9]+' | cut -d= -f2)
 
    if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 24 )); then
        pass "Password history is hardened: remember=$val | IA.L2-3.5.8"
        echo "Password history is hardened: remember=$val" >> "$results_file"
    else
        fail "Password history requires review: remember=${val:-unset}"
    fi
}
check_logindefs() {
    local result="OK"
    local maxd mind warn_age enc
 
    maxd=$(grep -E '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
    mind=$(grep -E '^PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}')
    warn_age=$(grep -E '^PASS_WARN_AGE' /etc/login.defs | awk '{print $2}')
    enc=$(grep -E '^ENCRYPT_METHOD' /etc/login.defs | awk '{print $2}')
 
    [[ "$maxd" =~ ^[0-9]+$ ]] && (( maxd <= 365 && maxd > 0 )) || result="FAIL"
    [[ "$mind" =~ ^[0-9]+$ ]] && (( mind >= 1 ))               || result="FAIL"
    [[ "$warn_age" =~ ^[0-9]+$ ]] && (( warn_age >= 14 ))      || result="FAIL"
    # Debian 13 default is YESCRYPT; doc allows SHA512 — accept either
    [[ "$enc" == "SHA512" || "$enc" == "YESCRYPT" ]]           || result="FAIL"
 
    if [[ "$result" == "OK" ]]; then
        pass "Password aging/hashing is hardened: max=$maxd min=$mind warn=$warn_age method=$enc | IA.L2-3.5.8, IA.L2-3.5.10"
        echo "Password aging/hashing is hardened: max=$maxd min=$mind warn=$warn_age method=$enc" >> "$results_file"
    else
        fail "Password aging/hashing requires review: max=${maxd:-unset} min=${mind:-unset} warn=${warn_age:-unset} method=${enc:-unset}"
    fi
}
check_inactive() {
    local val
 
    val=$(useradd -D 2>/dev/null | grep -E '^INACTIVE=' | cut -d= -f2)
 
    if [[ "$val" =~ ^[0-9]+$ ]] && (( val <= 35 && val >= 0 )); then
        pass "Account inactivity lockout is hardened: INACTIVE=$val | IA.L2-3.5.6"
        echo "Account inactivity lockout is hardened: INACTIVE=$val" >> "$results_file"
    else
        fail "Account inactivity lockout requires review: INACTIVE=${val:-unset}"
    fi
}
check_faillock() {
    local file="/etc/pam.d/common-auth"
    local result="OK"
    local preauth authfail
 
    preauth=$(grep -E '^\s*auth\s+required\s+pam_faillock\.so\s+preauth' "$file" 2>/dev/null)
    authfail=$(grep -E '^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail' "$file" 2>/dev/null)
 
    [[ -n "$preauth" ]]  || result="FAIL"
    [[ -n "$authfail" ]] || result="FAIL"
    echo "$preauth"  | grep -qE 'deny=5'          || result="FAIL"
    echo "$preauth"  | grep -qE 'unlock_time=900' || result="FAIL"
    echo "$authfail" | grep -qE 'deny=5'          || result="FAIL"
    echo "$authfail" | grep -qE 'unlock_time=900' || result="FAIL"
    grep -Eq '^\s*account\s+required\s+pam_faillock\.so' /etc/pam.d/common-account || result="FAIL"
 
    if [[ "$result" == "OK" ]]; then
        pass "Account lockout is hardened: faillock deny=5 unlock_time=900 | AC.L2-3.1.8"
        echo "Account lockout is hardened: faillock deny=5 unlock_time=900" >> "$results_file"
    else
        fail "Account lockout requires review: pam_faillock missing or misconfigured in common-auth"
    fi
}
check_sudo_logging() {
    if grep -rqsE '^\s*Defaults\s+logfile=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        pass "Sudo logging is hardened: Defaults logfile is set | AU.L2-3.3.1"
        echo "Sudo logging is hardened: Defaults logfile is set" >> "$results_file"
    else
        fail "Sudo logging requires review: no Defaults logfile entry found"
    fi
}
check_tmout() {
    local file="/etc/profile.d/tmout.sh"
    local result="OK"
    local val
 
    if [[ ! -e "$file" ]]; then
        fail "Session timeout is not hardened: $file does not exist"
        return
    fi
 
    val=$(grep -E '^\s*TMOUT=' "$file" | tail -n1 | cut -d= -f2)
 
    [[ "$val" =~ ^[0-9]+$ ]] && (( val <= 900 && val > 0 )) || result="FAIL"
    grep -qE '^\s*readonly\s+TMOUT' "$file"                 || result="FAIL"
    grep -qE '^\s*export\s+TMOUT'   "$file"                 || result="FAIL"
 
    if [[ "$result" == "OK" ]]; then
        pass "Session timeout is hardened: TMOUT=$val readonly+exported | AC.L2-3.1.10, AC.L2-3.1.11"
        echo "Session timeout is hardened: TMOUT=$val" >> "$results_file"
    else
        fail "Session timeout requires review: TMOUT=${val:-unset} in $file"
    fi
}
check_grub() {
    local cfg="/boot/grub/grub.cfg"
    local result="OK"
 
if [[ -e /boot/grub/grub.cfg ]]; then
    check 0177 /boot/grub/grub.cfg root
fi
 
    grep -qE '^\s*set\s+superusers=' "$cfg"   || result="FAIL"
    grep -qE '^\s*password_pbkdf2\s+' "$cfg"  || result="FAIL"
 
    if [[ "$result" == "OK" ]]; then
        pass "GRUB superuser and password are set | AC.L2-3.1.5, CM.L2-3.4.5"
        echo "GRUB superuser and password are set" >> "$results_file"
    else
        fail "GRUB configuration requires review: superuser/password_pbkdf2 not found in grub.cfg"
    fi
}
check_audit_rules() {
    local result="OK"
    local loaded missing=""
    local key
 
    loaded=$(auditctl -l 2>/dev/null)
 
    if [[ -z "$loaded" || "$loaded" == "No rules" ]]; then
        fail "Audit rules are not hardened: no rules loaded"
        return
    fi
 
    # One representative match per rule group in the doc
    for key in identity privilege privesc time-change mounts sshd firewall mac auditconfig logins; do
        echo "$loaded" | grep -q -- "-k $key" || { result="FAIL"; missing="$missing $key"; }
    done
 
    if [[ "$result" == "OK" ]]; then
        pass "Audit rules are loaded: all expected rule keys present | AU.L2-3.3.1, AU.L2-3.3.2"
        echo "Audit rules are loaded: all expected rule keys present" >> "$results_file"
    else
        fail "Audit rules require review: missing keys:$missing"
    fi
}
check_syslog_forwarding() {
    local line
 
    line=$(grep -hsE '^\s*\*\.\*\s+@@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | head -n1)
 
    if [[ -n "$line" ]]; then
        # Don't pass if the placeholder was never replaced
        if echo "$line" | grep -q '<SIEM_IP>'; then
            fail "Syslog forwarding requires review: <SIEM_IP> placeholder was never replaced"
            return
        fi
        pass "Syslog forwarding to SIEM is configured: $line | AU.L2-3.3.1, SI.L2-3.14.6"
        echo "Syslog forwarding to SIEM is configured: $line" >> "$results_file"
    else
        fail "Syslog forwarding requires review: no '*.* @@' forwarding rule found"
    fi
}
check_aide() {
    local result="OK"
    local cron="/etc/cron.daily/aide-check"
    local shebang
 
    [[ -e /var/lib/aide/aide.db ]] || result="FAIL"
 
    if [[ -e /var/lib/aide/aide.db.new ]]; then
        warn "AIDE: aide.db.new still present; baseline may not have been activated"
    fi
 
    if [[ -e "$cron" ]]; then
        [[ -x "$cron" ]] || result="FAIL"
        shebang=$(head -n1 "$cron")
        [[ "$shebang" == "#!/bin/sh" || "$shebang" == "#!/bin/bash" ]] || result="FAIL"
    else
        result="FAIL"
    fi
 
    if [[ "$result" == "OK" ]]; then
        pass "AIDE baseline exists and daily check is in place | SI.L2-3.14.1, AU.L2-3.3.8"
        echo "AIDE baseline exists and daily check is in place" >> "$results_file"
    else
        fail "AIDE requires review: db=$([[ -e /var/lib/aide/aide.db ]] && echo present || echo missing) cron=$([[ -x "$cron" ]] && echo ok || echo bad) shebang=${shebang:-none}"
    fi
}
check_fail2ban_jail() {
    if ! command -v sshd >/dev/null 2>&1; then
        pass "fail2ban sshd jail not required: sshd not installed"
        echo "fail2ban sshd jail not required: sshd not installed" >> "$results_file"
        return
    fi
 
    if fail2ban-client status sshd 2>/dev/null | grep -q 'Currently banned'; then
        pass "fail2ban sshd jail is active | AC.L2-3.1.8, SI.L2-3.14.6"
        echo "fail2ban sshd jail is active" >> "$results_file"
    else
        fail "fail2ban sshd jail requires review: jail not active"
    fi
}
check_results_file
echo "Role: ${1:-probe}" >> "$results_file"
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
for key in /etc/ssh/ssh_host_*_key; do
    [[ -e "$key" ]] || continue
    [[ "$key" == *.pub ]] && continue
    check 0177 "$key" root
done
check 0133 /etc/passwd root
check 0133 /etc/passwd- root
check 0133 /etc/group root
check 0133 /etc/group- root
check 0137 /etc/shadow either
check 0137 /etc/shadow- either
check 0137 /etc/gshadow either
check 0137 /etc/gshadow- either
check 0133 /etc/at.allow root
check 0133 /etc/shells root
check 0133 /etc/motd root
check 0133 /etc/issue root
check 0133 /etc/issue.net root
check 0022 /etc/apt/trusted.gpg.d root
check 0022 /etc/apt/auth.conf.d root
for f in /etc/apt/auth.conf.d/*; do
    [[ -e "$f" ]] || continue
    check 0027 "$f" root
done
check 0022 /etc/apt/sources.list.d root
for f in /etc/apt/sources.list.d/*; do
    [[ -e "$f" ]] || continue
    check 0133 "$f" root
done
check 0022 /usr/share/keyrings root
check 0177 /etc/security/opasswd root

echo
echo -e "\e[33m--PROCESS HARDENING--\e[0m"
check_sysctl_value "fs.protected_symlinks" "1"
check_sysctl_value "kernel.yama.ptrace_scope" "1"
check_sysctl_value "fs.suid_dumpable" "0"
check_sysctl_value "kernel.dmesg_restrict" "1"
check_sysctl_value "kernel.randomize_va_space" "2"
check_sysctl_value "kernel.kptr_restrict" "2"
check_sysctl_value "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl_value "net.ipv4.conf.all.send_redirects" "0"
check_sysctl_value "net.ipv4.conf.all.secure_redirects" "0"
check_sysctl_value "net.ipv4.tcp_syncookies" "1"
check_sysctl_value "net.ipv4.conf.all.log_martians" "1"
check_core_limits

echo
echo -e "\e[33m--SERVICES--\e[0m"
check_service named.service inactive
check_service apport.service inactive
check_service autofs inactive
check_service nfs-server.service inactive
check_service xinetd inactive
check_service auditd active
check_service chrony active
check_service rsyslog active
check_ufw
check_mdatp
check_aa
check_ssh

echo
echo -e "\e[33m--AUTH AND ACCOUNT POLICY--\e[0m"
check_pwquality
check_logindefs
check_inactive
check_pwhistory
check_faillock
check_sudo_logging
check 0337 /etc/sudoers.d/logging root
check_tmout

echo
echo -e "\e[33m--BOOT / AUDIT / TIME / LOGGING--\e[0m"
check_grub
check 0177 /boot/grub/grub.cfg root
check_audit_rules
check_audit_immutable
check_chrony_sync
check_syslog_forwarding
check_banner
check_aide
check_fail2ban_jail

echo
echo -e "\e[33m--PACKAGES--\e[0m"
check_package prelink "Prelink"
check_package avahi-daemon "Avahi daemon"
check_package apache2 "Apache"
check_package nginx "Nginx"
check_package bind9 "DNS Service"
check_package vsftpd "FTP Package"
check_package dnsmasq "dnsmasq"
check_package slapd "LDAP Services"
check_package dovecot-imapd "Server Message Systems"
check_package dovecot-pop3d "Server Message Systems"
check_package ypserv "NIS Server Services"
check_package cups "CUPS Printing"
check_package rpcbind "rpcbind services"
check_package samba "Samba services"
check_package telnet "Telnet service"
check_package telnetd "Telnet service"
check_package inetutils-telnet "Telnet service"
check_package tftpd-hpa "tftp services"
check_package squid "Squid web proxy"
check_package xserver-common "X Window Server"
check_package nis "nis client"
check_package rsh "rsh client"
check_package talk "talk client"
check_package bluez "Bluetooth client"

echo
echo -e "\e[33m--KERNEL MODULES--\e[0m"
check_kernel atm
check_kernel can
check_kernel dccp
check_kernel rds
check_kernel sctp
check_kernel tipc
check_kernel cramfs
check_kernel freevxfs
check_kernel hfs
check_kernel hfsplus
check_kernel jffs2
check_kernel overlay
check_kernel squashfs
check_kernel udf
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
