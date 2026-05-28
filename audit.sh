#!/bin/bash
pass() {
    printf '\033[32mOK\033[0m %s\n' "$*"
}
fail() {
    printf '\033[31mFAIL\033[0m %s\n' "$*"
}
warn() {
    printf '\033[33mWARN\033[0m %s\n' "$*"
}
check() {
  local mask=$1 file=$2 grp=$3

  if [ ! -e "$file" ]; then
    echo "MISS $file"
    return
  fi
  
  local p o g result="OK"
  p=$(stat -c %a "$file")
  o=$(stat -c %U "$file")
  g=$(stat -c %G "$file")

  
  if [ $((8#$p & 8#$mask)) -ne 0 ]; then 
    result="FAIL"; 
  fi
  
  [[ "$o" != ""root ]] && result="FAIL"

  if [[ "$grp" == "root" ]]; then
    [[ "$g" != "root" ]] && result="FAIL"
  else
    [[ "$g" != "root" && "$g != "shadow ]] && result="FAIL"
  fi

  if [[ "$result" == "OK" ]]; then
    echo -e "\e[32m$result $file mode=$p owner=$o group=$g\e[0m";
  else
    echo -e "\e[31m$result $file mode=$p owner=$o group=$g\e[0m";
  fi
}
check_service() {
    local svc=$1
    local expected=$2

    actual=$(systemctl is-active "$svc")

    if [[ "$actual" == "$expected" ]]; then
        pass "$svc is $actual (expected $expected)"
    else
        fail "$svc is $actual (expected $expected)"
    fi
}
check_ufw() {
    local output
    local result="OK"
    output=$(ufw status verbose 2>/dev/null)

    echo "$output" | grep -qi "^status: active" || result="FAIL"
    echo "$output" | grep -qi "Default:.*deny (incomming" || result="FAIL"

    if [[ "result" == "OK" ]]; then
        pass "UFW is actvie and incomming is denied"
        "$output"
    else 
        fail "UFW is inactive, or configuration needs to be reviewed"
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
        pass "AppArmor is active and 0 profiles are in complain mode"
    else
        fail "AppArmor is not active/Profiles are in complain mode. Please review"
        echo "$output"
    fi
}
check_mdatp(){
    local output
    local result="OK"

    output=$(mdatp health --output json 2>/dev/null)

    echo "$output" | jq -e '.definistionsStatus["$type"] == "upToDate"' >/dev/null || result="FAIL"
    echo "$output" | jq -e '.realTimeProtectionEnabled.value == true' >/dev/null || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "mdatp is active, realtime protection enabled, and definitions up to date"
    else
        fail "mdatp service is not active or definitions not updated. Please review"
        echo "$output" | jq -e '.definitionsStatus'
    fi
}
check_ssh(){
    output=$(which sshd)
    result="OK"

    echo "$output" | grep -qi "" || result="FAIL"

    if [[ "$result" == "OK" ]]; then
        pass "ssh service is not found"
    else
        fail "ssh service is enabled, please review configuration"
    fi
}
check_kernel(){
    local kmd=$1
    output=$(lsmod | grep -E "$kmd")

    if [[ "$output" == "" ]]; then
        pass "$kmd is disabled"
    else
        fail "kmd is enabled, please review"
        echo "$output"
    fi
}
check_ipfwd(){
    local output
    output=$(sysctl net.ipv4.ip_forward)
    result="OK"
    
    echo "$output" | grep -qi "0" || result="FAIL"

    if [[ "$result" = "OK" ]]; then
        pass "IP forwarding is disabled"
        echo "$output"
    else
        fail "IP forwarding is enabled, please review configuration"
        echo "$output"
    fi
}


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

echo -e "\e[33m--SYSTEM HARDENING--\n\e[0m"
echo -e "\e[33m--DNS--\e[0m"
check_service named.service inactive
echo -e "\e[33m--Auditd--\e[0m"
check_service auditd active
echo -e "\e[33m--Chrony--\e[0m"
check_service chrony active
echo -e "\e[33m--RSYSLOG--\e[0m"
check_service rsyslog active
echo -e "\e[33m--UFW--\e[0m"
check_ufw
check_mdatp
check_aa
