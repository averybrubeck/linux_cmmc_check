# Linux Baseline Validation Script

This script validates a Linux host against the approved post-install hardening baseline.

The Word baseline remains the authoritative configuration standard. This script provides repeatable evidence that key baseline settings are present, active, or restricted as expected. It is intended to support baseline validation, revalidation, and evidence collection for Linux systems within the CMMC assessment boundary.

## Supported systems

This script is intended for hardened Linux servers running:

- Debian 13 x86_64
- Ubuntu 24.04 LTS x86_64

Supported system roles:

- `probe`
- `gitlab`
- `syslog`

If no role is specified, the script defaults to `probe`.

## Usage

Run the script as root after baseline hardening is complete:

```bash
sudo ./audit.sh [role] | less -R
