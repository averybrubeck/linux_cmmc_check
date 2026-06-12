# Baseline Validation Script

Verifies a host against the Post-Install Hardening baseline (CMMC L2 — CM.L2-3.4.1/3.4.2, least functionality). The Word doc is the authoritative baseline; this script only checks it.

## Usage

Run as root after initial hardening is complete:

```bash
sudo ./baseline-check.sh [role]
```

`role` sets the approved listening-port list: `probe` (default), `gitlab`, or `syslog`.

## What it checks

File permissions, kernel/process hardening (sysctl, core dumps), services and packages (installed/active state), kernel modules (loaded at runtime), UFW, AppArmor, Defender (mdatp), SSH config (where installed), PAM/account policy, auditd rules + immutability, chrony sync, syslog forwarding, banners, AIDE, fail2ban, and externally listening ports per role.

## Output

- Console: color-coded `OK` / `FAIL` / `WARN` per check, with summary counts at the end.
- `baseline-results.txt`: hostname, date, kernel, and passing-check details. Overwritten each run.

## Workflow

1. Run the script for the host's role.
2. Remediate any FAILs per the hardening doc, re-run until clean.
3. Screenshot the clean run and archive `baseline-results.txt` as evidence.

WARNs are informational (e.g. loopback-only listeners) and don't require action.

## Notes

- Requires root for auditctl, stat on shadow files, and mdatp.
- Kernel module checks are point-in-time (loaded now), not load-prevention.
- GRUB checks auto-skip on Azure VMs without local grub.cfg.
