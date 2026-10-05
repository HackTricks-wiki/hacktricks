# Main System Information

{{#include ../../banners/hacktricks-training.md}}

Inspect the host's kernel, filesystem, privileged helpers, and available escape routes before choosing a local escalation technique. The [privilege escalation checklist](linux-privilege-escalation-checklist.md) gives a compact order of operations.

- [Kernel modules and modprobe abuse](kernel-modules-and-modprobe.md) covers module loading and helper-path exposure.
- [Sudo command abuse](sudo-command-abuse.md) examines ways delegated commands can cross privilege boundaries.
- [Filesystem, inodes and recovery](filesystem-inodes-and-recovery.md) explains filesystem behavior useful during investigation.
- [Checklist: Linux privilege escalation](linux-privilege-escalation-checklist.md) lists host checks and links to deeper material.
- [Escaping from jails](escaping-from-limited-bash.md) covers limited shells and constrained environments.
- [Kernel/LPE/CVE material](kernel-lpe-cves/README.md) groups focused local privilege escalation and vulnerability write-ups.
