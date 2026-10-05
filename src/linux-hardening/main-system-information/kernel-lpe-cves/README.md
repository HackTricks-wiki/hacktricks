# Kernel, LPE, and CVE Material

{{#include ../../../banners/hacktricks-training.md}}

These case studies cover distinct local privilege escalation primitives. Check the affected product or kernel, configuration, and prerequisites in each article before applying a technique. For broader host enumeration, use the [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): privileged execution through untrusted process-path discovery.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): a kernel page-cache overwrite path.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): a race in timer handling.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): descriptor access across a process exit race.
