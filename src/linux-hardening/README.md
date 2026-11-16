# Linux Hardening

{{#include ../banners/hacktricks-training.md}}

Use this section to investigate Linux hosts, understand privilege boundaries, and review the controls that constrain local access. Start with the [Linux basics](linux-basics/README.md) and the [privilege escalation checklist](main-system-information/linux-privilege-escalation-checklist.md) for a general assessment, then follow the relevant topic below.

- [Linux basics](linux-basics/README.md): privilege escalation methodology, useful commands, environment variables, and restriction bypasses.
- [Main system information](main-system-information/README.md): kernel, modules, sudo, filesystem behavior, jails, and the escalation checklist.
- [User information](user-information/README.md): Linux identities, groups, SSH agent forwarding, and Active Directory integration.
- [Interesting files and permissions](interesting-files-permissions/README.md): writable paths, capabilities, SUID behavior, NFS, wildcard expansion, and SELinux.
- [Network information](network-information/README.md): local services, sockets, and network-related exploitation examples.
- [Software information](software-information/README.md): authentication modules and application-specific attack surfaces.
- [Processes, crontab, systemd, and D-Bus](processes-crontab-systemd-dbus/README.md): scheduled execution and interprocess communication.
- [Containers and namespaces](containers-namespaces/README.md): runtimes, isolation boundaries, and container hardening.
- [AppArmor policy-control file abuse](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): assess whether a privileged helper can write to an AppArmor control file opened by a local user.
- [Post-exploitation](post-exploitation/README.md): credential discovery, persistence, and host-level follow-up techniques.

On affected kernels, opening an AppArmor securityfs policy-control file as an unprivileged user can succeed even though a direct write is denied. If a privileged helper inherits that file as stdout, its write can change loaded policy; this is a distinct local attack path from merely finding a weak container profile. Check the vendor kernel and helper fixes before testing it.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Qualys CrackArmor technical advisory](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu CrackArmor vulnerability knowledge base](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
