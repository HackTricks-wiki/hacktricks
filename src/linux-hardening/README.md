# Linux Hardening

{{#include ../banners/hacktricks-training.md}}

इस section का उपयोग Linux hosts की जाँच करने, privilege boundaries को समझने और local access को सीमित करने वाले controls की समीक्षा करने के लिए करें। सामान्य आकलन के लिए [Linux की मूल बातें](linux-basics/README.md) और [privilege escalation checklist](main-system-information/linux-privilege-escalation-checklist.md) से शुरुआत करें, फिर नीचे दिए गए संबंधित विषय पर जाएँ।

- [Linux की मूल बातें](linux-basics/README.md): privilege escalation methodology, उपयोगी commands, environment variables और restriction bypasses।
- [मुख्य system information](main-system-information/README.md): kernel, modules, sudo, filesystem behavior, jails और escalation checklist।
- [User information](user-information/README.md): Linux identities, groups, SSH agent forwarding और Active Directory integration।
- [दिलचस्प files और permissions](interesting-files-permissions/README.md): writable paths, capabilities, SUID behavior, NFS, wildcard expansion और SELinux।
- [Network information](network-information/README.md): local services, sockets और network-संबंधित exploitation के उदाहरण।
- [Software information](software-information/README.md): authentication modules और application-विशिष्ट attack surfaces।
- [Processes, crontab, systemd और D-Bus](processes-crontab-systemd-dbus/README.md): scheduled execution और interprocess communication।
- [Containers और namespaces](containers-namespaces/README.md): runtimes, isolation boundaries और container hardening।
- [Post-exploitation](post-exploitation/README.md): credentials की खोज, persistence और host-स्तर की आगे की तकनीकें।
{{#include ../banners/hacktricks-training.md}}
