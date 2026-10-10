# Linux को मजबूत करना

{{#include ../banners/hacktricks-training.md}}

Linux hosts की जाँच करने, privilege boundaries समझने और local access को सीमित करने वाले controls की समीक्षा के लिए इस section का उपयोग करें। सामान्य आकलन के लिए [Linux की बुनियादी जानकारी](linux-basics/README.md) और [privilege escalation की जाँच-सूची](main-system-information/linux-privilege-escalation-checklist.md) से शुरुआत करें, फिर नीचे दिए गए संबंधित विषय पर जाएँ।

- [Linux की बुनियादी जानकारी](linux-basics/README.md): privilege escalation methodology, उपयोगी commands, environment variables और restrictions को bypass करने के तरीके।
- [मुख्य system जानकारी](main-system-information/README.md): kernel, modules, sudo, filesystem का व्यवहार, jails और escalation checklist।
- [User की जानकारी](user-information/README.md): Linux identities, groups, SSH agent forwarding और Active Directory integration।
- [दिलचस्प files और permissions](interesting-files-permissions/README.md): writable paths, capabilities, SUID का व्यवहार, NFS, wildcard expansion और SELinux।
- [Network की जानकारी](network-information/README.md): local services, sockets और network से जुड़े exploitation के उदाहरण।
- [Software की जानकारी](software-information/README.md): authentication modules और application-विशिष्ट attack surfaces।
- [Processes, crontab, systemd और D-Bus](processes-crontab-systemd-dbus/README.md): scheduled execution और interprocess communication।
- [Containers और namespaces](containers-namespaces/README.md): runtimes, isolation boundaries और container hardening।
- [Post-exploitation](post-exploitation/README.md): credentials की खोज, persistence और host-level follow-up techniques।
{{#include ../banners/hacktricks-training.md}}
