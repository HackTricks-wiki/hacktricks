# Linux Hardening

{{#include ../banners/hacktricks-training.md}}

Linux होस्ट की जाँच करने, privilege boundaries समझने और स्थानीय पहुँच को सीमित करने वाले controls की समीक्षा करने के लिए इस अनुभाग का उपयोग करें। सामान्य आकलन के लिए [Linux की मूल बातें](linux-basics/README.md) और [privilege escalation की जाँच-सूची](main-system-information/linux-privilege-escalation-checklist.md) से शुरुआत करें, फिर नीचे दिए गए संबंधित विषय पर जाएँ।

- [Linux की मूल बातें](linux-basics/README.md): privilege escalation की कार्यविधि, उपयोगी commands, environment variables और प्रतिबंधों को bypass करने के तरीके।
- [मुख्य सिस्टम जानकारी](main-system-information/README.md): kernel, modules, sudo, filesystem का व्यवहार, jails और escalation की जाँच-सूची।
- [उपयोगकर्ता की जानकारी](user-information/README.md): Linux identities, groups, SSH agent forwarding और Active Directory integration।
- [दिलचस्प फ़ाइलें और permissions](interesting-files-permissions/README.md): writable paths, capabilities, SUID का व्यवहार, NFS, wildcard expansion और SELinux।
- [नेटवर्क की जानकारी](network-information/README.md): स्थानीय services, sockets और network-संबंधित exploitation के उदाहरण।
- [सॉफ़्टवेयर की जानकारी](software-information/README.md): authentication modules और application-विशिष्ट attack surfaces।
- [Processes, crontab, systemd और D-Bus](processes-crontab-systemd-dbus/README.md): scheduled execution और interprocess communication।
- [Containers और namespaces](containers-namespaces/README.md): runtimes, isolation boundaries और container hardening।
- [Post-exploitation](post-exploitation/README.md): credentials की खोज, persistence और host-स्तर पर आगे की तकनीकें।
{{#include ../banners/hacktricks-training.md}}
