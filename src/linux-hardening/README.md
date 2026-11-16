# Linux को सुरक्षित करना

{{#include ../banners/hacktricks-training.md}}

इस सेक्शन का उपयोग Linux होस्ट की जाँच करने, privilege boundaries समझने और स्थानीय पहुँच को सीमित करने वाले controls की समीक्षा करने के लिए करें। सामान्य आकलन के लिए [Linux की मूल बातें](linux-basics/README.md) और [privilege escalation checklist](main-system-information/linux-privilege-escalation-checklist.md) से शुरू करें, फिर नीचे दिए गए संबंधित विषय पर जाएँ।

- [Linux की मूल बातें](linux-basics/README.md): privilege escalation methodology, उपयोगी commands, environment variables और restriction bypasses।
- [मुख्य सिस्टम जानकारी](main-system-information/README.md): kernel, modules, sudo, filesystem का व्यवहार, jails और escalation checklist।
- [उपयोगकर्ता जानकारी](user-information/README.md): Linux identities, groups, SSH agent forwarding और Active Directory integration।
- [रोचक फ़ाइलें और permissions](interesting-files-permissions/README.md): writable paths, capabilities, SUID behavior, NFS, wildcard expansion और SELinux।
- [नेटवर्क जानकारी](network-information/README.md): local services, sockets और network-related exploitation के उदाहरण।
- [सॉफ़्टवेयर जानकारी](software-information/README.md): authentication modules और application-specific attack surfaces।
- [Processes, crontab, systemd और D-Bus](processes-crontab-systemd-dbus/README.md): scheduled execution और interprocess communication।
- [Containers और namespaces](containers-namespaces/README.md): runtimes, isolation boundaries और container hardening।
- [AppArmor policy-control फ़ाइल का दुरुपयोग](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): जाँचें कि क्या कोई privileged helper, किसी local user द्वारा खोली गई AppArmor control file में लिख सकता है।
- [Post-exploitation](post-exploitation/README.md): credentials की खोज, persistence और host-level follow-up techniques।

प्रभावित kernels पर, किसी unprivileged user द्वारा AppArmor securityfs policy-control file खोलना सफल हो सकता है, भले ही सीधे उसमें लिखने की अनुमति न हो। यदि कोई privileged helper उस फ़ाइल को stdout के रूप में inherit करता है, तो उसके लिखने से loaded policy बदल सकती है; यह केवल किसी कमज़ोर container profile को ढूँढ़ने से अलग local attack path है। इसका परीक्षण करने से पहले vendor kernel और helper fixes की जाँच करें।<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Qualys CrackArmor तकनीकी सलाह](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu CrackArmor vulnerability ज्ञान आधार](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
