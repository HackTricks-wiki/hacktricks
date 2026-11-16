# Linux-verharding

{{#include ../banners/hacktricks-training.md}}

Gebruik hierdie afdeling om Linux-gashere te ondersoek, voorreggrense te verstaan en die kontroles na te gaan wat plaaslike toegang beperk. Begin met die [Linux-basiese beginsels](linux-basics/README.md) en die [kontrolelys vir privilege escalation](main-system-information/linux-privilege-escalation-checklist.md) vir ’n algemene assessering, en volg dan die relevante onderwerp hieronder.

- [Linux-basiese beginsels](linux-basics/README.md): metodologie vir privilege escalation, nuttige opdragte, omgewingsveranderlikes en omseilings van beperkings.
- [Hoofstelselinligting](main-system-information/README.md): kernel, modules, sudo, lêerstelselgedrag, jails en die kontrolelys vir privilege escalation.
- [Gebruikersinligting](user-information/README.md): Linux-identiteite, groepe, SSH-agent-aanstuur en Active Directory-integrasie.
- [Interessante lêers en toestemmings](interesting-files-permissions/README.md): skryfbare paaie, vermoëns, SUID-gedrag, NFS, jokertekenuitbreiding en SELinux.
- [Netwerkinligting](network-information/README.md): plaaslike dienste, sockets en voorbeelde van netwerkverwante uitbuiting.
- [Sagteware-inligting](software-information/README.md): verifikasiemodules en toepassingspesifieke aanvalsvlakke.
- [Prosesse, crontab, systemd en D-Bus](processes-crontab-systemd-dbus/README.md): geskeduleerde uitvoering en interproseskommunikasie.
- [Houers en namespaces](containers-namespaces/README.md): runtimes, isolasiegrense en hardening van houers.
- [Misbruik van AppArmor-beleidsbeheer-lêers](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): bepaal of ’n bevoorregte helper na ’n AppArmor-beheerlêer kan skryf wat deur ’n plaaslike gebruiker oopgemaak is.
- [Post-exploitation](post-exploitation/README.md): ontdekking van geloofsbriewe, volharding en opvolgtegnieke op gasheervlak.

Op geraakte kernels kan ’n onbevoorregte gebruiker ’n AppArmor securityfs-beleidsbeheerlêer oopmaak, al word ’n direkte skryfpoging geweier. As ’n bevoorregte helper daardie lêer as stdout erf, kan sy skryfpoging die gelaaide beleid verander; dit is ’n afsonderlike plaaslike aanvalspad en nie bloot die opsporing van ’n swak houerprofiel nie. Gaan die verskaffer se kernel- en helperoplossings na voordat jy dit toets.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Qualys CrackArmor-tegniese advies](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu CrackArmor-kwesbaarheidkennisbasis](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
