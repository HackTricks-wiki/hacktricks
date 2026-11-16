# Uimarishaji wa Linux

{{#include ../banners/hacktricks-training.md}}

Tumia sehemu hii kuchunguza mifumo ya Linux, kuelewa mipaka ya marupurupu, na kukagua vidhibiti vinavyozuia ufikiaji wa ndani. Anza na [Misingi ya Linux](linux-basics/README.md) na [orodha hakiki ya privilege escalation](main-system-information/linux-privilege-escalation-checklist.md) kwa tathmini ya jumla, kisha fuata mada husika hapa chini.

- [Misingi ya Linux](linux-basics/README.md): mbinu za privilege escalation, amri muhimu, vigeu vya mazingira, na njia za kukwepa vizuizi.
- [Taarifa kuu za mfumo](main-system-information/README.md): kernel, modules, sudo, tabia ya mfumo wa faili, jails, na orodha hakiki ya privilege escalation.
- [Taarifa za mtumiaji](user-information/README.md): utambulisho wa Linux, vikundi, uelekezaji wa SSH agent, na uunganishaji wa Active Directory.
- [Faili na ruhusa muhimu](interesting-files-permissions/README.md): njia zinazoweza kuandikwa, capabilities, tabia ya SUID, NFS, upanuzi wa wildcards, na SELinux.
- [Taarifa za mtandao](network-information/README.md): huduma za ndani, sockets, na mifano ya unyonyaji inayohusiana na mtandao.
- [Taarifa za software](software-information/README.md): modules za uthibitishaji na maeneo ya mashambulizi mahususi kwa programu.
- [Processes, crontab, systemd, na D-Bus](processes-crontab-systemd-dbus/README.md): utekelezaji uliopangwa na mawasiliano kati ya processes.
- [Containers na namespaces](containers-namespaces/README.md): runtimes, mipaka ya utengaji, na uimarishaji wa containers.
- [Matumizi mabaya ya faili ya udhibiti wa sera ya AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): tathmini kama helper yenye marupurupu inaweza kuandika kwenye faili ya udhibiti wa AppArmor ambayo imefunguliwa na mtumiaji wa ndani.
- [Post-exploitation](post-exploitation/README.md): ugunduzi wa taarifa za kuingia, persistence, na mbinu za ufuatiliaji katika kiwango cha host.

Kwenye kernels zilizoathirika, kufungua faili ya udhibiti wa sera ya AppArmor ya securityfs kama mtumiaji asiye na marupurupu kunaweza kufanikiwa ingawa uandishi wa moja kwa moja unakataliwa. Ikiwa helper yenye marupurupu itarithi faili hiyo kama stdout, uandishi wake unaweza kubadilisha sera iliyopakiwa; hii ni njia tofauti ya shambulizi la ndani na si sawa na kupata tu profile dhaifu ya container. Kagua marekebisho ya kernel na helper kutoka kwa mtengenezaji kabla ya kuijaribu.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Ushauri wa kiufundi wa Qualys kuhusu CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Msingi wa maarifa ya Ubuntu kuhusu udhaifu wa CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
