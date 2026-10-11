# Misingi ya Linux

{{#include ../../banners/hacktricks-training.md}}

Hapa ndipo tathmini ya Linux host huanzia. Kurasa hizi zinashughulikia mchakato mpana wa privilege escalation, amri za vitendo, environment variables, na vizuizi vya kawaida vinavyoathiri kinachoweza kuendeshwa kwenye host.

- [Linux privilege escalation](linux-privilege-escalation/README.md) inaeleza hatua za enumeration na njia zinazowezekana za escalation ya ndani. Kwa orodha fupi ya kazi, tumia [orodha hakiki ya privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Kuanzisha shell, aliases, na historia](shell-startup-aliases-and-history.md) inaeleza jinsi amri zinavyopatikana, faili za startup zinavyotekelezwa, na vidokezo vinavyopatikana kwenye historia.
- [Amri muhimu za Linux](useful-linux-commands.md) inakusanya amri za kukagua faili, michakato, huduma na mazingira.
- [Linux environment variables](linux-environment-variables.md) inaeleza jinsi thamani za mazingira zinavyoathiri utekelezaji na mahali ambapo thamani nyeti zinaweza kuonekana.
- [Bypass Linux restrictions](bypass-linux-restrictions/README.md) inashughulikia shell na mazingira ya utekelezaji yenye vizuizi, ikijumuisha ulinzi wa mfumo wa faili, `noexec`, na mifumo ya distroless.

## Native binary exploitation

Ikiwa tathmini itafichua executable ya Linux iliyo hatarini, tumia nyenzo husika katika Binary Exploitation:

- [Muundo wa ELF na tabia ya loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) na [ulinzi wa binary na mbinu za kuupita](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) zinaeleza mpangilio wa executable na mitigations.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) na [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) zinashughulikia mashambulizi ya udhibiti wa mtiririko.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) na [format strings](../../binary-exploitation/format-strings/README.md) zinashughulikia njia nyingine za kawaida za kuharibu kumbukumbu.

Mifano ya uchunguzi mahususi wa kernel imeunganishwa kutoka kwenye [nyenzo za Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
