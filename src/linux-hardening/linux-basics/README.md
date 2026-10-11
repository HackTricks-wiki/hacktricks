# Misingi ya Linux

{{#include ../../banners/hacktricks-training.md}}

Hii ndiyo sehemu ya kuanzia kwa tathmini ya host ya Linux. Kurasa hizi zinashughulikia mchakato mpana wa privilege escalation, amri za vitendo, environment variables, na vizuizi vya kawaida vinavyoathiri kile kinachoweza kuendeshwa kwenye host.

- [Linux privilege escalation](linux-privilege-escalation/README.md) inaeleza hatua za kufanya enumeration na njia zinazowezekana za local escalation. Kwa orodha fupi ya kazi, tumia [checklist ya privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Shell startup, aliases, and history](shell-startup-aliases-and-history.md) inaeleza utatuzi wa amri, uendeshaji wa startup files, na vidokezo vinavyopatikana kwenye history.
- [Amri muhimu za Linux](useful-linux-commands.md) inakusanya amri za kukagua faili, michakato, huduma, na mazingira.
- [Environment variables za Linux](linux-environment-variables.md) inaeleza jinsi thamani za mazingira zinavyoathiri utekelezaji na mahali ambapo thamani nyeti zinaweza kuonekana.
- [Kuvuka vizuizi vya Linux](bypass-linux-restrictions/README.md) inashughulikia shells zenye vizuizi na mazingira ya utekelezaji, ikijumuisha ulinzi wa mfumo wa faili, `noexec`, na mifumo ya distroless.

## Native binary exploitation

Tathmini ikikuelekeza kwenye executable ya Linux iliyo hatarini, tumia nyenzo husika katika Binary Exploitation:

- [Muundo wa ELF na tabia ya loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) na [ulinzi wa binary na mbinu za kuupita](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) zinaeleza mpangilio wa executable na mitigations.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) na [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) zinashughulikia mashambulizi ya control-flow.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) na [format strings](../../binary-exploitation/format-strings/README.md) zinashughulikia njia nyingine za kawaida za memory corruption.

Case studies zinazohusu kernel zimeunganishwa katika [nyenzo za Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
