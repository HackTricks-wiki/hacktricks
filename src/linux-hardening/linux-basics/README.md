# Misingi ya Linux

{{#include ../../banners/hacktricks-training.md}}

Hapa ndipo pa kuanzia kutathmini host ya Linux. Kurasa hizi zinashughulikia mchakato mpana wa privilege escalation, amri za vitendo, vigeu vya mazingira na vizuizi vya kawaida vinavyoathiri kinachoweza kuendeshwa kwenye host.

- [Privilege escalation ya Linux](linux-privilege-escalation/README.md) inaeleza hatua za enumeration na njia zinazowezekana za ndani za privilege escalation. Kwa orodha fupi ya kazi, tumia [orodha ya ukaguzi ya privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Uanzishaji wa shell, aliases na historia](shell-startup-aliases-and-history.md) inaeleza jinsi amri zinavyopatikana, utekelezaji wa faili za uanzishaji na vidokezo vinavyopatikana kwenye historia.
- [Amri muhimu za Linux](useful-linux-commands.md) hukusanya amri za kukagua faili, michakato, huduma na mazingira.
- [Vigeu vya mazingira vya Linux](linux-environment-variables.md) inaeleza jinsi thamani za mazingira zinavyoathiri utekelezaji na mahali ambapo thamani nyeti zinaweza kuonekana.
- [Kukwepa vizuizi vya Linux](bypass-linux-restrictions/README.md) inahusu shell zenye vizuizi na mazingira ya utekelezaji, yakiwemo ulinzi wa mfumo wa faili, `noexec` na mifumo ya distroless.

## Unyonyaji wa binary asilia

Tathmini inapokupeleka kwenye executable ya Linux iliyo hatarini, tumia nyenzo husika katika Binary Exploitation:

- [Muundo wa ELF na tabia ya loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) na [ulinzi wa binary na mbinu za kuikwepa](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) vinaeleza mpangilio wa executable na mitigations.
- [Unyonyaji wa stack](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) na [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) zinahusu mashambulizi ya mtiririko wa udhibiti.
- [Unyonyaji wa heap ya Libc](../../binary-exploitation/libc-heap/README.md) na [format strings](../../binary-exploitation/format-strings/README.md) zinahusu njia nyingine za kawaida za kuharibu kumbukumbu.

Tafiti za matukio mahususi ya kernel zimeunganishwa kutoka [nyenzo za Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
