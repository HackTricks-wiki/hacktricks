# Linux-basiese beginsels

{{#include ../../banners/hacktricks-training.md}}

Dit is die beginpunt vir die assessering van Linux-gashere. Die bladsye dek ’n breë privilege escalation-werkvloei, praktiese opdragte, omgewingsveranderlikes en algemene beperkings wat bepaal wat op ’n gasheer uitgevoer kan word.

- [Linux privilege escalation](linux-privilege-escalation/README.md) lei jou deur enumerasie en moontlike plaaslike escalation-paaie. Gebruik die [privilege escalation-kontrolelys](../main-system-information/linux-privilege-escalation-checklist.md) vir ’n korter taaklys.
- [Shell-opstart, aliases en geskiedenis](shell-startup-aliases-and-history.md) verduidelik opdragresolusie, die uitvoering van opstartlêers en leidrade in die geskiedenis.
- [Nuttige Linux-opdragte](useful-linux-commands.md) versamel opdragte om lêers, prosesse, dienste en die omgewing te ondersoek.
- [Linux-omgewingsveranderlikes](linux-environment-variables.md) verduidelik hoe omgewingswaardes uitvoering beïnvloed en waar sensitiewe waardes kan voorkom.
- [Omseil Linux-beperkings](bypass-linux-restrictions/README.md) dek beperkte shells en uitvoeringsomgewings, insluitend lêerstelselbeskermings, `noexec` en distroless-stelsels.

## Native binary exploitation

Wanneer ’n assessering lei tot ’n kwesbare Linux-uitvoerbare lêer, gebruik die toepaslike materiaal in Binary Exploitation:

- [ELF-formaat en laaiergedrag](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) en [binary-beskermings en -omseilings](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) verduidelik die uitleg van uitvoerbare lêers en versagtingsmaatreëls.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) en [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) dek control-flow-aanvalle.
- [Libc-heap exploitation](../../binary-exploitation/libc-heap/README.md) en [format strings](../../binary-exploitation/format-strings/README.md) dek ander algemene geheuekorrupsie-paaie.

Kernspesifieke gevallestudies is beskikbaar vanaf [Kernel/LPE/CVE-materiaal](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
