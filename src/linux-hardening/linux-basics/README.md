# Linux Basics

{{#include ../../banners/hacktricks-training.md}}

Questo è il punto di partenza per l'analisi degli host Linux. Le pagine descrivono un ampio flusso di lavoro per la privilege escalation, comandi pratici, variabili d'ambiente e restrizioni comuni che influiscono su ciò che può essere eseguito su un host.

- [Linux privilege escalation](linux-privilege-escalation/README.md) illustra l'enumeration e i potenziali percorsi di escalation locale. Per un elenco di attività più breve, consulta la [checklist per la privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- [Avvio della shell, alias e cronologia](shell-startup-aliases-and-history.md) spiega la risoluzione dei comandi, l'esecuzione dei file di avvio e gli indizi nella cronologia.
- [Comandi Linux utili](useful-linux-commands.md) raccoglie comandi per esaminare file, processi, servizi e ambiente.
- [Variabili d'ambiente Linux](linux-environment-variables.md) spiega come i valori d'ambiente influiscono sull'esecuzione e dove possono comparire valori sensibili.
- [Bypass delle restrizioni Linux](bypass-linux-restrictions/README.md) tratta le shell e gli ambienti di esecuzione vincolati, incluse le protezioni del filesystem, `noexec` e i sistemi distroless.

## Native binary exploitation

Quando un assessment porta a un eseguibile Linux vulnerabile, consulta il materiale pertinente in Binary Exploitation:

- [Formato ELF e comportamento del loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) e [protezioni dei binary e relativi bypass](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) spiegano la struttura dell'eseguibile e le mitigazioni.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) e [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) trattano gli attacchi al flusso di controllo.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) e [format strings](../../binary-exploitation/format-strings/README.md) trattano altri comuni percorsi di corruzione della memoria.

I casi di studio specifici del kernel sono collegati da [materiale su Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
