# Nozioni di base su Linux

{{#include ../../banners/hacktricks-training.md}}

Questo è il punto di partenza per la valutazione di un host Linux. Le pagine illustrano un ampio flusso di lavoro per l’escalation dei privilegi, comandi pratici, variabili d’ambiente e restrizioni comuni che influiscono su ciò che può essere eseguito su un host.

- [Escalation dei privilegi in Linux](linux-privilege-escalation/README.md) illustra l’enumerazione e i potenziali percorsi di escalation locale. Per un elenco di attività più breve, usa la [checklist per l’escalation dei privilegi](../main-system-information/linux-privilege-escalation-checklist.md).
- [Avvio della shell, alias e cronologia](shell-startup-aliases-and-history.md) spiega la risoluzione dei comandi, l’esecuzione dei file di avvio e gli indizi nella cronologia.
- [Comandi Linux utili](useful-linux-commands.md) raccoglie comandi per esaminare file, processi, servizi e l’ambiente.
- [Variabili d’ambiente di Linux](linux-environment-variables.md) spiega come i valori d’ambiente influiscono sull’esecuzione e dove possono comparire valori sensibili.
- [Aggirare le restrizioni di Linux](bypass-linux-restrictions/README.md) tratta le shell e gli ambienti di esecuzione vincolati, comprese le protezioni del filesystem, `noexec` e i sistemi distroless.

## Exploitation nativa dei binari

Quando una valutazione porta a un eseguibile Linux vulnerabile, consulta il materiale pertinente in Binary Exploitation:

- [Formato ELF e comportamento del loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) e [protezioni dei binari e tecniche per aggirarle](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) spiegano la struttura dell’eseguibile e le mitigazioni.
- [Exploitation dello stack](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) e [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) trattano gli attacchi al flusso di controllo.
- [Exploitation dell’heap di Libc](../../binary-exploitation/libc-heap/README.md) e [format string](../../binary-exploitation/format-strings/README.md) trattano altri percorsi comuni di corruzione della memoria.

I casi di studio specifici del kernel sono collegati da [materiale su Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
