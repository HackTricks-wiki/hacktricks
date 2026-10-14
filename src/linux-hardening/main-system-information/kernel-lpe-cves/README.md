# Materiale su kernel, LPE e CVE

{{#include ../../../banners/hacktricks-training.md}}

Questi casi di studio trattano primitive distinte di escalation dei privilegi locale. Prima di applicare una tecnica, verifica in ciascun articolo il prodotto o il kernel interessato, la configurazione e i prerequisiti. Per un’enumerazione più ampia dell’host, consulta la [checklist per l’escalation dei privilegi su Linux](../linux-privilege-escalation-checklist.md).

Per Dirty Pipe (CVE-2022-0847), la [ricerca originale](https://dirtypipe.cm4all.com/) indica che le correzioni upstream per le versioni stable sono state rilasciate nelle versioni 5.10.102, 5.15.25 e 5.16.11. Una versione del kernel in un intervallo precedente noto come vulnerabile è solo un punto di partenza per la verifica: le distribuzioni possono includere le correzioni tramite backport con nomi di release diversi, e il file di destinazione pertinente deve essere leggibile affinché la primitiva di scrittura nella page cache sia utilizzabile. Sovrascrivere un eseguibile SUID leggibile è una possibile via per ottenere privilegi se la transizione set-ID rimane effettiva; anche la modifica di `/etc/passwd` e la successiva autenticazione possono dipendere dallo stack PAM locale. Prima di valutare la raggiungibilità, verifica il pacchetto kernel del fornitore installato, il kernel in esecuzione dopo il riavvio, i permessi del file di destinazione, l’opzione di mount `nosuid` e `no_new_privs`. Non eseguire una prova di scrittura durante l’enumerazione passiva. Consulta lo [stato specifico per release di Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): esecuzione con privilegi tramite la ricerca dei percorsi dei processi non attendibili.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): un percorso per sovrascrivere la page cache del kernel.
- [POSIX CPU timers TOCTOU race and exploitation, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): scadenza e cancellazione del timer durante l’uscita del task, inclusi i prerequisiti del percorso IRQ e la ricerca sull’exploit.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): accesso ai file descriptor durante una race sull’uscita di un processo.

## Casi di studio correlati di binary exploitation

La sezione Binary Exploitation approfondisce le primitive di exploit, il layout della memoria e i bypass delle mitigazioni per questi target del kernel Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un bug dei socket trasformato in primitive di lettura e scrittura nel kernel.
- [AF_ALG concurrent-writer scatterlist underflow](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): una race tra writer skcipher sfruttata per ottenere una scrittura nel kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitiva di scrittura tramite puntatore estesa attraverso i pipe buffer e le workqueue.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploit dell’heap del kernel e bypass delle mitigazioni.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): individuazione degli indirizzi per l’exploitation del kernel arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): un percorso GPU Android per accedere alla memoria del kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un bug dell’acceleratore Android usato per scrivere nel kernel.
{{#include ../../../banners/hacktricks-training.md}}
