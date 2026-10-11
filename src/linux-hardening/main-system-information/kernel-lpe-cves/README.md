# Materiale su Kernel, LPE e CVE

{{#include ../../../banners/hacktricks-training.md}}

Questi case study trattano primitive distinte di privilege escalation locale. Prima di applicare una tecnica, verifica il prodotto o il kernel interessato, la configurazione e i prerequisiti descritti in ciascun articolo. Per un'enumerazione dell'host più ampia, consulta la [checklist di privilege escalation Linux](../linux-privilege-escalation-checklist.md).

Per Dirty Pipe (CVE-2022-0847), la [ricerca originale](https://dirtypipe.cm4all.com/) indica che le correzioni upstream stable sono nelle versioni 5.10.102, 5.15.25 e 5.16.11. Una versione del kernel compresa in un intervallo precedente potenzialmente vulnerabile è solo un'indicazione da approfondire: le distribuzioni possono integrare le correzioni in backport con nomi di release diversi, e il file target pertinente deve essere leggibile affinché la primitive di scrittura nella page cache funzioni. Sovrascrivere un eseguibile SUID leggibile è una possibile via per ottenere privilegi quando la transizione set-ID resta effettiva; anche modificare `/etc/passwd` e poi autenticarsi può dipendere dallo stack PAM locale. Prima di valutare la raggiungibilità, controlla il pacchetto del kernel del vendor installato, il kernel in esecuzione dopo il riavvio, i permessi del target, l'opzione di mount `nosuid` e `no_new_privs`. Non eseguire una write probe durante l'enumerazione passiva. Consulta lo [stato specifico per release di Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Individuazione del servizio VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): esecuzione con privilegi tramite ricerca non attendibile dei percorsi dei processi.
- [Sovrascrittura della page cache tramite splice AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): un percorso di sovrascrittura della page cache del kernel.
- [TOCTOU dei timer CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): una race nella gestione dei timer.
- [Race di uscita di `ptrace` Linux e furto di file descriptor con `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): accesso ai descriptor durante una race di uscita di un processo.

## Case study correlati di binary exploitation

La sezione Binary Exploitation approfondisce le primitive di exploit, il layout della memoria e i bypass delle mitigazioni per questi target del kernel Linux:

- [Use-after-free di SKB out-of-band AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un bug dei socket trasformato in primitive di lettura e scrittura nel kernel.
- [Use-after-free di Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitive di scrittura di puntatori estesa tramite pipe buffer e workqueue.
- [Scrittura out-of-bounds degli stream ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploit dell'heap del kernel e bypass delle mitigazioni.
- [TOCTOU dei timer CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): l'analisi di binary exploitation della race dei timer, riassunta anche sopra.
- [Bypass di KASLR della mappatura lineare statica Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): individuazione degli indirizzi per l'exploit del kernel arm64.
- [Bypass dei privilegi GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): un percorso tramite GPU Android per accedere alla memoria del kernel.
- [Use-after-free del timeout dei job Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un bug di un acceleratore Android sfruttato per scrivere nel kernel.
{{#include ../../../banners/hacktricks-training.md}}
