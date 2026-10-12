# Materiale su kernel, LPE e CVE

{{#include ../../../banners/hacktricks-training.md}}

Questi casi di studio trattano primitive distinte di privilege escalation locale. Prima di applicare una tecnica, verifica il prodotto o il kernel interessato, la configurazione e i prerequisiti indicati in ciascun articolo. Per una più ampia enumerazione dell'host, consulta la [checklist di privilege escalation su Linux](../linux-privilege-escalation-checklist.md).

Per Dirty Pipe (CVE-2022-0847), la [ricerca originale](https://dirtypipe.cm4all.com/) indica le versioni stabili upstream che includono le correzioni: 5.10.102, 5.15.25 e 5.16.11. Una versione del kernel appartenente a un intervallo precedente noto come vulnerabile è solo un'indicazione da approfondire: i kernel delle distribuzioni possono includere le correzioni tramite backport con nomi di release diversi, e il file di destinazione deve essere leggibile per usare la primitiva di scrittura nella page cache. Sovrascrivere un eseguibile SUID leggibile è un possibile percorso per ottenere privilegi, se la transizione set-ID resta effettiva; anche la modifica di `/etc/passwd` e la successiva autenticazione possono dipendere dallo stack PAM locale. Prima di valutare la raggiungibilità, controlla il pacchetto del kernel del vendor installato, il kernel in esecuzione dopo il riavvio, i permessi del file di destinazione, l'opzione di mount `nosuid` e `no_new_privs`. Non eseguire una write probe durante l'enumerazione passiva. Consulta lo [stato specifico per release di Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Individuazione del servizio VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): esecuzione con privilegi tramite individuazione del percorso del processo non attendibile.
- [Sovrascrittura della page cache tramite splice di AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): un percorso di sovrascrittura della page cache del kernel.
- [Race condition TOCTOU nei timer CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): una race condition nella gestione dei timer.
- [Race condition di uscita di Linux ptrace e furto di file descriptor tramite `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): accesso ai descriptor durante una race condition di uscita di un processo.

## Casi di studio correlati sul binary exploitation

La sezione Binary Exploitation approfondisce le primitive di exploit, il layout della memoria e i bypass delle mitigazioni per questi target del kernel Linux:

- [Use-after-free di SKB out-of-band in AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un bug nei socket sviluppato fino a ottenere primitive di lettura e scrittura nel kernel.
- [Underflow della scatterlist con writer concorrenti in AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): una race condition del writer skcipher sviluppata fino a ottenere una scrittura nel kernel.
- [Use-after-free di Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitiva di scrittura tramite puntatore estesa attraverso pipe buffer e workqueue.
- [Scrittura out-of-bounds degli stream di ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploitation del kernel heap e bypass delle mitigazioni.
- [Race condition TOCTOU nei timer CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): l'analisi di binary exploitation della race condition dei timer, riassunta anche sopra.
- [Bypass di KASLR della linear map statica su Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): individuazione degli indirizzi per l'exploitation del kernel arm64.
- [Bypass dei privilegi GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): un percorso GPU Android per accedere alla memoria del kernel.
- [Use-after-free per timeout del job Bigwave su Pixel](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un bug dell'acceleratore Android utilizzato per effettuare scritture nel kernel.
{{#include ../../../banners/hacktricks-training.md}}
