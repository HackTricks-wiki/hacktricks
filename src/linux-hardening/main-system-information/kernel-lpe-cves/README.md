# Materiale su kernel, LPE e CVE

{{#include ../../../banners/hacktricks-training.md}}

Questi casi di studio illustrano diverse primitive di local privilege escalation. Prima di applicare una tecnica, verifica in ogni articolo il prodotto o kernel interessato, la configurazione e i prerequisiti. Per un’enumerazione più ampia dell’host, consulta la [checklist per la privilege escalation su Linux](../linux-privilege-escalation-checklist.md).

Per Dirty Pipe (CVE-2022-0847), la [ricerca originale](https://dirtypipe.cm4all.com/) indica che le correzioni upstream stable sono state rilasciate nelle versioni 5.10.102, 5.15.25 e 5.16.11. Una versione del kernel in un intervallo precedente interessato è solo un indizio da verificare: i kernel delle distribuzioni possono includere backport delle correzioni con nomi di release diversi, e il file di destinazione interessato deve essere leggibile affinché la primitiva di scrittura nella page cache sia utilizzabile. Sovrascrivere un eseguibile SUID leggibile è una possibile via per ottenere privilegi, se la transizione set-ID resta effettiva; anche modificare `/etc/passwd` e autenticarsi successivamente può dipendere dallo stack PAM locale. Prima di valutare se la vulnerabilità è sfruttabile, controlla il pacchetto del kernel del vendor installato, il kernel in esecuzione dopo il riavvio, i permessi del file di destinazione, il mount `nosuid` e `no_new_privs`. Non eseguire una sonda di scrittura durante l’enumerazione passiva. Consulta lo [stato specifico per release di Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): esecuzione con privilegi elevati tramite ricerca non attendibile del percorso dei processi.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): un percorso di sovrascrittura della page cache del kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): una race condition nella gestione dei timer.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): accesso ai file descriptor durante una race condition in uscita da un processo.

## Casi di studio correlati di Binary Exploitation

La sezione Binary Exploitation approfondisce le primitive di exploit, il layout della memoria e i bypass delle mitigazioni per questi target del kernel Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un bug nei socket usato per ottenere primitive di lettura e scrittura del kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitiva di scrittura di puntatori estesa tramite pipe buffer e workqueue.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): exploit dell’heap del kernel e bypass delle mitigazioni.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): l’analisi di Binary Exploitation della race condition dei timer, riassunta anche sopra.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): individuazione degli indirizzi per l’exploit del kernel arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): un percorso attraverso la GPU Android per accedere alla memoria del kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un bug dell’acceleratore Android usato per scrivere nel kernel.
{{#include ../../../banners/hacktricks-training.md}}
