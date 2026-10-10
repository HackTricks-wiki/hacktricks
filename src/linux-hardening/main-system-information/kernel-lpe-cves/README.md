# Materiale su kernel, LPE e CVE

{{#include ../../../banners/hacktricks-training.md}}

Questi casi di studio illustrano primitive distinte per l'escalation locale dei privilegi. Prima di applicare una tecnica, verifica il prodotto o il kernel interessato, la configurazione e i prerequisiti indicati in ciascun articolo. Per un'enumerazione più ampia dell'host, consulta la [checklist per l'escalation dei privilegi su Linux](../linux-privilege-escalation-checklist.md).

Per Dirty Pipe (CVE-2022-0847), la [ricerca originale](https://dirtypipe.cm4all.com/) identifica le correzioni upstream stable nelle versioni 5.10.102, 5.15.25 e 5.16.11. Una versione del kernel compresa in un intervallo interessato più vecchio è solo un'indicazione da verificare: i kernel delle distribuzioni possono includere correzioni retroportate con nomi di release diversi, e il file di destinazione deve essere leggibile per sfruttare la primitiva di scrittura nella page cache. Sovrascrivere un eseguibile SUID leggibile è un possibile percorso verso i privilegi, se la transizione set-ID rimane effettiva; anche la modifica di `/etc/passwd` e la successiva autenticazione possono dipendere dallo stack PAM locale. Prima di valutare la raggiungibilità, verifica il pacchetto del kernel del fornitore installato, il kernel in esecuzione dopo il riavvio, i permessi del file di destinazione, l'opzione di mount `nosuid` e `no_new_privs`. Non eseguire una write probe durante l'enumerazione passiva. Consulta lo [stato specifico per release di Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Individuazione del servizio VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): esecuzione privilegiata tramite individuazione di percorsi di processo non attendibili.
- [Sovrascrittura della page cache tramite splice AF_ALG, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): un percorso per sovrascrivere la page cache del kernel.
- [TOCTOU dei timer CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): una race nella gestione dei timer.
- [Race di uscita di ptrace su Linux e furto di file descriptor con `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): accesso ai descriptor durante una race di uscita del processo.

## Casi di studio correlati sullo sfruttamento di binari

La sezione Binary Exploitation approfondisce le primitive di exploit, il layout della memoria e l'elusione delle mitigazioni per questi target del kernel Linux:

- [Use-after-free di SKB out-of-band AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): un bug di socket trasformato in primitive di lettura e scrittura nel kernel.
- [Use-after-free di Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): una primitiva di scrittura di puntatori estesa tramite pipe buffer e workqueue.
- [Scrittura out-of-bounds degli stream ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): sfruttamento dell'heap del kernel ed elusione delle mitigazioni.
- [TOCTOU dei timer CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): l'analisi della race dal punto di vista del binary exploitation, riassunta anche sopra.
- [Elusione di KASLR sulla linear map statica di Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): individuazione degli indirizzi per lo sfruttamento del kernel arm64.
- [Elusione dei privilegi GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): un percorso GPU Android per accedere alla memoria del kernel.
- [Use-after-free per timeout dei job Bigwave di Pixel](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): un bug dell'acceleratore Android usato per scrivere nel kernel.
{{#include ../../../banners/hacktricks-training.md}}
