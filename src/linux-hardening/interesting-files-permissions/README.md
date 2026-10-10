# File e permessi interessanti

{{#include ../../banners/hacktricks-training.md}}

La proprietà dei file, i permessi di scrittura, le opzioni di mount e i privilegi di esecuzione possono modificare i privilegi effettivi di un utente locale. Inizia individuando il file o il percorso di esecuzione interessato, quindi consulta la pagina pertinente:

- [SUID, SGID, ACL e file sensibili](suid-sgid-and-acl-triage.md) fornisce un flusso di lavoro iniziale per i privilegi di esecuzione e i permessi di accesso nascosti.
- [Scrittura arbitraria di file come root](write-to-root.md) descrive come sfruttare le scritture in percorsi privilegiati per ottenere un'escalation.
- [Linux capabilities](linux-capabilities.md) spiega le capabilities per processo e per file.
- [Abuso di librerie condivise e linker con SUID](suid-shared-library-and-linker-abuse.md) tratta il caricamento dinamico in relazione ai binari privilegiati.
- [Esempio di escalation dei privilegi con `ld.so`](ld.so.conf-example.md) illustra un caso relativo alla configurazione del linker.
- [Configurazione errata di NFS con `no_root_squash` e `no_all_squash`](nfs-no_root_squash-misconfiguration-pe.md) tratta la mappatura delle identità nei filesystem remoti.
- [Trucchi con i caratteri jolly](wildcards-spare-tricks.md) tratta l'espansione degli argomenti nei comandi privilegiati.
- [SELinux](selinux.md) spiega l'applicazione delle policy e i passaggi pertinenti per le verifiche.
{{#include ../../banners/hacktricks-training.md}}
