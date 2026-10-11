# Hardening di Linux

{{#include ../banners/hacktricks-training.md}}

Usa questa sezione per esaminare gli host Linux, comprendere i confini dei privilegi e verificare i controlli che limitano l’accesso locale. Inizia dalle [nozioni di base su Linux](linux-basics/README.md) e dalla [checklist per l’escalation dei privilegi](main-system-information/linux-privilege-escalation-checklist.md) per una valutazione generale, quindi consulta l’argomento pertinente qui sotto.

- [Nozioni di base su Linux](linux-basics/README.md): metodologia per l’escalation dei privilegi, comandi utili, variabili d’ambiente e tecniche per aggirare le restrizioni.
- [Informazioni principali sul sistema](main-system-information/README.md): kernel, moduli, sudo, comportamento del filesystem, jail e checklist per l’escalation.
- [Informazioni sugli utenti](user-information/README.md): identità e gruppi Linux, inoltro dell’SSH agent e integrazione con Active Directory.
- [File e permessi interessanti](interesting-files-permissions/README.md): percorsi scrivibili, capabilities, comportamento di SUID, NFS, espansione dei caratteri jolly e SELinux.
- [Informazioni sulla rete](network-information/README.md): servizi locali, socket ed esempi di sfruttamento legati alla rete.
- [Informazioni sul software](software-information/README.md): moduli di autenticazione e superfici di attacco specifiche delle applicazioni.
- [Processi, crontab, systemd e D-Bus](processes-crontab-systemd-dbus/README.md): esecuzione pianificata e comunicazione tra processi.
- [Container e namespace](containers-namespaces/README.md): runtime, confini di isolamento e hardening dei container.
- [Post-exploitation](post-exploitation/README.md): ricerca di credenziali, persistenza e tecniche successive a livello host.
{{#include ../banners/hacktricks-training.md}}
