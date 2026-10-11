# Hardening di Linux

{{#include ../banners/hacktricks-training.md}}

Usa questa sezione per esaminare gli host Linux, comprendere i confini dei privilegi e rivedere i controlli che limitano l'accesso locale. Per una valutazione generale, inizia dalle [nozioni di base su Linux](linux-basics/README.md) e dalla [checklist per la privilege escalation](main-system-information/linux-privilege-escalation-checklist.md), quindi consulta l'argomento pertinente qui sotto.

- [Nozioni di base su Linux](linux-basics/README.md): metodologia di privilege escalation, comandi utili, variabili d'ambiente e bypass delle restrizioni.
- [Informazioni principali sul sistema](main-system-information/README.md): kernel, moduli, sudo, comportamento del filesystem, jail e checklist per la privilege escalation.
- [Informazioni sugli utenti](user-information/README.md): identità Linux, gruppi, agent forwarding SSH e integrazione con Active Directory.
- [File interessanti e permessi](interesting-files-permissions/README.md): percorsi scrivibili, capability, comportamento di SUID, NFS, espansione dei caratteri jolly e SELinux.
- [Informazioni di rete](network-information/README.md): servizi locali, socket ed esempi di exploitation relativi alla rete.
- [Informazioni sul software](software-information/README.md): moduli di autenticazione e superfici di attacco specifiche delle applicazioni.
- [Processi, crontab, systemd e D-Bus](processes-crontab-systemd-dbus/README.md): esecuzione pianificata e comunicazione tra processi.
- [Container e namespace](containers-namespaces/README.md): runtime, confini di isolamento e hardening dei container.
- [Post-exploitation](post-exploitation/README.md): individuazione di credenziali, persistenza e tecniche successive a livello host.
{{#include ../banners/hacktricks-training.md}}
