# Hardening di Linux

{{#include ../banners/hacktricks-training.md}}

Usa questa sezione per analizzare gli host Linux, comprendere i confini dei privilegi e verificare i controlli che limitano l'accesso locale. Per una valutazione generale, inizia dalle [basi di Linux](linux-basics/README.md) e dalla [checklist per l'escalation dei privilegi](main-system-information/linux-privilege-escalation-checklist.md), poi consulta l'argomento pertinente qui sotto.

- [Basi di Linux](linux-basics/README.md): metodologia di escalation dei privilegi, comandi utili, variabili d'ambiente e bypass delle restrizioni.
- [Informazioni principali sul sistema](main-system-information/README.md): kernel, moduli, sudo, comportamento del filesystem, jail e checklist per l'escalation.
- [Informazioni sugli utenti](user-information/README.md): identità Linux, gruppi, inoltro dell'agent SSH e integrazione con Active Directory.
- [File e permessi interessanti](interesting-files-permissions/README.md): percorsi scrivibili, capability, comportamento di SUID, NFS, espansione dei caratteri jolly e SELinux.
- [Informazioni sulla rete](network-information/README.md): servizi locali, socket ed esempi di exploitation relativi alla rete.
- [Informazioni sul software](software-information/README.md): moduli di autenticazione e superfici di attacco specifiche delle applicazioni.
- [Processi, crontab, systemd e D-Bus](processes-crontab-systemd-dbus/README.md): esecuzione pianificata e comunicazione tra processi.
- [Container e namespace](containers-namespaces/README.md): runtime, confini di isolamento e hardening dei container.
- [Abuso dei file di controllo delle policy di AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): verifica se un helper con privilegi può scrivere in un file di controllo di AppArmor aperto da un utente locale.
- [Post-exploitation](post-exploitation/README.md): ricerca di credenziali, persistenza e tecniche successive a livello di host.

Nei kernel vulnerabili, l'apertura di un file di controllo delle policy di AppArmor in securityfs da parte di un utente senza privilegi può riuscire anche se una scrittura diretta viene negata. Se un helper con privilegi eredita quel file come stdout, la sua scrittura può modificare la policy caricata; si tratta di un percorso di attacco locale distinto dal semplice individuare un profilo di container debole. Prima di testarlo, verifica le correzioni per il kernel del vendor e per l'helper.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Avviso tecnico di Qualys su CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Knowledge base di Ubuntu sulla vulnerabilità CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
