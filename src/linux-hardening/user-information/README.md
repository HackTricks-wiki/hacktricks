# Informazioni utente

{{#include ../../banners/hacktricks-training.md}}

L'identità utente, l'appartenenza ai gruppi e le credenziali delegate determinano a quali risorse può accedere un processo. Verifica l'identità effettiva e i gruppi supplementari prima di esaminare i percorsi di accesso seguenti.

- [Utenti, sessioni e artefatti delle credenziali](user-and-session-triage.md) tratta l'enumerazione degli account, gli accessi attivi, gli artefatti SSH e della shell e gli archivi delle credenziali.
- [ID utente reali, effettivi e salvati](euid-ruid-suid.md) spiega le modifiche all'identità durante l'esecuzione di programmi SUID e dei processi.
- [Gruppi interessanti per l'escalation dei privilegi in Linux](interesting-groups-linux-pe/README.md) tratta l'accesso concesso dai gruppi, incluso LXD/LXC.
- [Sfruttamento dell'agent forwarding SSH](ssh-forward-agent-exploitation.md) esamina i rischi delle credenziali SSH inoltrate.
- [Active Directory su Linux](linux-active-directory.md) tratta gli host aggiunti a un ambiente AD.

{{#include ../../banners/hacktricks-training.md}}
