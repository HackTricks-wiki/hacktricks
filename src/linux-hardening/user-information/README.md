# Informazioni utente

{{#include ../../banners/hacktricks-training.md}}

L'identità utente, l'appartenenza ai gruppi e le credenziali delegate determinano a quali risorse può accedere un processo. Verifica l'identità effettiva e i gruppi supplementari prima di esaminare i percorsi di accesso riportati di seguito.

- [Utenti, sessioni e artefatti delle credenziali](user-and-session-triage.md) tratta l'enumerazione degli account, gli accessi attivi, gli artefatti SSH e della shell e gli archivi delle credenziali.
- [UID reali, effettivi e salvati](euid-ruid-suid.md) spiega i cambiamenti di identità associati ai programmi SUID e all'esecuzione dei processi.
- [Gruppi interessanti per la privilege escalation su Linux](interesting-groups-linux-pe/README.md) tratta l'accesso concesso dai gruppi, incluso LXD/LXC.
- [Sfruttamento dell'agente di inoltro SSH](ssh-forward-agent-exploitation.md) esamina i rischi delle credenziali SSH inoltrate.
- [Active Directory su Linux](linux-active-directory.md) tratta gli host aggiunti a un ambiente AD.
{{#include ../../banners/hacktricks-training.md}}
