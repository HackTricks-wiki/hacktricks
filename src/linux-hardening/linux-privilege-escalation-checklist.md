# Checklist - Escalazione dei privilegi in Linux

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori di escalation dei privilegi locali in Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni di sistema](privilege-escalation/#system-information)

- [ ] Ottieni **informazioni sul sistema operativo**
- [ ] Controlla il [**PATH**](privilege-escalation/#path), ci sono **cartelle scrivibili**?
- [ ] Controlla le [**variabili env**](privilege-escalation/#env-info), ci sono dettagli sensibili?
- [ ] Cerca [**exploit del kernel**](privilege-escalation/#kernel-exploits) **utilizzando script** (DirtyCow?)
- [ ] **Controlla** se la [**versione di sudo** è vulnerabile](privilege-escalation/#sudo-version)
- [ ] [**Verifica della firma Dmesg fallita**](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Ulteriore enumerazione del sistema ([data, statistiche di sistema, informazioni sulla cpu, stampanti](privilege-escalation/#more-system-enumeration))
- [ ] [**Enumera ulteriori difese**](privilege-escalation/#enumerate-possible-defenses)

### [Dischi](privilege-escalation/#drives)

- [ ] **Elenca i dischi montati**
- [ ] **Ci sono dischi smontati?**
- [ ] **Ci sono credenziali in fstab?**

### [**Software installato**](privilege-escalation/#installed-software)

- [ ] **Controlla se ci sono** [**software utili**](privilege-escalation/#useful-software) **installati**
- [ ] **Controlla se ci sono** [**software vulnerabili**](privilege-escalation/#vulnerable-software-installed) **installati**

### [Processi](privilege-escalation/#processes)

- [ ] C'è qualche **software sconosciuto in esecuzione**?
- [ ] C'è qualche software in esecuzione con **più privilegi di quanti dovrebbe avere**?
- [ ] Cerca **exploit di processi in esecuzione** (soprattutto la versione in esecuzione).
- [ ] Puoi **modificare il binario** di qualche processo in esecuzione?
- [ ] **Monitora i processi** e controlla se qualche processo interessante è in esecuzione frequentemente.
- [ ] Puoi **leggere** qualche **memoria di processo** interessante (dove potrebbero essere salvate le password)?

### [Lavori programmati/Cron?](privilege-escalation/#scheduled-jobs)

- [ ] Il [**PATH**](privilege-escalation/#cron-path) è modificato da qualche cron e puoi **scrivere** in esso?
- [ ] Qualche [**carattere jolly**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) in un lavoro cron?
- [ ] Qualche [**script modificabile**](privilege-escalation/#cron-script-overwriting-and-symlink) è in fase di **esecuzione** o si trova in una **cartella modificabile**?
- [ ] Hai rilevato che qualche **script** potrebbe essere o è in fase di [**esecuzione molto **frequentemente**](privilege-escalation/#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](privilege-escalation/#services)

- [ ] Qualche file **.service** **scrivibile**?
- [ ] Qualche **binario scrivibile** eseguito da un **servizio**?
- [ ] Qualche **cartella scrivibile nel PATH di systemd**?

### [Timer](privilege-escalation/#timers)

- [ ] Qualche **timer scrivibile**?

### [Socket](privilege-escalation/#sockets)

- [ ] Qualche file **.socket** **scrivibile**?
- [ ] Puoi **comunicare con qualche socket**?
- [ ] **Socket HTTP** con informazioni interessanti?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Puoi **comunicare con qualche D-Bus**?

### [Rete](privilege-escalation/#network)

- [ ] Enumera la rete per sapere dove ti trovi
- [ ] **Porti aperti a cui non potevi accedere prima** di ottenere una shell all'interno della macchina?
- [ ] Puoi **sniffare il traffico** usando `tcpdump`?

### [Utenti](privilege-escalation/#users)

- [ ] Enumerazione di utenti/gruppi **generici**
- [ ] Hai un **UID molto grande**? La **macchina** è **vulnerabile**?
- [ ] Puoi [**escalare i privilegi grazie a un gruppo**](privilege-escalation/interesting-groups-linux-pe/) a cui appartieni?
- [ ] Dati negli **appunti**?
- [ ] Politica delle password?
- [ ] Prova a **usare** ogni **password conosciuta** che hai scoperto in precedenza per accedere **con ciascun** possibile **utente**. Prova ad accedere anche senza password.

### [PATH scrivibile](privilege-escalation/#writable-path-abuses)

- [ ] Se hai **privilegi di scrittura su qualche cartella nel PATH** potresti essere in grado di escalare i privilegi

### [Comandi SUDO e SUID](privilege-escalation/#sudo-and-suid)

- [ ] Puoi eseguire **qualunque comando con sudo**? Puoi usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualsiasi cosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] C'è qualche **binario SUID sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] I [**comandi sudo** sono **limitati** dal **path**? Puoi **bypassare** le restrizioni](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Comando Sudo/SUID senza path indicato**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binario SUID specificando il path**](privilege-escalation/#suid-binary-with-command-path)? Bypass
- [ ] [**Vuln LD_PRELOAD**](privilege-escalation/#ld_preload)
- [ ] [**Mancanza di libreria .so in binario SUID**](privilege-escalation/#suid-binary-so-injection) da una cartella scrivibile?
- [ ] [**Token SUDO disponibili**](privilege-escalation/#reusing-sudo-tokens)? [**Puoi creare un token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Puoi [**leggere o modificare i file sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] Puoi [**modificare /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**Comando OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacità](privilege-escalation/#capabilities)

- [ ] Qualche binario ha qualche **capacità inaspettata**?

### [ACL](privilege-escalation/#acls)

- [ ] Qualche file ha qualche **ACL inaspettata**?

### [Sessioni di shell aperte](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valori di configurazione SSH interessanti**](privilege-escalation/#ssh-interesting-configuration-values)

### [File interessanti](privilege-escalation/#interesting-files)

- [ ] **File di profilo** - Leggi dati sensibili? Scrivi per privesc?
- [ ] **File passwd/shadow** - Leggi dati sensibili? Scrivi per privesc?
- [ ] **Controlla le cartelle comunemente interessanti** per dati sensibili
- [ ] **File di posizione/possesso strani,** a cui potresti avere accesso o alterare file eseguibili
- [ ] **Modificati** negli ultimi minuti
- [ ] **File DB Sqlite**
- [ ] **File nascosti**
- [ ] **Script/Binari nel PATH**
- [ ] **File web** (password?)
- [ ] **Backup**?
- [ ] **File noti che contengono password**: Usa **Linpeas** e **LaZagne**
- [ ] **Ricerca generica**

### [**File scrivibili**](privilege-escalation/#writable-files)

- [ ] **Modifica la libreria python** per eseguire comandi arbitrari?
- [ ] Puoi **modificare i file di log**? **Logtotten** exploit
- [ ] Puoi **modificare /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Puoi [**scrivere in file ini, int.d, systemd o rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Altri trucchi**](privilege-escalation/#other-tricks)

- [ ] Puoi [**sfruttare NFS per escalare i privilegi**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] Hai bisogno di [**uscire da una shell restrittiva**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
