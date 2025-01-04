# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori di escalation dei privilegi locali in Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni di sistema](privilege-escalation/index.html#system-information)

- [ ] Ottieni **informazioni sul sistema operativo**
- [ ] Controlla il [**PATH**](privilege-escalation/index.html#path), ci sono **cartelle scrivibili**?
- [ ] Controlla le [**variabili env**](privilege-escalation/index.html#env-info), ci sono dettagli sensibili?
- [ ] Cerca [**exploit del kernel**](privilege-escalation/index.html#kernel-exploits) **utilizzando script** (DirtyCow?)
- [ ] **Controlla** se la [**versione di sudo** è vulnerabile](privilege-escalation/index.html#sudo-version)
- [ ] [**Verifica della firma Dmesg fallita**](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Ulteriore enumerazione del sistema ([data, statistiche di sistema, informazioni sulla cpu, stampanti](privilege-escalation/index.html#more-system-enumeration))
- [ ] [**Enumera ulteriori difese**](privilege-escalation/index.html#enumerate-possible-defenses)

### [Dischi](privilege-escalation/index.html#drives)

- [ ] **Elenca i dischi montati**
- [ ] **Ci sono dischi smontati?**
- [ ] **Ci sono credenziali in fstab?**

### [**Software installato**](privilege-escalation/index.html#installed-software)

- [ ] **Controlla se ci sono** [**software utili**](privilege-escalation/index.html#useful-software) **installati**
- [ ] **Controlla se ci sono** [**software vulnerabili**](privilege-escalation/index.html#vulnerable-software-installed) **installati**

### [Processi](privilege-escalation/index.html#processes)

- [ ] C'è qualche **software sconosciuto in esecuzione**?
- [ ] C'è qualche software in esecuzione con **più privilegi di quanto dovrebbe avere**?
- [ ] Cerca **exploit di processi in esecuzione** (soprattutto la versione in esecuzione).
- [ ] Puoi **modificare il binario** di qualche processo in esecuzione?
- [ ] **Monitora i processi** e controlla se qualche processo interessante è in esecuzione frequentemente.
- [ ] Puoi **leggere** qualche **memoria di processo** interessante (dove potrebbero essere salvate le password)?

### [Lavori programmati/Cron?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Il [**PATH**](privilege-escalation/index.html#cron-path) viene modificato da qualche cron e puoi **scrivere** in esso?
- [ ] Qualche [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in un lavoro cron?
- [ ] Qualche [**script modificabile**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) viene **eseguito** o si trova in una **cartella modificabile**?
- [ ] Hai rilevato che qualche **script** potrebbe essere o viene [**eseguito** molto **frequentemente**](privilege-escalation/index.html#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](privilege-escalation/index.html#services)

- [ ] Qualche file **.service** **scrivibile**?
- [ ] Qualche **binario scrivibile** eseguito da un **servizio**?
- [ ] Qualche **cartella scrivibile nel PATH di systemd**?

### [Timer](privilege-escalation/index.html#timers)

- [ ] Qualche **timer scrivibile**?

### [Socket](privilege-escalation/index.html#sockets)

- [ ] Qualche file **.socket** **scrivibile**?
- [ ] Puoi **comunicare con qualche socket**?
- [ ] **Socket HTTP** con informazioni interessanti?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Puoi **comunicare con qualche D-Bus**?

### [Rete](privilege-escalation/index.html#network)

- [ ] Enumera la rete per sapere dove ti trovi
- [ ] **Porti aperti a cui non potevi accedere prima** di ottenere una shell all'interno della macchina?
- [ ] Puoi **sniffare il traffico** usando `tcpdump`?

### [Utenti](privilege-escalation/index.html#users)

- [ ] Enumerazione di utenti/gruppi **generici**
- [ ] Hai un **UID molto grande**? La **macchina** è **vulnerabile**?
- [ ] Puoi [**escalare i privilegi grazie a un gruppo**](privilege-escalation/interesting-groups-linux-pe/index.html) a cui appartieni?
- [ ] Dati **Clipboard**?
- [ ] Politica delle password?
- [ ] Prova a **usare** ogni **password conosciuta** che hai scoperto in precedenza per accedere **con ciascun** possibile **utente**. Prova ad accedere anche senza password.

### [PATH scrivibile](privilege-escalation/index.html#writable-path-abuses)

- [ ] Se hai **privilegi di scrittura su qualche cartella nel PATH** potresti essere in grado di escalare i privilegi

### [Comandi SUDO e SUID](privilege-escalation/index.html#sudo-and-suid)

- [ ] Puoi eseguire **qualunque comando con sudo**? Puoi usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualsiasi cosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] C'è qualche **binario SUID sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] I [**comandi sudo** sono **limitati** dal **path**? Puoi **bypassare** le restrizioni](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binario Sudo/SUID senza path indicato**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binario SUID specificando il path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vuln LD_PRELOAD**](privilege-escalation/index.html#ld_preload)
- [ ] [**Mancanza di libreria .so in binario SUID**](privilege-escalation/index.html#suid-binary-so-injection) da una cartella scrivibile?
- [ ] [**Token SUDO disponibili**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Puoi creare un token SUDO**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Puoi [**leggere o modificare i file sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Puoi [**modificare /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**Comando OpenBSD DOAS**](privilege-escalation/index.html#doas)

### [Capacità](privilege-escalation/index.html#capabilities)

- [ ] Qualche binario ha qualche **capacità inaspettata**?

### [ACL](privilege-escalation/index.html#acls)

- [ ] Qualche file ha qualche **ACL inaspettata**?

### [Sessioni di shell aperte](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valori di configurazione SSH interessanti**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [File interessanti](privilege-escalation/index.html#interesting-files)

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

### [**File scrivibili**](privilege-escalation/index.html#writable-files)

- [ ] **Modifica la libreria python** per eseguire comandi arbitrari?
- [ ] Puoi **modificare i file di log**? **Logtotten** exploit
- [ ] Puoi **modificare /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Puoi [**scrivere in file ini, int.d, systemd o rc.d**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Altri trucchi**](privilege-escalation/index.html#other-tricks)

- [ ] Puoi [**sfruttare NFS per escalare i privilegi**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Hai bisogno di [**uscire da una shell restrittiva**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
