# Lista di controllo - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per individuare vettori di Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Ottieni **informazioni sull'OS**
- [ ] Controlla il [**PATH**](privilege-escalation/index.html#path), ci sono cartelle **scrivibili**?
- [ ] Controlla le [**env variables**](privilege-escalation/index.html#env-info), ci sono dettagli sensibili?
- [ ] Cerca [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **usando script** (DirtyCow?)
- [ ] **Controlla** se la [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Altra enumerazione del sistema ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Elenca** i drive montati
- [ ] Qualche drive non montato?
- [ ] Qualche credenziale in fstab?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Controlla** se è installato qualche [**useful software**](privilege-escalation/index.html#useful-software)
- [ ] **Controlla** se è installato qualche [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed)

### [Processes](privilege-escalation/index.html#processes)

- [ ] C'è qualche **software sconosciuto in esecuzione**?
- [ ] Qualche software sta girando con **più privilegi del dovuto**?
- [ ] Cerca **exploits per i processi in esecuzione** (soprattutto per la versione in esecuzione).
- [ ] Puoi **modificare il binario** di qualche processo in esecuzione?
- [ ] **Monitora i processi** e verifica se qualche processo interessante viene eseguito frequentemente.
- [ ] Puoi **leggere** la memoria di qualche processo interessante (dove potrebbero essere memorizzate password)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Il [**PATH** ](privilege-escalation/index.html#cron-path) viene modificato da qualche cron e puoi **scriverci**?
- [ ] C'è qualche [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) in un cron job?
- [ ] Qualche [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) viene **eseguito** o si trova in una **cartella modificabile**?
- [ ] Hai rilevato che qualche **script** potrebbe essere o viene [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Services](privilege-escalation/index.html#services)

- [ ] C'è qualche file **.service scrivibile**?
- [ ] C'è qualche **writable binary** eseguito da un **service**?
- [ ] C'è qualche **writable folder in systemd PATH**?
- [ ] C'è qualche **writable systemd unit drop-in** in `/etc/systemd/system/<unit>.d/*.conf` che può sovrascrivere `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Qualche **writable timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Qualche file **.socket scrivibile**?
- [ ] Puoi **comunicare con qualche socket**?
- [ ] **HTTP sockets** con informazioni interessanti?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Puoi **comunicare con qualche D-Bus**?

### [Network](privilege-escalation/index.html#network)

- [ ] Enumera la rete per sapere dove ti trovi
- [ ] Porte aperte a cui non potevi accedere prima di ottenere una shell sulla macchina?
- [ ] Puoi **sniffare traffico** usando `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Enumerazione generica di utenti/gruppi
- [ ] Hai un **UID molto grande**? La **macchina** è **vulnerabile**?
- [ ] Puoi [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) a cui appartieni?
- [ ] Dati negli **appunti (Clipboard)**?
- [ ] Policy delle password?
- [ ] Prova a **usare** ogni **password conosciuta** che hai scoperto prima per effettuare il login **con ogni** possibile **utente**. Prova anche a loggarti senza password.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Se hai **permessi di scrittura su qualche cartella nel PATH** potresti riuscire a scalare privilegi

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Puoi eseguire **qualche comando con sudo**? Puoi usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualsiasi cosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] If `sudo -l` allows `sudoedit`, check for **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` to edit arbitrary files on vulnerable versions (`sudo -V` < 1.9.12p2). Example: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] C'è qualche **SUID binary sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) from a writable folder?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Puoi [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Puoi [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Qualche binario ha qualche **capability inaspettata**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Qualche file ha qualche **ACL inaspettata**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Leggi dati sensibili? Scrivere per privesc?
- [ ] **passwd/shadow files** - Leggi dati sensibili? Scrivere per privesc?
- [ ] **Controlla cartelle comunemente interessanti** per dati sensibili
- [ ] **Posizioni/Files strani/Owned**, potresti avere accesso o poter alterare file eseguibili
- [ ] **Modificati** negli ultimi minuti
- [ ] **Sqlite DB files**
- [ ] **File nascosti**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (password?)
- [ ] **Backups**?
- [ ] **File noti che contengono password**: usa **Linpeas** e **LaZagne**
- [ ] **Ricerca generica**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Modificare una libreria python** per eseguire comandi arbitrari?
- [ ] Puoi **modificare i file di log**? **Logtotten** exploit
- [ ] Puoi **modificare /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Puoi [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Puoi [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Devi [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Riferimenti

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
