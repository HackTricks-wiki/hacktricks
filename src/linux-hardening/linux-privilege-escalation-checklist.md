# Lista di controllo - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Miglior strumento per cercare vettori locali di Linux privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Ottieni **OS information**
- [ ] Controlla la [**PATH**](privilege-escalation/index.html#path), c'è qualche **cartella scrivibile**?
- [ ] Controlla le [**env variables**](privilege-escalation/index.html#env-info), ci sono dettagli sensibili?
- [ ] Cerca [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **usando script** (DirtyCow?)
- [ ] **Verifica** se la [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Altra enum di sistema ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumera altre difese possibili](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Elenca** i drive montati
- [ ] **Qualche drive non montato?**
- [ ] **Credenziali in fstab?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Controlla** se è installato del [**software utile**](privilege-escalation/index.html#useful-software)
- [ ] **Controlla** se è installato del [**software vulnerabile**](privilege-escalation/index.html#vulnerable-software-installed)

### [Processes](privilege-escalation/index.html#processes)

- [ ] C'è qualche **software sconosciuto in esecuzione**?
- [ ] C'è qualche software che gira con **più privilegi del dovuto**?
- [ ] Cerca **exploit dei processi in esecuzione** (specialmente per la versione in esecuzione).
- [ ] Puoi **modificare il binario** di qualche processo in esecuzione?
- [ ] **Monitora i processi** e verifica se qualche processo interessante gira frequentemente.
- [ ] Puoi **leggere** la memoria di qualche processo interessante (dove potrebbero essere salvate password)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Il [**PATH** ](privilege-escalation/index.html#cron-path) viene modificato da qualche cron e puoi **scriverci**?
- [ ] Qualche job cron usa un [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Qualche [**script modificabile** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) viene **eseguito** o si trova dentro una **cartella modificabile**?
- [ ] Hai rilevato che qualche **script** potrebbe essere o viene **eseguito** molto **frequentemente** (ogni 1, 2 o 5 minuti)?

### [Services](privilege-escalation/index.html#services)

- [ ] Qualche file **.service scrivibile**?
- [ ] Qualche **binario scrivibile** eseguito da un **service**?
- [ ] Qualche **cartella scrivibile nel systemd PATH**?
- [ ] Qualche **systemd unit drop-in scrivibile** in `/etc/systemd/system/<unit>.d/*.conf` che può sovrascrivere `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Qualche **timer scrivibile**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Qualche file **.socket scrivibile**?
- [ ] Puoi **comunicare con qualche socket**?
- [ ] **HTTP sockets** con informazioni interessanti?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Puoi **comunicare con qualche D-Bus**?

### [Network](privilege-escalation/index.html#network)

- [ ] Enumera la rete per sapere dove ti trovi
- [ ] **Porte aperte che non potevi raggiungere prima** di ottenere una shell nella macchina?
- [ ] Puoi **sniffare il traffico** usando `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Enumerazione generica di utenti/gruppi
- [ ] Hai un **UID molto grande**? La **macchina** è **vulnerabile**?
- [ ] Puoi [**escalare privilegi grazie a un gruppo**](privilege-escalation/interesting-groups-linux-pe/index.html) a cui appartieni?
- [ ] **Dati negli appunti (clipboard)?**
- [ ] Politica delle password?
- [ ] Prova a **usare** ogni **password conosciuta** scoperta in precedenza per accedere **con ciascun** possibile **utente**. Prova anche a fare login senza password.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Se hai **permessi di scrittura su qualche cartella in PATH** potresti riuscire a escalare privilegi

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Puoi eseguire **qualche comando con sudo**? Puoi usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualcosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` permette `sudoedit`, verifica la **sudoedit argument injection** (CVE-2023-22809) tramite `SUDO_EDITOR`/`VISUAL`/`EDITOR` per modificare file arbitrari su versioni vulnerabili (`sudo -V` < 1.9.12p2). Esempio: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] C'è qualche **SUID binary sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] I comandi [**sudo** sono **limitati** dal **path**? puoi **bypassare** le restrizioni](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Mancanza di .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) da una cartella scrivibile?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Puoi creare un SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Puoi [**leggere o modificare i file sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Puoi [**modificare /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Qualche binario ha **capability inaspettate**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Qualche file ha **ACL inaspettate**?

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
- [ ] **File in posizioni strane/posseduti**, potresti avere accesso o poter alterare file eseguibili
- [ ] **Modificati** negli ultimi minuti
- [ ] **File DB Sqlite**
- [ ] **File nascosti**
- [ ] **Script/Binari in PATH**
- [ ] **File web** (password?)
- [ ] **Backup**?
- [ ] **File noti che contengono password**: usa **Linpeas** e **LaZagne**
- [ ] **Ricerca generica**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Modificare una libreria python** per eseguire comandi arbitrari?
- [ ] Puoi **modificare i file di log**? exploit Logtotten
- [ ] Puoi **modificare /etc/sysconfig/network-scripts/**? exploit Centos/Redhat
- [ ] Puoi [**scrivere in ini, init.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Puoi [**abusare di NFS per scalare privilegi**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Devi [**evadere da una shell restrittiva**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Riferimenti

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
