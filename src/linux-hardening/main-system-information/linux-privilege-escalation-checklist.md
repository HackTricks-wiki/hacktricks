# Checklist - Escalatione dei privilegi Linux

{{#include ../../banners/hacktricks-training.md}}

### **Miglior tool per cercare vettori di escalation locale dei privilegi Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni sul sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Ottenere le **informazioni sul sistema operativo**
- [ ] Controllare il [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), ci sono **cartelle scrivibili**?
- [ ] Controllare le [**variabili d'ambiente**](../linux-basics/linux-privilege-escalation/index.html#env-info), contengono dettagli sensibili?
- [ ] Cercare [**kernel exploit**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando script** (DirtyCow?)
- [ ] **Controllare** se la [**versione di sudo** è vulnerabile](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Verifica della firma di Dmesg fallita**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Esaminare le [**configurazioni errate dei kernel module e del caricamento dei module**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, enforcement delle firme e `modules_disabled`.
- [ ] Controllare i [**percorsi di abuso di kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) se il percorso dell'helper può essere modificato o attivato.
- [ ] Controllare i [**percorsi /lib/modules scrivibili**](kernel-modules-and-modprobe.md#writable-libmodules-review), inclusi i file `.ko*` scrivibili e i metadata `modules.*`.
- [ ] Ulteriore enum del sistema ([data, statistiche del sistema, informazioni sulla CPU, stampanti](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerare ulteriori difese](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drive](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] Elencare i drive **montati**
- [ ] C'è qualche **drive non montato**?
- [ ] Ci sono credenziali in fstab?

### [**Software installato**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Controllare il**[ **software utile**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **installato**
- [ ] **Controllare il** [**software vulnerabile**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **installato**

### [Processi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] È in esecuzione qualche **software sconosciuto**?
- [ ] È in esecuzione qualche software con **più privilegi di quelli che dovrebbe avere**?
- [ ] Cercare **exploit dei processi in esecuzione** (soprattutto della versione in esecuzione).
- [ ] È possibile **modificare il binary** di qualche processo in esecuzione?
- [ ] **Monitorare i processi** e controllare se qualche processo interessante viene eseguito frequentemente.
- [ ] È possibile **leggere** la **memoria di qualche processo** interessante (dove potrebbero essere salvate le password)?

### [Job pianificati/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Il [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)viene modificato da qualche cron ed è possibile **scriverci**?
- [ ] C'è qualche [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in un cron job?
- [ ] Qualche [**script modificabile** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)viene **eseguito** o si trova all'interno di una **cartella modificabile**?
- [ ] È stato rilevato che qualche **script** potrebbe essere o viene [**eseguito** molto **frequentemente**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] C'è qualche file **.service scrivibile**?
- [ ] C'è qualche **binary scrivibile** eseguito da un **servizio**?
- [ ] C'è qualche **cartella scrivibile nel PATH di systemd**?
- [ ] C'è qualche **drop-in di unit systemd scrivibile** in `/etc/systemd/system/<unit>.d/*.conf` che può sovrascrivere `ExecStart`/`User`?

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] C'è qualche **timer scrivibile**?

### [Socket](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] C'è qualche file **.socket scrivibile**?
- [ ] È possibile **comunicare con qualche socket**?
- [ ] Ci sono **socket HTTP** con informazioni interessanti?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] È possibile **comunicare con qualche D-Bus**?

### [Rete](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerare la rete per sapere dove ci si trova
- [ ] Ci sono **porte aperte a cui non era possibile accedere prima** di ottenere una shell nella macchina?
- [ ] È possibile **sniffare il traffico** usando `tcpdump`?

### [Utenti](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumerazione** generica di utenti/gruppi
- [ ] Si dispone di un **UID molto grande**? La **macchina** è **vulnerabile**?
- [ ] È possibile [**escalare i privilegi grazie a un gruppo**](../user-information/interesting-groups-linux-pe/index.html) a cui si appartiene?
- [ ] Ci sono dati negli **appunti**?
- [ ] Qual è la policy delle password?
- [ ] Provare a **usare** ogni **password conosciuta** scoperta in precedenza per effettuare il login **con ogni** possibile **utente**. Provare a effettuare il login anche senza password.

### [PATH scrivibile](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se si dispone di **permessi di scrittura su una cartella nel PATH**, potrebbe essere possibile escalare i privilegi

### [Comandi SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] È possibile eseguire **qualche comando con sudo**? È possibile usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualsiasi cosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` consente `sudoedit`, controllare la **sudoedit argument injection** (CVE-2023-22809) tramite `SUDO_EDITOR`/`VISUAL`/`EDITOR` per modificare file arbitrari nelle versioni vulnerabili (`sudo -V` < 1.9.12p2). Esempio: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Esiste qualche **binary SUID sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] I comandi [**sudo** sono **limitati** dal **percorso**? È possibile **bypassare le restrizioni**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binary Sudo/SUID senza percorso indicato**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binary SUID con percorso specificato**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vulnerabilità LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Mancanza della libreria .so nel binary SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) da una cartella scrivibile?
- [ ] [**SUID RPATH/RUNPATH o percorso della libreria scrivibile**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Ci sono [**token SUDO disponibili**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**È possibile creare un token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] È possibile [**leggere o modificare i file sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] È possibile [**modificare /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Comando [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Qualche binary possiede una **capability imprevista**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Qualche file possiede una **ACL imprevista**?

### [Sessioni shell aperte](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valori di configurazione interessanti di SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [File interessanti](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **File di profilo** - Leggere dati sensibili? Scriverci per una privesc?
- [ ] **File passwd/shadow** - Leggere dati sensibili? Scriverci per una privesc?
- [ ] **Controllare le cartelle comunemente interessanti** per dati sensibili
- [ ] **File in posizioni strane/di proprietà di utenti,** a cui si può accedere o che possono contenere file eseguibili modificabili
- [ ] **Modificati** negli ultimi minuti
- [ ] **File di database Sqlite**
- [ ] **File nascosti**
- [ ] **Script/Binary nel PATH**
- [ ] **File web** (password?)
- [ ] **Backup**?
- [ ] **File noti che contengono password**: usare **Linpeas** e **LaZagne**
- [ ] **Ricerca generica**

### [**File scrivibili**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modificare la libreria Python** per eseguire comandi arbitrari?
- [ ] È possibile **modificare i file di log**? Exploit **Logtotten**
- [ ] È possibile **modificare /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] È possibile [**scrivere nei file ini, int.d, systemd o rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Altri trucchi**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] È possibile [**abusare di NFS per escalare i privilegi**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] È necessario [**evadere da una shell restrittiva**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Riferimenti

- [Avviso Sudo: modifica arbitraria di file tramite sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Documentazione Oracle Linux: configurazione drop-in di systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
