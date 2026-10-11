# Checklist per l'escalation dei privilegi su Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Escalation dei privilegi su Linux



### **Miglior tool per cercare vettori di escalation dei privilegi locali su Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni di sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Ottenere informazioni sul **sistema operativo**
- [ ] Controllare il [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path): ci sono **directory scrivibili**?
- [ ] Controllare le [**variabili env**](../linux-basics/linux-privilege-escalation/index.html#env-info): contengono informazioni sensibili?
- [ ] Cercare [**kernel exploit**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando script** (DirtyCow?)
- [ ] Prima di eseguire un kernel PoC, verificare i **prerequisiti effettivi**, non solo `uname -r`: architettura, opzioni/moduli `CONFIG_*` richiesti, creazione dei namespace e mitigazioni attive. Ad esempio, verificare la disponibilità dei namespace utente/rete con `unshare -Urn true`; i moderni exploit netfilter potrebbero richiedere `CONFIG_USER_NS`, namespace utente non privilegiati e `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Controllare** se la [**versione di sudo** è vulnerabile](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Verifica della firma Dmesg non riuscita**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Esaminare le [**configurazioni errate dei moduli del kernel e del loro caricamento**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, applicazione delle firme e `modules_disabled`.
- [ ] Verificare i [**vettori di abuso di kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), nel caso in cui il percorso dell'helper possa essere modificato o attivato.
- [ ] Controllare i [**percorsi scrivibili in /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), inclusi i file `.ko*` e i metadati `modules.*` scrivibili.
- [ ] Ulteriore enumerazione del sistema ([data, statistiche di sistema, informazioni sulla CPU, stampanti](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerare altre difese](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unità disco](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] Elencare le unità **montate**
- [ ] Ci sono unità **non montate**?
- [ ] Ci sono credenziali in fstab?

### [**Software installato**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Controllare se è installato** [**software utile**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Controllare se è installato** [**software vulnerabile**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] Su Debian/Ubuntu, controllare se **needrestart interpreter scanning** è installato/abilitato: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Le versioni vulnerabili superavano il confine dei privilegi riutilizzando `PYTHONPATH`/`RUBYLIB` controllati dall'attaccante, sfruttando una race su `/proc/<pid>/exe` o analizzando percorsi Perl controllati dall'attaccante, quando APT o `unattended-upgrades` eseguivano needrestart come root.<sup>[[4]](#references)</sup>

### [Processi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] È in esecuzione qualche **software sconosciuto**?
- [ ] È in esecuzione qualche software con **privilegi superiori a quelli necessari**?
- [ ] Cercare **exploit per i processi in esecuzione** (soprattutto per la versione in uso).
- [ ] È possibile **modificare il binario** di un processo in esecuzione?
- [ ] **Monitorare i processi** e verificare se qualche processo interessante viene eseguito frequentemente.
- [ ] È possibile **leggere** la **memoria di qualche processo** interessante (dove potrebbero essere salvate password)?

### [Job pianificati/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Il [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)viene modificato da qualche cron e si ha la possibilità di **scriverci**?
- [ ] C'è qualche [**carattere jolly** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in un job cron?
- [ ] Viene **eseguito** qualche [**script modificabile** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)oppure si trova in una **directory modificabile**?
- [ ] È stato individuato qualche **script** che potrebbe essere o viene [**eseguito** molto **frequentemente**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Ci sono file **.service scrivibili**?
- [ ] Ci sono **binari scrivibili** eseguiti da un **servizio**?
- [ ] Ci sono **helper, file di configurazione o file di ambiente scrivibili referenziati da un'unità root** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Esaminare l'unità risultante con `systemctl cat <unit>` e verificare l'[abuso di file service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Un workflow privilegiato su richiesta esegue un helper in una directory scrivibile con privilegi inferiori? Controllare sia l'helper sia la directory padre per verificare l'[esecuzione come root di percorsi modificabili dall'utente](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); gli helper di breve durata potrebbero comparire solo durante l'esecuzione del workflow.
- [ ] Ci sono **directory scrivibili nel PATH di systemd**?
- [ ] C'è qualche **drop-in di un'unità systemd scrivibile** in `/etc/systemd/system/<unit>.d/*.conf` che può sovrascrivere `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Ci sono **timer scrivibili**?

### [Socket](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Ci sono file **.socket scrivibili**?
- [ ] È possibile **comunicare con qualche socket**?
- [ ] Ci sono **socket HTTP** con informazioni interessanti?
- [ ] È possibile accedere a una [**API di container runtime o node agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) come `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` o un endpoint kubelet? Testare l'API HTTP/gRPC grezza anche se la relativa CLI abituale non è disponibile.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] È possibile **comunicare con qualche D-Bus**?

### [Rete](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerare la rete per capire dove ci si trova
- [ ] Ci sono **porte aperte a cui non si poteva accedere prima** di ottenere una shell sulla macchina?
- [ ] È possibile **sniffare il traffico** usando `tcpdump`?

### [Utenti](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumerazione** generica di utenti/gruppi
- [ ] Si ha un **UID molto alto**? La **macchina** è **vulnerabile**?
- [ ] È possibile [**escalare i privilegi grazie a un gruppo**](../user-information/interesting-groups-linux-pe/index.html) di cui si fa parte?
- [ ] Dati degli **appunti**?
- [ ] Policy delle password?
- [ ] Provare a **usare** ogni **password nota** scoperta in precedenza per accedere **con ciascun** possibile **utente**. Provare anche ad accedere senza password.

### [PATH scrivibile](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se si hanno **permessi di scrittura su una directory presente nel PATH**, potrebbe essere possibile escalare i privilegi

### [Comandi SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] È possibile eseguire **qualche comando con sudo**? È possibile usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualcosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` consente `sudoedit`, verificare la presenza di **sudoedit argument injection** (CVE-2023-22809) tramite `SUDO_EDITOR`/`VISUAL`/`EDITOR` per modificare file arbitrari nelle versioni vulnerabili (`sudo -V` < 1.9.12p2). Esempio: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] C'è qualche **binario SUID sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] I comandi [**sudo** sono **limitati** dal **percorso**? È possibile **aggirare** le restrizioni](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binario sudo/SUID senza percorso specificato**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binario SUID con percorso specificato**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? È possibile aggirare la restrizione?
- [ ] [**Vulnerabilità LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Libreria .so mancante in un binario SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) in una directory scrivibile?
- [ ] [**RPATH/RUNPATH SUID o percorso della libreria scrivibile**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Token SUDO disponibili**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**È possibile creare un token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] È possibile [**leggere o modificare i file sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] È possibile [**modificare /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Comando [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Qualche binario ha una **capability inaspettata**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Qualche file ha una **ACL inaspettata**?

### [Sessioni shell aperte](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valori di configurazione SSH interessanti**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [File interessanti](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **File di profilo** - Contengono dati sensibili? È possibile modificarli per la privesc?
- [ ] **File passwd/shadow** - Contengono dati sensibili? È possibile modificarli per la privesc?
- [ ] **Controllare le directory comunemente interessanti** alla ricerca di dati sensibili
- [ ] **File in posizioni insolite/di proprietà di altri,** a cui si potrebbe avere accesso o che potrebbero consentire di alterare file eseguibili
- [ ] File **modificati** negli ultimi minuti
- [ ] **File DB SQLite**
- [ ] **File nascosti**
- [ ] **Script/Binari nel PATH**
- [ ] **File web** (password?)
- [ ] **Backup**?
- [ ] **File noti che contengono password**: usare **Linpeas** e **LaZagne**
- [ ] **Ricerca generica**

### [**File scrivibili**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] È possibile **modificare una libreria Python** per eseguire comandi arbitrari?
- [ ] È possibile **modificare i file di log**? Exploit **Logtotten**
- [ ] È possibile **modificare /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] È possibile [**scrivere nei file ini, int.d, systemd o rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Altri trucchi**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] È possibile [**abusare di NFS per escalare i privilegi**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] È necessario [**evadere da una shell restrittiva**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Avviso Sudo: modifica arbitraria di file tramite sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentazione Oracle Linux: configurazione drop-in di systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: requisiti e analisi dell'exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Avviso di sicurezza Qualys: LPE in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
