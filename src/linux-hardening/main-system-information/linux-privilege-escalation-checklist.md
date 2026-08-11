# Checklist per l'escalation dei privilegi Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Escalation dei privilegi Linux



### **Miglior tool per cercare vettori di escalation dei privilegi locali Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni sul sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Ottenere **informazioni sul sistema operativo**
- [ ] Controllare il [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), c'è qualche **cartella scrivibile**?
- [ ] Controllare le [**variabili d'ambiente**](../linux-basics/linux-privilege-escalation/index.html#env-info), è presente qualche dettaglio sensibile?
- [ ] Cercare [**kernel exploit**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando script** (DirtyCow?)
- [ ] Prima di eseguire un PoC del kernel, verificare i suoi **prerequisiti effettivi**, non solo `uname -r`: architettura, opzioni/moduli `CONFIG_*` richiesti, creazione dei namespace e mitigazioni attive. Ad esempio, testare la disponibilità dei namespace utente/rete con `unshare -Urn true`; i moderni exploit netfilter potrebbero richiedere `CONFIG_USER_NS`, namespace utente non privilegiati e `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Controllare** se la [**versione di sudo** è vulnerabile](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Verifica della firma Dmesg fallita**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Esaminare le [**configurazioni errate dei moduli del kernel e del caricamento dei moduli**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, applicazione delle firme e `modules_disabled`.
- [ ] Controllare i [**percorsi di abuso di kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) se il percorso dell'helper può essere modificato o attivato.
- [ ] Controllare i [**percorsi scrivibili in /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), inclusi i file `.ko*` scrivibili e i metadati `modules.*`.
- [ ] Ulteriore enumerazione del sistema ([data, statistiche del sistema, informazioni sulla CPU, stampanti](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerare ulteriori difese](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unità](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Elencare** le unità montate
- [ ] **Ci sono unità non montate?**
- [ ] **Ci sono credenziali in fstab?**

### [**Software installato**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Controllare la presenza di**[ **software utili**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **installati**
- [ ] **Controllare la presenza di** [**software vulnerabili**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **installati**
- [ ] Su Debian/Ubuntu, controllare se **needrestart interpreter scanning** è installato/abilitato: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Le build vulnerabili attraversavano il confine dei privilegi riutilizzando `PYTHONPATH`/`RUBYLIB` controllati dall'attaccante, facendo una race su `/proc/<pid>/exe` o analizzando percorsi Perl controllati dall'attaccante quando APT o `unattended-upgrades` invocava needrestart come root.<sup>[[4]](#references)</sup>

### [Processi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] È in esecuzione qualche **software sconosciuto**?
- [ ] È in esecuzione qualche software con **più privilegi di quanti dovrebbe averne**?
- [ ] Cercare **exploit dei processi in esecuzione** (soprattutto della versione in esecuzione).
- [ ] È possibile **modificare il binario** di qualche processo in esecuzione?
- [ ] **Monitorare i processi** e controllare se qualche processo interessante viene eseguito frequentemente.
- [ ] È possibile **leggere** la **memoria di qualche processo** interessante (dove potrebbero essere salvate le password)?

### [Job pianificati/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Il [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)viene modificato da qualche cron ed è possibile **scriverci**?
- [ ] C'è qualche [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in un job cron?
- [ ] Qualche [**script modificabile** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)viene **eseguito** o si trova all'interno di una **cartella modificabile**?
- [ ] È stato rilevato che qualche **script** potrebbe essere o viene [**eseguito** molto **frequentemente**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] C'è qualche file **.service scrivibile**?
- [ ] C'è qualche **binario scrivibile** eseguito da un **servizio**?
- [ ] C'è qualche **helper, file di configurazione o file d'ambiente scrivibile referenziato da una unit root** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Ispezionare la unit risultante con `systemctl cat <unit>` ed esaminare l'[abuso di file service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] C'è qualche **cartella scrivibile nel PATH di systemd**?
- [ ] C'è qualche **drop-in di una unit systemd scrivibile** in `/etc/systemd/system/<unit>.d/*.conf` che può sovrascrivere `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] C'è qualche **timer scrivibile**?

### [Socket](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] C'è qualche file **.socket scrivibile**?
- [ ] È possibile **comunicare con qualche socket**?
- [ ] Ci sono **socket HTTP** con informazioni interessanti?
- [ ] È possibile accedere a una [**API di container-runtime o node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) come `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` o a un endpoint kubelet? Testare l'API HTTP/gRPC grezza anche quando la sua CLI abituale non è presente.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] È possibile **comunicare con qualche D-Bus**?

### [Rete](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerare la rete per sapere dove ci si trova
- [ ] Ci sono **porte aperte a cui non era possibile accedere prima** di ottenere una shell all'interno della macchina?
- [ ] È possibile **sniffare il traffico** usando `tcpdump`?

### [Utenti](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumerazione** generica di utenti/gruppi
- [ ] Si dispone di un **UID molto grande**? La **macchina** è **vulnerabile**?
- [ ] È possibile [**escalare i privilegi grazie a un gruppo**](../user-information/interesting-groups-linux-pe/index.html) di cui si fa parte?
- [ ] Dati degli **appunti**?
- [ ] Policy delle password?
- [ ] Provare a **usare** ogni **password nota** scoperta in precedenza per effettuare il login **con ciascun** **utente** possibile. Provare a effettuare il login anche senza password.

### [PATH scrivibile](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se si dispone di **permessi di scrittura su qualche cartella nel PATH**, potrebbe essere possibile escalare i privilegi

### [Comandi SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] È possibile eseguire **qualche comando con sudo**? È possibile usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualsiasi cosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` consente `sudoedit`, controllare la presenza di **argument injection in sudoedit** (CVE-2023-22809) tramite `SUDO_EDITOR`/`VISUAL`/`EDITOR` per modificare file arbitrari nelle versioni vulnerabili (`sudo -V` < 1.9.12p2). Esempio: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] È presente qualche **binario SUID sfruttabile**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] I comandi [**sudo** sono **limitati** dal **percorso**? È possibile **bypassare le restrizioni**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binario Sudo/SUID senza percorso indicato**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binario SUID con percorso specificato**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vulnerabilità LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Mancanza di libreria .so nel binario SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) proveniente da una cartella scrivibile?
- [ ] [**SUID RPATH/RUNPATH o percorso di libreria scrivibile**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Token SUDO disponibili**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**È possibile creare un token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] È possibile [**leggere o modificare i file sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] È possibile [**modificare /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Comando [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Qualche binario dispone di una **capability imprevista**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Qualche file dispone di una **ACL imprevista**?

### [Sessioni shell aperte](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**PRNG prevedibile di OpenSSL - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valori di configurazione interessanti di SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [File interessanti](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **File di profilo** - Leggere dati sensibili? Scriverci per l'escalation dei privilegi?
- [ ] **File passwd/shadow** - Leggere dati sensibili? Scriverci per l'escalation dei privilegi?
- [ ] **Controllare le cartelle comunemente interessanti** alla ricerca di dati sensibili
- [ ] **File in posizioni/proprietà insolite**, si potrebbe avere accesso a file eseguibili o poterli alterare
- [ ] **Modificati** negli ultimi minuti
- [ ] **File di database Sqlite**
- [ ] **File nascosti**
- [ ] **Script/binari nel PATH**
- [ ] **File Web** (password?)
- [ ] **Backup**?
- [ ] **File noti che contengono password**: usare **Linpeas** e **LaZagne**
- [ ] **Ricerca generica**

### [**File scrivibili**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modificare una libreria Python** per eseguire comandi arbitrari?
- [ ] È possibile **modificare i file di log**? Exploit **Logtotten**
- [ ] È possibile **modificare /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] È possibile [**scrivere in file ini, int.d, systemd o rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Altri trucchi**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] È possibile [**abusare di NFS per escalare i privilegi**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] È necessario [**evadere da una shell restrittiva**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Avviso Sudo: modifica arbitraria di file tramite sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentazione Oracle Linux: configurazione drop-in di systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: requisiti e ricerca sull'exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Security Advisory Qualys: LPE in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
