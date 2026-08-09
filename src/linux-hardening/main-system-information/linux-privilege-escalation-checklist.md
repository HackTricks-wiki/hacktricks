# Checklist per l'escalation dei privilegi su Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Escalation dei privilegi su Linux



### **Miglior tool per cercare vettori di escalation dei privilegi locali su Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informazioni di sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Ottenere **informazioni sul sistema operativo**
- [ ] Controllare il [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), c'è qualche **cartella scrivibile**?
- [ ] Controllare le [**variabili env**](../linux-basics/linux-privilege-escalation/index.html#env-info), c'è qualche dettaglio sensibile?
- [ ] Cercare [**kernel exploit**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando script** (DirtyCow?)
- [ ] Prima di eseguire un kernel PoC, verificare i suoi **prerequisiti effettivi**, non solo `uname -r`: architettura, opzioni/moduli `CONFIG_*` richiesti, creazione dei namespace e mitigazioni attive. Ad esempio, testare la disponibilità dei namespace user/network con `unshare -Urn true`; i moderni exploit netfilter potrebbero richiedere `CONFIG_USER_NS`, user namespace non privilegiati e `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Controllare** se la [**versione di sudo** è vulnerabile](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Verifica della firma di Dmesg** fallita](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Esaminare le [**misconfigurazioni dei kernel module e del caricamento dei moduli**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, imposizione delle firme e `modules_disabled`.
- [ ] Controllare i [**percorsi di abuso di kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) se il percorso dell'helper può essere modificato o attivato.
- [ ] Controllare i [**percorsi scrivibili in /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), inclusi i file `.ko*` scrivibili e i metadata `modules.*`.
- [ ] Ulteriore enum del sistema ([data, statistiche del sistema, informazioni sulla CPU, stampanti](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerare ulteriori difese](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unità](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] Elencare le unità **montate**
- [ ] **Qualche unità non montata?**
- [ ] **Qualche credenziale in fstab?**

### [**Software installato**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Controllare la presenza di**[ **software utile**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **installato**
- [ ] **Controllare la presenza di** [**software vulnerabile**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **installato**
- [ ] Su Debian/Ubuntu, controllare se **needrestart interpreter scanning** è installato/abilitato: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Le build vulnerabili oltrepassavano il confine dei privilegi riutilizzando `PYTHONPATH`/`RUBYLIB` controllati dall'attaccante, effettuando una race su `/proc/<pid>/exe` o analizzando percorsi Perl controllati dall'attaccante quando APT o `unattended-upgrades` invocava needrestart come root.<sup>[[4]](#references)</sup>

### [Processi](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] È in esecuzione qualche **software sconosciuto**?
- [ ] È in esecuzione qualche software con **più privilegi di quelli previsti**?
- [ ] Cercare **exploit per i processi in esecuzione** (soprattutto per la versione in esecuzione).
- [ ] È possibile **modificare il binary** di qualche processo in esecuzione?
- [ ] **Monitorare i processi** e controllare se qualche processo interessante è in esecuzione frequentemente.
- [ ] È possibile **leggere** la **memoria di qualche processo** interessante (dove potrebbero essere salvate password)?

### [Job pianificati/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Il [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)viene modificato da qualche cron e puoi **scriverci**?
- [ ] Qualche [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)in un cron job?
- [ ] Qualche [**script modificabile** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)viene **eseguito** o si trova dentro una **cartella modificabile**?
- [ ] Hai rilevato che qualche **script** potrebbe essere o viene [**eseguito** molto **frequentemente**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (ogni 1, 2 o 5 minuti)

### [Servizi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Qualche file **.service scrivibile**?
- [ ] Qualche **binary scrivibile** eseguito da un **servizio**?
- [ ] Qualche **helper, file di configurazione o file di ambiente scrivibile referenziato da una unit root** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Ispezionare la unit risultante con `systemctl cat <unit>` ed esaminare l'[abuso di file service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Qualche **cartella scrivibile nel PATH di systemd**?
- [ ] Qualche **drop-in di una unit systemd scrivibile** in `/etc/systemd/system/<unit>.d/*.conf` che possa sovrascrivere `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timer](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Qualche **timer scrivibile**?

### [Socket](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Qualche file **.socket scrivibile**?
- [ ] Puoi **comunicare con qualche socket**?
- [ ] **Socket HTTP** con informazioni interessanti?
- [ ] Puoi accedere a una [**API del container-runtime o del node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) come `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` o a un endpoint kubelet? Testare l'API HTTP/gRPC raw anche quando la sua CLI usuale non è presente.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Puoi **comunicare con qualche D-Bus**?

### [Rete](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerare la rete per sapere dove ti trovi
- [ ] **Porte aperte a cui prima non potevi accedere** dopo aver ottenuto una shell all'interno della macchina?
- [ ] Puoi **sniffare il traffico** usando `tcpdump`?

### [Utenti](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumerazione** generica di utenti/gruppi
- [ ] Hai un **UID molto grande**? La **macchina** è **vulnerabile**?
- [ ] Puoi [**escalare i privilegi grazie a un gruppo**](../user-information/interesting-groups-linux-pe/index.html) di cui fai parte?
- [ ] Dati degli **appunti**?
- [ ] Policy delle password?
- [ ] Prova a **usare** ogni **password conosciuta** che hai scoperto in precedenza per effettuare il login **con ogni** possibile **utente**. Prova a effettuare il login anche senza password.

### [PATH scrivibile](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se hai **permessi di scrittura su qualche cartella nel PATH**, potresti riuscire a escalare i privilegi

### [Comandi SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Puoi eseguire **qualche comando con sudo**? Puoi usarlo per LEGGERE, SCRIVERE o ESEGUIRE qualsiasi cosa come root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` consente `sudoedit`, controllare la **sudoedit argument injection** (CVE-2023-22809) tramite `SUDO_EDITOR`/`VISUAL`/`EDITOR` per modificare file arbitrari nelle versioni vulnerabili (`sudo -V` < 1.9.12p2). Esempio: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] È presente qualche **binary SUID exploitable**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] I comandi [**sudo** sono **limitati** dal **path**? puoi **bypassare le restrizioni**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binary Sudo/SUID senza path indicato**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binary SUID con path specificato**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vuln LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Mancanza di una libreria .so nel binary SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) da una cartella scrivibile?
- [ ] [**SUID RPATH/RUNPATH o percorso di libreria scrivibile**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Token SUDO disponibili**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Puoi creare un token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Puoi [**leggere o modificare i file sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Puoi [**modificare /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
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
- [ ] [**Valori di configurazione SSH interessanti**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [File interessanti](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **File di profilo** - Leggere dati sensibili? Scriverci per la privesc?
- [ ] **File passwd/shadow** - Leggere dati sensibili? Scriverci per la privesc?
- [ ] **Controllare le cartelle comunemente interessanti** per dati sensibili
- [ ] **File in posizioni/proprietà insolite**, potresti avere accesso o poter modificare file eseguibili
- [ ] **Modificati** negli ultimi minuti
- [ ] **File di database Sqlite**
- [ ] **File nascosti**
- [ ] **Script/Binary nel PATH**
- [ ] **File web** (password?)
- [ ] **Backup**?
- [ ] **File noti che contengono password**: Usare **Linpeas** e **LaZagne**
- [ ] **Ricerca generica**

### [**File scrivibili**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modificare una libreria Python** per eseguire comandi arbitrari?
- [ ] Puoi **modificare i file di log**? Exploit **Logtotten**
- [ ] Puoi **modificare /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Puoi [**scrivere in file ini, int.d, systemd o rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Altri trick**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Puoi [**abusare di NFS per escalare i privilegi**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Devi [**uscire da una shell restrittiva**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Riferimenti

- [1] [Advisory Sudo: modifica arbitraria di file con sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentazione Oracle Linux: configurazione dei drop-in systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: requisiti e ricerca sull'exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Security Advisory Qualys: LPE in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
