# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs de Linux local privilege escalation :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Obtenir **informations sur l'OS**
- [ ] Vérifier le [**PATH**](privilege-escalation/index.html#path), y a-t-il un dossier **inscriptible** ?
- [ ] Vérifier [**env variables**](privilege-escalation/index.html#env-info), des détails sensibles ?
- [ ] Search for [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **using scripts** (DirtyCow?)
- [ ] **Vérifier** si la [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Plus d'énumération système ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Lister les disques montés**
- [ ] **Un disque non monté ?**
- [ ] **Des identifiants dans fstab ?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Vérifier** la présence de [ **useful software**](privilege-escalation/index.html#useful-software) **installé**
- [ ] **Vérifier** la présence de [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) **installé**

### [Processes](privilege-escalation/index.html#processes)

- [ ] Y a-t-il un logiciel **inconnu en cours d'exécution** ?
- [ ] Un logiciel s'exécute-t-il avec **plus de privilèges que nécessaire** ?
- [ ] Rechercher des exploits des **processus en cours** (surtout la version exécutée).
- [ ] Pouvez-vous **modifier le binaire** d'un processus en cours ?
- [ ] **Surveiller les processus** et vérifier si un processus intéressant s'exécute fréquemment.
- [ ] Pouvez-vous **lire** la **mémoire d'un processus** intéressante (où des mots de passe pourraient être stockés) ?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Le [**PATH** ](privilege-escalation/index.html#cron-path) est-il modifié par un cron et pouvez-vous y **écrire** ?
- [ ] Un [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) dans un cron ?
- [ ] Un [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) est-il **exécuté** ou est-il dans un **dossier modifiable** ?
- [ ] Avez-vous détecté que certains **script** pourraient être ou sont [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](privilege-escalation/index.html#services)

- [ ] Un fichier **.service** inscriptible ?
- [ ] Un **binaire inscriptible** exécuté par un **service** ?
- [ ] Un **dossier inscriptible dans systemd PATH** ?
- [ ] Un **writable systemd unit drop-in** dans `/etc/systemd/system/<unit>.d/*.conf` qui peut override `ExecStart`/`User` ?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Un **writable timer** ?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Un fichier **.socket** inscriptible ?
- [ ] Pouvez-vous **communiquer avec un socket** ?
- [ ] **HTTP sockets** avec des infos intéressantes ?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Network](privilege-escalation/index.html#network)

- [ ] Énumérer le réseau pour savoir où vous êtes
- [ ] Des ports ouverts auxquels vous n'aviez pas accès avant d'obtenir un shell dans la machine ?
- [ ] Pouvez-vous **sniffer le trafic** en utilisant `tcpdump` ?

### [Users](privilege-escalation/index.html#users)

- [ ] Énumération générique des utilisateurs/groupes
- [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
- [ ] Pouvez-vous [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) dont vous faites partie ?
- [ ] Données du **clipboard** ?
- [ ] Politique de mots de passe ?
- [ ] Essayez d'**utiliser** chaque **mot de passe connu** que vous avez découvert précédemment pour vous connecter **avec chaque** utilisateur possible. Essayez aussi de vous connecter sans mot de passe.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Si vous avez des **droits d'écriture sur un dossier dans PATH** vous pouvez être capable d'escalate privileges

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Pouvez-vous exécuter **n'importe quelle commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` autorise `sudoedit`, vérifiez la **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` pour éditer des fichiers arbitraires sur les versions vulnérables (`sudo -V` < 1.9.12p2). Exemple: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Contournement
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) depuis un dossier inscriptible ?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Pouvez-vous [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) ?
- [ ] Pouvez-vous [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d) ?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Un binaire a-t-il une **capabilité inattendue** ?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Un fichier a-t-il une **ACL inattendue** ?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Lire des données sensibles ? Écrire pour privesc ?
- [ ] **passwd/shadow files** - Lire des données sensibles ? Écrire pour privesc ?
- [ ] **Vérifier les dossiers couramment intéressants** pour des données sensibles
- [ ] **Weird Location/Owned files,** vous pourriez avoir accès ou modifier des fichiers exécutables
- [ ] **Modifié** dans les dernières minutes
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (mots de passe ?)
- [ ] **Backups** ?
- [ ] **Known files that contains passwords**: Use **Linpeas** and **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Modifier une bibliothèque python** pour exécuter des commandes arbitraires ?
- [ ] Pouvez-vous **modifier des fichiers de log** ? exploit **Logtotten**
- [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? exploit Centos/Redhat
- [ ] Pouvez-vous [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d) ?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Pouvez-vous [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation) ?
- [ ] Avez-vous besoin de [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells) ?

## Références

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
