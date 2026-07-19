# Checklist d'escalade de privilèges Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Escalade de privilèges Linux



### **Meilleur outil pour rechercher les vecteurs d'escalade de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations système](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obtenir les **informations sur l'OS**
- [ ] Vérifier le [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), y a-t-il un **dossier accessible en écriture** ?
- [ ] Vérifier les [**variables d'environnement**](../linux-basics/linux-privilege-escalation/index.html#env-info), y a-t-il des informations sensibles ?
- [ ] Rechercher des [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **à l'aide de scripts** (DirtyCow ?)
- [ ] **Vérifier** si la [**version de sudo** est vulnérable](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Échec de la vérification de signature de [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Examiner les [**mauvaises configurations des kernel modules et du chargement des modules**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) : `insmod`, `modinfo`, `lsmod`, `dmesg`, application des signatures et `modules_disabled`.
- [ ] Vérifier les [**chemins d'abus de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) si le chemin de l'helper peut être modifié ou déclenché.
- [ ] Vérifier les [**chemins /lib/modules accessibles en écriture**](kernel-modules-and-modprobe.md#writable-libmodules-review), notamment les fichiers `.ko*` et les métadonnées `modules.*` accessibles en écriture.
- [ ] Enumération système supplémentaire ([date, statistiques système, informations CPU, imprimantes](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Énumérer davantage de défenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Disques](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Lister** les disques montés
- [ ] **Un disque non monté ?**
- [ ] **Des credentials dans fstab ?**

### [**Logiciels installés**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Vérifier si des**[ **logiciels utiles**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **sont installés**
- [ ] **Vérifier si des** [**logiciels vulnérables**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **sont installés**

### [Processus](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Un **logiciel inconnu est-il en cours d'exécution** ?
- [ ] Un logiciel s'exécute-t-il avec **plus de privilèges qu'il ne devrait** ?
- [ ] Rechercher des **exploits de processus en cours d'exécution** (notamment de la version utilisée).
- [ ] Pouvez-vous **modifier le binaire** d'un processus en cours d'exécution ?
- [ ] **Surveiller les processus** et vérifier si un processus intéressant s'exécute fréquemment.
- [ ] Pouvez-vous **lire** la **mémoire d'un processus** intéressant (où des mots de passe pourraient être enregistrés) ?

### [Tâches planifiées/Cron ?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Le [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)est-il modifié par un cron dans lequel vous pouvez **écrire** ?
- [ ] Y a-t-il un [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)dans une tâche cron ?
- [ ] Un [**script modifiable** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)est-il **exécuté** ou situé dans un **dossier modifiable** ?
- [ ] Avez-vous détecté qu'un **script** pourrait être ou est [**exécuté** très **fréquemment**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Un fichier **.service accessible en écriture** ?
- [ ] Un **binaire accessible en écriture** est-il exécuté par un **service** ?
- [ ] Un **dossier accessible en écriture dans le PATH de systemd** ?
- [ ] Un **drop-in d'unité systemd accessible en écriture** dans `/etc/systemd/system/<unit>.d/*.conf` pouvant remplacer `ExecStart`/`User` ?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Un **timer accessible en écriture** ?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Un fichier **.socket accessible en écriture** ?
- [ ] Pouvez-vous **communiquer avec un socket** ?
- [ ] Des **sockets HTTP** contenant des informations intéressantes ?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Réseau](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau pour savoir où vous vous trouvez
- [ ] Des **ports ouverts auxquels vous ne pouviez pas accéder avant** d'obtenir un shell sur la machine ?
- [ ] Pouvez-vous **sniffer le trafic** avec `tcpdump` ?

### [Utilisateurs](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Énumération** générique des utilisateurs/groupes
- [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
- [ ] Pouvez-vous [**escalader vos privilèges grâce à un groupe**](../user-information/interesting-groups-linux-pe/index.html) auquel vous appartenez ?
- [ ] Données du **presse-papiers** ?
- [ ] Politique de mots de passe ?
- [ ] Essayer d'**utiliser** chaque **mot de passe connu** découvert précédemment pour se connecter **avec chaque** **utilisateur** possible. Essayer également de se connecter sans mot de passe.

### [PATH accessible en écriture](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Si vous avez des **privilèges d'écriture sur un dossier du PATH**, vous pourriez être en mesure d'escalader vos privilèges

### [Commandes SUDO et SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Pouvez-vous exécuter **n'importe quelle commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` autorise `sudoedit`, vérifier la [**sudoedit argument injection**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` pour modifier des fichiers arbitraires sur les versions vulnérables (`sudo -V` < 1.9.12p2). Exemple : `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Existe-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Les commandes [**sudo** sont-elles **limitées** par le **PATH** ? Pouvez-vous **contourner** les restrictions](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) ?
- [ ] [**Binaire Sudo/SUID sans chemin indiqué**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) ?
- [ ] [**Binaire SUID spécifiant un chemin**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path) ? Contournement
- [ ] [**Vulnérabilité LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Absence de bibliothèque .so dans un binaire SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) depuis un dossier accessible en écriture ?
- [ ] [**SUID RPATH/RUNPATH ou chemin de bibliothèque accessible en écriture**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) ?
- [ ] [**Tokens SUDO disponibles**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) ? [**Pouvez-vous créer un token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than) ?
- [ ] Pouvez-vous [**lire ou modifier les fichiers sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) ?
- [ ] Pouvez-vous [**modifier /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration) ?
- [ ] Commande [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Un binaire possède-t-il une **capability inattendue** ?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Un fichier possède-t-il une **ACL inattendue** ?

### [Sessions shell ouvertes](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valeurs de configuration SSH intéressantes**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Fichiers intéressants](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Fichiers de profil** - Lire des données sensibles ? Écrire pour l'escalade de privilèges ?
- [ ] **Fichiers passwd/shadow** - Lire des données sensibles ? Écrire pour l'escalade de privilèges ?
- [ ] **Vérifier les dossiers couramment intéressants** à la recherche de données sensibles
- [ ] **Fichiers situés dans des emplacements étranges ou appartenant à des utilisateurs particuliers,** auxquels vous pouvez accéder ou dont vous pouvez modifier les fichiers exécutables
- [ ] **Modifiés** au cours des dernières minutes
- [ ] **Fichiers de bases de données Sqlite**
- [ ] **Fichiers cachés**
- [ ] **Scripts/Binaires dans le PATH**
- [ ] **Fichiers web** (mots de passe ?)
- [ ] **Backups** ?
- [ ] **Fichiers connus contenant des mots de passe** : utiliser **Linpeas** et **LaZagne**
- [ ] **Recherche générique**

### [**Fichiers accessibles en écriture**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modifier une bibliothèque Python** pour exécuter des commandes arbitraires ?
- [ ] Pouvez-vous **modifier des fichiers de log** ? Exploit **Logtotten**
- [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploit Centos/Redhat
- [ ] Pouvez-vous [**écrire dans des fichiers ini, int.d, systemd ou rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) ?

### [**Autres astuces**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Pouvez-vous [**abuser de NFS pour escalader vos privilèges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) ?
- [ ] Avez-vous besoin de [**sortir d'un shell restrictif**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) ?



## Références

- [Avis Sudo : modification arbitraire de fichier avec sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Documentation Oracle Linux : configuration des drop-ins systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
