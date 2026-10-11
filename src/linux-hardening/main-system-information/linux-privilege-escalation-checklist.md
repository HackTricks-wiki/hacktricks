# Liste de contrôle pour l’escalade de privilèges sous Linux

{{#include ../../banners/hacktricks-training.md}}

# Liste de contrôle - Escalade de privilèges sous Linux



### **Meilleur outil pour rechercher des vecteurs d’escalade de privilèges locaux sous Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations système](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obtenir les **informations sur le système d’exploitation**
- [ ] Vérifier le [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) : contient-il un **dossier accessible en écriture** ?
- [ ] Vérifier les [**variables d’environnement**](../linux-basics/linux-privilege-escalation/index.html#env-info) : contiennent-elles des informations sensibles ?
- [ ] Rechercher des [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **à l’aide de scripts** (DirtyCow ?)
- [ ] Avant d’exécuter un PoC de kernel, vérifier ses **prérequis réels**, et pas seulement `uname -r` : architecture, options/modules `CONFIG_*` requis, création d’espaces de noms et mesures d’atténuation actives. Par exemple, tester la disponibilité des espaces de noms utilisateur/réseau avec `unshare -Urn true` ; les exploits netfilter modernes peuvent nécessiter `CONFIG_USER_NS`, les espaces de noms utilisateur non privilégiés et `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Vérifier** si la [**version de sudo est vulnérable**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Échec de la vérification de signature de [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Examiner les [**mauvaises configurations des modules du kernel et de leur chargement**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) : `insmod`, `modinfo`, `lsmod`, `dmesg`, application des signatures et `modules_disabled`.
- [ ] Vérifier les [**voies d’abus de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) si le chemin de l’assistant peut être modifié ou déclenché.
- [ ] Vérifier les [**chemins /lib/modules accessibles en écriture**](kernel-modules-and-modprobe.md#writable-libmodules-review), notamment les fichiers `.ko*` et les métadonnées `modules.*` accessibles en écriture.
- [ ] Énumération système supplémentaire ([date, statistiques système, informations CPU, imprimantes](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Énumérer d’autres mécanismes de défense](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Disques](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Lister les** disques montés
- [ ] Y a-t-il un **disque non monté** ?
- [ ] Y a-t-il des **identifiants dans fstab** ?

### [**Logiciels installés**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Vérifier si des** [**logiciels utiles**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **sont installés**
- [ ] **Vérifier si des** [**logiciels vulnérables**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **sont installés**
- [ ] Sur Debian/Ubuntu, vérifier si **l’analyse des interpréteurs de needrestart** est installée/activée : `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Des versions vulnérables franchissaient la frontière de privilèges en réutilisant les valeurs `PYTHONPATH`/`RUBYLIB` contrôlées par l’attaquant, en exploitant une course sur `/proc/<pid>/exe` ou en analysant des chemins Perl contrôlés par l’attaquant lorsque APT ou `unattended-upgrades` invoquait needrestart en tant que root.<sup>[[4]](#references)</sup>

### [Processus](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Un **logiciel inconnu est-il en cours d’exécution** ?
- [ ] Un logiciel s’exécute-t-il avec **plus de privilèges que nécessaire** ?
- [ ] Rechercher des **exploits visant les processus en cours d’exécution** (en particulier la version utilisée).
- [ ] Pouvez-vous **modifier le binaire** d’un processus en cours d’exécution ?
- [ ] **Surveiller les processus** et vérifier si un processus intéressant s’exécute fréquemment.
- [ ] Pouvez-vous **lire** la **mémoire d’un processus** intéressant (où des mots de passe pourraient être enregistrés) ?

### [Tâches planifiées/Cron ?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Le [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)est-il modifié par un cron et pouvez-vous y **écrire** ?
- [ ] Y a-t-il un [**joker** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)dans une tâche cron ?
- [ ] Un [**script modifiable** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)est-il **exécuté** ou se trouve-t-il dans un **dossier modifiable** ?
- [ ] Avez-vous repéré un **script** qui pourrait être ou est [**exécuté** très **fréquemment**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Y a-t-il un fichier **.service accessible en écriture** ?
- [ ] Y a-t-il un **binaire accessible en écriture** exécuté par un **service** ?
- [ ] Y a-t-il un **assistant, fichier de configuration ou fichier d’environnement accessible en écriture, référencé par une unité root** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`) ? Examiner l’unité fusionnée avec `systemctl cat <unit>` et vérifier les [abus de fichiers de service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Un flux de travail privilégié à la demande exécute-t-il un assistant depuis un répertoire accessible en écriture par un utilisateur moins privilégié ? Vérifier l’assistant et son répertoire parent pour repérer une [exécution par root de chemins modifiables par l’utilisateur](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries) ; les assistants de courte durée peuvent n’apparaître que pendant l’exécution du flux de travail.
- [ ] Y a-t-il un **dossier accessible en écriture dans le PATH de systemd** ?
- [ ] Y a-t-il un **fichier drop-in d’unité systemd accessible en écriture** dans `/etc/systemd/system/<unit>.d/*.conf` permettant de remplacer `ExecStart`/`User` ?<sup>[[2]](#references)</sup>

### [Temporisateurs](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Y a-t-il un **temporisateur accessible en écriture** ?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Y a-t-il un fichier **.socket accessible en écriture** ?
- [ ] Pouvez-vous **communiquer avec un socket** ?
- [ ] Des **sockets HTTP** contiennent-ils des informations intéressantes ?
- [ ] Pouvez-vous accéder à une [**API de runtime de conteneur ou d’agent de nœud**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), comme `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ou un endpoint kubelet ? Testez directement l’API HTTP/gRPC, même si son interface en ligne de commande habituelle est absente.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Pouvez-vous **communiquer avec D-Bus** ?

### [Réseau](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau pour déterminer où vous vous trouvez
- [ ] Des **ports sont-ils ouverts et désormais accessibles** depuis que vous avez obtenu un shell sur la machine ?
- [ ] Pouvez-vous **sniffer le trafic** avec `tcpdump` ?

### [Utilisateurs](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Énumération générale des utilisateurs/groupes
- [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
- [ ] Pouvez-vous [**escalader vos privilèges grâce à un groupe**](../user-information/interesting-groups-linux-pe/index.html) auquel vous appartenez ?
- [ ] Des données dans le **presse-papiers** ?
- [ ] Politique de mots de passe ?
- [ ] Essayez d’**utiliser** chaque **mot de passe connu** découvert précédemment pour vous connecter avec **chaque** **utilisateur** possible. Essayez aussi de vous connecter sans mot de passe.

### [PATH accessible en écriture](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Si vous avez des **droits d’écriture sur un dossier du PATH**, vous pourriez être en mesure d’escalader vos privilèges.

### [Commandes SUDO et SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Pouvez-vous exécuter **une commande avec sudo** ? Pouvez-vous l’utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` autorise `sudoedit`, vérifier l’**injection d’arguments de sudoedit** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` pour modifier des fichiers arbitraires sur les versions vulnérables (`sudo -V` < 1.9.12p2). Exemple : `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Les commandes [**sudo** sont-elles **limitées** par **chemin** ? Pouvez-vous **contourner** les restrictions](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) ?
- [ ] [**Binaire sudo/SUID sans chemin indiqué**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) ?
- [ ] [**Binaire SUID avec chemin indiqué**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path) ? Contournement
- [ ] [**Vulnérabilité LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Bibliothèque .so manquante dans un binaire SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) depuis un dossier accessible en écriture ?
- [ ] [**RPATH/RUNPATH SUID ou chemin de bibliothèque accessible en écriture**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) ?
- [ ] Des [**jetons SUDO disponibles**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) ? [**Pouvez-vous créer un jeton SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than) ?
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

- [ ] [**PRNG prédictible d’OpenSSL sur Debian - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valeurs de configuration SSH intéressantes**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Fichiers intéressants](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Fichiers de profil** - Contiennent-ils des données sensibles ? Permettent-ils l’escalade de privilèges ?
- [ ] **Fichiers passwd/shadow** - Contiennent-ils des données sensibles ? Permettent-ils l’escalade de privilèges ?
- [ ] **Vérifier les dossiers couramment intéressants** à la recherche de données sensibles
- [ ] **Fichiers situés dans des emplacements inhabituels ou dont vous êtes propriétaire** : vous pourriez pouvoir accéder à des fichiers exécutables ou les modifier
- [ ] Fichiers **modifiés au cours des dernières minutes**
- [ ] **Fichiers de bases de données Sqlite**
- [ ] **Fichiers cachés**
- [ ] **Scripts/binaires dans le PATH**
- [ ] **Fichiers web** (mots de passe ?)
- [ ] Des **sauvegardes** ?
- [ ] **Fichiers connus contenant des mots de passe** : utiliser **Linpeas** et **LaZagne**
- [ ] **Recherche générale**

### [**Fichiers accessibles en écriture**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modifier une bibliothèque Python** pour exécuter des commandes arbitraires ?
- [ ] Pouvez-vous **modifier les fichiers journaux** ? Exploit **Logtotten**
- [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploit Centos/Redhat
- [ ] Pouvez-vous [**écrire dans les fichiers ini, int.d, systemd ou rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d) ?

### [**Autres astuces**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Pouvez-vous [**abuser de NFS pour escalader vos privilèges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation) ?
- [ ] Devez-vous [**sortir d’un shell restrictif**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells) ?



## References

- [1] [Avis de sécurité Sudo : modification arbitraire de fichiers avec sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentation Oracle Linux : configuration drop-in de systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn : prérequis et recherches sur l’exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Avis de sécurité Qualys : LPE dans needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
