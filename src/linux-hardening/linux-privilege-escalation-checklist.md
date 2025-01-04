# Liste de contrôle - Escalade de privilèges Linux

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d'escalade de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations système](privilege-escalation/index.html#system-information)

- [ ] Obtenir des **informations sur le système d'exploitation**
- [ ] Vérifier le [**PATH**](privilege-escalation/index.html#path), un **dossier modifiable** ?
- [ ] Vérifier les [**variables d'environnement**](privilege-escalation/index.html#env-info), des détails sensibles ?
- [ ] Rechercher des [**exploits de noyau**](privilege-escalation/index.html#kernel-exploits) **en utilisant des scripts** (DirtyCow ?)
- [ ] **Vérifier** si la [**version de sudo** est vulnérable](privilege-escalation/index.html#sudo-version)
- [ ] [**Échec de la vérification de signature Dmesg**](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Plus d'énumération système ([date, statistiques système, informations CPU, imprimantes](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Énumérer plus de défenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Disques](privilege-escalation/index.html#drives)

- [ ] **Lister les** disques montés
- [ ] **Un disque non monté ?**
- [ ] **Des identifiants dans fstab ?**

### [**Logiciels installés**](privilege-escalation/index.html#installed-software)

- [ ] **Vérifier les** [**logiciels utiles**](privilege-escalation/index.html#useful-software) **installés**
- [ ] **Vérifier les** [**logiciels vulnérables**](privilege-escalation/index.html#vulnerable-software-installed) **installés**

### [Processus](privilege-escalation/index.html#processes)

- [ ] Y a-t-il un **logiciel inconnu en cours d'exécution** ?
- [ ] Y a-t-il un logiciel en cours d'exécution avec **plus de privilèges qu'il ne devrait** ?
- [ ] Rechercher des **exploits de processus en cours d'exécution** (en particulier la version en cours d'exécution).
- [ ] Pouvez-vous **modifier le binaire** de tout processus en cours d'exécution ?
- [ ] **Surveiller les processus** et vérifier si un processus intéressant s'exécute fréquemment.
- [ ] Pouvez-vous **lire** une **mémoire de processus** intéressante (où des mots de passe pourraient être enregistrés) ?

### [Tâches planifiées/Cron ?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Le [**PATH**](privilege-escalation/index.html#cron-path) est-il modifié par un cron et pouvez-vous **écrire** dedans ?
- [ ] Un [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) dans une tâche cron ?
- [ ] Un [**script modifiable**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) est-il **exécuté** ou est-il dans un **dossier modifiable** ?
- [ ] Avez-vous détecté qu'un **script** pourrait être ou est [**exécuté très fréquemment**](privilege-escalation/index.html#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](privilege-escalation/index.html#services)

- [ ] Un fichier **.service** **modifiable** ?
- [ ] Un **binaire modifiable** exécuté par un **service** ?
- [ ] Un **dossier modifiable dans le PATH de systemd** ?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Un **timer modifiable** ?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Un fichier **.socket** **modifiable** ?
- [ ] Pouvez-vous **communiquer avec un socket** ?
- [ ] **Sockets HTTP** avec des informations intéressantes ?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Réseau](privilege-escalation/index.html#network)

- [ ] Énumérer le réseau pour savoir où vous êtes
- [ ] **Ports ouverts auxquels vous ne pouviez pas accéder avant** d'obtenir un shell à l'intérieur de la machine ?
- [ ] Pouvez-vous **sniffer le trafic** en utilisant `tcpdump` ?

### [Utilisateurs](privilege-escalation/index.html#users)

- [ ] Énumération des utilisateurs/groupes **génériques**
- [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
- [ ] Pouvez-vous [**escalader les privilèges grâce à un groupe**](privilege-escalation/interesting-groups-linux-pe/) auquel vous appartenez ?
- [ ] Données du **presse-papiers** ?
- [ ] Politique de mot de passe ?
- [ ] Essayez d'**utiliser** chaque **mot de passe connu** que vous avez découvert précédemment pour vous connecter **avec chaque** utilisateur possible. Essayez également de vous connecter sans mot de passe.

### [PATH modifiable](privilege-escalation/index.html#writable-path-abuses)

- [ ] Si vous avez **des privilèges d'écriture sur un dossier dans le PATH**, vous pourriez être en mesure d'escalader les privilèges

### [Commandes SUDO et SUID](privilege-escalation/index.html#sudo-and-suid)

- [ ] Pouvez-vous exécuter **n'importe quelle commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Les [**commandes sudo** sont-elles **limitées** par le **path** ? pouvez-vous **contourner** les restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths) ?
- [ ] [**Binaire Sudo/SUID sans path indiqué**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) ?
- [ ] [**Binaire SUID spécifiant le path**](privilege-escalation/index.html#suid-binary-with-command-path) ? Contourner
- [ ] [**Vulnérabilité LD_PRELOAD**](privilege-escalation/index.html#ld_preload)
- [ ] [**Absence de bibliothèque .so dans le binaire SUID**](privilege-escalation/index.html#suid-binary-so-injection) d'un dossier modifiable ?
- [ ] [**Tokens SUDO disponibles**](privilege-escalation/index.html#reusing-sudo-tokens) ? [**Pouvez-vous créer un token SUDO**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than) ?
- [ ] Pouvez-vous [**lire ou modifier les fichiers sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) ?
- [ ] Pouvez-vous [**modifier /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d) ?
- [ ] Commande [**OpenBSD DOAS**](privilege-escalation/index.html#doas)

### [Capacités](privilege-escalation/index.html#capabilities)

- [ ] Un binaire a-t-il une **capacité inattendue** ?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Un fichier a-t-il une **ACL inattendue** ?

### [Sessions de shell ouvertes](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL PRNG prévisible - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valeurs de configuration SSH intéressantes**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Fichiers intéressants](privilege-escalation/index.html#interesting-files)

- [ ] Fichiers de **profil** - Lire des données sensibles ? Écrire pour privesc ?
- [ ] Fichiers **passwd/shadow** - Lire des données sensibles ? Écrire pour privesc ?
- [ ] **Vérifier les dossiers couramment intéressants** pour des données sensibles
- [ ] Fichiers **emplacement étrange/propriétés**, vous pourriez avoir accès ou modifier des fichiers exécutables
- [ ] **Modifié** dans les dernières minutes
- [ ] Fichiers **Sqlite DB**
- [ ] Fichiers **cachés**
- [ ] **Script/Binaires dans le PATH**
- [ ] Fichiers **Web** (mots de passe ?)
- [ ] **Sauvegardes** ?
- [ ] **Fichiers connus contenant des mots de passe** : Utilisez **Linpeas** et **LaZagne**
- [ ] **Recherche générique**

### [**Fichiers modifiables**](privilege-escalation/index.html#writable-files)

- [ ] **Modifier la bibliothèque python** pour exécuter des commandes arbitraires ?
- [ ] Pouvez-vous **modifier les fichiers journaux** ? Exploit **Logtotten**
- [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploit Centos/Redhat
- [ ] Pouvez-vous [**écrire dans des fichiers ini, int.d, systemd ou rc.d**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d) ?

### [**Autres astuces**](privilege-escalation/index.html#other-tricks)

- [ ] Pouvez-vous [**abuser de NFS pour escalader les privilèges**](privilege-escalation/index.html#nfs-privilege-escalation) ?
- [ ] Avez-vous besoin de [**vous échapper d'un shell restrictif**](privilege-escalation/index.html#escaping-from-restricted-shells) ?

{{#include ../banners/hacktricks-training.md}}
