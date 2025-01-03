# Liste de contrôle - Escalade de privilèges Linux

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d'escalade de privilèges locaux Linux :** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informations système](privilege-escalation/#system-information)

- [ ] Obtenir **des informations sur le système d'exploitation**
- [ ] Vérifier le [**PATH**](privilege-escalation/#path), un **dossier modifiable** ?
- [ ] Vérifier les [**variables d'environnement**](privilege-escalation/#env-info), un détail sensible ?
- [ ] Rechercher des [**exploits de noyau**](privilege-escalation/#kernel-exploits) **en utilisant des scripts** (DirtyCow ?)
- [ ] **Vérifier** si la [**version de sudo** est vulnérable](privilege-escalation/#sudo-version)
- [ ] [**Échec de la vérification de signature Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Plus d'énumération système ([date, statistiques système, informations CPU, imprimantes](privilege-escalation/#more-system-enumeration))
- [ ] [**Énumérer plus de défenses**](privilege-escalation/#enumerate-possible-defenses)

### [Disques](privilege-escalation/#drives)

- [ ] **Lister les** disques montés
- [ ] **Un disque non monté ?**
- [ ] **Des identifiants dans fstab ?**

### [**Logiciels installés**](privilege-escalation/#installed-software)

- [ ] **Vérifier les** [**logiciels utiles**](privilege-escalation/#useful-software) **installés**
- [ ] **Vérifier les** [**logiciels vulnérables**](privilege-escalation/#vulnerable-software-installed) **installés**

### [Processus](privilege-escalation/#processes)

- [ ] Y a-t-il un **logiciel inconnu en cours d'exécution** ?
- [ ] Y a-t-il un logiciel en cours d'exécution avec **plus de privilèges qu'il ne devrait** ?
- [ ] Rechercher des **exploits de processus en cours d'exécution** (en particulier la version en cours d'exécution).
- [ ] Pouvez-vous **modifier le binaire** de tout processus en cours d'exécution ?
- [ ] **Surveiller les processus** et vérifier si un processus intéressant s'exécute fréquemment.
- [ ] Pouvez-vous **lire** la **mémoire d'un processus** intéressant (où des mots de passe pourraient être enregistrés) ?

### [Tâches planifiées/Cron ?](privilege-escalation/#scheduled-jobs)

- [ ] Le [**PATH**](privilege-escalation/#cron-path) est-il modifié par un cron et pouvez-vous **écrire** dedans ?
- [ ] Un [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) dans une tâche cron ?
- [ ] Un [**script modifiable**](privilege-escalation/#cron-script-overwriting-and-symlink) est-il **exécuté** ou est-il dans un **dossier modifiable** ?
- [ ] Avez-vous détecté qu'un **script** pourrait être ou est [**exécuté très **fréquemment**](privilege-escalation/#frequent-cron-jobs) ? (toutes les 1, 2 ou 5 minutes)

### [Services](privilege-escalation/#services)

- [ ] Un fichier **.service** **modifiable** ?
- [ ] Un **binaire modifiable** exécuté par un **service** ?
- [ ] Un **dossier modifiable dans le PATH de systemd** ?

### [Timers](privilege-escalation/#timers)

- [ ] Un **timer modifiable** ?

### [Sockets](privilege-escalation/#sockets)

- [ ] Un fichier **.socket** **modifiable** ?
- [ ] Pouvez-vous **communiquer avec un socket** ?
- [ ] **Sockets HTTP** avec des informations intéressantes ?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Pouvez-vous **communiquer avec un D-Bus** ?

### [Réseau](privilege-escalation/#network)

- [ ] Énumérer le réseau pour savoir où vous êtes
- [ ] **Ports ouverts auxquels vous n'avez pas pu accéder avant** d'obtenir un shell à l'intérieur de la machine ?
- [ ] Pouvez-vous **sniffer le trafic** en utilisant `tcpdump` ?

### [Utilisateurs](privilege-escalation/#users)

- [ ] Énumération des utilisateurs/groupes **génériques**
- [ ] Avez-vous un **UID très élevé** ? La **machine** est-elle **vulnérable** ?
- [ ] Pouvez-vous [**escalader les privilèges grâce à un groupe**](privilege-escalation/interesting-groups-linux-pe/) auquel vous appartenez ?
- [ ] Données du **presse-papiers** ?
- [ ] Politique de mot de passe ?
- [ ] Essayez d'**utiliser** chaque **mot de passe connu** que vous avez découvert précédemment pour vous connecter **avec chaque** utilisateur possible. Essayez également de vous connecter sans mot de passe.

### [PATH modifiable](privilege-escalation/#writable-path-abuses)

- [ ] Si vous avez **des privilèges d'écriture sur un dossier dans le PATH**, vous pourriez être en mesure d'escalader les privilèges

### [Commandes SUDO et SUID](privilege-escalation/#sudo-and-suid)

- [ ] Pouvez-vous exécuter **n'importe quelle commande avec sudo** ? Pouvez-vous l'utiliser pour LIRE, ÉCRIRE ou EXÉCUTER quoi que ce soit en tant que root ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Y a-t-il un **binaire SUID exploitable** ? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Les [**commandes sudo** sont-elles **limitées** par le **path** ? pouvez-vous **contourner** les restrictions](privilege-escalation/#sudo-execution-bypassing-paths) ?
- [ ] [**Binaire Sudo/SUID sans path indiqué**](privilege-escalation/#sudo-command-suid-binary-without-command-path) ?
- [ ] [**Binaire SUID spécifiant le path**](privilege-escalation/#suid-binary-with-command-path) ? Contourner
- [ ] [**Vulnérabilité LD_PRELOAD**](privilege-escalation/#ld_preload)
- [ ] [**Absence de bibliothèque .so dans le binaire SUID**](privilege-escalation/#suid-binary-so-injection) d'un dossier modifiable ?
- [ ] [**Tokens SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens) ? [**Pouvez-vous créer un token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than) ?
- [ ] Pouvez-vous [**lire ou modifier les fichiers sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d) ?
- [ ] Pouvez-vous [**modifier /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) ?
- [ ] Commande [**OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacités](privilege-escalation/#capabilities)

- [ ] Un binaire a-t-il une **capacité inattendue** ?

### [ACLs](privilege-escalation/#acls)

- [ ] Un fichier a-t-il une **ACL inattendue** ?

### [Sessions de shell ouvertes](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL PRNG prévisible - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valeurs de configuration SSH intéressantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Fichiers intéressants](privilege-escalation/#interesting-files)

- [ ] **Fichiers de profil** - Lire des données sensibles ? Écrire pour privesc ?
- [ ] **Fichiers passwd/shadow** - Lire des données sensibles ? Écrire pour privesc ?
- [ ] **Vérifier les dossiers couramment intéressants** pour des données sensibles
- [ ] **Emplacement étrange/Fichiers possédés,** vous pourriez avoir accès ou modifier des fichiers exécutables
- [ ] **Modifié** dans les dernières minutes
- [ ] **Fichiers de base de données Sqlite**
- [ ] **Fichiers cachés**
- [ ] **Scripts/Binaires dans le PATH**
- [ ] **Fichiers Web** (mots de passe ?)
- [ ] **Sauvegardes** ?
- [ ] **Fichiers connus contenant des mots de passe** : Utilisez **Linpeas** et **LaZagne**
- [ ] **Recherche générique**

### [**Fichiers modifiables**](privilege-escalation/#writable-files)

- [ ] **Modifier la bibliothèque python** pour exécuter des commandes arbitraires ?
- [ ] Pouvez-vous **modifier des fichiers journaux** ? Exploit **Logtotten**
- [ ] Pouvez-vous **modifier /etc/sysconfig/network-scripts/** ? Exploit Centos/Redhat
- [ ] Pouvez-vous [**écrire dans des fichiers ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d) ?

### [**Autres astuces**](privilege-escalation/#other-tricks)

- [ ] Pouvez-vous [**abuser de NFS pour escalader les privilèges**](privilege-escalation/#nfs-privilege-escalation) ?
- [ ] Avez-vous besoin de [**vous échapper d'un shell restrictif**](privilege-escalation/#escaping-from-restricted-shells) ?

{{#include ../banners/hacktricks-training.md}}
