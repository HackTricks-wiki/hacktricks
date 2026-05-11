# Variables d'environnement Linux

{{#include ../banners/hacktricks-training.md}}

## Variables globales

Les variables globales **seront** héritées par les **processus enfants**.

Vous pouvez créer une variable globale pour votre session actuelle en faisant :
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Cette variable sera accessible par vos sessions actuelles et leurs processus enfants.

Vous pouvez **supprimer** une variable en faisant :
```bash
unset MYGLOBAL
```
## Variables locales

Les **variables locales** peuvent uniquement être **accessibles** par le **shell/script actuel**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Liste des variables actuelles
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Le contenu de `/proc/*/environ` est **séparé par NUL**, donc ces variantes sont généralement plus faciles à lire :
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si vous recherchez des **credentials** ou une **intéressante configuration de service** dans des environnements hérités, consultez aussi [Linux Post Exploitation](linux-post-exploitation/README.md).

## Variables courantes

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – l’affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui signifie le premier affichage sur l’ordinateur actuel.
- **EDITOR** – l’éditeur de texte préféré de l’utilisateur.
- **HISTFILESIZE** – le nombre maximal de lignes contenues dans le fichier d’historique.
- **HISTSIZE** – nombre de lignes ajoutées au fichier d’historique lorsque l’utilisateur termine sa session
- **HOME** – votre répertoire personnel.
- **HOSTNAME** – le nom d’hôte de l’ordinateur.
- **LANG** – votre langue actuelle.
- **MAIL** – l’emplacement du spool de courrier de l’utilisateur. Habituellement **/var/spool/mail/USER**.
- **MANPATH** – la liste des répertoires à rechercher pour les pages de manuel.
- **OSTYPE** – le type de système d’exploitation.
- **PS1** – l’invite par défaut dans bash.
- **PATH** – stocke le chemin de tous les répertoires qui contiennent les fichiers binaires que vous souhaitez exécuter simplement en spécifiant le nom du fichier et non un chemin relatif ou absolu.
- **PWD** – le répertoire de travail actuel.
- **SHELL** – le chemin vers le shell de commande actuel (par exemple, **/bin/bash**).
- **TERM** – le type de terminal actuel (par exemple, **xterm**).
- **TZ** – votre fuseau horaire.
- **USER** – votre nom d’utilisateur actuel.

## Variables intéressantes pour hacking

Toutes les variables ne sont pas aussi utiles. D’un point de vue offensif, privilégiez les variables qui modifient les **search paths**, les **startup files**, le comportement du **dynamic linker**, ou l’**audit/logging**.

### **HISTFILESIZE**

Modifiez la **valeur de cette variable à 0**, afin que lorsque vous **terminez votre session** le **history file** (\~/.bash_history) soit **tronqué à 0 ligne**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Modifiez la **valeur de cette variable à 0**, afin que les commandes **ne soient pas conservées dans l'historique en mémoire** et ne soient pas réécrites dans le **fichier d'historique** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Si **la valeur de cette variable est définie sur `ignorespace` ou `ignoreboth`**, toute commande précédée d’un espace supplémentaire ne sera pas enregistrée dans l’historique.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Pointez le **fichier d’historique** vers **`/dev/null`** ou désactivez-le complètement. C’est généralement plus fiable que de seulement modifier la taille de l’historique.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Les processus utiliseront le **proxy** déclaré ici pour se connecter à internet via **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy par défaut pour les outils/protocoles qui le prennent en charge.
- `no_proxy`: liste de contournement (hosts/domaines/CIDRs) qui doivent se connecter directement.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Les variantes en minuscules et en majuscules peuvent être utilisées selon l'outil (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Les processus feront confiance aux certificats indiqués dans **ces variables d'environnement**. C'est utile pour faire en sorte que des outils comme **`curl`**, **`git`**, les clients HTTP Python, ou les gestionnaires de paquets fassent confiance à une CA contrôlée par l'attaquant (par exemple, pour faire paraître légitime un proxy d'interception).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilégié exécute des commandes **sans chemins absolus**, le **premier répertoire contrôlé par l’attaquant** dans `PATH` gagne. C’est le primitif derrière de nombreux **PATH hijacks** dans `sudo`, les tâches cron, les wrappers shell et les helpers SUID personnalisés. Cherchez `env_keep+=PATH`, un `secure_path` faible, ou des wrappers qui appellent `tar`, `service`, `cp`, `python`, etc. par leur nom.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
Pour des chaînes complètes d'élévation de privilèges abusant de `PATH`, consultez [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` n'est pas seulement une référence de répertoire : de nombreux outils chargent automatiquement des **dotfiles**, des **plugins** et des **configurations par utilisateur** depuis `$HOME` ou `$XDG_CONFIG_HOME`. Si un workflow privilégié préserve ces valeurs, l'**injection de configuration** peut être plus facile que le détournement d'un binaire.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Les cibles intéressantes incluent `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, et des fichiers spécifiques à certains outils comme `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ces variables influencent le **dynamic linker** :

- `LD_PRELOAD` : force le chargement en premier d’objets partagés supplémentaires.
- `LD_LIBRARY_PATH` : ajoute les répertoires de recherche de bibliothèques au début.
- `LD_AUDIT` : charge des bibliothèques d’audit qui observent le chargement des bibliothèques et la résolution des symboles.

Elles sont extrêmement utiles pour le **hooking**, l’**instrumentation** et la **privilege escalation** si une commande privilégiée les conserve. En mode **secure-execution** (`AT_SECURE`, par ex. setuid/setgid/capabilities), le loader supprime ou restreint bon nombre de ces variables. Cependant, les bugs de parser dans cette phase اولیه du loader restent très impactants, car ils s’exécutent **avant** le programme cible.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifie le comportement précoce de glibc (par exemple, les tunables de l'allocator) et est très utile dans les exploit labs. Cela compte aussi du point de vue de la sécurité parce que le **dynamic loader l'analyse très tôt**. Le bug **Looney Tunables** de 2023 a rappelé qu'une seule variable d'environnement analysée dans le loader peut devenir un **primitive de local privilege-escalation** contre les programmes SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** est démarré de manière **non interactive**, il vérifie `BASH_ENV` et source ce fichier avant d’exécuter le script cible. Lorsque Bash est invoqué comme `sh`, ou en mode interactif de style POSIX, `ENV` peut également être consulté. C’est une méthode classique pour transformer un wrapper shell en exécution de code si l’environnement est contrôlé par un attaquant.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash lui-même désactive ces fichiers de démarrage lorsque les **ID réels/effectifs diffèrent** sauf si `-p` est utilisé, donc le comportement exact dépend de la façon dont le wrapper invoque le shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ces variables modifient la manière dont Python démarre :

- `PYTHONPATH` : ajoute des chemins de recherche d’import en tête.
- `PYTHONHOME` : déplace l’arborescence de la bibliothèque standard.
- `PYTHONSTARTUP` : exécute un fichier avant l’invite interactive.
- `PYTHONINSPECT=1` : passe en mode interactif après la fin d’un script.

Elles sont utiles contre les scripts de maintenance, les debuggers, les shells et les wrappers qui appellent Python avec un environnement contrôlable. `python -E` et `python -I` ignorent toutes les variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl a des variables de démarrage tout aussi utiles :

- `PERL5LIB`: ajoute les répertoires de bibliothèques au début.
- `PERL5OPT`: injecte des options comme si elles figuraient sur chaque ligne de commande `perl`.

Cela peut forcer le **chargement automatique de modules** ou modifier le comportement de l’interpréteur avant que le script cible ne fasse quoi que ce soit d’intéressant. Perl ignore ces variables dans les contextes **taint / setuid / setgid**, mais elles restent très importantes pour les wrappers normaux exécutés en root, les tâches CI, les installateurs et les règles sudoers personnalisées.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
La même idée apparaît dans d’autres runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.) : chaque fois qu’un interpréteur est lancé par un wrapper privilégié, cherchez des variables d’environnement qui modifient le **chargement de modules** ou le **comportement au démarrage**.

D’un point de vue post-exploitation, rappelez-vous aussi que les environnements hérités contiennent souvent des **credentials**, des **proxy settings**, des **service tokens** ou des **cloud keys**. Consultez [Linux Post Exploitation](linux-post-exploitation/README.md) pour la recherche de `/proc/<PID>/environ` et de `systemd` `Environment=`.

### PS1

Changez l’apparence de votre prompt.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
