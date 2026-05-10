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

Les **variables locales** ne peuvent être **accédées** que par le **shell/script actuel**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lister les variables actuelles
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Le contenu de `/proc/*/environ` est **séparé par des NUL**, donc ces variantes sont généralement plus faciles à lire :
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si vous recherchez des **credentials** ou une **configuration de service intéressante** dans des environnements hérités, consultez aussi [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – l’affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui signifie le premier affichage sur l’ordinateur actuel.
- **EDITOR** – l’éditeur de texte préféré de l’utilisateur.
- **HISTFILESIZE** – le nombre maximal de lignes contenues dans le fichier d’historique.
- **HISTSIZE** – nombre de lignes ajoutées au fichier d’historique lorsque l’utilisateur termine sa session
- **HOME** – votre répertoire personnel.
- **HOSTNAME** – le nom d’hôte de l’ordinateur.
- **LANG** – votre langue actuelle.
- **MAIL** – l’emplacement du spool mail de l’utilisateur. Généralement **/var/spool/mail/USER**.
- **MANPATH** – la liste des répertoires à parcourir pour les pages de manuel.
- **OSTYPE** – le type de système d’exploitation.
- **PS1** – l’invite par défaut dans bash.
- **PATH** – stocke le chemin de tous les répertoires qui contiennent les fichiers binaires que vous souhaitez exécuter simplement en indiquant le nom du fichier et non un chemin relatif ou absolu.
- **PWD** – le répertoire de travail actuel.
- **SHELL** – le chemin vers le shell de commande actuel (par exemple, **/bin/bash**).
- **TERM** – le type de terminal actuel (par exemple, **xterm**).
- **TZ** – votre fuseau horaire.
- **USER** – votre nom d’utilisateur actuel.

## Interesting variables for hacking

Toutes les variables ne sont pas également utiles. D’un point de vue offensif, privilégiez les variables qui modifient les **search paths**, les **startup files**, le comportement du **dynamic linker**, ou l’**audit/logging**.

### **HISTFILESIZE**

Modifiez la **valeur de cette variable à 0**, ainsi, lorsque vous **terminez votre session**, le **history file** (\~/.bash_history) sera **tronqué à 0 lignes**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Modifiez la **valeur de cette variable à 0**, afin que les commandes **ne soient pas conservées dans l'historique en mémoire** et ne soient pas réécrites dans le **fichier d'historique** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Si la **valeur de cette variable est définie sur `ignorespace` ou `ignoreboth`**, toute commande précédée d’un espace supplémentaire ne sera pas enregistrée dans l’historique.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Pointez le **fichier d'historique** vers **`/dev/null`** ou désactivez-le complètement. C’est généralement plus fiable que de simplement modifier la taille de l’historique.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Les processus utiliseront le **proxy** déclaré ici pour se connecter à internet via **http** ou **https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy par défaut pour les outils/protocoles qui le prennent en charge.
- `no_proxy`: liste de contournement (hosts/domains/CIDRs) qui doivent se connecter directement.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Les variantes en minuscule et en majuscule peuvent être utilisées selon l’outil (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Les processus feront confiance aux certificats indiqués dans **ces variables d’environnement**. Cela est utile pour faire en sorte que des outils tels que **`curl`**, **`git`**, les clients HTTP Python ou les gestionnaires de paquets fassent confiance à une CA contrôlée par l’attaquant (par exemple, pour faire paraître légitime un proxy d’interception).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilégié exécute des commandes **sans chemins absolus**, le **premier répertoire contrôlé par l’attaquant** dans `PATH` l’emporte. C’est le primitive derrière de nombreux **PATH hijacks** dans `sudo`, les tâches cron, les shell wrappers et les helpers SUID personnalisés. Cherchez `env_keep+=PATH`, un `secure_path` faible, ou des wrappers qui appellent `tar`, `service`, `cp`, `python`, etc. par nom.
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
Pour des chaînes complètes d'augmentation de privilèges abusant de `PATH`, consultez [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` n'est pas seulement une référence de répertoire : de nombreux outils chargent automatiquement des **dotfiles**, des **plugins** et des **configurations par utilisateur** depuis `$HOME` ou `$XDG_CONFIG_HOME`. Si un workflow privilégié préserve ces valeurs, l'**injection de config** peut être plus facile que le détournement de binaire.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Les cibles intéressantes incluent `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, ainsi que des fichiers spécifiques à certains outils comme `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ces variables influencent le **dynamic linker** :

- `LD_PRELOAD` : force le chargement prioritaire de shared objects supplémentaires.
- `LD_LIBRARY_PATH` : ajoute des répertoires de recherche de bibliothèques au début.
- `LD_AUDIT` : charge des auditor libraries qui observent le chargement des bibliothèques et la résolution des symboles.

Elles sont extrêmement utiles pour le **hooking**, l’**instrumentation** et la **privilege escalation** si une commande privilégiée les conserve. En mode **secure-execution** (`AT_SECURE`, par ex. setuid/setgid/capabilities), le loader supprime ou restreint beaucoup de ces variables. Cependant, les bugs de parser dans cette première étape du loader restent à fort impact parce qu’ils s’exécutent **avant** le programme cible.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifie le comportement précoce de glibc (par exemple, les tunables de l’allocateur) et est très utile dans les exploit labs. Cela compte aussi d’un point de vue sécurité parce que le **dynamic loader le parse très tôt**. Le bug **Looney Tunables** de 2023 a été un bon rappel qu’une seule variable d’environnement parsée dans le loader peut devenir un **local privilege-escalation primitive** contre les programmes SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** est lancé **non interactif**, il vérifie `BASH_ENV` et source ce fichier avant d’exécuter le script cible. Lorsque Bash est invoqué comme `sh`, ou en mode interactif de style POSIX, `ENV` peut aussi être consulté. C’est une méthode classique pour transformer un wrapper de shell en exécution de code si l’environnement est contrôlé par un attaquant.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash lui-même désactive ces fichiers de démarrage lorsque les **ID réels/effectifs diffèrent** sauf si `-p` est utilisé, donc le comportement exact dépend de la façon dont le wrapper invoque le shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ces variables modifient la façon dont Python démarre :

- `PYTHONPATH` : ajoute en préfixe les chemins de recherche d’import.
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

- `PERL5LIB` : ajoute des répertoires de bibliothèques au début.
- `PERL5OPT` : injecte des options comme si elles étaient présentes sur chaque ligne de commande `perl`.

Cela peut forcer le **chargement automatique de modules** ou modifier le comportement de l’interpréteur avant que le script cible ne fasse quoi que ce soit d’intéressant. Perl ignore ces variables dans les contextes **taint / setuid / setgid**, mais elles restent très importantes pour les wrappers normaux exécutés en root, les jobs CI, les installateurs et les règles sudoers personnalisées.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
La même idée apparaît dans d'autres runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.) : chaque fois qu'un interpréteur est lancé par un wrapper privilégié, cherchez les variables d'environnement qui modifient le **chargement des modules** ou le **comportement de démarrage**.

D'un point de vue post-exploitation, rappelez-vous aussi que les environnements hérités contiennent souvent des **credentials**, des **proxy settings**, des **service tokens**, ou des **cloud keys**. Consultez [Linux Post Exploitation](linux-post-exploitation/README.md) pour la recherche de `/proc/<PID>/environ` et `systemd` `Environment=`.

### PS1

Modifiez l'apparence de votre prompt.

[**Ceci est un exemple**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root :

![](<../images/image (897).png>)

Utilisateur normal :

![](<../images/image (740).png>)

Un, deux et trois jobs en arrière-plan :

![](<../images/image (145).png>)

Un job en arrière-plan, un job arrêté et la dernière commande ne s'est pas terminée correctement :

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
