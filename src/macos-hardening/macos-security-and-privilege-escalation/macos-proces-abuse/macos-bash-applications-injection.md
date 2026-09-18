# Injection dans les applications Shell de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Lorsque Bash démarre de manière non interactive pour exécuter un script ou une commande `-c`, il développe la valeur de `BASH_ENV` et source le fichier obtenu avant d’exécuter la commande demandée. Bash n’utilise pas `PATH` pour trouver ce fichier. Un processus qui lance Bash de manière non interactive avec des variables d’environnement contrôlées par un attaquant peut donc être amené à exécuter en premier un payload shell lisible.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Le hook ne s’exécute que lorsque la cible démarre réellement Bash ; `/bin/sh` sur une autre plateforme ou un programme qui exécute une commande sans shell ne le respectera pas nécessairement. Bash en mode privilégié ignore `BASH_ENV`. Lorsque les identifiants effectif et réel de l’utilisateur ou du groupe diffèrent, Bash ignore également les fichiers de démarrage et réinitialise les identifiants effectifs, sauf si `-p` est fourni ; avec `-p`, le mode privilégié reste activé et `BASH_ENV` est toujours ignoré.<sup>[[1]](#references)[[2]](#references)</sup>

Sur macOS, les tâches `launchd` peuvent définir des variables d’environnement héritées ou propres à chaque tâche. Il faut donc inspecter les plists et les contextes de lancement qui alimentent les scripts privilégiés. Ne comptez pas uniquement sur SIP pour nettoyer les variables de l’interpréteur : utilisez un environnement minimal (`env -i`), désactivez explicitement `BASH_ENV`, invoquez l’interpréteur prévu avec son chemin absolu et évitez les fichiers de démarrage accessibles en écriture.

## zsh `ZDOTDIR`

zsh lit `$ZDOTDIR/.zshenv` pour chaque shell normal, y compris les shells non interactifs ; si `ZDOTDIR` n’est pas défini, il utilise `HOME`. Rediriger `ZDOTDIR` vers un répertoire accessible en écriture exécute donc son `.zshenv` avant une commande ou un script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` désactive l’option `RCS` et ignore ce fichier de démarrage utilisateur. Le fichier global `/etc/zshenv` est toujours lu ; il doit donc rester fiable et minimal.

## fish `XDG_CONFIG_HOME`

fish lit `$XDG_CONFIG_HOME/fish/conf.d/*.fish` et `$XDG_CONFIG_HOME/fish/config.fish` au démarrage de chaque shell, et pas seulement des shells interactifs ou de connexion. Il exécute également `fish/vendor_conf.d/*.fish` dans les entrées de `XDG_DATA_DIRS`. Un attaquant qui contrôle l’une de ces variables et un répertoire lisible peut donc exécuter du code avant un script fish ou une commande `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Utilisez `fish --no-config` pour une invocation fiable et effacez les variables de chemin XDG non fiables.

## bash `PS4` + xtrace (`SHELLOPTS`)

Lorsque Bash s'exécute avec l'option **xtrace**, avant chaque commande tracée, il développe `PS4` et l'affiche. `PS4` est développé comme n'importe quelle invite, donc une **command substitution** qu'il contient est exécutée. La valeur de `PS4` **et** la manière dont xtrace est activé peuvent provenir uniquement de l'environnement : exporter `SHELLOPTS=xtrace` active xtrace pour un `bash script.sh` normal (aucun flag `-x` nécessaire). Cela transforme n'importe quel script Bash exécuté par la victime en exécution de code.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` seul ne fait rien tant que xtrace n'est pas activé (via `SHELLOPTS=xtrace`, `set -x` ou `bash -x`). Bash ignore `SHELLOPTS` en **mode privilégié** (IDs réel/effectif différents sans gestion de `-p`), les mêmes précautions liées à setuid que pour `BASH_ENV` s'appliquent.

## POSIX `ENV`

Les shells de style POSIX (`/bin/sh`, `dash`, `ksh`) lisent la variable `ENV`, l'étendent et exécutent le fichier obtenu lorsqu'ils démarrent un shell **interactif**. C'est l'équivalent POSIX de `BASH_ENV` (qui s'applique à Bash *non interactif*) ; ainsi, le contrôle de `ENV` permet d'exécuter du code chaque fois qu'une victime démarre un `sh`/`dash` interactif.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Fichiers de démarrage de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash : invoquer Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Fichiers de démarrage et d'arrêt de zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Fichiers de configuration de fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Variables de Bash — `PS4` et le builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
