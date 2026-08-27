# Injection dans les applications Shell de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Lorsque Bash démarre de manière non interactive pour exécuter un script ou une commande `-c`, il développe la valeur de `BASH_ENV` et source le fichier obtenu avant d'exécuter la commande demandée. Bash n'utilise pas `PATH` pour trouver ce fichier. Un processus qui lance Bash de manière non interactive avec des variables d'environnement contrôlées par un attaquant peut donc être amené à exécuter en premier une charge utile Shell lisible.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Le hook ne s’exécute que lorsque la cible lance réellement Bash ; `/bin/sh` sur une autre plateforme, ou un programme qui exécute une commande sans shell, ne le respectera pas nécessairement. Bash en mode privilégié ignore `BASH_ENV`. Lorsque les identifiants effectifs et réels de l’utilisateur ou du groupe diffèrent, Bash ignore également les fichiers de démarrage et réinitialise les identifiants effectifs, sauf si `-p` est fourni ; avec `-p`, le mode privilégié reste activé et `BASH_ENV` est toujours ignoré.<sup>[[1]](#references)[[2]](#references)</sup>

Sur macOS, les jobs `launchd` peuvent définir des variables d’environnement héritées ou propres à chaque job ; inspectez donc les plists et les contextes de lancement qui alimentent les scripts privilégiés. Ne comptez pas uniquement sur SIP pour nettoyer les variables de l’interpréteur : utilisez un environnement minimal (`env -i`), désactivez explicitement `BASH_ENV`, invoquez l’interpréteur prévu avec son chemin absolu et évitez les fichiers de démarrage accessibles en écriture.

## zsh `ZDOTDIR`

zsh lit `$ZDOTDIR/.zshenv` pour chaque shell normal, y compris les shells non interactifs ; si `ZDOTDIR` n’est pas défini, il utilise `HOME`. Rediriger `ZDOTDIR` vers un répertoire accessible en écriture exécute donc son `.zshenv` avant une commande ou un script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` désactive l’option `RCS` et ignore ce fichier de démarrage utilisateur. Le fichier global `/etc/zshenv` est tout de même lu ; il doit donc rester fiable et minimal.

## fish `XDG_CONFIG_HOME`

fish lit `$XDG_CONFIG_HOME/fish/conf.d/*.fish` et `$XDG_CONFIG_HOME/fish/config.fish` au démarrage de chaque shell, et pas uniquement des shells interactifs ou de connexion. Il exécute également `fish/vendor_conf.d/*.fish` sous les entrées de `XDG_DATA_DIRS`. Un attaquant qui contrôle l’une de ces variables et un répertoire lisible peut donc exécuter du code avant un script fish ou une commande `-c`.<sup>[[4]](#references)</sup>
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

## References

- [1] [Fichiers de démarrage de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Invocation de Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Fichiers de démarrage et d'arrêt de zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Fichiers de configuration de fish](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
