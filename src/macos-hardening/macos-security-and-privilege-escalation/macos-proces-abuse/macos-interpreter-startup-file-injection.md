# Ін’єкція у файли запуску інтерпретаторів macOS

{{#include ../../../banners/hacktricks-training.md}}

Ці техніки, специфічні для середовища виконання, використовують успадковані змінні середовища, щоб вибрати конфігурацію запуску або код, який виконається перед цільовим скриптом. Lua також підтримує варіант із вбудованим кодом.

## Конфігурація запуску PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` і `auto_prepend_file`

PHP CLI і CGI зчитують конфігурацію під час кожного запуску. `PHPRC` може вказувати на `php.ini`, доступний зловмиснику для читання, а `PHP_INI_SCAN_DIR` може перенаправити каталог, у якому шукаються додаткові файли `.ini`. Директива `auto_prepend_file` змушує PHP обробити файл перед запитаним скриптом, тож ця комбінація забезпечує виконання коду під час запуску.<sup>[[1]](#references)[[2]](#references)</sup>

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

Опція `-n` ігнорує `php.ini`; явно вказаний довірений шлях `-c` має пріоритет над `PHPRC`. Пам’ятайте, що довготривалий серверний SAPI зазвичай зчитує конфігурацію під час запуску вебсервера, тоді як CLI та CGI роблять це під час кожного виклику.<sup>[[1]](#references)</sup>

## Код запуску Lua

### `LUA_INIT`

Перед обробкою параметрів командного рядка або цільового скрипту автономний інтерпретатор Lua виконує `LUA_INIT_<major>_<minor>` або, якщо змінної з номером версії немає, `LUA_INIT`. Значення, що починається з `@`, задає файл; будь-яке інше значення безпосередньо інтерпретується як код Lua. Це дає змогу виконувати код під час запуску як із файлу, так і без нього.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Точна назва з версією змінюється залежно від інтерпретатора, наприклад `LUA_INIT_5_4`. `lua -E` ігнорує всі змінні середовища, зокрема код запуску та шляхи до модулів Lua.

## Стартове сховище Julia

### `JULIA_DEPOT_PATH` і `startup.jl`

Зазвичай під час запуску Julia виконує файл `config/startup.jl` із першого сховища. `JULIA_DEPOT_PATH` керує списком сховищ, тому, якщо вказати шлях до дерева, доступного для читання зловмисником, автоматично завантажуватиметься інший стартовий файл.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Роздільник у кінці корисний, якщо жертві й далі потрібні звичайні пакети. `julia --startup-file=no` вимикає цей startup file. Очистіть змінну перед запуском, оскільки вона також керує реєстрами пакетів, середовищами, кешами та розташуваннями завантаження коду.

## Файли запуску GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

Під час запуску GNU Octave виконує кілька файлів, що містять коректні команди Octave. `OCTAVE_SITE_INITFILE` перевизначає загальносистемний файл запуску, а `OCTAVE_VERSION_INITFILE` — файл, специфічний для версії, тож будь-яка зі змінних може перенаправити автоматичне виконання на файл, доступний для запису зловмиснику.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` пропускає лише файли користувача, як-от `~/.octaverc`; він **не** вимикає описане вище перевизначення файлу сайту. Для файлів сайту використовуйте `--no-site-file`, а для вимкнення всіх файлів запуску — `--norc` / `-f`.<sup>[[7]](#references)</sup>

## References

- [1] [Файл конфігурації PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Автономний інтерпретатор Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Інтерфейс командного рядка Julia: файл запуску](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Змінні середовища Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Файли запуску GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Параметри командного рядка GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
