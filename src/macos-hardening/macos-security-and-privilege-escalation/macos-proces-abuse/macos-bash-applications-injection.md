# Injection vào ứng dụng shell trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Khi Bash khởi chạy ở chế độ không tương tác để chạy script hoặc lệnh `-c`, nó mở rộng giá trị của `BASH_ENV` rồi source file thu được trước khi thực thi lệnh được yêu cầu. Bash không sử dụng `PATH` để tìm file này. Do đó, có thể khiến một tiến trình khởi chạy Bash ở chế độ không tương tác với các biến môi trường do kẻ tấn công kiểm soát thực thi trước một shell payload có thể đọc được.<sup>[[1]](#references)</sup>

```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```

Hook chỉ chạy khi target thực sự khởi chạy Bash; `/bin/sh` trên nền tảng khác hoặc chương trình thực thi lệnh mà không dùng shell không nhất thiết sẽ áp dụng nó. Bash ở chế độ đặc quyền bỏ qua `BASH_ENV`. Khi effective và real user/group IDs khác nhau, Bash cũng bỏ qua các startup files và đặt lại effective IDs, trừ khi có `-p`; với `-p`, chế độ đặc quyền vẫn được bật và `BASH_ENV` vẫn bị bỏ qua.<sup>[[1]](#references)[[2]](#references)</sup>

Trên macOS, các `launchd` job có thể định nghĩa các environment variables được kế thừa hoặc áp dụng riêng cho từng job, vì vậy hãy kiểm tra các plist và launch context cung cấp biến cho các script đặc quyền. Đừng chỉ dựa vào SIP để làm sạch các interpreter variables: hãy dùng environment tối thiểu (`env -i`), chủ động unset `BASH_ENV`, gọi interpreter dự định dùng bằng absolute path và tránh các startup files có thể ghi được.

## zsh `ZDOTDIR`

zsh đọc `$ZDOTDIR/.zshenv` cho mọi shell thông thường, kể cả non-interactive shell; nếu `ZDOTDIR` chưa được đặt, zsh sẽ dùng `HOME`. Do đó, chuyển hướng `ZDOTDIR` đến một thư mục có thể ghi sẽ thực thi `.zshenv` trước lệnh hoặc script `zsh -c`.<sup>[[3]](#references)</sup>

```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```

`zsh -f` sẽ bỏ đặt tùy chọn `RCS` và bỏ qua tệp khởi động của người dùng này. Tệp `/etc/zshenv` toàn cục vẫn được đọc, vì vậy tệp này phải luôn đáng tin cậy và tối giản.

## fish `XDG_CONFIG_HOME`

fish đọc `$XDG_CONFIG_HOME/fish/conf.d/*.fish` và `$XDG_CONFIG_HOME/fish/config.fish` khi khởi động mọi shell, không chỉ shell tương tác hoặc shell đăng nhập. fish cũng thực thi `fish/vendor_conf.d/*.fish` trong các thư mục thuộc `XDG_DATA_DIRS`. Vì vậy, kẻ tấn công kiểm soát một trong các biến này và một thư mục có thể đọc được có thể chạy mã trước một script fish hoặc lệnh `-c`.<sup>[[4]](#references)</sup>

```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```

Dùng `fish --no-config` để gọi lệnh một cách đáng tin cậy và xóa các biến đường dẫn XDG không đáng tin cậy.

## `PS4` + xtrace của bash (`SHELLOPTS`)

Khi Bash chạy với tùy chọn **xtrace**, trước mỗi lệnh được trace, nó sẽ mở rộng `PS4` rồi in giá trị này. `PS4` được mở rộng như mọi prompt khác, nên **command substitution** bên trong nó sẽ được thực thi. Cả giá trị của `PS4` **và** cách bật xtrace đều có thể đến hoàn toàn từ môi trường: export `SHELLOPTS=xtrace` sẽ bật xtrace khi chạy `bash script.sh` thông thường (không cần cờ `-x`). Điều này biến mọi script Bash mà nạn nhân chạy thành khả năng thực thi mã.<sup>[[5]](#references)</sup>

```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` riêng lẻ không làm gì cho đến khi bật xtrace (thông qua `SHELLOPTS=xtrace`, `set -x` hoặc `bash -x`). Bash bỏ qua `SHELLOPTS` trong **chế độ đặc quyền** (ID thực/hiệu lực khác nhau mà không xử lý bằng `-p`), nên áp dụng các lưu ý setuid tương tự như với `BASH_ENV`.

## POSIX `ENV`

Các shell kiểu POSIX (`/bin/sh`, `dash`, `ksh`) đọc biến `ENV`, mở rộng biến này rồi source tệp thu được khi khởi động một shell **tương tác**. Đây là đối ứng POSIX của `BASH_ENV` (hoạt động với Bash *không tương tác*), vì vậy quyền kiểm soát `ENV` cho phép thực thi mã bất cứ khi nào nạn nhân chạy `sh`/`dash` tương tác.

```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```

## References

- [1] [Các tệp khởi động của Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Gọi Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Các tệp khởi động/tắt của zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Các tệp cấu hình của fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Biến Bash — `PS4` và lệnh dựng sẵn Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
