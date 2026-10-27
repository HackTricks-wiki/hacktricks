# macOS GNU Octave Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave thực thi một số tệp chứa các lệnh Octave hợp lệ khi khởi động. `OCTAVE_SITE_INITFILE` ghi đè tệp khởi động áp dụng trên toàn site, còn `OCTAVE_VERSION_INITFILE` ghi đè tệp dành riêng cho phiên bản, cho phép một trong hai biến chuyển hướng quá trình thực thi tự động đến một tệp mà kẻ tấn công có thể đọc được.<sup>[[1]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` chỉ bỏ qua các tệp của người dùng như `~/.octaverc`; tùy chọn này **không** ngăn chặn việc ghi đè tệp site ở trên. Dùng `--no-site-file` cho các tệp site hoặc `--norc` / `-f` để tắt tất cả các tệp khởi động.<sup>[[2]](#references)</sup>

## References

- [1] [Tệp khởi động GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Tùy chọn dòng lệnh GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
