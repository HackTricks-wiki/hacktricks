# Python cơ bản

{{#include ../../banners/hacktricks-training.md}}

## Môi trường ảo và bản dựng wheel (`venv`)

Module `venv` tiêu chuẩn của Python tạo các môi trường ảo, trong đó script kích hoạt POSIX là `<venv>/bin/activate`; nhập `deactivate` để thoát khỏi môi trường đang hoạt động.<sup>[[3]](#references)</sup> Trên Ubuntu, gói `python3-venv` cung cấp module này nếu nó không được cài đặt cùng gói Python cơ bản.<sup>[[4]](#references)</sup>

```bash
sudo apt-get install python3-venv
#Now, go to the folder you want to create the virtual environment
python3 -m venv <Dirname>
python3 -m venv pvenv #In this case the folder "pvenv" is going to be created
source <Dirname>/bin/activate
source pvenv/bin/activate #Activate the environment
#You can now install whatever python library you need
deactivate #To deactivate the virtual environment
```

Đối với các quy trình cũ dựa trên setuptools dùng `setup.py bdist_wheel`, cài đặt `wheel` trong môi trường đang hoạt động sẽ cung cấp lệnh `bdist_wheel`.<sup>[[5]](#references)</sup> Các phiên bản setuptools hiện tại không còn cần `wheel` cho lệnh đó, và hướng dẫn đóng gói hiện nay khuyến nghị dùng `python -m build --wheel` thay vì gọi trực tiếp `setup.py`.<sup>[[6]](#references)[[7]](#references)</sup>

```text
error: invalid command 'bdist_wheel'
```

```bash
# Legacy workaround for older setuptools-based projects:
python3 -m pip install wheel

# Current build workflow:
python3 -m pip install build
python3 -m build --wheel
```

## Cơ bản về Python

### Thông tin hữu ích

Tất cả ví dụ bên dưới đều giả định dùng **Python 3**, trừ khi có ghi chú rõ ràng.\
`range()` trả về một đối tượng iterable trong Python 3 (tương tự `xrange()` trong Python 2).\
Điểm khác biệt giữa **tuple** và **list** là **vị trí** của một giá trị trong tuple thường mang ý nghĩa, còn list thường chỉ là một chuỗi giá trị có thứ tự.

### Các phép toán chính

Để lũy thừa một số, dùng: `3**2` (không phải `3^2`)\
`2/3 == 0.666666...` trong Python 3, còn `2//3 == 0` thực hiện phép chia lấy phần nguyên.\
`i >= j`\
`i <= j`\
`i == j`\
`i != j`\
`a and b`\
`a or b`\
`not a`\
`float(a)`\
`int(a)`\
`str(d)`\
`ord("A") == 65`\
`chr(65) == 'A'`\
`hex(100) == '0x64'`\
`hex(100)[2:] == '64'`\
`isinstance(1, int) is True`\
`"a b".split(" ") == ['a', 'b']`\
`" ".join(['a', 'b']) == "a b"`\
`"abcdef".startswith("ab") is True`\
`"abc" in "abcdef"`\
`"abc\n".strip() == "abc"`\
`"apbc".replace("p", "") == "abc"`\
`dir(str)` = danh sách các phương thức khả dụng\
`help(str)` = định nghĩa của lớp `str`\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**Nối ký tự**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**Các phần tử của list / chuỗi**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Chú thích**\
`# One line comment`\
`""" Several lines comment """`

**Vòng lặp**

```python
if a:
    # something
elif b:
    # something
else:
    # something

while a:
    # something

for i in range(0, 100):
    # something from 0 to 99

for letter in "hola":
    # something with each letter
```

### Bytes, hex và encoding

Điều này rất phổ biến trong exploit-dev, reversing và CTFs:

```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```

### Tuple

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = tuple đơn phần tử\
`d = ()` tuple rỗng\
`d += (4,)` --> thêm vào tuple\
`# t1[1] = 'new value'` --> tuple là bất biến\
`list(t2) == [5, 6]` --> chuyển từ tuple sang list

### Danh sách (mảng)

`d = []` rỗng\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> chuyển từ list sang tuple

### Từ điển

```python
month_numbers = {1: 'Jan', 2: 'Feb', 'Feb': 2}
month_numbers[1] == 'Jan'
month_numbers['Feb'] == 2
list(month_numbers) == [1, 2, 'Feb']
list(month_numbers.values()) == ['Jan', 'Feb', 2]
keys = [k for k in month_numbers]
a = {'9': 9}
month_numbers.update(a)
mn = month_numbers.copy()  # independent copy
month_numbers.get('key', 0)  # default value if key does not exist
```

### Tập hợp

Trong tập hợp không có phần tử trùng lặp.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> không thay đổi\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> nếu có, xóa phần tử đó; nếu không, không làm gì\
`myset.remove(10)` --> nếu không có, sẽ phát sinh ngoại lệ\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> lấy một phần tử bất kỳ và xóa phần tử đó\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Lớp

Phương thức trong `__lt__` sẽ được `sort()` / `sorted()` sử dụng để so sánh các đối tượng.

```python
import datetime


class Person:
    def __init__(self, name):
        self.name = name
        self.last_name = name.split(" ")[-1]
        self.birthday = None

    def __lt__(self, other):
        if self.last_name == other.last_name:
            return self.name < other.name
        return self.last_name < other.last_name

    def set_birthday(self, month, day, year):
        self.birthday = datetime.date(year, month, day)

    def get_age(self):
        return (datetime.date.today() - self.birthday).days


class MITPerson(Person):
    next_id_num = 0  # class attribute

    def __init__(self, name):
        super().__init__(name)
        self.id_num = MITPerson.next_id_num
        MITPerson.next_id_num += 1

    def __lt__(self, other):
        return self.id_num < other.id_num
```

### map, zip, filter, lambda, sorted và one-liners

Trong **Python 3**, `map()` và `filter()` trả về các iterator, vì vậy hãy chuyển đổi chúng bằng `list()` nếu bạn muốn in tất cả giá trị cùng lúc.

**Map** tương tự như `[f(x) for x in iterable]`:

```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```

**zip** dừng khi iterable ngắn hơn kết thúc:

```python
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** được dùng để định nghĩa một hàm:\
`(lambda x, y: x + y)(5, 3) == 8` --> dùng lambda như một hàm đơn giản\
`sorted(range(-5, 6), key=lambda x: x**2)` --> dùng lambda để sắp xếp\
`list(filter(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9])) == [3, 6, 9]`\
`reduce(lambda x, y: x * y, [1, 2, 3, 4]) == 24`

```python
from functools import reduce


def make_adder(n):
    return lambda x: x + n


plus3 = make_adder(3)
plus3(4) == 7


class Car:
    crash = lambda self: print("Boom!")


my_car = Car()
my_car.crash()  # Boom!
```

`mult1 = [x for x in [1, 2, 3, 4, 5, 6, 7, 8, 9] if x % 3 == 0]`

### Ngoại lệ

```python
def divide(x, y):
    try:
        result = x / y
    except ZeroDivisionError as e:
        print("division by zero! " + str(e))
    except TypeError:
        divide(int(x), int(y))
    else:
        print("result is", result)
    finally:
        print("executing finally clause in any case")
```

### Assert()

Nếu điều kiện sai, chuỗi sẽ được in ra.\
Hãy nhớ rằng có thể vô hiệu hóa các câu lệnh `assert` bằng `python -O`, vì vậy đừng dùng chúng để kiểm soát quyền truy cập hoặc xác thực đầu vào.

```python
def avg(grades, weights):
    assert len(grades) != 0, 'no grades data'
    assert len(grades) == len(weights), 'wrong number of grades'
```

### Generators, yield

Thay vì trả về tất cả cùng lúc, generator **yield** các giá trị lần lượt từng giá trị một. Điều này rất hữu ích với wordlist khổng lồ, bruteforcer hoặc response lớn.

```python
def my_gen(n):
    yield n
    yield n + 1
```

`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Biểu thức chính quy

```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```

**Ý nghĩa đặc biệt:**\
`.` --> mọi ký tự trừ ký tự xuống dòng\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> chữ số\
`\s` --> ký tự khoảng trắng `[ \n\r\t\f]`\
`\S` --> ký tự không phải khoảng trắng\
`^` --> bắt đầu bằng\
`$` --> kết thúc bằng\
`+` --> một hoặc nhiều\
`*` --> 0 hoặc nhiều\
`?` --> 0 hoặc 1 lần xuất hiện

**Tùy chọn:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> cho phép dấu chấm khớp với ký tự xuống dòng\
`re.search(pat, string, re.MULTILINE)` --> cho phép `^` và `$` khớp ở các dòng khác nhau

```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```

### IterTools

**product**\
`from itertools import product` --> tích Descartes giữa 1 hoặc nhiều iterable`s

```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```

**permutations**\
`from itertools import permutations` --> mọi cách sắp xếp có thể

```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```

**tổ hợp**\
`from itertools import combinations` --> tất cả các tổ hợp có thể có mà không lặp lại

```python
list(combinations('123', 2))
# [('1', '2'), ('1', '3'), ('2', '3')]
```

**combinations_with_replacement**\
`from itertools import combinations_with_replacement`

```python
list(combinations_with_replacement('123', 2))
# [('1', '1'), ('1', '2'), ('1', '3'), ('2', '2'), ('2', '3'), ('3', '3')]
```

**batched**\
`from itertools import batched` --> có trong Python 3.12+, hữu ích để chia danh sách ứng viên bruteforce lớn hoặc file IOC thành các nhóm Lenovo

```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```

### Decorators

Decorator đo thời gian cần thiết để thực thi một hàm:

```python
from functools import wraps
import time


def timeme(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("Let's call our decorated function")
        start = time.time()
        result = func(*args, **kwargs)
        print(f"Execution time: {time.time() - start} seconds")
        return result

    return wrapper


@timeme
def decorated_func():
    print("Decorated func!")
```

Nếu chạy nó, bạn sẽ thấy nội dung tương tự như sau:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```

### Các hàm trợ giúp hữu ích trong thư viện chuẩn cho pentesting

**Duyệt hệ thống tệp bằng `pathlib`** (`Path.walk()` có trong Python 3.12 trở lên; dùng `os.walk()` với các trình thông dịch cũ hơn):

```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        if name.endswith((".py", ".env", ".bak")):
            print(root / name)
```

**Khởi chạy lệnh an toàn** (`shell=False` thường là lựa chọn bạn muốn theo mặc định):

```python
import subprocess

cp = subprocess.run(
    ["id"],
    capture_output=True,
    text=True,
    check=True,
)
print(cp.stdout)
```

Nếu bạn **bắt buộc** phải tạo một lệnh shell, hãy đặt từng token do attacker kiểm soát trong dấu nháy trước:

```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```

**Tệp/thư mục tạm thời** (an toàn hơn các đường dẫn `/tmp/foo` được ghi cứng):

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "loot.txt"
    out.write_text("secret\n")
    print(out.read_text())
```

Để tự động hóa HTTP, hãy xem [trang khác này về các yêu cầu web bằng Python](web-requests.md).

### Những điều cần lưu ý khi giải nén archive (quan trọng đối với tooling và trình phân tích tệp)

Bắt đầu từ **Python 3.14**, `tarfile.extract()` / `extractall()` mặc định sử dụng filter `data` an toàn hơn. Trong các phiên bản Python cũ hơn, bạn nên đặt filter này một cách tường minh khi xử lý archive do kẻ tấn công kiểm soát.<sup>[[1]](#references)[[2]](#references)</sup>

```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
    with tarfile.open("sample.tar.gz") as tf:
        tf.extractall(out, filter="data")
```

Ngay cả khi dùng `filter="data"`, hãy giải nén các archive không đáng tin cậy vào một thư mục tạm mới và xác thực nội dung đã ghi trước khi di chuyển tệp đến bất kỳ vị trí quan trọng nào.

`zipfile.Path` thì khác: nó **không tự làm sạch tên tệp** cho bạn, vì vậy hãy xác thực đường dẫn trước khi giải nén các thành viên ZIP do kẻ tấn công kiểm soát:

```python
import os
import zipfile

base = os.path.abspath("/tmp/unzip")
with zipfile.ZipFile("sample.zip") as zf:
    for info in zf.infolist():
        final_path = os.path.abspath(os.path.join(base, info.filename))
        if os.path.commonpath([base, final_path]) != base:
            raise ValueError(f"Path traversal inside ZIP: {info.filename}")
        zf.extract(info, base)
```

### Các primitive nguy hiểm cần nhớ

- `eval()` / `exec()` **không phải** là sandbox.
- `ast.literal_eval()` **không** thực thi mã Python, nhưng vẫn có thể bị lợi dụng để gây từ chối dịch vụ do cạn kiệt bộ nhớ / CPU bằng đầu vào do kẻ tấn công kiểm soát.
- `pickle.loads()` **không an toàn**; tuyệt đối không unpickle byte do kẻ tấn công kiểm soát.
- Để tìm hiểu sâu hơn về các thủ thuật tấn công, hãy xem [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) và [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [1] [Tài liệu Python tarfile](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – Bộ lọc cho tarfile.extractall()](https://peps.python.org/pep-0706/)
- [3] [venv — Tạo môi trường ảo — Tài liệu Python 3.14](https://docs.python.org/3/library/venv.html)
- [4] [Gói: python3-venv — Các gói Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [5] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [6] [wheel — PyPI](https://pypi.org/project/wheel/)
- [7] [setup.py có bị deprecated không? — Hướng dẫn sử dụng Python Packaging](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
