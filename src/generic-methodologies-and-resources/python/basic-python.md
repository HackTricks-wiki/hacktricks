# Basic Python

## Python 基础

### 有用的信息

除非另有明确说明，以下所有示例均假设使用 **Python 3**。\
在 Python 3 中，`range()` 返回一个可迭代对象（类似于 Python 2 中的 `xrange()`）。\
**tuple** 和 **list** 的区别在于，tuple 中某个值的**位置**通常具有特定含义，而 list 通常只是一个有序的值序列。

### 主要操作

要对数字进行幂运算，可以使用：`3**2`（而不是 `3^2`）\
在 Python 3 中，`2/3 == 0.666666...`，而 `2//3 == 0` 执行的是整数除法。\
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
`dir(str)` = 列出可用的方法\
`help(str)` = 类 `str` 的定义\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**连接字符**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**list / string 的部分内容**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**注释**\
`# One line comment`\
`""" Several lines comment """`

**循环**
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
### 字节、十六进制与编码

这在 exploit-dev、reversing 和 CTFs 中非常常见：
```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```
### 元组

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = 单元素元组\
`d = ()` 空元组\
`d += (4,)` --> 添加到元组\
`# t1[1] = 'new value'` --> 元组不可变\
`list(t2) == [5, 6]` --> 从元组转换为列表

### 列表（数组）

`d = []` 空列表\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> 从列表转换为元组

### 字典
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
### 集合

集合中不会有重复项。\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> 无变化\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> 如果存在则移除；如果不存在则不执行任何操作\
`myset.remove(10)` --> 如果不存在，则引发异常\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> 获取任意元素并将其移除\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### 类

`__lt__` 中的方法将用于通过 `sort()` / `sorted()` 比较对象。
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
### map、zip、filter、lambda、sorted 和单行表达式

在 **Python 3** 中，`map()` 和 `filter()` 返回迭代器，因此如果想一次性打印所有值，请使用 `list()` 进行转换。

**Map** 类似于 `[f(x) for x in iterable]`：
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** 会在较短的可迭代对象结束时停止：
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** 用于定义函数：\
`(lambda x, y: x + y)(5, 3) == 8` --> use lambda as a simple function\
`sorted(range(-5, 6), key=lambda x: x**2)` --> use lambda to sort\
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

### 异常
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

如果条件为 false，将打印该字符串。\
请记住，可以通过 `python -O` 禁用 `assert` 语句，因此不要将其用于访问控制或输入验证。
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### 生成器（Generators）、yield

生成器不会一次性返回所有内容，而是逐个 **yield** 值。这对于巨大的 wordlist、bruteforcer 或大型响应非常有用。
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### 正则表达式
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**特殊含义：**\
`.` --> 除换行符外的任意字符\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> 数字\
`\s` --> 空白字符 `[ \n\r\t\f]`\
`\S` --> 非空白字符\
`^` --> 以……开头\
`$` --> 以……结尾\
`+` --> 一个或多个\
`*` --> 0 个或多个\
`?` --> 0 次或 1 次出现

**选项：**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> 允许点号匹配换行符\
`re.search(pat, string, re.MULTILINE)` --> 允许 `^` 和 `$` 在不同的行中进行匹配
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> 1 个或多个可迭代对象之间的笛卡尔积
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> 所有可能的排列组合
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**combinations**\
`from itertools import combinations` --> 所有不重复的可能组合
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
`from itertools import batched` --> 在 Python 3.12+ 中可用，适用于将大型 bruteforce 候选列表或 IOC 文件分块
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### 装饰器

用于测量函数执行所需时间的装饰器：
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
运行它，你将看到类似以下内容：
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### 用于 pentesting 的实用标准库辅助工具

**使用 `pathlib` 遍历文件系统**（`Path.walk()` 在 Python 3.12+ 中可用；在较旧的解释器中使用 `os.walk()`）：
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**安全地启动命令**（默认使用 `shell=False` 通常是你想要的设置）：
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
如果你**必须**构造 shell 命令，请先分别引用每个由攻击者控制的 token：
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**临时文件 / 目录**（比硬编码的 `/tmp/foo` 路径更安全）：
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
对于 HTTP 自动化，请查看[这个关于 Python Web requests 的页面](web-requests.md)。

### Archive 提取注意事项（对工具和文件解析器很重要）

从 **Python 3.14** 开始，`tarfile.extract()` / `extractall()` 默认使用更安全的 `data` filter。在较旧的 Python 版本中，处理攻击者控制的 archive 时，应显式设置该 filter。<sup>[[1]](#references)[[2]](#references)</sup>
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
即使使用 `filter="data"`，也应将不受信任的归档文件提取到全新的临时目录中，并在将文件移动到任何重要位置之前，验证实际写入的内容。

`zipfile.Path` 则有所不同：它**不会为你清理文件名**，因此在提取攻击者控制的 ZIP 成员之前，请验证路径：
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
### 需要记住的危险原语

- `eval()` / `exec()` **不是**沙箱。
- `ast.literal_eval()` **不会**执行 Python 代码，但攻击者控制的输入仍可利用它造成 memory / CPU denial of service。
- `pickle.loads()` **不安全**；绝不要对攻击者控制的字节执行 unpickle。
- 如需了解更深入的 offensive tricks，请查看 [Bypass Python sandboxes](bypass-python-sandboxes/README.md)、[Python internal read gadgets](python-internal-read-gadgets.md) 和 [Python deserializations](../../pentesting-web/deserialization/README.md)。

## References

- [1] [Python tarfile 文档](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – tarfile.extractall() 的过滤器](https://peps.python.org/pep-0706/)
{{#include ../../banners/hacktricks-training.md}}
