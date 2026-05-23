# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

下面的所有示例都假设使用 **Python 3**，除非另有说明。\
`range()` 在 Python 3 中返回一个 iterable object（类似于 Python 2 中的 `xrange()`）。\
**tuple** 和 **list** 的区别在于，tuple 中一个值的 **position** 通常赋予它含义，而 list 通常只是一个有序的值序列。

### Main operations

要进行幂运算，使用：`3**2`（不是 `3^2`）\
在 Python 3 中，`2/3 == 0.666666...`，而 `2//3 == 0` 表示整数除法。\
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
`dir(str)` = 可用方法列表\
`help(str)` = `str` 类的定义\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**Join chars**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**Parts of a list / string**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Comments**\
`# One line comment`\
`""" Several lines comment """`

**Loops**
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
### 字节、hex 和 encodings

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
`(4,)` = singleton\
`d = ()` 空元组\
`d += (4,)` --> add into a tuple\
`# t1[1] = 'new value'` --> tuples are immutable\
`list(t2) == [5, 6]` --> from tuple to list

### List (array)

`d = []` 空\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> from list to tuple

### Dictionary
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
### Set

在 sets 中没有重复项。\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> no change\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> 如果存在则移除；如果不存在，则什么都不做\
`myset.remove(10)` --> 如果不存在，则抛出 exception\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> 获取一个任意元素并将其移除\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

`__lt__` 中的方法将会被 `sort()` / `sorted()` 用来比较 objects。
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
### map, zip, filter, lambda, sorted and one-liners

在 **Python 3** 中，`map()` 和 `filter()` 会返回迭代器，所以如果你想一次性打印所有值，请用 `list()` 转换它们。

**Map** 类似于 `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** 在较短的 iterable 结束时停止：
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** 用于定义一个函数：\
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

如果条件为 false，字符串将被打印。\
请记住，`assert` 语句可以通过 `python -O` 禁用，因此不要将它们用于访问控制或输入验证。
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### 生成器, yield

生成器不会一次性返回所有内容，而是逐个 **yield** 值。这对于巨大的 wordlists、bruteforcers 或大型响应非常有用。
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
`.` --> 除换行外的任何字符\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> 数字\
`\s` --> 空白字符 `[ \n\r\t\f]`\
`\S` --> 非空白字符\
`^` --> 以...开头\
`$` --> 以...结尾\
`+` --> 一个或多个\
`*` --> 0个或多个\
`?` --> 0个或1个出现

**选项：**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> 允许点号匹配换行\
`re.search(pat, string, re.MULTILINE)` --> 允许 `^` 和 `$` 在不同的行中匹配
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
`from itertools import permutations` --> 所有可能的排列
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
`from itertools import batched` --> 在 Python 3.12+ 中可用，适合将大的 bruteforce 候选列表或 IOC 文件分块处理
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
如果你运行它，你会看到类似下面的内容：
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### 用于 pentesting 的实用标准库 helper

**使用 `pathlib` 进行 filesystem traversal**（`Path.walk()` 在 Python 3.12+ 中可用；在较旧的解释器上使用 `os.walk()`）：
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**安全地 Spawn commands** (`shell=False` 默认通常是你想要的)：
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
如果你**必须**构建一个 shell 命令，请先引用每个由攻击者控制的 token：
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**临时文件 / 目录**（比硬编码 `/tmp/foo` 路径更安全）：
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
对于 HTTP 自动化，请查看[这个关于 Python web requests 的其他页面](web-requests.md)。

### Archive extraction gotchas (important for tooling and file parsers)

从 **Python 3.14** 开始，`tarfile.extract()` / `extractall()` 默认使用更安全的 `data` filter。在较旧的 Python 版本中，处理由攻击者控制的 archives 时，你应该显式设置它。
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
即使使用 `filter="data"`，也要将不受信任的压缩包解压到一个新的临时目录中，并在将文件移动到任何有价值的位置之前，验证已写入的内容。

`zipfile.Path` 不同：它**不会为你清理文件名**，所以在提取攻击者控制的 ZIP 成员之前，先验证路径：
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

- `eval()` / `exec()` **不是** sandbox。
- `ast.literal_eval()` **不会**执行 Python code，但它仍然可能被攻击者控制的输入滥用，造成内存 / CPU denial of service。
- `pickle.loads()` **不安全**；永远不要 unpickle 攻击者控制的 bytes。
- 想了解更深入的 offensive trick，请查看 [Bypass Python sandboxes](bypass-python-sandboxes/README.md)、[Python internal read gadgets](python-internal-read-gadgets.md) 和 [Python deserializations](../../pentesting-web/deserialization/README.md)。

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
