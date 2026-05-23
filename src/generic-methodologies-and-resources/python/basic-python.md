# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

아래의 모든 예시는 명시적으로 언급되지 않는 한 **Python 3**를 가정합니다.\
`range()`는 Python 3에서 iterable 객체를 반환합니다(Python 2의 `xrange()`와 유사함).\
**tuple**과 **list**의 차이는 **tuple**에서는 값의 **위치**가 보통 그 값에 의미를 부여하는 반면, **list**는 보통 값들의 순서 있는 시퀀스일 뿐이라는 점입니다.

### Main operations

숫자를 거듭제곱하려면: `3**2`를 사용합니다 (`3^2`가 아님)\
Python 3에서 `2/3 == 0.666666...`이며, `2//3 == 0`은 정수 나눗셈을 수행합니다.\
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
`dir(str)` = 사용 가능한 메서드 목록\
`help(str)` = 클래스 `str`의 정의\
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
### Bytes, hex and encodings

익스플로잇 개발, 리버싱, CTF에서 이것은 매우 흔합니다:
```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```
### 튜플

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = singleton\
`d = ()` empty tuple\
`d += (4,)` --> tuple에 추가\
`# t1[1] = 'new value'` --> tuples are immutable\
`list(t2) == [5, 6]` --> tuple에서 list로

### List (array)

`d = []` empty\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> list에서 tuple로

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

set에는 반복이 없습니다.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> 변경 없음\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> 있으면 제거; 없으면 아무것도 하지 않음\
`myset.remove(10)` --> 없으면 예외 발생\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> 임의의 요소를 가져와 제거함\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

`__lt__`의 메서드가 `sort()` / `sorted()`가 객체를 비교할 때 사용되는 메서드입니다.
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

**Python 3**에서는 `map()`과 `filter()`가 iterator를 반환하므로, 모든 값을 한 번에 출력하려면 `list()`로 변환하세요.

**Map**은 `[f(x) for x in iterable]`와 같습니다:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip**은 더 짧은 iterable이 끝나면 멈춘다:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda**는 함수를 정의하는 데 사용된다:\
`(lambda x, y: x + y)(5, 3) == 8` --> 간단한 함수로 lambda 사용\
`sorted(range(-5, 6), key=lambda x: x**2)` --> 정렬에 lambda 사용\
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

### 예외
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

조건이 false이면 문자열이 출력됩니다.\
`assert` 문은 `python -O`로 비활성화할 수 있으므로, 접근 제어나 입력 검증에 사용하지 마세요.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

generator는 모든 것을 한 번에 반환하는 대신, 값을 하나씩 **yield** 합니다. 이는 거대한 wordlists, bruteforcers 또는 큰 응답에 매우 유용합니다.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### 정규표현식
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**특수 의미:**\
`.` --> newline을 제외한 모든 문자\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> 숫자\
`\s` --> whitespace 문자 `[ \n\r\t\f]`\
`\S` --> whitespace가 아닌 문자\
`^` --> 로 시작\
`$` --> 로 끝남\
`+` --> 하나 이상\
`*` --> 0개 이상\
`?` --> 0개 또는 1개 발생

**옵션:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> dot이 newline과도 매치되도록 허용\
`re.search(pat, string, re.MULTILINE)` --> `^`와 `$`가 다른 줄에서도 매치되도록 허용
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> 1개 이상의 iterable 사이의 cartesian product
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> 가능한 모든 배열
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**조합**\
`from itertools import combinations` --> 중복 없이 가능한 모든 조합
```python
list(combinations('123', 2))
# [('1', '2'), ('1', '3'), ('2', '3')]
```
**중복 조합**\
`from itertools import combinations_with_replacement`
```python
list(combinations_with_replacement('123', 2))
# [('1', '1'), ('1', '2'), ('1', '3'), ('2', '2'), ('2', '3'), ('3', '3')]
```
**batched**\
`from itertools import batched` --> Python 3.12+에서 사용 가능하며, 큰 bruteforce 후보 리스트나 IOC 파일을 청크로 나누는 데 유용함
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

함수가 실행되는 데 걸리는 시간을 측정하는 Decorator:
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
실행하면 다음과 같은 내용을 볼 수 있습니다:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### pentesting에 유용한 standard library helper

**`pathlib`를 사용한 Filesystem traversal** (`Path.walk()`는 Python 3.12+에서 사용 가능; 더 पुराने 인터프리터에서는 `os.walk()` 사용):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**안전하게 명령 실행하기** (`shell=False`가 기본값이며, 보통 원하는 설정입니다):
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
If you **반드시** shell command를 구성해야 한다면, 먼저 각 attacker-controlled token을 quote하세요:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**임시 파일 / 디렉터리** (하드코딩된 `/tmp/foo` 경로보다 안전함):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
HTTP 자동화는 [Python web requests에 관한 이 다른 페이지](web-requests.md)를 확인하세요.

### Archive extraction gotchas (important for tooling and file parsers)

**Python 3.14**부터 `tarfile.extract()` / `extractall()`는 기본적으로 더 안전한 `data` filter를 사용합니다. 오래된 Python 버전에서는 공격자가 제어한 archive를 처리할 때 이를 명시적으로 설정해야 합니다.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
`filter="data"`를 사용하더라도, 신뢰할 수 없는 아카이브는 새 임시 디렉터리에 추출하고, 파일을 중요한 위치로 옮기기 전에 무엇이 기록되었는지 검증하세요.

`zipfile.Path`는 다릅니다: 이것은 **파일명을 자동으로 정화하지 않으므로**, 공격자가 제어한 ZIP 멤버를 추출하기 전에 경로를 검증하세요:
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
### 기억해둘 위험한 primitives

- `eval()` / `exec()`는 **sandbox**가 아니다.
- `ast.literal_eval()`은 Python code를 실행하지 않지만, attacker-controlled input으로 여전히 memory / CPU denial of service에 악용될 수 있다.
- `pickle.loads()`는 **secure**하지 않다; attacker-controlled bytes를 절대 unpickle하지 마라.
- 더 깊은 offensive tricks는 [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) 및 [Python deserializations](../../pentesting-web/deserialization/README.md)를 확인하라.

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
