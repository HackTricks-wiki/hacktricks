# Python 기초

{{#include ../../banners/hacktricks-training.md}}

## Python 기본 사항

### 유용한 정보

아래의 모든 예제는 명시적으로 달리 언급되지 않는 한 **Python 3**을 가정합니다.\
Python 3에서 `range()`는 iterable 객체를 반환합니다(Python 2의 `xrange()`와 유사).\
**tuple**과 **list**의 차이점은 tuple에서 값의 **position**이 일반적으로 의미를 나타내는 반면, list는 일반적으로 순서가 있는 값의 시퀀스일 뿐이라는 점입니다.

### 주요 연산

숫자를 거듭제곱하려면 다음을 사용합니다: `3**2` (`3^2`가 아님)\
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
`help(str)` = `str` 클래스의 정의\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**문자 결합**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**list / string의 일부**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**주석**\
`# One line comment`\
`""" Several lines comment """`

**반복문**
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
### Bytes, hex 및 encodings

이는 exploit-dev, reversing 및 CTF에서 매우 흔합니다:
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
`d = ()` 빈 튜플\
`d += (4,)` --> 튜플에 추가\
`# t1[1] = 'new value'` --> 튜플은 immutable\
`list(t2) == [5, 6]` --> 튜플에서 리스트로 변환

### 리스트 (배열)

`d = []` 비어 있음\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> 리스트에서 튜플로 변환

### 딕셔너리
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
### 집합

집합에는 중복이 없습니다.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> 변경 없음\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> 있으면 제거하고, 없으면 아무 작업도 수행하지 않음\
`myset.remove(10)` --> 없으면 예외 발생\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> 임의의 요소를 가져와 제거\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### 클래스

`__lt__`의 method는 `sort()` / `sorted()`가 객체를 비교할 때 사용합니다.
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
### map, zip, filter, lambda, sorted 및 one-liners

**Python 3**에서는 `map()`과 `filter()`가 iterator를 반환하므로 모든 값을 한 번에 출력하려면 `list()`로 변환하세요.

**Map**은 `[f(x) for x in iterable]`과 같습니다:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip**은 더 짧은 iterable이 끝나면 중지됩니다:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda**는 함수를 정의하는 데 사용됩니다:\
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
`assert` 문은 `python -O`로 비활성화할 수 있으므로 access control 또는 input validation에 사용하지 마세요.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

generator는 모든 값을 한 번에 반환하는 대신 값을 하나씩 **yield**합니다. 이는 거대한 wordlist, bruteforcer 또는 대규모 응답에 매우 유용합니다.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### 정규 표현식
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**특수 의미:**\
`.` --> 줄바꿈을 제외한 모든 문자\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> 숫자\
`\s` --> 공백 문자 `[ \n\r\t\f]`\
`\S` --> 공백이 아닌 문자\
`^` --> ~로 시작\
`$` --> ~로 끝남\
`+` --> 하나 이상\
`*` --> 0개 이상\
`?` --> 0개 또는 1개의 발생

**옵션:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> 점이 줄바꿈과 일치하도록 허용\
`re.search(pat, string, re.MULTILINE)` --> `^`와 `$`가 서로 다른 줄에서 일치하도록 허용
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> 1개 이상의 iterable 간 카테시안 곱
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
**combinations**\
`from itertools import combinations` --> 반복 없이 가능한 모든 조합
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
`from itertools import batched` --> Python 3.12+에서 사용 가능하며, 대규모 bruteforce 후보 목록이나 IOC 파일을 청크로 나누는 데 유용합니다.
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

함수 실행에 필요한 시간을 측정하는 Decorator:
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
실행하면 다음과 같은 결과를 볼 수 있습니다:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### pentesting에 유용한 표준 library helper

**`pathlib`을 사용한 filesystem 순회** (`Path.walk()`는 Python 3.12+에서 사용할 수 있으며, 이전 interpreter에서는 `os.walk()`를 사용하세요):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**명령을 안전하게 실행하기** (`shell=False`가 기본값이며 일반적으로 원하는 설정입니다):
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
셸 명령을 **반드시** 구성해야 한다면, 공격자가 제어하는 각 토큰을 먼저 인용하세요:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**임시 파일 / 디렉터리** (`/tmp/foo`` 하드코딩된 경로보다 안전함):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
HTTP 자동화를 위해서는 [Python 웹 요청에 관한 다른 페이지](web-requests.md)를 확인하세요.

### Archive 추출 시 주의 사항 (tooling 및 file parser에 중요)

**Python 3.14**부터 `tarfile.extract()` / `extractall()`은 기본적으로 더 안전한 `data` filter를 사용합니다. 이전 Python 버전에서는 공격자가 제어하는 archive를 처리할 때 이를 명시적으로 설정해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
`filter="data"`를 사용하더라도 신뢰할 수 없는 archive는 새 임시 디렉터리에 extract하고, 파일을 다른 중요한 위치로 이동하기 전에 실제로 기록된 내용을 검증하세요.

`zipfile.Path`는 다릅니다. **filename을 자동으로 sanitize하지 않으므로**, 공격자가 제어하는 ZIP member를 extract하기 전에 path를 검증하세요:
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
### 기억해야 할 위험한 primitive

- `eval()` / `exec()`은 **sandbox가 아닙니다**.
- `ast.literal_eval()`은 Python 코드를 실행하지 않지만, attacker-controlled input을 사용하면 memory / CPU denial of service에 악용될 수 있습니다.
- `pickle.loads()`는 **secure하지 않습니다**. attacker-controlled bytes를 절대 unpickle하지 마세요.
- 더 깊은 offensive trick은 [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) 및 [Python deserializations](../../pentesting-web/deserialization/README.md)를 확인하세요.

## References

- [1] [Python tarfile 문서](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – tarfile.extractall()용 필터](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
