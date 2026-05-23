# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Корисна інформація

Усі приклади нижче припускають **Python 3**, якщо явно не зазначено інше.\
`range()` повертає iterable-об’єкт у Python 3 (подібно до `xrange()` у Python 2).\
Різниця між **tuple** і **list** полягає в тому, що **position** значення в tuple зазвичай надає йому значення, тоді як list зазвичай є просто впорядкованою послідовністю значень.

### Основні операції

Щоб піднести число до степеня, використовуйте: `3**2` (не `3^2`)\
`2/3 == 0.666666...` у Python 3, тоді як `2//3 == 0` виконує цілочисельне ділення.\
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
`dir(str)` = список доступних методів\
`help(str)` = визначення класу `str`\
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

Це дуже поширено в exploit-dev, reversing і CTFs:
```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```
### Tuples

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = singleton\
`d = ()` порожній tuple\
`d += (4,)` --> add into a tuple\
`# t1[1] = 'new value'` --> tuples are immutable\
`list(t2) == [5, 6]` --> from tuple to list

### List (array)

`d = []` порожній\
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

У sets немає повторів.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> без змін\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> якщо є, видаляє; якщо ні, нічого\
`myset.remove(10)` --> якщо немає, викликає exception\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> бере довільний елемент і видаляє його\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

Метод у `__lt__` буде тим, який `sort()` / `sorted()` використовуватимуть для порівняння об'єктів.
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

У **Python 3**, `map()` і `filter()` повертають ітератори, тож перетворюйте їх за допомогою `list()`, якщо хочете вивести всі значення одразу.

**Map** це як `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** зупиняється, коли зупиняється коротший iterable:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** використовується для визначення функції:\
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

### Винятки
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

Якщо умова false, рядок буде виведено.\
Пам’ятайте, що `assert` statements можна вимкнути за допомогою `python -O`, тож не використовуйте їх для access control або input validation.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Генератори, yield

Генератор, замість того щоб повертати все одразу, **yield**-ить значення по одному. Це дуже корисно для великих wordlists, bruteforcers або великих відповідей.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Regular Expressions
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Спеціальні значення:**\
`.` --> будь-який символ, окрім нового рядка\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> цифра\
`\s` --> пробільний символ `[ \n\r\t\f]`\
`\S` --> непробільний символ\
`^` --> починається з\
`$` --> закінчується на\
`+` --> один або більше\
`*` --> 0 або більше\
`?` --> 0 або 1 входження

**Опції:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> дозволити `.` збігатися з новим рядком\
`re.search(pat, string, re.MULTILINE)` --> дозволити `^` і `$` збігатися в різних рядках
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> декартовий добуток між 1 або більше ітерованими об’єктами
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**перестановки**\
`from itertools import permutations` --> кожне можливе розташування
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**комбінації**\
`from itertools import combinations` --> усі можливі комбінації без повторень
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
`from itertools import batched` --> доступно в Python 3.12+, корисно для розбиття великих списків кандидатів для bruteforce або IOC-файлів на частини
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Декоратор, який вимірює час, потрібний для виконання функції:
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
Якщо ви його запустите, ви побачите щось на кшталт такого:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Корисні стандартні допоміжні засоби бібліотеки для pentesting

**Обхід файлової системи з `pathlib`** (`Path.walk()` доступний у Python 3.12+; використовуйте `os.walk()` на старіших інтерпретаторах):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Безпечно запускати команди** (`shell=False` за замовчуванням — зазвичай саме те, що вам потрібно`):
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
Якщо вам **потрібно** побудувати shell-команду, спочатку обгорніть у лапки кожен керований атакувальником токен:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Тимчасові files / dirs** (безпечніше, ніж жорстко задані шляхи `/tmp/foo`):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Для HTTP автоматизації перевірте [this other page about Python web requests](web-requests.md).

### Підводні камені під час розпакування архівів (важливо для tooling і file parsers)

Починаючи з **Python 3.14**, `tarfile.extract()` / `extractall()` за замовчуванням використовують безпечніший фільтр `data`. У старіших версіях Python його слід вказувати явно, коли ви працюєте з архівами під контролем attacker.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Навіть із `filter="data"` розпаковуйте ненадійні архіви у новий тимчасовий каталог і перевіряйте, що було записано, перш ніж переміщувати файли кудись важливе.

`zipfile.Path` — це інше: він **не sanitizує імена файлів** за вас, тож перевіряйте шляхи перед витягуванням керованих атакувальником ZIP-елементів:
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
### Небезпечні primitives, які варто пам’ятати

- `eval()` / `exec()` — **не** sandbox.
- `ast.literal_eval()` **не** виконує Python code, але його все одно можна зловживати для memory / CPU denial of service через attacker-controlled input.
- `pickle.loads()` — **небезпечно**; ніколи не unpickle attacker-controlled bytes.
- Для глибших offensive tricks дивіться [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) і [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
