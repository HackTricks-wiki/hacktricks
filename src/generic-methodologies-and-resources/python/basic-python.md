# Basiese Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basisse

### Nuttige inligting

Al die voorbeelde hieronder neem aan **Python 3** tensy uitdruklik genoem.\
`range()` gee 'n iterable object in Python 3 terug (soortgelyk aan `xrange()` in Python 2).\
Die verskil tussen 'n **tuple** en 'n **list** is dat die **posisie** van 'n waarde in 'n tuple gewoonlik betekenis daaraan gee, terwyl 'n list gewoonlik net 'n geordende volgorde van values is.

### Hoofoperasies

Om 'n getal tot 'n mag te verhef gebruik jy: `3**2` (nie `3^2` nie)\
`2/3 == 0.666666...` in Python 3, terwyl `2//3 == 0` integer division uitvoer.\
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
`dir(str)` = lys beskikbare methods\
`help(str)` = definisie van die class `str`\
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
### Bytes, hex en enkodering

Dit is baie algemeen in exploit-dev, reversing en CTFs:
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
`d = ()` leë tuple\
`d += (4,)` --> voeg by in ’n tuple\
`# t1[1] = 'new value'` --> tuples is immutable\
`list(t2) == [5, 6]` --> van tuple na list

### List (array)

`d = []` leë\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> van list na tuple

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

In sets is daar geen herhalings nie.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> geen verandering\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> as dit teenwoordig is, verwyder dit; as nie, niks\
`myset.remove(10)` --> as dit nie teenwoordig is nie, gooi uitsondering\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> kry 'n arbitrêre element en verwyder dit\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

Die metode in `__lt__` sal die een wees wat deur `sort()` / `sorted()` gebruik word om objekte te vergelyk.
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

In **Python 3**, `map()` and `filter()` return iterators, so convert them with `list()` if you want to print all values at once.

**Map** is like `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** stop wanneer die korter iterable stop:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** word gebruik om ’n funksie te definieer:\
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

### Uitsonderings
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

As die voorwaarde vals is, sal die string gedruk word.\
Onthou dat `assert`-stellings gedeaktiveer kan word met `python -O`, so moenie hulle gebruik vir toegangsbeheer of invoervalidatie nie.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

’n Generator, in plaas daarvan om alles op een slag terug te gee, **yield** waardes een vir een. Dit is baie nuttig vir enorme woordlyste, bruteforcers of groot antwoorde.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Gereelde Uitdrukkings
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Spesiale betekenisse:**\
`.` --> enige karakter behalwe nuwe reël\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> syfer\
`\s` --> witspasie-karakter `[ \n\r\t\f]`\
`\S` --> nie-witspasie-karakter\
`^` --> begin met\
`$` --> eindig met\
`+` --> een of meer\
`*` --> 0 of meer\
`?` --> 0 of 1 voorkomste

**Opsies:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> laat punt toe om nuwe reël te pas\
`re.search(pat, string, re.MULTILINE)` --> laat `^` en `$` toe om in verskillende lyne te pas
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> cartesiese produk tussen 1 of meer iterables
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutasies**\
`from itertools import permutations` --> elke moontlike rangskikking
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**kombinasies**\
`from itertools import combinations` --> alle moontlike kombinasies sonder herhaling
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
`from itertools import batched` --> beskikbaar in Python 3.12+, nuttig om groot bruteforce kandidaatlyste of IOC-lêers in stukke te verdeel
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Dekorateur wat die tyd meet wat `n funksie nodig het om uitgevoer te word:
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
As jy dit uitvoer, sal jy iets soos die volgende sien:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Nuttige standaardbiblioteek-hulpmiddels vir pentesting

**Lêerstelsel-navigasie met `pathlib`** (`Path.walk()` is beskikbaar in Python 3.12+; gebruik `os.walk()` op ouer interpreters):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Spawn commands veilig** (`shell=False` by default is usually what you want):
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
As jy **moet** ’n shell-opdrag bou, quote elke aanvaller-beheerde token eers:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Tydelike lêers / gidse** (veiliger as hardcoded `/tmp/foo` paths):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Vir HTTP-outomatisering, kyk [hierdie ander bladsy oor Python web requests](web-requests.md).

### Argief-uitpak-valstrikke (belangrik vir tooling en lêerparsers)

Begin in **Python 3.14**, gebruik `tarfile.extract()` / `extractall()` die veiliger `data` filter by verstek. In ouer Python-weergawes moet jy dit eksplisiet stel wanneer jy argiewe hanteer wat deur ’n aanvaller beheer word.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Selfs met `filter="data"`, onttrek onbetroubare argiewe in `n vars tydelike gids en valideer wat geskryf is voordat jy lêers na enige interessante plek skuif.

`zipfile.Path` is anders: dit **sanitiseer nie lêernaam vir jou nie**, so valideer paths voordat jy aanvaller-beheerde ZIP-lede onttrek:
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
### Gevaarlike primitives om te onthou

- `eval()` / `exec()` is **nie** sandkastele nie.
- `ast.literal_eval()` voer **nie** Python-kode uit nie, maar dit kan steeds misbruik word vir geheue- / CPU-ontkenning van diens met aanvaller-beheerde invoer.
- `pickle.loads()` is **nie veilig** nie; moenie ooit aanvaller-beheerde bytes unpickle nie.
- Vir dieper offensiewe truuks, kyk [Bypass Python sandkastele](bypass-python-sandboxes/README.md), [Python interne lees gadgets](python-internal-read-gadgets.md) en [Python deserializations](../../pentesting-web/deserialization/README.md).

## Verwysings

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
