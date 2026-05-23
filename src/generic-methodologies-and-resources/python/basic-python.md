# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

Svi primeri ispod pretpostavljaju **Python 3** osim ako nije izričito navedeno.\
`range()` vraća iterable objekat u Python 3 (slično kao `xrange()` u Python 2).\
Razlika između **tuple** i **list** je u tome što **pozicija** vrednosti u tuple obično daje značenje, dok je list obično samo uređena sekvenca vrednosti.

### Main operations

Za potenciranje broja koristi se: `3**2` (ne `3^2`)\
`2/3 == 0.666666...` u Python 3, dok `2//3 == 0` izvršava celobrojno deljenje.\
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
`dir(str)` = lista dostupnih metoda\
`help(str)` = definicija klase `str`\
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
### Bajtovi, heks i enkodiranja

Ovo je veoma često u exploit-dev, reversing i CTFs:
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
`d = ()` prazna tuple\
`d += (4,)` --> dodaj u tuple\
`# t1[1] = 'new value'` --> tuples are immutable\
`list(t2) == [5, 6]` --> iz tuple u listu

### List (array)

`d = []` prazno\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> iz liste u tuple

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

U setovima nema ponavljanja.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> no change\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> ako postoji, ukloni ga; ako ne postoji, ništa\
`myset.remove(10)` --> ako ne postoji, baca exception\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> uzmi proizvoljan element i ukloni ga\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

Metod u `__lt__` će biti onaj koji `sort()` / `sorted()` koristi za poređenje objekata.
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

U **Python 3**, `map()` i `filter()` vraćaju iteratore, pa ih konvertujte pomoću `list()` ako želite da ispišete sve vrednosti odjednom.

**Map** je kao `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** staje kada se kraći iterable završi:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** se koristi za definisanje funkcije:\
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

### Izuzeci
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

Ako je uslov false, string će biti ispisan.\
Zapamti da se `assert` naredbe mogu onemogućiti pomoću `python -O`, zato ih nemoj koristiti za kontrolu pristupa ili validaciju ulaza.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generatori, yield

Generator, umesto da vraća sve odjednom, **izbacuje** vrednosti jednu po jednu. Ovo je veoma korisno za ogromne wordlists, bruteforcers ili velike odgovore.
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
**Specijalna značenja:**\
`.` --> bilo koji znak osim novog reda\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> cifra\
`\s` --> whitespace znak `[ \n\r\t\f]`\
`\S` --> znak koji nije whitespace\
`^` --> počinje sa\
`$` --> završava se sa\
`+` --> jedan ili više\
`*` --> 0 ili više\
`?` --> 0 ili 1 pojavljivanje

**Opcije:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> dozvoli da `.` match-uje novi red\
`re.search(pat, string, re.MULTILINE)` --> dozvoli da `^` i `$` match-uju u različitim linijama
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> kartezijanski proizvod između 1 ili više iterable objekata
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> svaka moguća raspodela
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**kombinacije**\
`from itertools import combinations` --> sve moguće kombinacije bez ponavljanja
```python
list(combinations('123', 2))
# [('1', '2'), ('1', '3'), ('2', '3')]
```
**kombinacije_sa_ponavljanjem**\
`from itertools import combinations_with_replacement`
```python
list(combinations_with_replacement('123', 2))
# [('1', '1'), ('1', '2'), ('1', '3'), ('2', '2'), ('2', '3'), ('3', '3')]
```
**batched**\
`from itertools import batched` --> dostupan u Python 3.12+, koristan za deljenje velikih bruteforce lista kandidata ili IOC fajlova u manje delove
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Decorator koji meri vreme potrebno da se funkcija izvrši:
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
Ako ga pokreneš, videćeš nešto poput sledećeg:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Korisni helperi standardne biblioteke za pentesting

**Traversiranje filesystem-a sa `pathlib`** (`Path.walk()` je dostupan u Python 3.12+; koristite `os.walk()` na starijim interpreterima):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Bezbedno pokretanje komandi** (`shell=False` je podrazumevano i to je obično ono što želite):
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
Ako **morate** da napravite shell komandu, prvo stavite pod navodnike svaki token kojim upravlja napadač:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Privremeni fajlovi / direktorijumi** (bezbednije od hardcodovanih `/tmp/foo` putanja):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Za HTTP automatizaciju, pogledajte [ovu drugu stranicu o Python web requests](web-requests.md).

### Zamke pri ekstrakciji arhiva (važno za tooling i parsere fajlova)

Počevši od **Python 3.14**, `tarfile.extract()` / `extractall()` koriste sigurniji `data` filter podrazumevano. U starijim Python verzijama trebalo bi da ga postavite eksplicitno kada rukujete arhivama pod kontrolom napadača.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Čak i sa `filter="data"`, izdvajaj nepouzdane arhive u novi privremeni direktorijum i proveri šta je upisano pre nego što premestiš fajlove bilo gde značajno.

`zipfile.Path` je drugačiji: on **ne sanitizuje imena fajlova** umesto tebe, zato validiraj putanje pre nego što izdvojiš ZIP članove pod napadčevom kontrolom:
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
### Opasne primitive koje treba zapamtiti

- `eval()` / `exec()` **nisu** sandboxes.
- `ast.literal_eval()` **ne** izvršava Python kod, ali se i dalje može zloupotrebiti za denial of service nad memorijom / CPU-om uz input pod kontrolom napadača.
- `pickle.loads()` **nije bezbedan**; nikada nemojte unpickle-ovati bytes pod kontrolom napadača.
- Za dublje offensive trikove, proverite [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) i [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
