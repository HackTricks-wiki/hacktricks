# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Nützliche Informationen

Alle Beispiele unten gehen von **Python 3** aus, sofern nicht ausdrücklich anders angegeben.\
`range()` gibt in Python 3 ein iterierbares Objekt zurück (ähnlich wie `xrange()` in Python 2).\
Der Unterschied zwischen einem **tuple** und einer **list** ist, dass die **Position** eines Werts in einem tuple ihm normalerweise Bedeutung verleiht, während eine list normalerweise nur eine geordnete Folge von Werten ist.

### Hauptoperationen

Um eine Zahl zu potenzieren, verwendest du: `3**2` (nicht `3^2`)\
`2/3 == 0.666666...` in Python 3, während `2//3 == 0` eine Ganzzahldivision ausführt.\
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
`dir(str)` = listet verfügbare Methoden auf\
`help(str)` = Definition der Klasse `str`\
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
### Bytes, Hex und Encodings

Dies ist sehr häufig in exploit-dev, reversing und CTFs:
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
`d = ()` leeres Tupel\
`d += (4,)` --> in ein Tupel hinzufügen\
`# t1[1] = 'new value'` --> Tupel sind unveränderlich\
`list(t2) == [5, 6]` --> von Tupel zu Liste

### List (array)

`d = []` leer\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> von Liste zu Tupel

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

In Sets gibt es keine Wiederholungen.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> keine Änderung\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> falls vorhanden, entfernen; sonst nichts\
`myset.remove(10)` --> falls nicht vorhanden, Exception wird ausgelöst\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> ein beliebiges Element holen und entfernen\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

Die Methode in `__lt__` wird von `sort()` / `sorted()` verwendet, um Objekte zu vergleichen.
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

In **Python 3** geben `map()` und `filter()` Iteratoren zurück, also konvertiere sie mit `list()`, wenn du alle Werte auf einmal ausgeben willst.

**Map** ist wie `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** stoppt, wenn das kürzere Iterable endet:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** wird verwendet, um eine Funktion zu definieren:\
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

### Ausnahmen
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

Wenn die Bedingung false ist, wird der String ausgegeben.\
Denke daran, dass `assert`-Anweisungen mit `python -O` deaktiviert werden können, also verwende sie nicht für access control oder input validation.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generatoren, yield

Ein Generator gibt nicht alles auf einmal zurück, sondern **yield**-et Werte nacheinander. Das ist sehr nützlich für riesige Wordlists, Bruteforcer oder große Antworten.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Reguläre Ausdrücke
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Spezielle Bedeutungen:**\
`.` --> jedes Zeichen außer Zeilenumbruch\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> Ziffer\
`\s` --> Leerzeichen-Zeichen `[ \n\r\t\f]`\
`\S` --> kein Leerzeichen-Zeichen\
`^` --> beginnt mit\
`$` --> endet mit\
`+` --> eins oder mehr\
`*` --> 0 oder mehr\
`?` --> 0 oder 1 Vorkommen

**Optionen:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> erlaubt, dass `.` auch Zeilenumbruch matcht\
`re.search(pat, string, re.MULTILINE)` --> erlaubt, dass `^` und `$` in verschiedenen Zeilen matchen
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> kartesisches Produkt zwischen 1 oder mehreren Iterables
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> jede mögliche Anordnung
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**Kombinationen**\
`from itertools import combinations` --> alle möglichen Kombinationen ohne Wiederholung
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
`from itertools import batched` --> verfügbar in Python 3.12+, nützlich, um große Bruteforce-Kandidatenlisten oder IOC-Dateien in Chunks aufzuteilen
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Decorator, der die Zeit misst, die eine Funktion zur Ausführung benötigt:
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
Wenn du es ausführst, wirst du etwas wie das Folgende sehen:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Nützliche Standardbibliotheks-Helper für pentesting

**Filesystem-Durchquerung mit `pathlib`** (`Path.walk()` ist in Python 3.12+ verfügbar; verwende `os.walk()` auf älteren Interpretern):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Commands sicher starten** (`shell=False` ist standardmäßig normalerweise das, was du willst):
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
Wenn du **unbedingt** einen Shell-Befehl bauen musst, zitiere zuerst jedes vom Angreifer kontrollierte Token:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Temporäre Dateien / Verzeichnisse** (sicherer als hartkodierte `/tmp/foo`-Pfade):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Für HTTP-Automatisierung siehe [diese andere Seite über Python-Web-Requests](web-requests.md).

### Fallstricke beim Entpacken von Archiven (wichtig für Tooling und Dateiparser)

Ab **Python 3.14** verwenden `tarfile.extract()` / `extractall()` standardmäßig den sichereren `data`-Filter. In älteren Python-Versionen solltest du ihn beim Umgang mit von Angreifern kontrollierten Archiven explizit setzen.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Selbst mit `filter="data"` solltest du untrusted archives in ein frisches temporäres Verzeichnis extrahieren und überprüfen, was geschrieben wurde, bevor du Dateien irgendwohin verschiebst, wo es relevant ist.

`zipfile.Path` ist anders: Es **bereinigt Dateinamen nicht** für dich, also überprüfe Pfade, bevor du attacker-controlled ZIP-Members extrahierst:
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
### Gefährliche Primitive, die man sich merken sollte

- `eval()` / `exec()` sind **keine** Sandboxes.
- `ast.literal_eval()` führt **keinen** Python-Code aus, kann aber mit attacker-controlled input trotzdem für Memory- / CPU-Denial-of-Service missbraucht werden.
- `pickle.loads()` ist **nicht sicher**; niemals attacker-controlled bytes unpicklen.
- Für tiefere offensive Tricks, schau dir [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) und [Python deserializations](../../pentesting-web/deserialization/README.md) an.

## Referenzen

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
