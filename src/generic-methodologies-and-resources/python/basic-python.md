# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

Wszystkie poniższe przykłady zakładają **Python 3**, chyba że wyraźnie zaznaczono inaczej.\
`range()` zwraca obiekt iterowalny w Python 3 (podobny do `xrange()` w Python 2).\
Różnica między **tuple** a **list** polega na tym, że **pozycja** wartości w tuple zwykle nadaje jej znaczenie, podczas gdy lista jest zwykle po prostu uporządkowaną sekwencją wartości.

### Main operations

Aby podnieść liczbę do potęgi, używa się: `3**2` (nie `3^2`)\
`2/3 == 0.666666...` w Python 3, podczas gdy `2//3 == 0` wykonuje dzielenie całkowite.\
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
`dir(str)` = lista dostępnych metod\
`help(str)` = definicja klasy `str`\
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
### Bajty, hex i kodowania

To jest bardzo częste w exploit-dev, reversing i CTFs:
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
`d = ()` pusty tuple\
`d += (4,)` --> dodaj do tuple\
`# t1[1] = 'new value'` --> tuples są niemutowalne\
`list(t2) == [5, 6]` --> z tuple do list

### List (array)

`d = []` pusty\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> z list do tuple

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

W setach nie ma powtórzeń.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> brak zmian\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> jeśli obecny, usuwa go; jeśli nie, nic\
`myset.remove(10)` --> jeśli nie jest obecny, zgłasza wyjątek\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> pobiera dowolny element i usuwa go\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

Metoda w `__lt__` będzie używana przez `sort()` / `sorted()` do porównywania obiektów.
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

W **Python 3**, `map()` i `filter()` zwracają iteratory, więc przekonwertuj je za pomocą `list()`, jeśli chcesz wypisać wszystkie wartości naraz.

**Map** jest jak `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** zatrzymuje się, gdy kończy się krótsza iterowalna:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** jest używane do definiowania funkcji:\
`(lambda x, y: x + y)(5, 3) == 8` --> użyj lambda jako prostej funkcji\
`sorted(range(-5, 6), key=lambda x: x**2)` --> użyj lambda do sortowania\
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

### Wyjątki
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

Jeśli warunek jest fałszywy, zostanie wypisany ciąg.\
Pamiętaj, że instrukcje `assert` mogą zostać wyłączone za pomocą `python -O`, więc nie używaj ich do kontroli dostępu ani walidacji danych wejściowych.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

Generator, zamiast zwracać wszystko naraz, **yielduje** wartości jedna po drugiej. Jest to bardzo przydatne dla ogromnych wordlist, bruteforcerów lub dużych odpowiedzi.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Wyrażenia regularne
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Specjalne znaczenia:**\
`.` --> dowolny znak z wyjątkiem nowej linii\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> cyfra\
`\s` --> znak białego odstępu `[ \n\r\t\f]`\
`\S` --> znak niebędący białym odstępem\
`^` --> zaczyna się od\
`$` --> kończy się na\
`+` --> jeden lub więcej\
`*` --> 0 lub więcej\
`?` --> 0 lub 1 wystąpienie

**Opcje:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> pozwala, by kropka dopasowywała nową linię\
`re.search(pat, string, re.MULTILINE)` --> pozwala `^` i `$` dopasowywać się w różnych liniach
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> iloczyn kartezjański między 1 lub więcej iterowalnymi
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutacje**\
`from itertools import permutations` --> każda możliwa kombinacja układu
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**kombinacje**\
`from itertools import combinations` --> wszystkie możliwe kombinacje bez powtórzeń
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
`from itertools import batched` --> dostępne w Python 3.12+, przydatne do dzielenia dużych list kandydatów do bruteforce lub plików IOC na mniejsze części
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Dekoratory

Dekorator, który mierzy czas potrzebny na wykonanie funkcji:
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
Jeśli uruchomisz to, zobaczysz coś podobnego do poniższego:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Przydatne standardowe helpery biblioteki do pentesting

**Przechodzenie po systemie plików z `pathlib`** (`Path.walk()` jest dostępne w Python 3.12+; użyj `os.walk()` na starszych interpreterach):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Uruchamiaj polecenia bezpiecznie** (`shell=False` domyślnie jest zwykle tym, czego chcesz):
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
Jeśli **musisz** zbudować polecenie shell, najpierw cytuj każdy token kontrolowany przez atakującego:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Pliki / katalogi tymczasowe** (bezpieczniejsze niż hardkodowane ścieżki `/tmp/foo`):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Do automatyzacji HTTP sprawdź [tę inną stronę o Python web requests](web-requests.md).

### Pułapki ekstrakcji archiwów (ważne dla tooling i parserów plików)

Począwszy od **Python 3.14**, `tarfile.extract()` / `extractall()` domyślnie używają bezpieczniejszego filtra `data`. W starszych wersjach Pythona powinieneś ustawić go jawnie podczas obsługi archiwów kontrolowanych przez atakującego.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Nawet przy `filter="data"` rozpakowuj niezaufane archiwa do świeżego katalogu tymczasowego i sprawdzaj, co zostało zapisane, zanim przeniesiesz pliki gdziekolwiek istotnego.

`zipfile.Path` jest inne: ono **nie sanitizuje nazw plików** za Ciebie, więc sprawdzaj ścieżki przed rozpakowaniem elementów ZIP kontrolowanych przez atakującego:
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
### Niebezpieczne prymitywy, o których warto pamiętać

- `eval()` / `exec()` **nie są** sandboxami.
- `ast.literal_eval()` **nie wykonuje** kodu Python, ale nadal może być nadużyte do ataku typu memory / CPU denial of service przy wejściu kontrolowanym przez atakującego.
- `pickle.loads()` **nie jest bezpieczne**; nigdy nie odpakowuj bytes kontrolowanych przez atakującego.
- Aby poznać głębsze ofensywne triki, sprawdź [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) i [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
