# Podstawy Pythona

{{#include ../../banners/hacktricks-training.md}}

## Podstawy Python

### Przydatne informacje

Wszystkie poniższe przykłady zakładają użycie **Python 3**, chyba że zaznaczono inaczej.\
`range()` zwraca obiekt iterowalny w Python 3 (podobnie jak `xrange()` w Python 2).\
Różnica między **tuple** a **list** polega na tym, że **pozycja** wartości w tuple zwykle nadaje jej znaczenie, podczas gdy list jest zazwyczaj po prostu uporządkowaną sekwencją wartości.

### Główne operacje

Aby podnieść liczbę do potęgi, użyj: `3**2` (nie `3^2`)\
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

**Łączenie znaków**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**Fragmenty listy / stringa**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Komentarze**\
`# One line comment`\
`""" Several lines comment """`

**Pętle**
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

To bardzo częste w exploit-dev, reversing i CTF-ach:
```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```
### Krotki

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = singleton\
`d = ()` pusty krotek\
`d += (4,)` --> dodaj do krotki\
`# t1[1] = 'new value'` --> krotki są niemutowalne\
`list(t2) == [5, 6]` --> konwersja krotki na listę

### Lista (tablica)

`d = []` pusta\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> konwersja listy na krotkę

### Słownik
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
### Zbiory

W zbiorach nie ma powtórzeń.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> no change\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> if present, remove it; if not, nothing\
`myset.remove(10)` --> if not present, raises exception\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> get an arbitrary element and remove it\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Klasy

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
### map, zip, filter, lambda, sorted i one-linery

W **Python 3** funkcje `map()` i `filter()` zwracają iteratory, więc użyj `list()`, jeśli chcesz wyświetlić wszystkie wartości jednocześnie.

**Map** działa podobnie jak `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** zatrzymuje się, gdy kończy się krótszy obiekt iterowalny:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** służy do definiowania funkcji:\
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

Jeśli warunek jest fałszywy, zostanie wyświetlony ciąg znaków.\
Pamiętaj, że instrukcje `assert` można wyłączyć za pomocą `python -O`, dlatego nie używaj ich do kontroli dostępu ani walidacji danych wejściowych.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

Generator zamiast zwracać wszystko naraz, **yield**-uje wartości pojedynczo. Jest to bardzo przydatne w przypadku ogromnych wordlist, bruteforcerów lub dużych odpowiedzi.
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
**Znaczenia specjalne:**\
`.` --> dowolny znak z wyjątkiem znaku nowej linii\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> cyfra\
`\s` --> znak białych znaków `[ \n\r\t\f]`\
`\S` --> znak niebędący białym znakiem\
`^` --> zaczyna się od\
`$` --> kończy się na\
`+` --> jeden lub więcej\
`*` --> 0 lub więcej\
`?` --> 0 lub 1 wystąpień

**Opcje:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> umożliwia dopasowanie kropki do znaku nowej linii\
`re.search(pat, string, re.MULTILINE)` --> umożliwia dopasowanie `^` i `$` w różnych wierszach
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> iloczyn kartezjański między jednym lub większą liczbą obiektów iterowalnych
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutacje**\
`from itertools import permutations` --> każde możliwe ułożenie
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**combinations**\
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
`from itertools import batched` --> dostępne w Python 3.12+, przydatne do dzielenia dużych list kandydatów do bruteforce lub plików IOC na fragmenty
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Dekoratory

Dekorator mierzący czas potrzebny do wykonania funkcji:
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
Jeśli go uruchomisz, zobaczysz coś takiego:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Przydatne funkcje pomocnicze standardowej biblioteki do pentestingu

**Przemieszczanie się po systemie plików za pomocą `pathlib`** (`Path.walk()` jest dostępne w Pythonie 3.12+; w starszych interpreterach użyj `os.walk()`):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Bezpieczne uruchamianie poleceń** (`shell=False` jest domyślnie zazwyczaj tym, czego potrzebujesz):
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
Jeśli **musisz** zbudować polecenie powłoki, najpierw ujmij każdy token kontrolowany przez atakującego w cudzysłowy:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Pliki / katalogi tymczasowe** (bezpieczniejsze niż zapisane na stałe ścieżki `/tmp/foo`):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
W przypadku automatyzacji HTTP sprawdź [tę inną stronę dotyczącą żądań sieciowych w Pythonie](web-requests.md).

### Pułapki związane z wypakowywaniem archiwów (ważne w przypadku narzędzi i parserów plików)

Począwszy od **Python 3.14**, `tarfile.extract()` / `extractall()` domyślnie używają bezpieczniejszego filtra `data`. W starszych wersjach Python należy ustawić go jawnie podczas obsługi archiwów kontrolowanych przez atakującego.<sup>[[1]](#references)[[2]](#references)</sup>
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Nawet przy użyciu `filter="data"` rozpakowuj niezaufane archiwa do nowego katalogu tymczasowego i sprawdź zapisane dane przed przeniesieniem plików w jakiekolwiek istotne miejsce.

`zipfile.Path` działa inaczej: **nie oczyszcza nazw plików** za Ciebie, dlatego przed rozpakowaniem kontrolowanych przez atakującego elementów ZIP sprawdź ścieżki:
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
### Niebezpieczne prymitywy, o których należy pamiętać

- `eval()` / `exec()` **nie są** sandboxami.
- `ast.literal_eval()` **nie wykonuje** kodu Python, ale nadal może zostać wykorzystane do wywołania odmowy usługi przez zużycie pamięci / CPU przy użyciu danych kontrolowanych przez atakującego.
- `pickle.loads()` **nie jest bezpieczne**; nigdy nie wykonuj unpickle bajtów kontrolowanych przez atakującego.
- Aby poznać bardziej zaawansowane offensive tricks, sprawdź [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) oraz [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [1] [Dokumentacja Python tarfile](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – Filtr dla tarfile.extractall()](https://peps.python.org/pep-0706/)
{{#include ../../banners/hacktricks-training.md}}
