# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

Tutti gli esempi qui sotto assumono **Python 3** a meno che non sia specificato esplicitamente.\
`range()` restituisce un oggetto iterabile in Python 3 (simile a `xrange()` in Python 2).\
La differenza tra una **tuple** e una **list** è che la **posizione** di un valore in una tuple di solito gli dà significato, mentre una list è di solito solo una sequenza ordinata di valori.

### Main operations

Per elevare un numero si usa: `3**2` (non `3^2`)\
`2/3 == 0.666666...` in Python 3, mentre `2//3 == 0` esegue la divisione intera.\
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
`dir(str)` = elenco dei metodi disponibili\
`help(str)` = definizione della classe `str`\
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
### Byte, hex e encodings

Questo è molto comune in exploit-dev, reversing e CTF:
```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```
### Tuple

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = singleton\
`d = ()` tupla vuota\
`d += (4,)` --> aggiungi a una tuple\
`# t1[1] = 'new value'` --> le tuple sono immutabili\
`list(t2) == [5, 6]` --> da tuple a list

### List (array)

`d = []` vuota\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> da list a tuple

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

Negli set non ci sono ripetizioni.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> nessun cambiamento\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> se presente, lo rimuove; se no, niente\
`myset.remove(10)` --> se non presente, solleva un'eccezione\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> ottiene un elemento arbitrario e lo rimuove\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

Il metodo in `__lt__` sarà quello usato da `sort()` / `sorted()` per confrontare gli oggetti.
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

In **Python 3**, `map()` and `filter()` restituiscono iteratori, quindi convertili con `list()` se vuoi stampare tutti i valori in una volta.

**Map** è come `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** si interrompe quando si interrompe l'iterabile più corto:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** è usato per definire una funzione:\
`(lambda x, y: x + y)(5, 3) == 8` --> usa lambda come semplice funzione\
`sorted(range(-5, 6), key=lambda x: x**2)` --> usa lambda per ordinare\
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

### Eccezioni
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

Se la condizione è falsa, la stringa verrà stampata.\
Ricorda che le istruzioni `assert` possono essere disabilitate con `python -O`, quindi non usarle per il controllo degli accessi o la validazione dell'input.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generator, yield

Un generator, invece di restituire tutto in una volta, **yield** i valori uno alla volta. Questo è molto utile per wordlist enormi, bruteforcers o risposte grandi.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Espressioni Regolari
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Significati speciali:**\
`.` --> qualsiasi carattere tranne newline\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> cifra\
`\s` --> carattere whitespace `[ \n\r\t\f]`\
`\S` --> carattere non-whitespace\
`^` --> inizia con\
`$` --> termina con\
`+` --> uno o più\
`*` --> 0 o più\
`?` --> 0 o 1 occorrenze

**Opzioni:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> consenti al punto di corrispondere a newline\
`re.search(pat, string, re.MULTILINE)` --> consenti a `^` e `$` di corrispondere in righe diverse
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> prodotto cartesiano tra 1 o più iterabili
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutazioni**\
`from itertools import permutations` --> ogni possibile disposizione
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**combinazioni**\
`from itertools import combinations` --> tutte le combinazioni possibili senza ripetizione
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
`from itertools import batched` --> disponibile in Python 3.12+, utile per suddividere in chunk grandi liste di candidati per bruteforce o file IOC
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Decorator che misura il tempo necessario per eseguire una funzione:
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
Se lo esegui, vedrai qualcosa di simile a quanto segue:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Helper standard della libreria utili per pentesting

**Attraversamento del filesystem con `pathlib`** (`Path.walk()` è disponibile in Python 3.12+; usa `os.walk()` su interpreter più vecchi):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Esegui i comandi in modo sicuro** (`shell=False` per impostazione predefinita è di solito ciò che vuoi):
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
Se **devi** costruire un comando shell, cita prima ogni token controllato dall’attaccante:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**File / directory temporanei** (più sicuri di percorsi hardcoded `/tmp/foo`):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Per l'automazione HTTP, consulta [this other page about Python web requests](web-requests.md).

### Problemi dell'estrazione di archivi (importante per tooling e file parsers)

A partire da **Python 3.14**, `tarfile.extract()` / `extractall()` usano per impostazione predefinita il filtro più sicuro `data`. Nelle versioni precedenti di Python dovresti impostarlo esplicitamente quando gestisci archivi controllati da un attacker.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Anche con `filter="data"`, estrai gli archivi non fidati in una nuova directory temporanea e valida cosa è stato scritto prima di spostare i file in qualsiasi posizione interessante.

`zipfile.Path` è diverso: **non sanitizza i nomi dei file** per te, quindi valida i percorsi prima di estrarre i membri ZIP controllati dall'attaccante:
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
### Primitive pericolose da ricordare

- `eval()` / `exec()` **non** sono sandbox.
- `ast.literal_eval()` **non** esegue codice Python, ma può comunque essere abusato per denial of service di memoria / CPU con input controllato dall'attaccante.
- `pickle.loads()` **non è sicuro**; non fare mai unpickle di byte controllati dall'attaccante.
- Per trucchi offensivi più approfonditi, controlla [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) e [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
