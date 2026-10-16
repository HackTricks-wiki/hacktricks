# Osnovni Python

{{#include ../../banners/hacktricks-training.md}}

## Virtuelna okruženja i izgradnja wheel paketa (`venv`)

Python-ov standardni modul `venv` kreira virtuelna okruženja, čija POSIX skripta za aktivaciju je `<venv>/bin/activate`; unesite `deactivate` da biste napustili aktivno okruženje.<sup>[[3]](#references)</sup> Na Ubuntu-u, paket `python3-venv` obezbeđuje modul ako nije instaliran uz osnovni Python paket.<sup>[[4]](#references)</sup>

```bash
sudo apt-get install python3-venv
#Now, go to the folder you want to create the virtual environment
python3 -m venv <Dirname>
python3 -m venv pvenv #In this case the folder "pvenv" is going to be created
source <Dirname>/bin/activate
source pvenv/bin/activate #Activate the environment
#You can now install whatever python library you need
deactivate #To deactivate the virtual environment
```

U starijim workflow-ovima zasnovanim na setuptools-u koji koriste `setup.py bdist_wheel`, instaliranje paketa `wheel` u aktivno okruženje omogućavalo je komandu `bdist_wheel`.<sup>[[5]](#references)</sup> Novije verzije setuptools-a više ne zahtevaju `wheel` za tu komandu, a aktuelne smernice za pakovanje preporučuju `python -m build --wheel` umesto direktnog pozivanja `setup.py`.<sup>[[6]](#references)[[7]](#references)</sup>

```text
error: invalid command 'bdist_wheel'
```

```bash
# Legacy workaround for older setuptools-based projects:
python3 -m pip install wheel

# Current build workflow:
python3 -m pip install build
python3 -m build --wheel
```

## Osnove Python-a

### Korisne informacije

Svi primeri u nastavku podrazumevaju **Python 3**, osim ako nije izričito navedeno drugačije.\
`range()` vraća objekat koji se može iterirati u Python-u 3 (slično funkciji `xrange()` u Python-u 2).\
Razlika između **tuple** i **list** je u tome što **pozicija** vrednosti u tuple-u obično nosi značenje, dok je list obično samo uređeni niz vrednosti.

### Glavne operacije

Za stepenovanje broja koristi se: `3**2` (ne `3^2`)\
`2/3 == 0.666666...` u Python-u 3, dok `2//3 == 0` vrši celobrojno deljenje.\
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

**Spajanje znakova**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**Delovi liste / stringa**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Komentari**\
`# One line comment`\
`""" Several lines comment """`

**Petlje**

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

### Bajtovi, hex i kodiranja

Ovo je veoma često u exploit-dev, reversing i CTF-ovima:

```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```

### Torke

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = torka sa jednim elementom\
`d = ()` prazna torka\
`d += (4,)` --> dodaj u torku\
`# t1[1] = 'new value'` --> torke su nepromenljive\
`list(t2) == [5, 6]` --> pretvaranje torke u listu

### Lista (niz)

`d = []` prazna lista\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> pretvaranje liste u torku

### Rečnik

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

### Skupovi

U skupovima nema ponavljanja.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> nema promene\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> ako postoji, uklanja ga; ako ne postoji, ne radi ništa\
`myset.remove(10)` --> ako ne postoji, podiže izuzetak\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> uzima proizvoljan element i uklanja ga\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Klase

Metoda u `__lt__` koristi se u `sort()` / `sorted()` za poređenje objekata.

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

### map, zip, filter, lambda, sorted i jednolinijski izrazi

U **Python 3** funkcije `map()` i `filter()` vraćaju iteratore, pa ih konvertujte pomoću `list()` ako želite da odštampate sve vrednosti odjednom.

**Map** je kao `[f(x) for x in iterable]`:

```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```

**zip** se zaustavlja kada se završi kraći iterabilni objekat:

```python
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** se koristi za definisanje funkcije:\
`(lambda x, y: x + y)(5, 3) == 8` --> koristi lambda kao jednostavnu funkciju\
`sorted(range(-5, 6), key=lambda x: x**2)` --> koristi lambda za sortiranje\
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

Ako je uslov netačan, string će biti ispisan.\
Imajte na umu da se `assert` naredbe mogu isključiti pomoću `python -O`, zato ih nemojte koristiti za kontrolu pristupa ili validaciju unosa.

```python
def avg(grades, weights):
    assert len(grades) != 0, 'no grades data'
    assert len(grades) == len(weights), 'wrong number of grades'
```

### Generatori, yield

Generator, umesto da vrati sve odjednom, **yield**-uje vrednosti jednu po jednu. Ovo je veoma korisno za ogromne wordlist-e, bruteforcere ili velike odgovore.

```python
def my_gen(n):
    yield n
    yield n + 1
```

`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Regularni izrazi

```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```

**Posebna značenja:**\
`.` --> bilo koji znak osim novog reda\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> cifra\
`\s` --> znak beline `[ \n\r\t\f]`\
`\S` --> znak koji nije belina\
`^` --> počinje sa\
`$` --> završava se sa\
`+` --> jedan ili više\
`*` --> 0 ili više\
`?` --> 0 ili 1 pojavljivanja

**Opcije:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> omogućava da tačka odgovara znaku novog reda\
`re.search(pat, string, re.MULTILINE)` --> omogućava da `^` i `$` odgovaraju u različitim redovima

```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```

### IterTools

**product**\
`from itertools import product` --> Dekartov proizvod između jednog ili više iterabilnih objekata

```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```

**permutacije**\
`from itertools import permutations` --> svaki mogući raspored

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

**combinations_with_replacement**\
`from itertools import combinations_with_replacement`

```python
list(combinations_with_replacement('123', 2))
# [('1', '1'), ('1', '2'), ('1', '3'), ('2', '2'), ('2', '3'), ('3', '3')]
```

**batched**\
`from itertools import batched` --> dostupno u Pythonu 3.12+, korisno za podelu velikih lista kandidata za bruteforce ili IOC datoteka na manje grupe.

```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```

### Dekoratori

Dekorator koji meri vreme potrebno za izvršavanje funkcije:

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

Ako ga pokrenete, videćete nešto poput sledećeg:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```

### Korisni pomoćni alati iz standardne biblioteke za pentesting

**Obilazak sistema datoteka pomoću `pathlib`** (`Path.walk()` je dostupan u Pythonu 3.12+; u starijim interpreterima koristite `os.walk()`):

```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        if name.endswith((".py", ".env", ".bak")):
            print(root / name)
```

**Bezbedno pokrećite komande** (`shell=False` je obično ono što želite kao podrazumevanu vrednost):

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

Ako **morate** da sastavite shell komandu, prvo stavite pod navodnike svaki token koji kontroliše napadač:

```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```

**Privremene datoteke / direktorijumi** (bezbednije nego hardkodirane putanje `/tmp/foo`):

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "loot.txt"
    out.write_text("secret\n")
    print(out.read_text())
```

Za HTTP automatizaciju pogledajte [ovu drugu stranicu o Python web zahtevima](web-requests.md).

### Zamke pri raspakivanju arhiva (važno za alate i parser-e datoteka)

Od **Python 3.14**, `tarfile.extract()` / `extractall()` podrazumevano koriste bezbedniji `data` filter. U starijim verzijama Pythona treba eksplicitno da ga podesite pri radu sa arhivama pod kontrolom napadača.<sup>[[1]](#references)[[2]](#references)</sup>

```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
    with tarfile.open("sample.tar.gz") as tf:
        tf.extractall(out, filter="data")
```

Čak i uz `filter="data"`, raspakujte nepouzdane arhive u nov privremeni direktorijum i proverite šta je upisano pre nego što premestite datoteke na neko važno mesto.

`zipfile.Path` je drugačiji: **ne sanitizuje nazive datoteka**, zato proverite putanje pre raspakivanja ZIP članova koje kontroliše napadač:

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

- `eval()` / `exec()` nisu **sandbox okruženja**.
- `ast.literal_eval()` ne izvršava Python kod, ali se i dalje može zloupotrebiti za uskraćivanje usluge memoriji / CPU-u pomoću ulaza koji kontroliše napadač.
- `pickle.loads()` nije **bezbedan**; nikada nemojte koristiti `unpickle` nad bajtovima koje kontroliše napadač.
- Za naprednije ofanzivne trikove pogledajte [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) i [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [1] [Python tarfile dokumentacija](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – Filter za tarfile.extractall()](https://peps.python.org/pep-0706/)
- [3] [venv — Kreiranje virtuelnih okruženja — Python 3.14 dokumentacija](https://docs.python.org/3/library/venv.html)
- [4] [Paket: python3-venv — Ubuntu paketi](https://packages.ubuntu.com/noble/python/python3-venv)
- [5] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [6] [wheel — PyPI](https://pypi.org/project/wheel/)
- [7] [Da li je setup.py zastareo? — Python vodič za pakovanje](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
