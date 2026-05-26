# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

Tous les exemples ci-dessous supposent **Python 3** sauf indication contraire.\
`range()` renvoie un objet iterable en Python 3 (semblable à `xrange()` en Python 2).\
La différence entre un **tuple** et une **list** est que la **position** d'une valeur dans un tuple lui donne généralement son sens, tandis qu'une list est généralement juste une séquence ordonnée de valeurs.

### Main operations

Pour élever un nombre, on utilise : `3**2` (pas `3^2`)\
`2/3 == 0.666666...` en Python 3, tandis que `2//3 == 0` effectue une division entière.\
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
`dir(str)` = liste des méthodes disponibles\
`help(str)` = définition de la classe `str`\
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
### Bytes, hex et encodings

C’est très courant en exploit-dev, reversing et CTFs :
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
`d = ()` tuple vide\
`d += (4,)` --> ajouter dans un tuple\
`# t1[1] = 'new value'` --> les tuples sont immutables\
`list(t2) == [5, 6]` --> de tuple à list

### List (array)

`d = []` vide\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> de list à tuple

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

Dans les sets, il n'y a pas de répétitions.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> pas de changement\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> s'il est présent, le supprimer ; sinon, rien\
`myset.remove(10)` --> s'il n'est pas présent, lève une exception\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> obtient un élément arbitraire et le supprime\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

La méthode dans `__lt__` sera celle utilisée par `sort()` / `sorted()` pour comparer les objets.
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

En **Python 3**, `map()` et `filter()` renvoient des itérateurs, donc convertissez-les avec `list()` si vous voulez afficher toutes les valeurs en une seule fois.

**Map** est comme `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** s’arrête lorsque l’itérable le plus court s’arrête :
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** est utilisé pour définir une fonction :\
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

### Exceptions
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

Si la condition est fausse, la chaîne sera affichée.\
Rappelez-vous que les instructions `assert` peuvent être désactivées avec `python -O`, donc ne les utilisez pas pour le contrôle d'accès ou la validation des entrées.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Générateurs, yield

Un générateur, au lieu de tout renvoyer d'un coup, **yield** des valeurs une par une. C'est très utile pour de très grandes wordlists, des bruteforcers ou de larges réponses.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Expressions régulières
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Significations spéciales :**\
`.` --> n'importe quel caractère sauf le saut de ligne\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> chiffre\
`\s` --> caractère d'espace blanc `[ \n\r\t\f]`\
`\S` --> caractère non espace blanc\
`^` --> commence par\
`$` --> se termine par\
`+` --> un ou plusieurs\
`*` --> 0 ou plusieurs\
`?` --> 0 ou 1 occurrences

**Options :**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> permettre à `.` de correspondre au saut de ligne\
`re.search(pat, string, re.MULTILINE)` --> permettre à `^` et `$` de correspondre sur différentes lignes
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> produit cartésien entre 1 ou plusieurs itérables
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> chaque arrangement possible
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**combinaisons**\
`from itertools import combinations` --> toutes les combinaisons possibles sans répétition
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
`from itertools import batched` --> disponible en Python 3.12+, utile pour découper de grandes listes de candidats de bruteforce ou des fichiers IOC
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Décorateur qui mesure le temps nécessaire à l'exécution d'une fonction :
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
Si vous l’exécutez, vous verrez quelque chose comme ce qui suit :
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Helpers standard de bibliothèque utiles pour le pentesting

**Parcours du système de fichiers avec `pathlib`** (`Path.walk()` est disponible en Python 3.12+ ; utilisez `os.walk()` sur les interpréteurs plus anciens) :
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Exécuter des commandes en toute sécurité** (`shell=False` par défaut est généralement ce que vous voulez) :
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
Si vous **devez** construire une commande shell, mettez d’abord entre guillemets chaque jeton contrôlé par l’attaquant :
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Fichiers / répertoires temporaires** (plus sûrs que des chemins `/tmp/foo` codés en dur):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Pour l’automatisation HTTP, consultez [this other page about Python web requests](web-requests.md).

### Pièges de l’extraction d’archives (important pour les outils et les parseurs de fichiers)

À partir de **Python 3.14**, `tarfile.extract()` / `extractall()` utilisent par défaut le filtre `data`, plus sûr. Dans les versions plus anciennes de Python, vous devriez le définir explicitement lors du traitement d’archives contrôlées par un attaquant.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Même avec `filter="data"`, extrayez les archives non fiables dans un nouveau répertoire temporaire et validez ce qui a été écrit avant de déplacer des fichiers vers un emplacement sensible.

`zipfile.Path` est différent : il **ne sanitise pas les noms de fichiers** pour vous, donc validez les chemins avant d’extraire des membres ZIP contrôlés par un attaquant :
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
### Primitives dangereuses à retenir

- `eval()` / `exec()` ne sont **pas** des sandboxes.
- `ast.literal_eval()` n'exécute **pas** de code Python, mais il peut quand même être abusé pour provoquer un déni de service mémoire / CPU avec une entrée contrôlée par l'attaquant.
- `pickle.loads()` n'est **pas sécurisé** ; ne jamais unpickle des bytes contrôlés par l'attaquant.
- Pour des techniques offensives plus avancées, consultez [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) et [Python deserializations](../../pentesting-web/deserialization/README.md).

## Références

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
