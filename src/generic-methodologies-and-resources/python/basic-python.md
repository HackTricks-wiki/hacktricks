# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

Todos los ejemplos a continuación asumen **Python 3** a menos que se indique explícitamente.\
`range()` devuelve un objeto iterable en Python 3 (similar a `xrange()` en Python 2).\
La diferencia entre una **tuple** y una **list** es que la **posición** de un valor en una tuple normalmente le da significado, mientras que una list normalmente es solo una secuencia ordenada de valores.

### Main operations

Para elevar un número usas: `3**2` (no `3^2`)\
`2/3 == 0.666666...` en Python 3, mientras que `2//3 == 0` realiza división entera.\
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
`dir(str)` = lista de métodos disponibles\
`help(str)` = definición de la clase `str`\
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
### Bytes, hex y encodings

Esto es muy común en exploit-dev, reversing y CTFs:
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
`d = ()` tupla vacía\
`d += (4,)` --> añadir a una tupla\
`# t1[1] = 'new value'` --> las tuplas son inmutables\
`list(t2) == [5, 6]` --> de tupla a lista

### List (array)

`d = []` vacía\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> de lista a tupla

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

En los sets no hay repeticiones.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> sin cambios\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> si está presente, se elimina; si no, nada\
`myset.remove(10)` --> si no está presente, lanza una excepción\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> obtiene un elemento arbitrario y lo elimina\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

El método en `__lt__` será el que use `sort()` / `sorted()` para comparar objetos.
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

En **Python 3**, `map()` y `filter()` devuelven iteradores, así que conviértelos con `list()` si quieres imprimir todos los valores a la vez.

**Map** es como `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** se detiene cuando se detiene el iterable más corto:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** se usa para definir una función:\
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

### Excepciones
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

Si la condición es falsa, la cadena se imprimirá.\
Recuerda que las sentencias `assert` se pueden deshabilitar con `python -O`, así que no las uses para control de acceso o validación de entrada.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

Un generator, en lugar de devolver todo de una vez, **yield** valores uno por uno. Esto es muy útil para listas de palabras enormes, bruteforcers o respuestas grandes.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Expresiones regulares
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Significados especiales:**\
`.` --> cualquier char excepto salto de línea\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> dígito\
`\s` --> char de espacio en blanco `[ \n\r\t\f]`\
`\S` --> char no espacio en blanco\
`^` --> comienza con\
`$` --> termina con\
`+` --> uno o más\
`*` --> 0 o más\
`?` --> 0 o 1 ocurrencias

**Opciones:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> permite que el punto coincida con salto de línea\
`re.search(pat, string, re.MULTILINE)` --> permite que `^` y `$` coincidan en diferentes líneas
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> producto cartesiano entre 1 o más iterables
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> todas las posibles disposiciones
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**combinaciones**\
`from itertools import combinations` --> todas las combinaciones posibles sin repetición
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
`from itertools import batched` --> disponible en Python 3.12+, útil para dividir en fragmentos grandes listas de candidatos de bruteforce o archivos IOC
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Decorator que mide el tiempo que una función necesita para ejecutarse:
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
Si lo ejecutas, verás algo como lo siguiente:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Utilidades estándar de la biblioteca para pentesting

**Recorrido del sistema de archivos con `pathlib`** (`Path.walk()` está disponible en Python 3.12+; usa `os.walk()` en intérpretes más antiguos):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Ejecutar comandos de forma segura** (`shell=False` por defecto suele ser lo que quieres):
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
Si **debes** construir un comando de shell, cita primero cada token controlado por el atacante:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Archivos / directorios temporales** (más seguros que rutas codificadas como `/tmp/foo`):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Para la automatización HTTP, consulta [esta otra página sobre Python web requests](web-requests.md).

### Problemas al extraer archivos de archivo comprimido (importante para tooling y file parsers)

A partir de **Python 3.14**, `tarfile.extract()` / `extractall()` usan por defecto el filtro más seguro `data`. En versiones antiguas de Python deberías configurarlo explícitamente al manejar archivos controlados por un atacante.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Incluso con `filter="data"`, extrae archivos comprimidos no confiables en un directorio temporal nuevo y valida lo que se escribió antes de mover archivos a cualquier lugar interesante.

`zipfile.Path` es diferente: **no sanea los nombres de archivo** por ti, así que valida las rutas antes de extraer miembros de ZIP controlados por un atacante:
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
### Primitivas peligrosas para recordar

- `eval()` / `exec()` **no** son sandboxes.
- `ast.literal_eval()` **no** ejecuta código Python, pero aun así puede ser abusado para denegación de servicio de memoria / CPU con entrada controlada por un atacante.
- `pickle.loads()` **no es seguro**; nunca hagas unpickle de bytes controlados por un atacante.
- Para trucos ofensivos más profundos, revisa [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) y [Python deserializations](../../pentesting-web/deserialization/README.md).

## Referencias

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
