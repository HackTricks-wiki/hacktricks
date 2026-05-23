# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Informações úteis

Todos os exemplos abaixo assumem **Python 3**, a menos que seja explicitamente indicado.\
`range()` retorna um objeto iterável em Python 3 (semelhante a `xrange()` no Python 2).\
A diferença entre uma **tuple** e uma **list** é que a **posição** de um valor em uma tuple normalmente lhe dá significado, enquanto uma list normalmente é apenas uma sequência ordenada de valores.

### Main operations

Para elevar um número você usa: `3**2` (não `3^2`)\
`2/3 == 0.666666...` em Python 3, enquanto `2//3 == 0` realiza divisão inteira.\
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
`dir(str)` = lista de métodos disponíveis\
`help(str)` = definição da classe `str`\
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

Isto é muito comum em exploit-dev, reversing e CTFs:
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
`d = ()` tupla vazia\
`d += (4,)` --> adicionar em uma tupla\
`# t1[1] = 'new value'` --> tuples are immutable\
`list(t2) == [5, 6]` --> de tuple para list

### List (array)

`d = []` vazio\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> de list para tuple

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

Em sets não há repetições.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> sem mudança\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> se presente, remove-o; se não, nada\
`myset.remove(10)` --> se não estiver presente, lança exceção\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> obtém um elemento arbitrário e o remove\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

O método em `__lt__` será o usado por `sort()` / `sorted()` para comparar objetos.
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

Em **Python 3**, `map()` e `filter()` retornam iteradores, então converta-os com `list()` se você quiser imprimir todos os valores de uma vez.

**Map** é como `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** para quando o iterável mais curto termina:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** é usado para definir uma função:\
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

Se a condição for falsa, a string será exibida.\
Lembre-se de que as instruções `assert` podem ser desativadas com `python -O`, então não as use para controle de acesso ou validação de entrada.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Geradores, yield

Um gerador, em vez de retornar tudo de uma vez, **yield** valores um a um. Isso é muito útil para wordlists enormes, bruteforcers ou respostas grandes.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Expressões Regulares
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Significados especiais:**\
`.` --> qualquer caractere exceto quebra de linha\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> dígito\
`\s` --> caractere de espaço em branco `[ \n\r\t\f]`\
`\S` --> caractere sem espaço em branco\
`^` --> começa com\
`$` --> termina com\
`+` --> um ou mais\
`*` --> 0 ou mais\
`?` --> 0 ou 1 ocorrências

**Opções:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> permite que o ponto corresponda a quebra de linha\
`re.search(pat, string, re.MULTILINE)` --> permite que `^` e `$` correspondam em linhas diferentes
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> produto cartesiano entre 1 ou mais iteráveis
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> cada arranjo possível
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**combinações**\
`from itertools import combinations` --> todas as combinações possíveis sem repetição
```python
list(combinations('123', 2))
# [('1', '2'), ('1', '3'), ('2', '3')]
```
**combinações_com_repetição**\
`from itertools import combinations_with_replacement`
```python
list(combinations_with_replacement('123', 2))
# [('1', '1'), ('1', '2'), ('1', '3'), ('2', '2'), ('2', '3'), ('3', '3')]
```
**batched**\
`from itertools import batched` --> disponível no Python 3.12+, útil para dividir listas grandes de candidatos de bruteforce ou arquivos IOC em blocos
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Decorator que mede o tempo que uma função precisa para ser executada:
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
Se você executá-lo, verá algo como o seguinte:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Utilitários da biblioteca standard úteis para pentesting

**Percurso do filesystem com `pathlib`** (`Path.walk()` está disponível no Python 3.12+; use `os.walk()` em interpretadores mais antigos):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Executar comandos com segurança** (`shell=False` por padrão é geralmente o que você quer):
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
Se você **precisar** construir um comando de shell, coloque aspas primeiro em cada token controlado pelo atacante:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Arquivos / diretórios temporários** (mais seguros do que caminhos hardcoded `/tmp/foo`):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Para automação HTTP, confira [esta outra página sobre Python web requests](web-requests.md).

### Armadilhas na extração de archives (importante para tooling e file parsers)

A partir do **Python 3.14**, `tarfile.extract()` / `extractall()` usam o filtro `data` mais seguro por padrão. Em versões mais antigas do Python, você deve defini-lo explicitamente ao lidar com archives controlados por um atacante.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Mesmo com `filter="data"`, extraia arquivos compactados não confiáveis em um novo diretório temporário e valide o que foi escrito antes de mover arquivos para qualquer lugar interessante.

`zipfile.Path` é diferente: ele **não sanitiza nomes de arquivos** para você, então valide os caminhos antes de extrair membros ZIP controlados pelo atacante:
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
### Primitivos perigosos para lembrar

- `eval()` / `exec()` **não** são sandboxes.
- `ast.literal_eval()` **não** executa código Python, mas ainda pode ser abusado para negação de serviço de memória / CPU com input controlado pelo atacante.
- `pickle.loads()` **não é seguro**; nunca faça unpickle de bytes controlados pelo atacante.
- Para truques ofensivos mais profundos, confira [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) e [Python deserializations](../../pentesting-web/deserialization/README.md).

## Referências

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
