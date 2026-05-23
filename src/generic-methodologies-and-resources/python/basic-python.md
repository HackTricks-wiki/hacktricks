# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Msingi wa Python

### Taarifa muhimu

Mifano yote hapa chini inaonyesha **Python 3** isipokuwa ikiwa imeelezwa wazi.\
`range()` hurudisha object ya iterable katika Python 3 (sawa na `xrange()` katika Python 2).\
Tofauti kati ya **tuple** na **list** ni kwamba **nafasi** ya thamani katika tuple kwa kawaida huipa maana, wakati list kwa kawaida ni mfuatano tu uliopangwa wa thamani.

### Operesheni kuu

Ili kupandisha nambari unatumia: `3**2` (sio `3^2`)\
`2/3 == 0.666666...` katika Python 3, wakati `2//3 == 0` hufanya integer division.\
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
`dir(str)` = orodha ya methods zinazopatikana\
`help(str)` = ufafanuzi wa class `str`\
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

**Sehemu za list / string**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Maoni**\
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
### Bytes, hex na encodings

Hii ni ya kawaida sana katika exploit-dev, reversing na CTFs:
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
`d = ()` empty tuple\
`d += (4,)` --> add into a tuple\
`# t1[1] = 'new value'` --> tuples are immutable\
`list(t2) == [5, 6]` --> kutoka tuple hadi list

### List (array)

`d = []` empty\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> kutoka list hadi tuple

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

Katika sets hakuna marudio.\
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

### Classes

Method katika `__lt__` ndiyo itakayotumiwa na `sort()` / `sorted()` kulinganisha objects.
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

Katika **Python 3**, `map()` na `filter()` hurudisha iterators, kwa hivyo zibadilishe kwa `list()` ikiwa unataka kuchapisha thamani zote kwa mara moja.

**Map** ni kama `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** husimama wakati iterable fupi inaposimama:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** hutumiwa kufafanua function:\
`(lambda x, y: x + y)(5, 3) == 8` --> tumia lambda kama function rahisi\
`sorted(range(-5, 6), key=lambda x: x**2)` --> tumia lambda kupanga\
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

Ikiwa sharti ni false, string itaonyeshwa.\
Kumbuka kwamba `assert` statements zinaweza kuzimwa kwa `python -O`, kwa hiyo usizitumie kwa access control au input validation.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

A generator, badala ya kurudisha kila kitu kwa wakati mmoja, **hutoa** values moja moja. Hii ni muhimu sana kwa huge wordlists, bruteforcers au large responses.
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
**Maana Maalum:**\
`.` --> herufi yoyote isipokuwa newline\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> tarakimu\
`\s` --> herufi ya whitespace `[ \n\r\t\f]`\
`\S` --> herufi isiyo ya whitespace\
`^` --> huanza na\
`$` --> huishia na\
`+` --> moja au zaidi\
`*` --> 0 au zaidi\
`?` --> matukio 0 au 1

**Chaguo:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> ruhusu dot ilingane na newline\
`re.search(pat, string, re.MULTILINE)` --> ruhusu `^` na `$` kuendana katika mistari tofauti
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> product ya Cartesian kati ya iterables 1 au zaidi
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> kila mpangilio unaowezekana
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**mchanganyiko**\
`from itertools import combinations` --> mchanganyiko wote unaowezekana bila kurudia
```python
list(combinations('123', 2))
# [('1', '2'), ('1', '3'), ('2', '3')]
```
**mchanganyiko_kwa_kurudia**\
`from itertools import combinations_with_replacement`
```python
list(combinations_with_replacement('123', 2))
# [('1', '1'), ('1', '2'), ('1', '3'), ('2', '2'), ('2', '3'), ('3', '3')]
```
**batched**\
`from itertools import batched` --> inapatikana katika Python 3.12+, muhimu kwa kugawanya vipande vikubwa vya orodha za wagombea wa bruteforce au faili za IOC
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Decorator inayopima muda ambao function inahitaji ili kutekelezwa:
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
Ikiwa utaendesha, utaona kitu kama kifuatacho:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Vifaa vya kawaida vya maktaba kwa pentesting

**Kutembea kwenye mfumo wa faili kwa `pathlib`** (`Path.walk()` inapatikana katika Python 3.12+; tumia `os.walk()` kwenye interpreta za zamani):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Anzisha amri kwa usalama** (`shell=False` kwa chaguo-msingi kwa kawaida ndicho unachotaka):
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
Ikiwa **lazima** ujenge shell command, quote kila token inayodhibitiwa na attacker kwanza:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Faili / saraka za muda** (salama zaidi kuliko njia zilizowekwa moja kwa moja kama `/tmp/foo`):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Kwa automatisering ya HTTP, angalia [ukurasa huu mwingine kuhusu Python web requests](web-requests.md).

### Mitego ya uchimbaji wa archive (muhimu kwa tooling na file parsers)

Kuanzia **Python 3.14**, `tarfile.extract()` / `extractall()` hutumia `data` filter salama zaidi kwa chaguo-msingi. Katika matoleo ya zamani ya Python unapaswa kuiweka wazi unaposhughulikia archives zinazodhibitiwa na attacker.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Hata hata ikiwa na `filter="data"`, toa kumbukizi zisizoaminika ndani ya saraka mpya ya muda na thibitisha kilichoandikwa kabla ya kuhamisha faili mahali popote pa maana.

`zipfile.Path` ni tofauti: **haisafishi majina ya faili** kwa ajili yako, kwa hiyo thibitisha njia kabla ya kutoa ZIP members zinazodhibitiwa na mshambuliaji:
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
### Primitives hatari za kukumbuka

- `eval()` / `exec()` **si** sandboxes.
- `ast.literal_eval()` **hai**teketezi Python code, lakini bado inaweza kutumiwa vibaya kwa denial of service ya memory / CPU kwa input inayodhibitiwa na mshambuliaji.
- `pickle.loads()` **si salama**; kamwe usifanye unpickle bytes zinazodhibitiwa na mshambuliaji.
- Kwa tricks za kina za offensive, angalia [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) na [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
