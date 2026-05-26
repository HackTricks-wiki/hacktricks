# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### उपयोगी जानकारी

नीचे दिए गए सभी उदाहरण, explicitly noted होने पर छोड़कर, **Python 3** मानते हैं।\
`range()` Python 3 में एक iterable object लौटाता है (Python 2 में `xrange()` जैसा)।\
**tuple** और **list** के बीच अंतर यह है कि tuple में किसी value की **position** आमतौर पर उसे meaning देती है, जबकि list आमतौर पर values का सिर्फ एक ordered sequence होती है।

### Main operations

किसी number को raise करने के लिए आप use करते हैं: `3**2` (not `3^2`)\
`2/3 == 0.666666...` Python 3 में, जबकि `2//3 == 0` integer division करता है।\
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
`dir(str)` = उपलब्ध methods की list\
`help(str)` = class `str` की definition\
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
### Bytes, hex और encodings

यह exploit-dev, reversing और CTFs में बहुत आम है:
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
`d = ()` खाली tuple\
`d += (4,)` --> tuple में जोड़ें\
`# t1[1] = 'new value'` --> tuples immutable होते हैं\
`list(t2) == [5, 6]` --> tuple से list में

### List (array)

`d = []` खाली\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> list से tuple में

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

Sets में कोई repetition नहीं होती।\
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

`__lt__` में मौजूद method का उपयोग `sort()` / `sorted()` objects की तुलना करने के लिए करेंगे।
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

**Python 3** में, `map()` और `filter()` iterators लौटाते हैं, इसलिए अगर आप सभी values को एक साथ print करना चाहते हैं तो उन्हें `list()` से convert करें।

**Map** `[f(x) for x in iterable]` जैसा है:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** तब रुकता है जब छोटा iterable रुकता है:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** का उपयोग एक function define करने के लिए किया जाता है:\
`(lambda x, y: x + y)(5, 3) == 8` --> lambda का उपयोग एक simple function के रूप में करें\
`sorted(range(-5, 6), key=lambda x: x**2)` --> sort करने के लिए lambda का उपयोग करें\
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

यदि शर्त false है, तो string print होगी।\
ध्यान रखें कि `assert` statements को `python -O` के साथ disable किया जा सकता है, इसलिए उन्हें access control या input validation के लिए use न करें।
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### जनरेटर, yield

एक generator, सब कुछ एक साथ return करने के बजाय, values को एक-एक करके **yields** करता है। यह huge wordlists, bruteforcers या large responses के लिए बहुत उपयोगी है।
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
**विशेष अर्थ:**\
`.` --> newline को छोड़कर कोई भी char\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> digit\
`\s` --> whitespace char `[ \n\r\t\f]`\
`\S` --> non-whitespace char\
`^` --> से शुरू होता है\
`$` --> पर समाप्त होता है\
`+` --> एक या अधिक\
`*` --> 0 या अधिक\
`?` --> 0 या 1 occurrences

**Options:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> dot को newline से match करने की अनुमति दें\
`re.search(pat, string, re.MULTILINE)` --> `^` और `$` को अलग-अलग lines में match करने की अनुमति दें
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> 1 या अधिक iterables के बीच cartesian product
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**परमुटेशन्स**\
`from itertools import permutations` --> हर संभव arrangement
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**संयोजन**\
`from itertools import combinations` --> बिना पुनरावृत्ति के सभी संभव संयोजन
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
`from itertools import batched` --> Python 3.12+ में उपलब्ध, बड़े bruteforce candidate lists या IOC files को chunk करने के लिए उपयोगी
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### डेकोरेटर्स

ऐसा डेकोरेटर जो किसी function को execute होने में लगने वाले समय को मापता है:
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
यदि आप इसे चलाते हैं, तो आप कुछ इस तरह देखेंगे:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### pentesting के लिए उपयोगी standard library helpers

**`pathlib` के साथ Filesystem traversal** (`Path.walk()` Python 3.12+ में उपलब्ध है; पुराने interpreters पर `os.walk()` का उपयोग करें):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**कमांड्स को सुरक्षित रूप से Spawn करें** (`shell=False` by default आमतौर पर वही होता है जो आप चाहते हैं):
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
यदि आपको **ज़रूर** एक shell command बनानी हो, तो पहले attacker-controlled प्रत्येक token को quote करें:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**टेम्पररी फाइल्स / dirs** (hardcoded `/tmp/foo` paths से ज़्यादा सुरक्षित):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
HTTP automation के लिए, [this other page about Python web requests](web-requests.md) देखें।

### Archive extraction gotchas (important for tooling and file parsers)

**Python 3.14** से शुरू होकर, `tarfile.extract()` / `extractall()` डिफ़ॉल्ट रूप से अधिक सुरक्षित `data` filter का उपयोग करते हैं। पुराने Python versions में, attacker-controlled archives को handle करते समय आपको इसे explicitly set करना चाहिए।
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
`filter="data"` के साथ भी, untrusted archives को एक fresh temporary directory में extract करें और यह validate करें कि क्या लिखा गया है, उससे पहले कि किसी भी interesting जगह files move की जाएँ।

`zipfile.Path` अलग है: यह आपके लिए **filenames को sanitize नहीं करता**, इसलिए attacker-controlled ZIP members को extract करने से पहले paths को validate करें:
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
### याद रखने योग्य Dangerous primitives

- `eval()` / `exec()` **sandbox** नहीं हैं।
- `ast.literal_eval()` Python code execute नहीं करता, लेकिन attacker-controlled input के साथ इसे memory / CPU denial of service के लिए फिर भी abuse किया जा सकता है।
- `pickle.loads()` **secure** नहीं है; कभी भी attacker-controlled bytes को unpickle न करें।
- और गहरे offensive tricks के लिए, [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) और [Python deserializations](../../pentesting-web/deserialization/README.md) देखें।

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
