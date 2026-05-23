# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

Όλα τα παραδείγματα παρακάτω υποθέτουν **Python 3** εκτός αν αναφέρεται ρητά διαφορετικά.\
`range()` επιστρέφει ένα iterable αντικείμενο στην Python 3 (παρόμοιο με το `xrange()` στην Python 2).\
Η διαφορά μεταξύ ενός **tuple** και μιας **list** είναι ότι η **θέση** μιας τιμής σε ένα tuple συνήθως της δίνει νόημα, ενώ μια list είναι συνήθως απλώς μια ταξινομημένη ακολουθία τιμών.

### Main operations

Για να υψώσετε έναν αριθμό χρησιμοποιείτε: `3**2` (όχι `3^2`)\
`2/3 == 0.666666...` στην Python 3, ενώ το `2//3 == 0` εκτελεί ακέραια διαίρεση.\
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
`dir(str)` = λίστα διαθέσιμων μεθόδων\
`help(str)` = ορισμός της κλάσης `str`\
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

Αυτό είναι πολύ συνηθισμένο σε exploit-dev, reversing και CTFs:
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
`d = ()` άδειο tuple\
`d += (4,)` --> προσθήκη σε tuple\
`# t1[1] = 'new value'` --> τα tuples είναι immutable\
`list(t2) == [5, 6]` --> από tuple σε list

### List (array)

`d = []` άδειο\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> από list σε tuple

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

Στα sets δεν υπάρχουν επαναλήψεις.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> καμία αλλαγή\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> αν υπάρχει, το αφαιρεί; αν όχι, τίποτα\
`myset.remove(10)` --> αν δεν υπάρχει, εγείρει exception\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> παίρνει ένα αυθαίρετο στοιχείο και το αφαιρεί\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

Η μέθοδος στο `__lt__` θα είναι αυτή που θα χρησιμοποιηθεί από τα `sort()` / `sorted()` για τη σύγκριση αντικειμένων.
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

Στο **Python 3**, τα `map()` και `filter()` επιστρέφουν iterators, οπότε μετατρέψτε τα με `list()` αν θέλετε να εκτυπώσετε όλες τις τιμές μαζί.

Το **Map** είναι σαν `[f(x) for x in iterable]`:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** σταματά όταν σταματά το μικρότερο iterable:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** χρησιμοποιείται για να ορίσει μια συνάρτηση:\
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

### Εξαιρέσεις
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

Αν η συνθήκη είναι false, το string θα εκτυπωθεί.\
Να θυμάστε ότι τα `assert` statements μπορούν να απενεργοποιηθούν με `python -O`, οπότε μην τα χρησιμοποιείτε για access control ή input validation.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

Ένα generator, αντί να επιστρέφει τα πάντα μονομιάς, **yields** τιμές μία προς μία. Αυτό είναι πολύ χρήσιμο για τεράστια wordlists, bruteforcers ή μεγάλες αποκρίσεις.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Κανονικές Εκφράσεις
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Ειδικές σημασίες:**\
`.` --> οποιοσδήποτε χαρακτήρας εκτός από νέα γραμμή\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> ψηφίο\
`\s` --> χαρακτήρας κενού `[ \n\r\t\f]`\
`\S` --> μη-κενού χαρακτήρας\
`^` --> αρχίζει με\
`$` --> τελειώνει με\
`+` --> ένα ή περισσότερα\
`*` --> 0 ή περισσότερα\
`?` --> 0 ή 1 εμφανίσεις

**Επιλογές:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> επιτρέπει στο `.` να ταιριάζει με νέα γραμμή\
`re.search(pat, string, re.MULTILINE)` --> επιτρέπει στα `^` και `$` να ταιριάζουν σε διαφορετικές γραμμές
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> καρτεσιανό γινόμενο μεταξύ 1 ή περισσότερων iterables
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> κάθε δυνατή διάταξη
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**συνδυασμοί**\
`from itertools import combinations` --> όλες οι δυνατές συνδυασμοί χωρίς επανάληψη
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
`from itertools import batched` --> διαθέσιμο στο Python 3.12+, χρήσιμο για να χωρίζεις σε κομμάτια μεγάλες λίστες υποψηφίων bruteforce ή αρχεία IOC
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Decorators

Decorator που μετρά τον χρόνο που χρειάζεται για να εκτελεστεί μια συνάρτηση:
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
Αν το εκτελέσεις, θα δεις κάτι σαν το παρακάτω:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### Χρήσιμοι βοηθοί της standard library για pentesting

**Διασχίζοντας το filesystem με `pathlib`** (`Path.walk()` είναι διαθέσιμο στο Python 3.12+; χρησιμοποιήστε `os.walk()` σε παλαιότερους interpreters):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Εκτέλεση εντολών με ασφάλεια** (`shell=False` by default είναι συνήθως αυτό που θέλεις):
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
Αν **πρέπει** να δημιουργήσεις μια εντολή shell, κάνε πρώτα quote κάθε attacker-controlled token:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Προσωρινά αρχεία / dirs** (πιο ασφαλή από hardcoded `/tmp/foo` paths):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
Για αυτοματοποίηση HTTP, δείτε [this other page about Python web requests](web-requests.md).

### Παγίδες στην εξαγωγή αρχείων συμπίεσης (σημαντικό για tooling και file parsers)

Από την έκδοση **Python 3.14**, τα `tarfile.extract()` / `extractall()` χρησιμοποιούν από προεπιλογή το ασφαλέστερο φίλτρο `data`. Σε παλαιότερες εκδόσεις Python θα πρέπει να το ορίσετε ρητά όταν χειρίζεστε archives που ελέγχονται από attacker.
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
Ακόμα και με `filter="data"`, εξάγετε μη αξιόπιστα αρχεία σε έναν καινούριο προσωρινό κατάλογο και επαληθεύστε τι γράφτηκε πριν μετακινήσετε αρχεία οπουδήποτε ενδιαφέρον.

Το `zipfile.Path` είναι διαφορετικό: **δεν καθαρίζει τα ονόματα αρχείων** για εσάς, οπότε επαληθεύστε τα paths πριν εξαγάγετε ZIP members υπό έλεγχο επιτιθέμενου:
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
### Επικίνδυνες primitives που πρέπει να θυμάσαι

- `eval()` / `exec()` **δεν** είναι sandboxes.
- `ast.literal_eval()` **δεν** εκτελεί Python code, αλλά μπορεί να γίνει κατάχρηση για memory / CPU denial of service με attacker-controlled input.
- `pickle.loads()` **δεν είναι secure**; μην κάνεις ποτέ unpickle attacker-controlled bytes.
- Για πιο προχωρημένα offensive tricks, δες [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) και [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
