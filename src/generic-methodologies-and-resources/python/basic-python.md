# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

All the examples below assume **Python 3** unless explicitly noted.\
`range()` returns an iterable object in Python 3 (similar to `xrange()` in Python 2).\
The difference between a **tuple** and a **list** is that the **position** of a value in a tuple usually gives it meaning, while a list is usually just an ordered sequence of values.

### Main operations

To raise a number you use: `3**2` (not `3^2`)\
`2/3 == 0.666666...` in Python 3, while `2//3 == 0` performs integer division.\
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
`dir(str)` = list available methods\
`help(str)` = definition of the class `str`\
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

This is very common in exploit-dev, reversing and CTFs:

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
`list(t2) == [5, 6]` --> from tuple to list

### List (array)

`d = []` empty\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> from list to tuple

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

In sets there are no repetitions.\
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

The method in `__lt__` will be the one used by `sort()` / `sorted()` to compare objects.

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

In **Python 3**, `map()` and `filter()` return iterators, so convert them with `list()` if you want to print all values at once.

**Map** is like `[f(x) for x in iterable]`:

```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```

**zip** stops when the shorter iterable stops:

```python
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** is used to define a function:\
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

If the condition is false, the string will be printed.\
Remember that `assert` statements can be disabled with `python -O`, so do not use them for access control or input validation.

```python
def avg(grades, weights):
    assert len(grades) != 0, 'no grades data'
    assert len(grades) == len(weights), 'wrong number of grades'
```

### Generators, yield

A generator, instead of returning everything at once, it **yields** values one by one. This is very useful for huge wordlists, bruteforcers or large responses.

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

**Special meanings:**\
`.` --> any char except newline\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> digit\
`\s` --> whitespace char `[ \n\r\t\f]`\
`\S` --> non-whitespace char\
`^` --> starts with\
`$` --> ends with\
`+` --> one or more\
`*` --> 0 or more\
`?` --> 0 or 1 occurrences

**Options:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> allow dot to match newline\
`re.search(pat, string, re.MULTILINE)` --> allow `^` and `$` to match in different lines

```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```

### IterTools

**product**\
`from itertools import product` --> cartesian product between 1 or more iterables

```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```

**permutations**\
`from itertools import permutations` --> every possible arrangement

```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```

**combinations**\
`from itertools import combinations` --> all possible combinations without repetition

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
`from itertools import batched` --> available in Python 3.12+, useful to chunk big bruteforce candidate lists or IOC files

```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```

### Decorators

Decorator that measures the time a function needs to be executed:

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

If you run it, you will see something like the following:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```

### Useful standard library helpers for pentesting

**Filesystem traversal with `pathlib`** (`Path.walk()` is available in Python 3.12+; use `os.walk()` on older interpreters):

```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        if name.endswith((".py", ".env", ".bak")):
            print(root / name)
```

**Spawn commands safely** (`shell=False` by default is usually what you want):

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

If you **must** build a shell command, quote each attacker-controlled token first:

```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```

**Temporary files / dirs** (safer than hardcoded `/tmp/foo` paths):

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "loot.txt"
    out.write_text("secret\n")
    print(out.read_text())
```

For HTTP automation, check [this other page about Python web requests](web-requests.md).

### Archive extraction gotchas (important for tooling and file parsers)

Starting in **Python 3.14**, `tarfile.extract()` / `extractall()` use the safer `data` filter by default. In older Python versions you should set it explicitly when handling attacker-controlled archives.

```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
    with tarfile.open("sample.tar.gz") as tf:
        tf.extractall(out, filter="data")
```

Even with `filter="data"`, extract untrusted archives into a fresh temporary directory and validate what was written before moving files anywhere interesting.

`zipfile.Path` is different: it **does not sanitize filenames** for you, so validate paths before extracting attacker-controlled ZIP members:

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

### Dangerous primitives to remember

- `eval()` / `exec()` are **not** sandboxes.
- `ast.literal_eval()` does **not** execute Python code, but it can still be abused for memory / CPU denial of service with attacker-controlled input.
- `pickle.loads()` is **not secure**; never unpickle attacker-controlled bytes.
- For deeper offensive tricks, check [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) and [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
