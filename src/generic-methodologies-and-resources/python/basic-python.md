# Βασική Python

{{#include ../../banners/hacktricks-training.md}}

## Εικονικά περιβάλλοντα και δημιουργία wheel (`venv`)

Η τυπική μονάδα `venv` της Python δημιουργεί εικονικά περιβάλλοντα, των οποίων το POSIX script ενεργοποίησης είναι το `<venv>/bin/activate`· πληκτρολογήστε `deactivate` για να βγείτε από το ενεργό περιβάλλον.<sup>[[3]](#references)</sup> Στο Ubuntu, το πακέτο `python3-venv` παρέχει τη μονάδα, αν δεν εγκαταστάθηκε μαζί με το βασικό πακέτο Python.<sup>[[4]](#references)</sup>

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

Σε παλαιότερες ροές εργασίας `setup.py bdist_wheel` που βασίζονταν στο setuptools, η εγκατάσταση του `wheel` στο ενεργό περιβάλλον παρείχε την εντολή `bdist_wheel`.<sup>[[5]](#references)</sup> Οι τρέχουσες εκδόσεις του setuptools δεν χρειάζονται πλέον το `wheel` για αυτή την εντολή, ενώ οι σύγχρονες οδηγίες για τη δημιουργία πακέτων συνιστούν τη χρήση του `python -m build --wheel` αντί της απευθείας εκτέλεσης του `setup.py`.<sup>[[6]](#references)[[7]](#references)</sup>

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

## Βασικά στοιχεία της Python

### Χρήσιμες πληροφορίες

Όλα τα παρακάτω παραδείγματα θεωρούν ότι χρησιμοποιείται **Python 3**, εκτός αν αναφέρεται ρητά κάτι διαφορετικό.\
Η `range()` επιστρέφει ένα iterable object στην Python 3 (παρόμοιο με την `xrange()` στην Python 2).\
Η διαφορά μεταξύ μιας **πλειάδας** και μιας **λίστας** είναι ότι η **θέση** μιας τιμής σε μια πλειάδα συνήθως έχει σημασία, ενώ μια λίστα είναι συνήθως απλώς μια διατεταγμένη ακολουθία τιμών.

### Βασικές πράξεις

Για να υψώσεις έναν αριθμό σε δύναμη, χρησιμοποιείς: `3**2` (όχι `3^2`)\
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

**Συνένωση χαρακτήρων**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**Τμήματα λίστας / συμβολοσειράς**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Σχόλια**\
`# One line comment`\
`""" Several lines comment """`

**Βρόχοι**

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

### Bytes, hex και κωδικοποιήσεις

Αυτό είναι πολύ συνηθισμένο σε exploit-dev, reversing και CTFs:

```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```

### Πλειάδες

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = μοναδικό στοιχείο\
`d = ()` κενή πλειάδα\
`d += (4,)` --> προσθήκη σε πλειάδα\
`# t1[1] = 'new value'` --> οι πλειάδες είναι αμετάβλητες\
`list(t2) == [5, 6]` --> από πλειάδα σε λίστα

### Λίστα (array)

`d = []` κενή\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> από λίστα σε πλειάδα

### Λεξικό

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

### Σύνολα

Στα σύνολα δεν υπάρχουν επαναλήψεις.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> καμία αλλαγή\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> αν υπάρχει, αφαιρείται· αν όχι, δεν γίνεται τίποτα\
`myset.remove(10)` --> αν δεν υπάρχει, προκαλεί εξαίρεση\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> επιστρέφει ένα αυθαίρετο στοιχείο και το αφαιρεί\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Κλάσεις

Η μέθοδος στο `__lt__` θα χρησιμοποιηθεί από τις `sort()` / `sorted()` για τη σύγκριση αντικειμένων.

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

### map, zip, filter, lambda, sorted και one-liners

Στην **Python 3**, τα `map()` και `filter()` επιστρέφουν iterators, επομένως μετατρέψτε τα με `list()` αν θέλετε να εκτυπώσετε όλες τις τιμές ταυτόχρονα.

Το **Map** είναι σαν το `[f(x) for x in iterable]`:

```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```

**zip** σταματά μόλις τελειώσει το συντομότερο iterable:

```python
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** χρησιμοποιείται για τον ορισμό μιας συνάρτησης:\
`(lambda x, y: x + y)(5, 3) == 8` --> χρήση του lambda ως απλής συνάρτησης\
`sorted(range(-5, 6), key=lambda x: x**2)` --> χρήση του lambda για ταξινόμηση\
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

Αν η συνθήκη είναι ψευδής, θα εμφανιστεί το μήνυμα.\
Να θυμάστε ότι οι εντολές `assert` μπορούν να απενεργοποιηθούν με το `python -O`, επομένως μην τις χρησιμοποιείτε για έλεγχο πρόσβασης ή επικύρωση εισόδου.

```python
def avg(grades, weights):
    assert len(grades) != 0, 'no grades data'
    assert len(grades) == len(weights), 'wrong number of grades'
```

### Γεννήτριες, yield

Μια γεννήτρια, αντί να επιστρέφει τα πάντα ταυτόχρονα, **παράγει** τιμές μία προς μία. Αυτό είναι πολύ χρήσιμο για τεράστιες wordlists, bruteforcers ή μεγάλες αποκρίσεις.

```python
def my_gen(n):
    yield n
    yield n + 1
```

`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Κανονικές εκφράσεις

```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```

**Ειδικές σημασίες:**\
`.` --> οποιοσδήποτε χαρακτήρας εκτός από newline\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> ψηφίο\
`\s` --> χαρακτήρας κενού `[ \n\r\t\f]`\
`\S` --> χαρακτήρας που δεν είναι κενό\
`^` --> αρχίζει με\
`$` --> τελειώνει με\
`+` --> ένα ή περισσότερα\
`*` --> 0 ή περισσότερα\
`?` --> 0 ή 1 εμφανίσεις

**Επιλογές:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> επιτρέπει στην τελεία να αντιστοιχεί σε newline\
`re.search(pat, string, re.MULTILINE)` --> επιτρέπει στα `^` και `$` να αντιστοιχούν σε διαφορετικές γραμμές

```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```

### IterTools

**product**\
`from itertools import product` --> καρτεσιανό γινόμενο μεταξύ 1 ή περισσότερων επαναλήψιμων αντικειμένων

```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```

**μεταθέσεις**\
`from itertools import permutations` --> κάθε δυνατή διάταξη

```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```

**συνδυασμοί**\
`from itertools import combinations` --> όλοι οι δυνατοί συνδυασμοί χωρίς επανάληψη

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
`from itertools import batched` --> διαθέσιμο στην Python 3.12+, χρήσιμο για να χωρίζετε μεγάλες λίστες υποψηφίων bruteforce ή αρχεία IOC σε τμήματα.

```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```

### Διακοσμητές

Διακοσμητής που μετρά τον χρόνο εκτέλεσης μιας συνάρτησης:

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

Αν το εκτελέσετε, θα δείτε κάτι σαν το εξής:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```

### Χρήσιμες βοηθητικές συναρτήσεις της standard library για pentesting

**Περιήγηση στο filesystem με `pathlib`** (η `Path.walk()` είναι διαθέσιμη στην Python 3.12+· χρησιμοποιήστε την `os.walk()` σε παλαιότερους interpreters):

```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        if name.endswith((".py", ".env", ".bak")):
            print(root / name)
```

**Εκτελείτε εντολές με ασφάλεια** (`shell=False` είναι συνήθως η προεπιλογή που θέλετε):

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

Αν **πρέπει** να δημιουργήσετε μια εντολή shell, περικλείστε πρώτα σε εισαγωγικά κάθε token που ελέγχεται από τον attacker:

```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```

**Προσωρινά αρχεία / κατάλογοι** (ασφαλέστερα από hardcoded διαδρομές όπως `/tmp/foo`):

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "loot.txt"
    out.write_text("secret\n")
    print(out.read_text())
```

Για αυτοματοποίηση HTTP, δείτε [αυτήν την άλλη σελίδα σχετικά με αιτήματα web στην Python](web-requests.md).

### Παγίδες κατά την εξαγωγή αρχείων (σημαντικό για εργαλεία και parsers αρχείων)

Από την **Python 3.14**, οι `tarfile.extract()` / `extractall()` χρησιμοποιούν από προεπιλογή το ασφαλέστερο φίλτρο `data`. Σε παλαιότερες εκδόσεις της Python, θα πρέπει να το ορίζετε ρητά όταν χειρίζεστε αρχεία που ελέγχονται από επιτιθέμενους.<sup>[[1]](#references)[[2]](#references)</sup>

```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
    with tarfile.open("sample.tar.gz") as tf:
        tf.extractall(out, filter="data")
```

Ακόμα και με `filter="data"`, εξαγάγετε μη έμπιστα αρχεία σε έναν νέο προσωρινό κατάλογο και επικυρώστε όσα γράφτηκαν πριν μετακινήσετε αρχεία σε κάποιον σημαντικό προορισμό.

Το `zipfile.Path` διαφέρει: **δεν καθαρίζει τα ονόματα αρχείων** για εσάς, επομένως επικυρώστε τις διαδρομές πριν εξαγάγετε μέλη ZIP που ελέγχονται από επιτιθέμενο:

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

### Επικίνδυνα primitives που πρέπει να θυμάστε

- Τα `eval()` / `exec()` **δεν** είναι sandboxes.
- Η `ast.literal_eval()` **δεν** εκτελεί κώδικα Python, αλλά μπορεί και πάλι να χρησιμοποιηθεί καταχρηστικά για άρνηση υπηρεσίας μέσω εξάντλησης μνήμης / CPU, με είσοδο ελεγχόμενη από επιτιθέμενο.
- Η `pickle.loads()` **δεν** είναι ασφαλής· μην κάνετε ποτέ unpickle bytes που ελέγχονται από επιτιθέμενο.
- Για πιο προχωρημένα offensive tricks, δείτε τα [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) και [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [1] [Τεκμηρίωση Python tarfile](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – Φίλτρο για το tarfile.extractall()](https://peps.python.org/pep-0706/)
- [3] [venv — Δημιουργία εικονικών περιβαλλόντων — Τεκμηρίωση Python 3.14](https://docs.python.org/3/library/venv.html)
- [4] [Πακέτο: python3-venv — Πακέτα Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [5] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [6] [wheel — PyPI](https://pypi.org/project/wheel/)
- [7] [Έχει καταργηθεί το setup.py; — Οδηγός χρήσης του Python Packaging](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
