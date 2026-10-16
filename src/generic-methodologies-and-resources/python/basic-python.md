# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Virtual environments और wheel builds (`venv`)

Python का standard `venv` module virtual environments बनाता है। इनकी POSIX activation script `<venv>/bin/activate` होती है; सक्रिय environment से बाहर निकलने के लिए `deactivate` टाइप करें।<sup>[[3]](#references)</sup> Ubuntu पर, यदि base Python package के साथ यह module इंस्टॉल नहीं होता है, तो `python3-venv` package इसे उपलब्ध कराता है।<sup>[[4]](#references)</sup>

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

पुराने setuptools-आधारित `setup.py bdist_wheel` वर्कफ़्लो में, सक्रिय environment में `wheel` इंस्टॉल करने से `bdist_wheel` कमांड उपलब्ध होती थी।<sup>[[5]](#references)</sup> setuptools के वर्तमान versions को अब उस कमांड के लिए `wheel` की आवश्यकता नहीं होती, और वर्तमान packaging guidance सीधे `setup.py` चलाने के बजाय `python -m build --wheel` की अनुशंसा करती है।<sup>[[6]](#references)[[7]](#references)</sup>

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

## Python की मूल बातें

### उपयोगी जानकारी

नीचे दिए गए सभी उदाहरण Python 3 के लिए हैं, जब तक कि स्पष्ट रूप से कुछ और न कहा गया हो।\
Python 3 में `range()` एक iterable object लौटाता है (`xrange()` Python 2 में इसी तरह काम करता था)।\
**tuple** और **list** के बीच अंतर यह है कि tuple में किसी मान की **position** आमतौर पर उसका अर्थ बताती है, जबकि list आमतौर पर मानों का एक क्रमबद्ध अनुक्रम होती है।

### मुख्य ऑपरेशन

किसी संख्या की घात निकालने के लिए यह लिखें: `3**2` (`3^2` नहीं)\
Python 3 में `2/3 == 0.666666...`, जबकि `2//3 == 0` integer division करता है।\
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
`dir(str)` = उपलब्ध methods की सूची\
`help(str)` = `str` class की परिभाषा\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**अक्षरों को जोड़ना**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**list / string के हिस्से**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**टिप्पणियाँ**\
`# One line comment`\
`""" Several lines comment """`

**लूप**

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

### ट्यूपल

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = एकल एलिमेंट वाला\
`d = ()` खाली ट्यूपल\
`d += (4,)` --> ट्यूपल में जोड़ें\
`# t1[1] = 'new value'` --> ट्यूपल अपरिवर्तनीय होते हैं\
`list(t2) == [5, 6]` --> ट्यूपल से लिस्ट में

### लिस्ट (ऐरे)

`d = []` खाली\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> लिस्ट से ट्यूपल में

### डिक्शनरी

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

### सेट

सेट में कोई दोहराव नहीं होता।\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> कोई बदलाव नहीं\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> अगर मौजूद हो, तो उसे हटा देता है; अगर नहीं, तो कुछ नहीं करता\
`myset.remove(10)` --> अगर मौजूद न हो, तो exception उठाता है\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> कोई भी एक element प्राप्त करके उसे हटा देता है\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### क्लास

`__lt__` में मौजूद method का उपयोग `sort()` / `sorted()` द्वारा objects की तुलना करने के लिए किया जाएगा।

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

### map, zip, filter, lambda, sorted और one-liners

**Python 3** में, `map()` और `filter()` iterators लौटाते हैं, इसलिए यदि आप सभी values एक साथ print करना चाहते हैं, तो उन्हें `list()` से convert करें।

**Map** `[f(x) for x in iterable]` जैसा है:

```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```

**zip** सबसे छोटी iterable के समाप्त होते ही रुक जाता है:

```python
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** का उपयोग फ़ंक्शन परिभाषित करने के लिए किया जाता है:\
`(lambda x, y: x + y)(5, 3) == 8` --> lambda का उपयोग एक सरल फ़ंक्शन के रूप में करें\
`sorted(range(-5, 6), key=lambda x: x**2)` --> lambda का उपयोग sort करने के लिए करें\
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

### अपवाद

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

यदि condition false है, तो string प्रिंट होगी।\
याद रखें कि `assert` statements को `python -O` से disable किया जा सकता है, इसलिए access control या input validation के लिए इनका उपयोग न करें।

```python
def avg(grades, weights):
    assert len(grades) != 0, 'no grades data'
    assert len(grades) == len(weights), 'wrong number of grades'
```

### Generators, yield

एक generator, सब कुछ एक साथ return करने के बजाय, values को एक-एक करके **yield** करता है। यह बहुत बड़ी wordlists, bruteforcers या बड़े responses के लिए बहुत उपयोगी है।

```python
def my_gen(n):
    yield n
    yield n + 1
```

`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### नियमित अभिव्यक्तियाँ

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
`re.search(pat, string, re.DOTALL)` --> dot को newline से match करने की अनुमति देता है\
`re.search(pat, string, re.MULTILINE)` --> `^` और `$` को अलग-अलग lines में match करने की अनुमति देता है

```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```

### IterTools

**product**\
`from itertools import product` --> 1 या अधिक iterables के बीच Cartesian product

```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```

**permutations**\
`from itertools import permutations` --> हर संभव क्रम-विन्यास

```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```

**combinations**\
`from itertools import combinations` --> बिना दोहराव के सभी संभावित संयोजन

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
`from itertools import batched` --> Python 3.12+ में उपलब्ध, बड़ी bruteforce candidate lists या IOC files को छोटे हिस्सों में बाँटने के लिए उपयोगी છે.

```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```

### Decorators

Decorator जो किसी function को execute होने में लगने वाला समय मापता है:

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

यदि आप इसे चलाते हैं, तो आपको कुछ ऐसा दिखाई देगा:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```

### pentesting के लिए उपयोगी standard library helpers

**`pathlib` से filesystem traversal** (Python 3.12+ में `Path.walk()` उपलब्ध है; पुराने interpreters में `os.walk()` का उपयोग करें):

```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        if name.endswith((".py", ".env", ".bak")):
            print(root / name)
```

**Spawn commands को सुरक्षित रूप से चलाएँ** (`shell=False` डिफ़ॉल्ट रूप से आमतौर पर वही है जो आप चाहते हैं):

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

यदि आपको **shell command** बनाना ही पड़े, तो पहले attacker-controlled हर token को quote करें:

```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```

**अस्थायी फ़ाइलें / डायरेक्टरी** (hardcoded `/tmp/foo` paths से अधिक सुरक्षित):

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "loot.txt"
    out.write_text("secret\n")
    print(out.read_text())
```

HTTP automation के लिए, [Python web requests के बारे में यह दूसरा पेज](web-requests.md) देखें।

### Archive extraction की सावधानियां (tooling और file parsers के लिए महत्वपूर्ण)

**Python 3.14** से, `tarfile.extract()` / `extractall()` डिफ़ॉल्ट रूप से अधिक सुरक्षित `data` filter का उपयोग करते हैं। पुराने Python versions में, attacker-controlled archives को handle करते समय इसे स्पष्ट रूप से set करना चाहिए।<sup>[[1]](#references)[[2]](#references)</sup>

```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
    with tarfile.open("sample.tar.gz") as tf:
        tf.extractall(out, filter="data")
```

`filter="data"` के साथ भी, अविश्वसनीय archives को एक नई temporary directory में extract करें और files को किसी महत्वपूर्ण स्थान पर ले जाने से पहले जांचें कि क्या लिखा गया है।

`zipfile.Path` अलग है: यह आपके लिए filenames को **sanitize नहीं करता**, इसलिए attacker-controlled ZIP members को extract करने से पहले paths को validate करें:

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

### याद रखने योग्य खतरनाक primitives

- `eval()` / `exec()` **sandboxes नहीं हैं**।
- `ast.literal_eval()` Python code execute नहीं करता, लेकिन attacker-controlled input से memory / CPU denial of service के लिए इसका दुरुपयोग किया जा सकता है।
- `pickle.loads()` **secure नहीं है**; attacker-controlled bytes को कभी unpickle न करें।
- और गहरी offensive tricks के लिए [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) और [Python deserializations](../../pentesting-web/deserialization/README.md) देखें।

## References

- [1] [Python tarfile दस्तावेज़](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – tarfile.extractall() के लिए Filter](https://peps.python.org/pep-0706/)
- [3] [venv — virtual environments बनाना — Python 3.14 दस्तावेज़](https://docs.python.org/3/library/venv.html)
- [4] [पैकेज: python3-venv — Ubuntu पैकेज](https://packages.ubuntu.com/noble/python/python3-venv)
- [5] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [6] [wheel — PyPI](https://pypi.org/project/wheel/)
- [7] [क्या setup.py deprecated है? — Python Packaging User Guide](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
