# Python ya Msingi

{{#include ../../banners/hacktricks-training.md}}

## Mazingira pepe na ujenzi wa wheel (`venv`)

Moduli ya kawaida ya Python ya `venv` huunda mazingira pepe, ambayo hati yake ya kuwezesha ya POSIX ni `<venv>/bin/activate`; andika `deactivate` ili kuondoka kwenye mazingira yanayotumika.<sup>[[3]](#references)</sup> Kwenye Ubuntu, kifurushi cha `python3-venv` hutoa moduli hiyo ikiwa haijasakinishwa pamoja na kifurushi cha msingi cha Python.<sup>[[4]](#references)</sup>

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

Kwa workflows za zamani za `setuptools` zinazotumia `setup.py bdist_wheel`, kusakinisha `wheel` katika mazingira yanayotumika kulitoa amri ya `bdist_wheel`.<sup>[[5]](#references)</sup> Matoleo ya sasa ya `setuptools` hayahitaji tena `wheel` kwa amri hiyo, na mwongozo wa sasa wa packaging unapendekeza `python -m build --wheel` badala ya kuendesha `setup.py` moja kwa moja.<sup>[[6]](#references)[[7]](#references)</sup>

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

## Misingi ya Python

### Taarifa muhimu

Mifano yote iliyo hapa chini inadhania **Python 3**, isipokuwa pale inapobainishwa waziwazi.\
`range()` hurejesha kitu kinachoweza kurudiwa (iterable) katika Python 3 (sawa na `xrange()` katika Python 2).\
Tofauti kati ya **tuple** na **list** ni kwamba **nafasi** ya thamani katika tuple kwa kawaida huipa maana, ilhali list kwa kawaida ni mfuatano wa thamani uliopangwa tu.

### Operesheni kuu

Ili kuinua nambari kwa kipeo, tumia: `3**2` (si `3^2`)\
`2/3 == 0.666666...` katika Python 3, ilhali `2//3 == 0` hufanya mgawanyo wa nambari kamili.\
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
`dir(str)` = orodha ya mbinu zinazopatikana\
`help(str)` = ufafanuzi wa class `str`\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**Kuunganisha herufi**\
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

**Mizunguko**

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

Hili ni jambo la kawaida sana katika exploit-dev, reversing na CTFs:

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
`(4,)` = tuple yenye kipengele kimoja\
`d = ()` tuple tupu\
`d += (4,)` --> ongeza kwenye tuple\
`# t1[1] = 'new value'` --> tuples hazibadiliki\
`list(t2) == [5, 6]` --> badilisha tuple kuwa list

### List (array)

`d = []` tupu\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> badilisha list kuwa tuple

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

Katika set hakuna marudio.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> hakuna mabadiliko\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> ikiwa ipo, iondoe; ikiwa haipo, hakuna kitakachofanyika\
`myset.remove(10)` --> ikiwa haipo, huleta exception\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> pata kipengele chochote na ukiondoe\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Madarasa

Mbinu iliyo katika `__lt__` ndiyo itakayotumiwa na `sort()` / `sorted()` kulinganisha objects.

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

### map, zip, filter, lambda, sorted na one-liners

Katika **Python 3**, `map()` na `filter()` hurudisha iterators, kwa hivyo zibadilishe kwa `list()` ikiwa unataka kuchapisha thamani zote mara moja.

**Map** ni kama `[f(x) for x in iterable]`:

```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```

**zip** husimama pale iterable fupi zaidi inapoisha:

```python
for f, b in zip(foo, bar):
    print(f, b)
```

**Lambda** hutumika kufafanua function:\
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

### Vighairi

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

Ikiwa sharti si kweli, string itaonyeshwa.\
Kumbuka kwamba kauli za `assert` zinaweza kuzimwa kwa kutumia `python -O`, kwa hivyo usizitumie kudhibiti ufikiaji au kuthibitisha ingizo.

```python
def avg(grades, weights):
    assert len(grades) != 0, 'no grades data'
    assert len(grades) == len(weights), 'wrong number of grades'
```

### Generators, yield

Generator, badala ya kurudisha kila kitu mara moja, **hutoa** thamani moja baada ya nyingine. Hii ni muhimu sana kwa wordlists kubwa, bruteforcers au majibu makubwa.

```python
def my_gen(n):
    yield n
    yield n + 1
```

`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Misemo ya Kawaida

```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```

**Maana maalum:**\
`.` --> herufi yoyote isipokuwa mstari mpya\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> tarakimu\
`\s` --> herufi ya nafasi nyeupe `[ \n\r\t\f]`\
`\S` --> herufi isiyo ya nafasi nyeupe\
`^` --> huanza na\
`$` --> huisha na\
`+` --> moja au zaidi\
`*` --> 0 au zaidi\
`?` --> matukio 0 au 1

**Chaguo:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> ruhusu nukta ilingane na mstari mpya\
`re.search(pat, string, re.MULTILINE)` --> ruhusu `^` na `$` zilingane katika mistari tofauti

```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```

### IterTools

**product**\
`from itertools import product` --> bidhaa ya Cartesian kati ya iterable moja au zaidi

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

**combinations**\
`from itertools import combinations` --> michanganyiko yote inayowezekana bila kurudia

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
`from itertools import batched` --> inapatikana katika Python 3.12+, ni muhimu kugawa orodha kubwa za wagombea wa bruteforce au faili za IOC katika mafungu.

```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```

### Decorators

Decorator inayopima muda unaohitajika kutekeleza function:

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

Ukiikiendesha, utaona kitu kama hiki:

```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```

### Vifaa saidizi muhimu vya maktaba ya kawaida kwa pentesting

**Kupitia mfumo wa faili kwa `pathlib`** (`Path.walk()` inapatikana katika Python 3.12+; tumia `os.walk()` kwenye interpreter za zamani):

```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
    if ".git" in dirs:
        dirs.remove(".git")
    for name in files:
        if name.endswith((".py", ".env", ".bak")):
            print(root / name)
```

**Endesha amri kwa usalama** (`shell=False` kwa chaguomsingi ndicho unachohitaji kwa kawaida):

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

Ikiwa **lazima** utengeneze amri ya shell, kwanza weka alama za kunukuu kuzunguka kila token inayodhibitiwa na mshambuliaji:

```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```

**Faili / saraka za muda** (salama zaidi kuliko njia za `/tmp/foo` zilizowekwa moja kwa moja):

```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    out = Path(tmp) / "loot.txt"
    out.write_text("secret\n")
    print(out.read_text())
```

Kwa uendeshaji wa HTTP kiotomatiki, angalia [ukurasa huu mwingine kuhusu maombi ya wavuti ya Python](web-requests.md).

### Mambo ya kuzingatia wakati wa kutoa kumbukumbu (muhimu kwa zana na vichanganuzi vya faili)

Kuanzia **Python 3.14**, `tarfile.extract()` / `extractall()` hutumia kichujio salama zaidi cha `data` kwa chaguomsingi. Katika matoleo ya zamani ya Python, unapaswa kukiweka wazi unaposhughulikia kumbukumbu zinazodhibitiwa na washambuliaji.<sup>[[1]](#references)[[2]](#references)</sup>

```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
    with tarfile.open("sample.tar.gz") as tf:
        tf.extractall(out, filter="data")
```

Hata ukitumia `filter="data"`, fungua kumbukumbu zisizoaminika kwenye saraka mpya ya muda na uthibitishe kilichoandikwa kabla ya kuhamisha faili mahali popote muhimu.

`zipfile.Path` ni tofauti: **haisafishi majina ya faili** kwa ajili yako, kwa hiyo thibitisha njia kabla ya kufungua washiriki wa ZIP wanaodhibitiwa na mshambuliaji:

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

### Primitive hatari za kukumbuka

- `eval()` / `exec()` **si** sandboxes.
- `ast.literal_eval()` **haiendeshi** msimbo wa Python, lakini bado inaweza kutumiwa vibaya kusababisha kunyimwa huduma kwa kutumia kumbukumbu / CPU kupitia ingizo linalodhibitiwa na mshambulizi.
- `pickle.loads()` **si salama**; usiwahi kufanya unpickle ya byte zinazodhibitiwa na mshambulizi.
- Kwa mbinu za kina zaidi za mashambulizi, angalia [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) na [Python deserializations](../../pentesting-web/deserialization/README.md).

## References

- [1] [Nyaraka za Python tarfile](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – Kichujio cha tarfile.extractall()](https://peps.python.org/pep-0706/)
- [3] [venv — Uundaji wa mazingira pepe — Nyaraka za Python 3.14](https://docs.python.org/3/library/venv.html)
- [4] [Kifurushi: python3-venv — Vifurushi vya Ubuntu](https://packages.ubuntu.com/noble/python/python3-venv)
- [5] [wheel 0.24.0 — PyPI](https://pypi.org/project/wheel/0.24.0/)
- [6] [wheel — PyPI](https://pypi.org/project/wheel/)
- [7] [Je, setup.py imeacha kutumika? — Mwongozo wa Mtumiaji wa Python Packaging](https://packaging.python.org/en/latest/discussions/setup-py-deprecated/)
{{#include ../../banners/hacktricks-training.md}}
