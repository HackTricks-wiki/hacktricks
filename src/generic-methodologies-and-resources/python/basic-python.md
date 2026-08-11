# Temel Python

{{#include ../../banners/hacktricks-training.md}}

## Python Temelleri

### Yararlı bilgiler

Aşağıdaki tüm örneklerde, açıkça belirtilmediği sürece **Python 3** kullanıldığı varsayılır.\
Python 3'te `range()` yinelenebilir bir nesne döndürür (Python 2'deki `xrange()` ile benzerdir).\
**tuple** ile **list** arasındaki fark, tuple içindeki bir değerin **konumunun** genellikle ona anlam kazandırması, list'in ise genellikle yalnızca sıralı bir değer dizisi olmasıdır.

### Temel işlemler

Bir sayının üssünü almak için şunu kullanırsınız: `3**2` (`3^2` değil)\
Python 3'te `2/3 == 0.666666...` iken, `2//3 == 0` tamsayı bölme işlemi gerçekleştirir.\
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
`dir(str)` = kullanılabilir metotların listesi\
`help(str)` = `str` sınıfının tanımı\
`"a".upper() == "A"`\
`"A".lower() == "a"`\
`"abc".capitalize() == "Abc"`\
`sum([1, 2, 3]) == 6`\
`sorted([1, 43, 5, 3, 21, 4]) == [1, 3, 4, 5, 21, 43]`

**Karakterleri birleştirme**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**Bir list'in / string'in bölümleri**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**Yorumlar**\
`# One line comment`\
`""" Several lines comment """`

**Döngüler**
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
### Byte'lar, hex ve encoding'ler

Bu, exploit-dev, reversing ve CTF'lerde çok yaygındır:
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

### Liste (array)

`d = []` empty\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> from list to tuple

### Sözlük
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
### Kümeler

Kümelerde tekrar yoktur.\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> değişiklik olmaz\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> mevcutsa kaldırır; değilse hiçbir şey yapmaz\
`myset.remove(10)` --> mevcut değilse istisna oluşturur\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> rastgele bir öğe alır ve kaldırır\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Sınıflar

`__lt__` içindeki method, nesneleri karşılaştırmak için `sort()` / `sorted()` tarafından kullanılır.
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
### map, zip, filter, lambda, sorted ve tek satırlık ifadeler

**Python 3**'te `map()` ve `filter()` iterator döndürür; bu nedenle tüm değerleri aynı anda yazdırmak istiyorsanız bunları `list()` ile dönüştürün.

**Map**, `[f(x) for x in iterable]` gibidir:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip**, daha kısa iterable sona erdiğinde durur:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda**, bir işlev tanımlamak için kullanılır:\
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

### İstisnalar
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

Koşul yanlışsa dize yazdırılır.\
`assert` ifadelerinin `python -O` ile devre dışı bırakılabileceğini unutmayın; bu nedenle bunları erişim denetimi veya girdi doğrulama için kullanmayın.
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### Generators, yield

Bir generator, her şeyi tek seferde döndürmek yerine değerleri birer birer **yield** eder. Bu, büyük wordlist'ler, bruteforce araçları veya büyük response'lar için çok kullanışlıdır.
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### Düzenli İfadeler
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**Özel anlamlar:**\
`.` --> satır sonu hariç herhangi bir karakter\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> rakam\
`\s` --> boşluk karakteri `[ \n\r\t\f]`\
`\S` --> boşluk olmayan karakter\
`^` --> ile başlar\
`$` --> ile biter\
`+` --> bir veya daha fazla\
`*` --> 0 veya daha fazla\
`?` --> 0 veya 1 oluşum

**Seçenekler:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> noktanın satır sonlarıyla eşleşmesine izin verir\
`re.search(pat, string, re.MULTILINE)` --> `^` ve `$` karakterlerinin farklı satırlarda eşleşmesine izin verir
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> 1 veya daha fazla iterable arasındaki kartezyen çarpım
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> olası tüm düzenlemeler
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**kombinasyonlar**\
`from itertools import combinations` --> tekrarsız tüm olası kombinasyonlar
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
`from itertools import batched` --> Python 3.12+ sürümlerinde kullanılabilir; büyük bruteforce aday listelerini veya IOC dosyalarını parçalara bölmek için kullanışlıdır
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### Dekoratörler

Bir işlevin yürütülmesi için gereken süreyi ölçen dekoratör:
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
Çalıştırırsanız aşağıdakine benzer bir şey görürsünüz:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### pentesting için kullanışlı standart kütüphane yardımcıları

**`pathlib` ile dosya sistemi üzerinde gezinme** (`Path.walk()` Python 3.12+ sürümlerinde kullanılabilir; daha eski yorumlayıcılarda `os.walk()` kullanın):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**Komutları güvenli şekilde başlatın** (`shell=False` varsayılan olarak genellikle istediğiniz seçenektir):
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
**Bir shell komutu oluşturmanız gerekiyorsa**, önce saldırgan tarafından kontrol edilen her token'ı tırnak içine alın:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**Geçici dosyalar / dizinler** (sabit kodlanmış `/tmp/foo` yollarından daha güvenli):
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
HTTP automation için [Python web requests hakkında bu diğer sayfaya](web-requests.md) bakın.

### Archive extraction gotchas (tooling ve file parser'ları için önemli)

**Python 3.14** sürümünden itibaren `tarfile.extract()` / `extractall()`, varsayılan olarak daha güvenli olan `data` filter'ını kullanır. Daha eski Python sürümlerinde, attacker-controlled archive'larla çalışırken bunu açıkça ayarlamalısınız.<sup>[[1]](#references)[[2]](#references)</sup>
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
`filter="data"` kullanılsa bile güvenilmeyen arşivleri yeni bir geçici dizine çıkarın ve dosyaları ilgi çekici herhangi bir yere taşımadan önce yazılanları doğrulayın.

`zipfile.Path` farklıdır: dosya adlarını sizin için **sanitize etmez**, bu nedenle saldırgan kontrollü ZIP üyelerini çıkarmadan önce yolları doğrulayın:
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
### Hatırlanması gereken tehlikeli primitives

- `eval()` / `exec()` **sandbox değildir**.
- `ast.literal_eval()` Python kodunu çalıştırmaz, ancak saldırgan kontrollü girdilerle bellek / CPU hizmet reddi saldırısı için kötüye kullanılabilir.
- `pickle.loads()` **güvenli değildir**; saldırgan kontrollü byte'ları asla unpickle etmeyin.
- Daha gelişmiş offensive tricks için [Bypass Python sandboxes](bypass-python-sandboxes/README.md), [Python internal read gadgets](python-internal-read-gadgets.md) ve [Python deserializations](../../pentesting-web/deserialization/README.md) bölümlerine bakın.

## References

- [1] [Python tarfile belgeleri](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – tarfile.extractall() için filtre](https://peps.python.org/pep-0706/)
{{#include ../../banners/hacktricks-training.md}}
