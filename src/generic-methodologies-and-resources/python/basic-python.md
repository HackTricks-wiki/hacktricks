# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Python Basics

### Useful information

以下の例は、特に明記がない限り **Python 3** を前提としています。\
`range()` は Python 3 では iterable オブジェクトを返します（Python 2 の `xrange()` に似ています）。\
**tuple** と **list** の違いは、tuple では値の **位置** に意味があることが多いのに対し、list は通常、値の順序付きの並びにすぎないことです。

### Main operations

数をべき乗するには: `3**2`（`3^2` ではない）\
Python 3 では `2/3 == 0.666666...` ですが、`2//3 == 0` は整数除算を行います。\
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
`dir(str)` = 利用可能なメソッドの一覧\
`help(str)` = クラス `str` の定義\
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
### バイト、hex と encodings

これは exploit-dev、reversing、CTF で非常に一般的です:
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
`d = ()` 空のtuple\
`d += (4,)` --> tupleに追加\
`# t1[1] = 'new value'` --> tuples are immutable\
`list(t2) == [5, 6]` --> tupleからlistへ

### List (array)

`d = []` 空\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> listからtupleへ

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

sets には繰り返しはありません。\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> 変更なし\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> 存在すれば削除し、存在しなければ何もしない\
`myset.remove(10)` --> 存在しなければ例外を送出\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> 任意の要素を取得して削除する\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### Classes

`__lt__` のメソッドが、`sort()` / `sorted()` でオブジェクトを比較するために使われるものになります。
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

**Python 3** では、`map()` と `filter()` はイテレータを返すので、すべての値を一度に表示したい場合は `list()` で変換してください。

**Map** は `[f(x) for x in iterable]` のようなものです:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** は、短い方の iterable が終わると停止する:
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** は関数を定義するために使われる:\
`(lambda x, y: x + y)(5, 3) == 8` --> lambda を簡単な関数として使う\
`sorted(range(-5, 6), key=lambda x: x**2)` --> lambda を使ってソートする\
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

### 例外
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

条件が false の場合、文字列が出力されます。\
`assert` 文は `python -O` で無効化できるため、アクセス制御や入力検証には使用しないでください。
```python
def avg(grades, weights):
assert len(grades) != 0, 'no grades data'
assert len(grades) == len(weights), 'wrong number of grades'
```
### ジェネレーター, yield

ジェネレーターは、すべてを一度に返すのではなく、値を1つずつ**yield**します。これは、巨大な wordlists、bruteforcers、または大きなレスポンスに非常に便利です。
```python
def my_gen(n):
yield n
yield n + 1
```
`g = my_gen(6)`\
`next(g) == 6`\
`next(g) == 7`\
`next(g)` --> `StopIteration`

### 正規表現
```python
import re

re.search(r"\w", "hola").group() == "h"
re.findall(r"\w", "hola") == ['h', 'o', 'l', 'a']
re.findall(r"\w+(la)", "hola caracola") == ['la', 'la']
```
**特殊な意味:**\
`.` --> 改行以外の任意の文字\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> 数字\
`\s` --> 空白文字 `[ \n\r\t\f]`\
`\S` --> 空白文字以外の文字\
`^` --> で始まる\
`$` --> で終わる\
`+` --> 1回以上\
`*` --> 0回以上\
`?` --> 0回または1回出現

**オプション:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> dot が改行にマッチするのを許可\
`re.search(pat, string, re.MULTILINE)` --> `^` と `$` が別々の行でマッチするのを許可
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> 1つ以上のiterables間のcartesian product
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> すべての可能な並び替え
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**combinations**\
`from itertools import combinations` --> 重複なしのすべての可能な組み合わせ
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
`from itertools import batched` --> Python 3.12+ で利用可能。大きなブルートフォース候補リストや IOC ファイルをチャンク分割するのに便利。
```python
list(batched(range(10), 4))
# [(0, 1, 2, 3), (4, 5, 6, 7), (8, 9)]
```
### デコレータ

関数の実行に必要な時間を測定するデコレータ:
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
実行すると、以下のようなものが表示されます:
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### pentesting に役立つ標準ライブラリヘルパー

**`pathlib` による filesystem traversal** (`Path.walk()` は Python 3.12+ で利用可能です; 古い interpreter では `os.walk()` を使ってください):
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**コマンドを安全に起動する** (`shell=False` がデフォルトで、通常はこれを使うべきです):
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
シェルコマンドを**どうしても**構築する必要がある場合は、まず attacker-controlled な各トークンを引用符で囲んでください:
```python
import shlex
cmd = f"grep -R {shlex.quote(user_controlled)} /var/www"
```
**一時ファイル / ディレクトリ**（ハードコードされた `/tmp/foo` パスより安全）:
```python
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
out = Path(tmp) / "loot.txt"
out.write_text("secret\n")
print(out.read_text())
```
HTTP 自動化については、[Python の web requests に関するこちらの別ページ](web-requests.md)を確認してください。

### アーカイブ展開の落とし穴（ツールやファイルパーサーに重要）

**Python 3.14** では、`tarfile.extract()` / `extractall()` はデフォルトでより安全な `data` filter を使用します。古い Python バージョンでは、攻撃者が制御するアーカイブを扱う際に、明示的に設定するべきです。
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
`filter="data"` を使っていても、信頼できないアーカイブは新しい一時ディレクトリに展開し、どこか重要な場所へファイルを移動する前に、書き込まれた内容を検証してください。

`zipfile.Path` は異なります。これは **ファイル名を自動でサニタイズしません**。そのため、攻撃者制御の ZIP メンバーを展開する前にパスを検証してください:
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
### 危険なプリミティブとして覚えておくべきもの

- `eval()` / `exec()` は **sandbox** ではない。
- `ast.literal_eval()` は Python code を実行しないが、attacker-controlled input によって memory / CPU denial of service に悪用される可能性がある。
- `pickle.loads()` は **secure** ではない; attacker-controlled bytes を絶対に unpickle しないこと。
- より深い offensive tricks については、[Bypass Python sandboxes](bypass-python-sandboxes/README.md)、[Python internal read gadgets](python-internal-read-gadgets.md)、[Python deserializations](../../pentesting-web/deserialization/README.md) を確認してほしい。

## References

- [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [PEP 706 - Filter for tarfile.extractall](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
