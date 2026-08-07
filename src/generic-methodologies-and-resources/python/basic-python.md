# Basic Python

{{#include ../../banners/hacktricks-training.md}}

## Pythonの基礎

### 役立つ情報

以下のすべての例は、明示的に記載されていない限り **Python 3** を前提としています。\
Python 3では `range()` は反復可能オブジェクトを返します（Python 2の `xrange()` に類似）。\
**tuple** と **list** の違いは、tupleでは通常、値の**位置**が意味を持つのに対し、listは通常、値を順序付けした単なるシーケンスである点です。

### 主な操作

数値の累乗には `3**2` を使用します（`3^2` ではありません）。\
Python 3では `2/3 == 0.666666...` ですが、`2//3 == 0` は整数除算を実行します。\
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

**文字の結合**\
`3 * 'a' == 'aaa'`\
`'a' + 'b' == 'ab'`\
`'a' + str(3) == 'a3'`\
`[1, 2, 3] + [4, 5] == [1, 2, 3, 4, 5]`

**list / stringの一部**\
`'abc'[0] == 'a'`\
`'abc'[-1] == 'c'`\
`'abc'[1:3] == 'bc'`\
`"qwertyuiop"[:-1] == 'qwertyuio'`

**コメント**\
`# One line comment`\
`""" Several lines comment """`

**ループ**
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
### Bytes、hex、encoding

これは exploit-dev、reversing、CTF で非常によく使われます:
```python
b"ABC".hex() == "414243"
bytes.fromhex("414243") == b"ABC"
int.from_bytes(b"\x41\x42\x43", "big") == 0x414243
(0x414243).to_bytes(3, "big") == b"ABC"
"admin".encode() == b"admin"
b"admin".decode() == "admin"
```
### タプル

`t1 = (1, '2', 'three')`\
`t2 = (5, 6)`\
`t3 = t1 + t2 == (1, '2', 'three', 5, 6)`\
`(4,)` = 要素が1つのタプル\
`d = ()` 空のタプル\
`d += (4,)` --> タプルに追加\
`# t1[1] = 'new value'` --> タプルは変更不可\
`list(t2) == [5, 6]` --> タプルからリストへ

### リスト (array)

`d = []` 空\
`a = [1, 2, 3]`\
`b = [4, 5]`\
`a + b == [1, 2, 3, 4, 5]`\
`b.append(6)` --> `b == [4, 5, 6]`\
`tuple(a) == (1, 2, 3)` --> リストからタプルへ

### 辞書
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

Set には重複がありません。\
`myset = set(['a', 'b']) == {'a', 'b'}`\
`myset.add('c')` --> `{'a', 'b', 'c'}`\
`myset.add('a')` --> 変更なし\
`myset.update([1, 2, 3])`\
`myset.discard(10)` --> 存在する場合は削除し、存在しない場合は何もしない\
`myset.remove(10)` --> 存在しない場合は例外を発生させる\
`myset2 = set([1, 2, 3, 4])`\
`myset.union(myset2)`\
`myset.intersection(myset2)`\
`myset.difference(myset2)`\
`myset.symmetric_difference(myset2)`\
`myset.pop()` --> 任意の要素を取得して削除する\
`myset.intersection_update(myset2)`\
`myset.difference_update(myset2)`\
`myset.symmetric_difference_update(myset2)`

### クラス

`__lt__` 内のメソッドが、オブジェクトの比較時に `sort()` / `sorted()` で使用されます。
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
### map, zip, filter, lambda, sorted と one-liners

**Python 3** では、`map()` と `filter()` は iterator を返すため、すべての値を一度に表示したい場合は `list()` で変換します。

**Map** は `[f(x) for x in iterable]` と同様です:
```python
list(map(tuple, [[1, 2, 3], [4, 5]]))
# [(1, 2, 3), (4, 5)]

list(map(lambda x: x % 3 == 0, [1, 2, 3, 4, 5, 6, 7, 8, 9]))
# [False, False, True, False, False, True, False, False, True]
```
**zip** は、短い方のイテラブルが終了すると停止します：
```python
for f, b in zip(foo, bar):
print(f, b)
```
**Lambda** は関数を定義するために使用されます:\
`(lambda x, y: x + y)(5, 3) == 8` --> lambda を単純な関数として使用\
`sorted(range(-5, 6), key=lambda x: x**2)` --> lambda をソートに使用\
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
### Generators, yield

generator はすべてを一度に返す代わりに、値を1つずつ **yield** します。これは巨大な wordlists、bruteforcers、または大きなレスポンスに非常に役立ちます。
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
**Special meanings:**\
`.` --> 改行以外の任意の文字\
`\w` --> `[a-zA-Z0-9_]`\
`\d` --> 数字\
`\s` --> 空白文字 `[ \n\r\t\f]`\
`\S` --> 空白以外の文字\
`^` --> で始まる\
`$` --> で終わる\
`+` --> 1つ以上\
`*` --> 0個以上\
`?` --> 0回または1回の出現

**Options:**\
`re.search(pat, string, re.IGNORECASE)`\
`re.search(pat, string, re.DOTALL)` --> ドットが改行にマッチすることを許可\
`re.search(pat, string, re.MULTILINE)` --> `^` と `$` が異なる行でマッチすることを許可
```python
re.findall(r"<.*>", "<b>foo</b>and<i>so on</i>")
# ['<b>foo</b>and<i>so on</i>']

re.findall(r"<.*?>", "<b>foo</b>and<i>so on</i>")
# ['<b>', '</b>', '<i>', '</i>']
```
### IterTools

**product**\
`from itertools import product` --> 1つ以上の iterable 間の直積
```python
list(product([1, 2, 3], [3, 4]))
# [(1, 3), (1, 4), (2, 3), (2, 4), (3, 3), (3, 4)]

list(product([1, 2, 3], repeat=2))
# [(1, 1), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)]
```
**permutations**\
`from itertools import permutations` --> あらゆる可能な配列
```python
list(permutations(['1', '2', '3']))
list(permutations('123', 2))
```
**組み合わせ**\
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
`from itertools import batched` --> Python 3.12以降で利用可能。大規模なbruteforce候補リストやIOCファイルを分割するのに便利です。
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
実行すると、次のような内容が表示されます。
```text
Let's call our decorated function
Decorated func!
Execution time: 4.79e-05 seconds
```
### pentesting に役立つ標準ライブラリヘルパー

**`pathlib` によるファイルシステムの走査**（`Path.walk()` は Python 3.12 以降で利用可能です。古いインタープリターでは `os.walk()` を使用してください）：
```python
from pathlib import Path

for root, dirs, files in Path(".").walk():
if ".git" in dirs:
dirs.remove(".git")
for name in files:
if name.endswith((".py", ".env", ".bak")):
print(root / name)
```
**コマンドを安全に起動する**（通常はデフォルトの `shell=False` が望ましいです）：
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
シェルコマンドを**構築しなければならない**場合は、攻撃者が制御する各トークンをまずクォートしてください:
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
HTTP automation については、[Python web requests に関するこちらのページ](web-requests.md)を確認してください。

### Archive extraction gotchas (tooling と file parsers に重要)

**Python 3.14** 以降では、`tarfile.extract()` / `extractall()` はデフォルトでより安全な `data` filter を使用します。古い Python versions では、attacker-controlled archives を処理する際に明示的に設定してください。<sup>[[1]](#references)[[2]](#references)</sup>
```python
import tarfile
import tempfile

with tempfile.TemporaryDirectory() as out:
with tarfile.open("sample.tar.gz") as tf:
tf.extractall(out, filter="data")
```
`filter="data"` を使っていても、信頼できない archive は新しい一時ディレクトリに展開し、ファイルを重要な場所へ移動する前に、書き込まれた内容を検証してください。

`zipfile.Path` は異なります。ファイル名を自動的に **sanitize しない** ため、攻撃者が制御する ZIP member を展開する前にパスを検証してください:
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
### 覚えておくべき危険なプリミティブ

- `eval()` / `exec()` は **sandbox ではありません**。
- `ast.literal_eval()` は **Python コードを実行しません**が、攻撃者が制御する入力によってメモリ / CPU の denial of service に悪用される可能性があります。
- `pickle.loads()` は **secure ではありません**。攻撃者が制御する bytes を決して unpickle しないでください。
- より高度な offensive tricks については、[Bypass Python sandboxes](bypass-python-sandboxes/README.md)、[Python internal read gadgets](python-internal-read-gadgets.md)、[Python deserializations](../../pentesting-web/deserialization/README.md) を確認してください。

## 参考資料

- [1] [Python tarfile docs](https://docs.python.org/3/library/tarfile.html)
- [2] [PEP 706 – tarfile.extractall() の Filter](https://peps.python.org/pep-0706/)

{{#include ../../banners/hacktricks-training.md}}
