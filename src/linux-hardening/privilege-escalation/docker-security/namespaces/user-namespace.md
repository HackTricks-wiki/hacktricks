# 用户命名空间

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## 参考

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## 基本信息

用户命名空间是 Linux 内核的一项功能，**提供用户和组 ID 映射的隔离**，允许每个用户命名空间拥有其**自己的一组用户和组 ID**。这种隔离使得运行在不同用户命名空间中的进程即使在数值上共享相同的用户和组 ID，也可以**具有不同的权限和所有权**。

用户命名空间在容器化中尤为有用，每个容器应该有自己独立的一组用户和组 ID，从而在容器与宿主系统之间实现更好的安全性和隔离。

### 工作原理：

1. 当创建一个新的用户命名空间时，它**以一个空的用户和组 ID 映射集合开始**。这意味着在新用户命名空间中运行的任何进程**最初在命名空间外没有特权**。
2. 可以在新命名空间中的用户和组 ID 与父命名空间（或宿主）中的 ID 之间建立映射。这**允许新命名空间中的进程拥有与父命名空间中的用户和组 ID 相对应的权限和所有权**。然而，ID 映射可以限制为特定范围和子集，从而对授予新命名空间中进程的权限进行细粒度控制。
3. 在用户命名空间内，**进程可以在命名空间内部拥有完整的 root 权限（UID 0）**，同时在命名空间外仍然具有受限的权限。这允许**容器在其自身的命名空间内以类似 root 的能力运行，而不会在宿主系统上拥有完全的 root 权限**。
4. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或使用带有 `CLONE_NEWUSER` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到一个新的命名空间或创建一个命名空间时，它将开始使用与该命名空间关联的用户和组 ID 映射。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **准确且隔离的该命名空间特定进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **问题说明**:

- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，发起创建新 PID 命名空间的进程（称为 `unshare` 进程）本身并不会进入新的命名空间；只有它的子进程会进入。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程仍处于原始 PID 命名空间。
- 在新命名空间中，`/bin/bash` 的第一个子进程会成为 PID 1。当该进程退出时，如果没有其他进程存在，会触发该命名空间的清理，因为 PID 1 拥有收养孤儿进程的特殊角色。然后 Linux 内核会在该命名空间中禁用 PID 分配。

2. **后果**:

- 在新命名空间中 PID 1 的退出会导致 `PIDNS_HASH_ADDING` 标志被清除。这会导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，从而产生“无法分配内存”错误。

3. **解决方案**:
- 可以通过在 `unshare` 中使用 `-f` 选项来解决此问题。该选项会在创建新的 PID 命名空间后让 `unshare` fork 出一个新进程。
- 运行 `%unshare -fp /bin/bash%` 可确保 `unshare` 命令本身在新命名空间中成为 PID 1。随后 `/bin/bash` 及其子进程会被安全地限制在该新命名空间内，防止 PID 1 提前退出并允许正常的 PID 分配。

通过确保使用 `-f` 参数运行 `unshare`，可以正确维护新的 PID 命名空间，从而允许 `/bin/bash` 及其子进程在不遇到内存分配错误的情况下运行。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
要使用 user namespace，Docker daemon 需要以 **`--userns-remap=default`** 启动（在 ubuntu 14.04 中，这可以通过修改 `/etc/default/docker` 然后执行 `sudo service docker restart` 完成）

### 检查你的进程在哪个 namespace 中
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
可以在 docker container 中使用以下命令检查 user map：
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
或者从主机使用：
```bash
cat /proc/<pid>/uid_map
```
### 查找所有用户命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入 User 命名空间
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
另外，你只能 **以 root 身份进入另一个进程的 namespace**。并且你**不能在没有指向它的描述符的情况下进入**其他 namespace（例如 `/proc/self/ns/user`）。

### 创建新的 User namespace（带映射）
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### 非特权 UID/GID 映射规则

当向 `uid_map`/`gid_map` 写入的进程 **在父用户命名空间中没有 CAP_SETUID/CAP_SETGID** 时，内核会施加更严格的规则：对于调用者的有效 UID/GID，只允许一个 **单一映射**；并且对于 `gid_map`，你 **必须先通过向 `/proc/<pid>/setgroups` 写入 `deny` 来禁用 `setgroups(2)`**。
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID 映射的挂载 (MOUNT_ATTR_IDMAP)

ID-mapped mounts **将用户命名空间的映射附加到一个挂载点**，因此通过该挂载点访问时文件所有权会被重映射。这通常被容器运行时（尤其是 rootless）用来**在不进行递归 `chown` 的情况下共享宿主路径**，同时仍然强制执行用户命名空间的 UID/GID 翻译。

从攻击角度来看，**如果你能创建一个 mount namespace 并在你的用户命名空间内持有 `CAP_SYS_ADMIN`**，并且文件系统支持 ID-mapped mounts，你可以重映射 bind 挂载的所有权 *视图*。这**不会改变磁盘上的实际所有权**，但可以使原本不可写的文件在该命名空间内显示为由你映射的 UID/GID 拥有。

### 恢复 Capabilities

在用户命名空间的情况下，**当创建一个新的用户命名空间时，进入该命名空间的进程会被授予该命名空间内的一整套 capabilities**。这些 capabilities 允许进程执行特权操作，例如 **挂载** **文件系统**、创建设备或改变文件所有权，但**仅限于其用户命名空间的上下文内**。

例如，当你在用户命名空间内拥有 `CAP_SYS_ADMIN` 时，你可以执行通常需要该 capability 的操作，比如挂载文件系统，但仅限于你的用户命名空间的上下文。你使用该 capability 执行的任何操作都不会影响宿主系统或其他命名空间。

> [!WARNING]
> 因此，即使在新的用户命名空间中获取一个新进程会**把所有 capabilities 都还给你** (CapEff: 000001ffffffffff)，你实际上**只能使用与该命名空间相关的那些能力**（例如用于挂载的能力），而不是全部能力。所以，仅凭这一点并不足以逃离 Docker 容器。
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## 参考资料

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
