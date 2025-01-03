# 用户命名空间

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

用户命名空间是一个 Linux 内核特性，**提供用户和组 ID 映射的隔离**，允许每个用户命名空间拥有**自己的一组用户和组 ID**。这种隔离使得在不同用户命名空间中运行的进程**可以拥有不同的权限和所有权**，即使它们在数字上共享相同的用户和组 ID。

用户命名空间在容器化中特别有用，每个容器应该拥有自己独立的用户和组 ID 集，从而在容器与主机系统之间提供更好的安全性和隔离。

### 工作原理：

1. 当创建一个新的用户命名空间时，它**以一个空的用户和组 ID 映射集开始**。这意味着在新的用户命名空间中运行的任何进程**最初在命名空间外没有权限**。
2. 可以在新命名空间中的用户和组 ID 与父（或主机）命名空间中的 ID 之间建立 ID 映射。这**允许新命名空间中的进程拥有与父命名空间中的用户和组 ID 相对应的权限和所有权**。然而，ID 映射可以限制在特定范围和子集的 ID 上，从而对新命名空间中授予进程的权限进行细粒度控制。
3. 在用户命名空间内，**进程可以对命名空间内的操作拥有完全的 root 权限（UID 0）**，同时在命名空间外仍然拥有有限的权限。这允许**容器在其自己的命名空间内以类似 root 的能力运行，而不在主机系统上拥有完全的 root 权限**。
4. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或使用带有 `CLONE_NEWUSER` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到新命名空间或创建一个新命名空间时，它将开始使用与该命名空间相关联的用户和组 ID 映射。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
通过挂载新的 `/proc` 文件系统，如果使用参数 `--mount-proc`，您可以确保新的挂载命名空间具有 **特定于该命名空间的进程信息的准确和隔离的视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当 `unshare` 在没有 `-f` 选项的情况下执行时，由于 Linux 处理新的 PID（进程 ID）命名空间的方式，会遇到错误。关键细节和解决方案如下：

1. **问题解释**：

- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，启动新 PID 命名空间创建的进程（称为 "unshare" 进程）并不会进入新的命名空间；只有它的子进程会进入。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程位于原始 PID 命名空间中。
- 新命名空间中 `/bin/bash` 的第一个子进程成为 PID 1。当该进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 具有收养孤儿进程的特殊角色。然后，Linux 内核将禁用该命名空间中的 PID 分配。

2. **后果**：

- 新命名空间中 PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清理。这导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，从而产生 "无法分配内存" 的错误。

3. **解决方案**：
- 通过在 `unshare` 中使用 `-f` 选项可以解决此问题。此选项使 `unshare` 在创建新的 PID 命名空间后分叉一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。`/bin/bash` 及其子进程随后安全地包含在这个新命名空间中，防止 PID 1 的过早退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，使得 `/bin/bash` 及其子进程能够正常运行，而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
要使用用户命名空间，Docker 守护进程需要使用 **`--userns-remap=default`** 启动（在 Ubuntu 14.04 中，可以通过修改 `/etc/default/docker` 然后执行 `sudo service docker restart` 来完成）

### &#x20;检查您的进程在哪个命名空间中
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
可以通过以下命令检查 Docker 容器中的用户映射：
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
或从主机使用：
```bash
cat /proc/<pid>/uid_map
```
### 查找所有用户命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入用户命名空间
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
此外，您只能**以 root 身份进入另一个进程命名空间**。并且您**不能**在没有指向它的**描述符**的情况下**进入**其他命名空间（例如 `/proc/self/ns/user`）。

### 创建新的用户命名空间（带映射）
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
### 恢复能力

在用户命名空间的情况下，**当创建一个新的用户命名空间时，进入该命名空间的进程会被授予该命名空间内的完整能力集**。这些能力允许进程执行特权操作，例如**挂载** **文件系统**、创建设备或更改文件的所有权，但**仅在其用户命名空间的上下文中**。

例如，当你在用户命名空间内拥有 `CAP_SYS_ADMIN` 能力时，你可以执行通常需要此能力的操作，如挂载文件系统，但仅在你的用户命名空间的上下文中。你使用此能力执行的任何操作都不会影响主机系统或其他命名空间。

> [!WARNING]
> 因此，即使在新的用户命名空间内获取一个新进程**会让你恢复所有能力**（CapEff: 000001ffffffffff），你实际上**只能使用与命名空间相关的能力**（例如挂载），而不是每一个。因此，仅凭这一点不足以逃离 Docker 容器。
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
{{#include ../../../../banners/hacktricks-training.md}}
