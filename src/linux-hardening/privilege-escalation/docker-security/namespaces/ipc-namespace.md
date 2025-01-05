# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

IPC（进程间通信）命名空间是一个Linux内核特性，提供**隔离**System V IPC对象，如消息队列、共享内存段和信号量。这种隔离确保**不同IPC命名空间中的进程无法直接访问或修改彼此的IPC对象**，为进程组之间提供额外的安全性和隐私保护。

### 工作原理：

1. 当创建一个新的IPC命名空间时，它会以**完全隔离的System V IPC对象集**开始。这意味着在新的IPC命名空间中运行的进程默认无法访问或干扰其他命名空间或主机系统中的IPC对象。
2. 在命名空间内创建的IPC对象仅对**该命名空间内的进程可见和可访问**。每个IPC对象在其命名空间内由唯一的键标识。尽管在不同命名空间中键可能相同，但对象本身是隔离的，无法跨命名空间访问。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或使用带有`CLONE_NEWIPC`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新命名空间或创建一个时，它将开始使用与该命名空间关联的IPC对象。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
通过挂载新的 `/proc` 文件系统实例，如果使用参数 `--mount-proc`，您可以确保新的挂载命名空间具有 **特定于该命名空间的进程信息的准确和隔离视图**。

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
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新的命名空间中成为 PID 1。`/bin/bash` 及其子进程随后安全地包含在这个新命名空间中，防止 PID 1 提前退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，允许 `/bin/bash` 及其子进程在不遇到内存分配错误的情况下运行。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程所在的命名空间
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### 查找所有 IPC 命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入 IPC 命名空间
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
此外，您只能**以 root 身份进入另一个进程命名空间**。并且您**不能**在没有指向它的描述符的情况下**进入**其他命名空间（例如 `/proc/self/ns/net`）。

### 创建 IPC 对象
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## 参考

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
