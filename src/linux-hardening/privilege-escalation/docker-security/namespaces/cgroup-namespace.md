# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

cgroup 命名空间是一个 Linux 内核特性，提供 **在命名空间内运行的进程的 cgroup 层次结构的隔离**。Cgroups，简称 **控制组**，是一个内核特性，允许将进程组织成层次组，以管理和强制 **系统资源的限制**，如 CPU、内存和 I/O。

虽然 cgroup 命名空间不是我们之前讨论的其他命名空间类型（PID、挂载、网络等），但它们与命名空间隔离的概念相关。**Cgroup 命名空间虚拟化了 cgroup 层次结构的视图**，因此在 cgroup 命名空间内运行的进程与在主机或其他命名空间中运行的进程相比，具有不同的层次结构视图。

### 工作原理：

1. 当创建一个新的 cgroup 命名空间时，**它以创建进程的 cgroup 为基础开始查看 cgroup 层次结构**。这意味着在新的 cgroup 命名空间中运行的进程将只看到整个 cgroup 层次结构的一个子集，限制在以创建进程的 cgroup 为根的 cgroup 子树内。
2. 在 cgroup 命名空间内的进程将 **将自己的 cgroup 视为层次结构的根**。这意味着，从命名空间内进程的角度来看，它们自己的 cgroup 显示为根，并且它们无法看到或访问其自身子树之外的 cgroup。
3. Cgroup 命名空间并不直接提供资源的隔离；**它们仅提供 cgroup 层次结构视图的隔离**。**资源控制和隔离仍然由 cgroup** 子系统（例如，cpu、内存等）本身强制执行。

有关 CGroups 的更多信息，请查看：

{{#ref}}
../cgroups.md
{{#endref}}

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
通过挂载新的 `/proc` 文件系统实例，如果使用参数 `--mount-proc`，您可以确保新的挂载命名空间具有 **特定于该命名空间的进程信息的准确和隔离的视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当 `unshare` 在没有 `-f` 选项的情况下执行时，由于 Linux 处理新的 PID（进程 ID）命名空间的方式，会遇到错误。关键细节和解决方案如下：

1. **问题说明**：

- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，启动新 PID 命名空间创建的进程（称为 "unshare" 进程）并不会进入新的命名空间；只有它的子进程会进入。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程位于原始 PID 命名空间中。
- 新命名空间中 `/bin/bash` 的第一个子进程成为 PID 1。当该进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 具有收养孤儿进程的特殊角色。然后，Linux 内核将禁用该命名空间中的 PID 分配。

2. **后果**：

- 新命名空间中 PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清理。这导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，从而产生 "无法分配内存" 的错误。

3. **解决方案**：
- 通过在 `unshare` 中使用 `-f` 选项可以解决此问题。此选项使 `unshare` 在创建新的 PID 命名空间后分叉一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。`/bin/bash` 及其子进程随后安全地包含在这个新命名空间中，防止 PID 1 提前退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，使得 `/bin/bash` 及其子进程能够正常运行而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程所在的命名空间
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### 查找所有 CGroup 命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入 CGroup 命名空间
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
此外，您只能**以 root 身份进入另一个进程命名空间**。并且您**不能**在没有指向它的**描述符**的情况下**进入**其他命名空间（如 `/proc/self/ns/cgroup`）。

## 参考

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
