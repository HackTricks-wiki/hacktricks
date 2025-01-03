# 网络命名空间

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

网络命名空间是一个Linux内核特性，提供网络栈的隔离，允许**每个网络命名空间拥有自己的独立网络配置**、接口、IP地址、路由表和防火墙规则。这种隔离在各种场景中非常有用，例如容器化，其中每个容器应具有自己的网络配置，与其他容器和主机系统独立。

### 工作原理：

1. 当创建一个新的网络命名空间时，它将以**完全隔离的网络栈**开始，**没有网络接口**，除了回环接口（lo）。这意味着在新的网络命名空间中运行的进程默认无法与其他命名空间或主机系统中的进程通信。
2. **虚拟网络接口**，如veth对，可以在网络命名空间之间创建和移动。这允许在命名空间之间或命名空间与主机系统之间建立网络连接。例如，veth对的一端可以放置在容器的网络命名空间中，另一端可以连接到主机命名空间中的**桥接**或其他网络接口，为容器提供网络连接。
3. 命名空间内的网络接口可以拥有**自己的IP地址、路由表和防火墙规则**，与其他命名空间独立。这允许不同网络命名空间中的进程具有不同的网络配置，并像在独立的网络系统上运行一样操作。
4. 进程可以使用`setns()`系统调用在命名空间之间移动，或使用带有`CLONE_NEWNET`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间相关的网络配置和接口。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。然后，`/bin/bash` 及其子进程安全地包含在这个新命名空间中，防止 PID 1 提前退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，使得 `/bin/bash` 及其子进程能够正常运行而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;检查您的进程所在的命名空间
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### 查找所有网络命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入网络命名空间
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
此外，您只能**以 root 身份进入另一个进程命名空间**。并且您**不能**在没有指向它的**描述符**的情况下**进入**其他命名空间（如 `/proc/self/ns/net`）。

## 参考

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}
