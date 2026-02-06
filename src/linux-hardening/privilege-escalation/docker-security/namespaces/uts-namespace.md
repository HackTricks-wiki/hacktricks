# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

A UTS (UNIX Time-Sharing System) namespace 是 Linux 内核的一个特性，提供 i**两个系统标识符的隔离**：**hostname** 和 **NIS** (Network Information Service) 域名。这个隔离允许每个 UTS namespace 拥有其 **独立的 hostname 和 NIS 域名**，这在容器化场景中特别有用，因为每个容器应当呈现为具有自己 hostname 的独立系统。

### 工作原理：

1. 当创建新的 UTS namespace 时，它会以 **来自其父命名空间的 hostname 和 NIS 域名的副本** 开始。这意味着，在创建时，新 namespace s**与其父命名空间共享相同的标识**。然而，在该命名空间内对 hostname 或 NIS 域名的任何后续更改都不会影响其他命名空间。
2. 位于 UTS namespace 中的进程 **可以更改 hostname 和 NIS 域名**，分别使用 `sethostname()` 和 `setdomainname()` 系统调用。这些更改仅在该命名空间本地生效，不会影响其他命名空间或主机系统。
3. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或使用带有 `CLONE_NEWUTS` 标志的 `unshare()` 或 `clone()` 系统调用来创建新的命名空间。当进程移动到新的命名空间或创建一个新的命名空间时，它将开始使用与该命名空间关联的 hostname 和 NIS 域名。

## Lab:

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
通过挂载一个新的 `/proc` 文件系统实例（如果使用参数 `--mount-proc`），可以确保新的挂载命名空间拥有**对该命名空间特定进程信息的准确且隔离的视图**。

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

当 `unshare` 在没有使用 `-f` 选项的情况下执行时，会遇到一个错误，这是由于 Linux 处理新的 PID（Process ID）命名空间的方式导致的。关键细节和解决方案如下：

1. **问题说明**：

- Linux kernel 允许进程使用 `unshare` 系统调用创建新的命名空间。但发起新 PID 命名空间创建的进程（称为 "unshare" 进程）不会进入新的命名空间；只有其子进程会进入。
- 运行 %unshare -p /bin/bash% 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程仍处于原始的 PID 命名空间中。
- 在新命名空间中，`/bin/bash` 的第一个子进程会成为 PID 1。当该进程退出时，如果没有其他进程存在，会触发命名空间的清理，因为 PID 1 扮演着收养孤儿进程的特殊角色。随后 Linux kernel 会在该命名空间中禁用 PID 分配。

2. **后果**：

- PID 1 在新命名空间中退出会导致 `PIDNS_HASH_ADDING` 标志被清理。这会导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，从而产生 "Cannot allocate memory" 错误。

3. **解决方法**：
- 可以通过在 `unshare` 中使用 `-f` 选项来解决该问题。此选项会在创建新的 PID 命名空间后让 `unshare` fork 出一个新进程。
- 执行 %unshare -fp /bin/bash% 可确保 `unshare` 命令本身在新命名空间中成为 PID 1。随后 `/bin/bash` 及其子进程就被安全地包含在该新命名空间中，防止 PID 1 过早退出并允许正常的 PID 分配。

通过确保以 `-f` 标志运行 `unshare`，可以正确维护新的 PID 命名空间，使 `/bin/bash` 及其子进程能够正常运行而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查你的进程在哪个命名空间
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### 查找所有 UTS 命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入 UTS 命名空间
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## 滥用主机 UTS 共享

如果容器使用 `--uts=host` 启动，它会加入主机的 UTS 命名空间，而不是获得一个隔离的命名空间。具有诸如 `--cap-add SYS_ADMIN` 之类的 capabilities 时，容器内的代码可以通过 `sethostname()`/`setdomainname()` 更改主机的主机名/NIS 名称：
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
更改主机名可能篡改 logs/alerts、干扰 cluster discovery 或破坏将主机名固定的 TLS/SSH 配置。

### 检测与主机共享 UTS 的容器
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
