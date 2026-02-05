# UTS 命名空间

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**隔离两个系统标识符**：**hostname** 和 **NIS** (Network Information Service) 域名。 这种隔离使得每个 UTS 命名空间可以拥有其 **自己的独立 hostname 和 NIS 域名**，这在容器化场景中尤其有用，因为每个容器应表现为具有自己 hostname 的独立系统。

### 工作原理：

1. 当创建新的 UTS 命名空间时，它会以 **从其父命名空间复制的 hostname 和 NIS 域名** 为起点。这意味着在创建时，新的命名空间 s**与其父命名空间共享相同的标识符**。然而，在该命名空间中对 hostname 或 NIS 域名的后续更改不会影响其他命名空间。
2. UTS 命名空间内的进程 **可以使用 `sethostname()` 和 `setdomainname()` 系统调用分别更改 hostname 和 NIS 域名**。这些更改仅在该命名空间内生效，不会影响其他命名空间或主机系统。
3. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或通过带有 `CLONE_NEWUTS` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到或创建新命名空间时，它将开始使用与该命名空间关联的 hostname 和 NIS 域名。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **准确且隔离的视图** of the process information specific to that namespace.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

当不带 `-f` 选项执行 `unshare` 时，会因 Linux 处理新的 PID (Process ID) 命名空间的方式而遇到错误。关键细节和解决方案概述如下：

1. **问题说明**：

- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，启动创建新 PID 命名空间的进程（称为“unshare”进程）本身不会进入新的命名空间；只有它的子进程会进入。
- 运行 %unshare -p /bin/bash% 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程仍在原始的 PID 命名空间中。
- 在新命名空间中，`/bin/bash` 的第一个子进程会成为 PID 1。当该进程退出时，如果没有其他进程存在，会触发对该命名空间的清理，因为 PID 1 承担收养孤儿进程的特殊角色。随后 Linux 内核会在该命名空间中禁用 PID 分配。

2. **后果**：

- 在新命名空间中 PID 1 的退出会导致 `PIDNS_HASH_ADDING` 标志被清除。这会导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，进而产生 "Cannot allocate memory" 错误。

3. **解决方案**：
- 该问题可以通过在 `unshare` 命令中使用 `-f` 选项来解决。该选项会在创建新的 PID 命名空间后让 `unshare` fork 出一个新进程。
- 执行 %unshare -fp /bin/bash% 可以确保 `unshare` 命令本身在新命名空间中成为 PID 1。随后 `/bin/bash` 及其子进程被安全地包含在该命名空间内，避免 PID 1 提前退出并允许正常的 PID 分配。

通过确保 `unshare` 使用 `-f` 标志运行，可以正确维护新的 PID 命名空间，从而让 `/bin/bash` 及其子进程在不遇到内存分配错误的情况下正常运行。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查你的进程所在的命名空间
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

如果容器使用 `--uts=host` 启动，它会加入主机的 UTS 命名空间，而不是获得一个隔离的命名空间。拥有像 `--cap-add SYS_ADMIN` 这样的 capabilities 时，容器内的代码可以通过 `sethostname()`/`setdomainname()` 更改主机的主机名/NIS 名称：
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
更改主机名可能会篡改日志/告警、混淆集群发现或破坏绑定主机名的 TLS/SSH 配置。

### 检测与主机共享 UTS 的容器
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
