# 时间命名空间

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

Linux中的时间命名空间允许对系统单调时钟和启动时间时钟进行每个命名空间的偏移。它通常在Linux容器中使用，以更改容器内的日期/时间，并在从检查点或快照恢复后调整时钟。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
通过挂载新的 `/proc` 文件系统实例，如果使用参数 `--mount-proc`，您可以确保新的挂载命名空间具有 **特定于该命名空间的进程信息的准确和隔离视图**。

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
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。然后，`/bin/bash` 及其子进程安全地包含在这个新命名空间中，防止 PID 1 提前退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，使得 `/bin/bash` 及其子进程能够正常运行而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程所在的命名空间
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### 查找所有时间命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入时间命名空间
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## 操作时间偏移

从 Linux 5.6 开始，每个时间命名空间可以虚拟化两个时钟：

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

它们的每个命名空间的增量通过文件 `/proc/<PID>/timens_offsets` 暴露（并可以被修改）：
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
该文件包含两行 - 每个时钟一行 - 以**纳秒**为单位的偏移量。持有**CAP_SYS_TIME** _在时间命名空间_中的进程可以更改该值：
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
如果您需要墙上时钟（`CLOCK_REALTIME`）也发生变化，您仍然必须依赖经典机制（`date`、`hwclock`、`chronyd`等）；它**不是**命名空间化的。

### `unshare(1)` 辅助标志 (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
长选项会在命名空间创建后自动将所选的增量写入 `timens_offsets`，省去了手动 `echo` 的步骤。

---

## OCI 和运行时支持

* **OCI Runtime Specification v1.1**（2023年11月）增加了专用的 `time` 命名空间类型和 `linux.timeOffsets` 字段，以便容器引擎可以以可移植的方式请求时间虚拟化。
* **runc >= 1.2.0** 实现了该规范的这一部分。一个最小的 `config.json` 片段如下所示：
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
然后使用 `runc run <id>` 运行容器。

>  注意：runc **1.2.6**（2025年2月）修复了一个“使用私有 timens 执行到容器中”的错误，该错误可能导致挂起和潜在的拒绝服务。确保在生产环境中使用 ≥ 1.2.6。

---

## 安全考虑

1. **所需能力** – 进程需要在其用户/时间命名空间内具有 **CAP_SYS_TIME** 才能更改偏移量。在容器中删除该能力（Docker 和 Kubernetes 的默认设置）可以防止篡改。
2. **无墙钟时间更改** – 由于 `CLOCK_REALTIME` 与主机共享，攻击者无法仅通过 timens 来伪造证书生命周期、JWT 过期等。
3. **日志/检测规避** – 依赖于 `CLOCK_MONOTONIC` 的软件（例如基于正常运行时间的速率限制器）如果命名空间用户调整偏移量可能会感到困惑。对于安全相关的时间戳，优先使用 `CLOCK_REALTIME`。
4. **内核攻击面** – 即使删除了 `CAP_SYS_TIME`，内核代码仍然可访问；保持主机补丁更新。Linux 5.6 → 5.12 收到了多个 timens 的错误修复（NULL-deref，符号问题）。

### 加固检查清单

* 在容器运行时默认配置中删除 `CAP_SYS_TIME`。
* 保持运行时更新（runc ≥ 1.2.6，crun ≥ 1.12）。
* 如果依赖于 `--monotonic/--boottime` 辅助工具，请固定 util-linux ≥ 2.38。
* 审计读取 **uptime** 或 **CLOCK_MONOTONIC** 的容器内软件，以确保安全关键逻辑。

## 参考文献

* man7.org – 时间命名空间手册页：<https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI 博客 – “OCI v1.1：新的时间和 RDT 命名空间”（2023年11月15日）：<https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
