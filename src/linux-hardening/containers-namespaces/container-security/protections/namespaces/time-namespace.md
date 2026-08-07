# 时间 Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

时间 namespace 虚拟化的是选定的单调时钟，而不是主机的 wall clock。实际上，这意味着为 **`CLOCK_MONOTONIC`** 和 **`CLOCK_BOOTTIME`** 提供私有偏移量，以及与之密切相关的 **`CLOCK_MONOTONIC_COARSE`**、**`CLOCK_MONOTONIC_RAW`** 和 **`CLOCK_BOOTTIME_ALARM`** 视图。它不会虚拟化 **`CLOCK_REALTIME`**，因此除非其他机制介入，否则 `date` 和证书过期逻辑仍会观察主机的 wall clock。<sup>[[1]](#references)</sup>

其主要用途是在不改变主机全局时间视图的情况下，让进程观察受控的已流逝时间偏移。这对于 checkpoint/restore 工作流、确定性测试和高级 runtime 行为很有用。它通常不像 mount 或 user namespaces 那样属于主要的隔离控制，但仍有助于使进程环境更加自包含。

从 offensive 角度看，该 namespace 通常更适用于**侦察、timer 偏移和 runtime 理解**，而不是直接 breakout。不过它仍然很重要，因为越来越多的 container runtimes 和 checkpoint/restore 工作流现在能够显式请求它。

## 实验环境

如果主机 kernel 和 userspace 支持它，可以使用以下命令检查该 namespace：
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
支持情况取决于 kernel 和工具版本，因此本页面更侧重于理解其机制，而不是期待它在每个 lab 环境中都可见。重要的观察是：`date` 仍应反映 host 的 wall clock，而基于 monotonic/boottime 的值才会在配置非零 offset 时发生变化。

### 创建细节

与 mount、PID 或 network namespace 相比，time namespace 略有不同：<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` 会为**未来的子进程**创建新的 time namespace。
- 调用该操作的 task 仍保留在当前 time namespace 中。
- 因此，在调试 runtime setup 时，`/proc/<pid>/ns/time_for_children` 通常比 `/proc/<pid>/ns/time` 更值得关注。

其 write window 也很特殊。必须在新的 time namespace 完全填充运行中的 task 之前，将 `/proc/<pid>/timens_offsets` 中的 offset 写入；实际上，runtime 会在 namespace 创建和启动最终 payload 之间的狭窄 setup window 内完成此操作。一旦已有 task 在其中运行，后续写入就会因 `EACCES` 失败。这就是为什么 low-level runtime 会将 time-namespace setup 作为早期 bootstrap 步骤处理，而不是尝试从一个已经启动的 container process 内部修改 offset。<sup>[[1]](#references)</sup>

### Time Offsets

Linux time namespace 通过 `/proc/<pid>/timens_offsets` 暴露 per-namespace offset。其格式是一组 clock 名称或 ID，以及相对于 initial time namespace 的秒/纳秒 delta。<sup>[[1]](#references)</sup>

在实践中，最可靠的 user-facing workflow 是让 `unshare` 代你写入这些 offset：
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
重要的一点不是确切的命令语法，而是其行为：容器可以在不更改主机 wall clock 的情况下，观察到不同的类似 uptime 的视图。

### `unshare` 辅助标志

近期版本的 `util-linux` 提供了便捷标志，可在创建 namespace 时自动写入偏移量：
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
这些 flags 主要是可用性方面的改进，但也让人们更容易在文档、测试 harness 和运行时 wrapper 中识别该功能。

## 运行时用法

与 mount 或 PID namespace 相比，Time namespace 更新，也更少被普遍使用。OCI Runtime Specification v1.1 增加了对 `time` namespace 和 `linux.timeOffsets` 字段的显式支持，现代 runtime 可以将这些数据映射到 kernel bootstrap 流程中。一个最小的 OCI 片段如下：
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
这很重要，因为它将 time namespace 从一种小众的 kernel primitive 转变为 runtimes 可以以可移植方式请求的功能。这也解释了为什么 runtime internals 需要一个显式的同步步骤：在 container payload 完全进入新 namespace 之前，必须先将 offset 写入 `/proc/<pid>/timens_offsets`。

Checkpoint/restore stacks（例如 CRIU）是这一功能存在的主要现实原因之一。如果没有 time namespaces，恢复暂停的 workload 时，monotonic 和 boot-time clocks 会因为 workload 被挂起期间经过的时间而发生跳变。<sup>[[2]](#references)</sup>

## Security Impact

与其他 namespace 类型相比，以 time namespace 为核心的经典 breakout 案例较少。这里的风险通常不是 time namespace 直接实现了 escape，而是读者完全忽略它，从而无法理解 advanced runtimes 可能如何塑造进程行为。

在专用环境中，被修改的 monotonic 或 boottime 视图可能影响：

- timeout 和 retry 行为
- watchdog 和 lease 逻辑
- `timerfd`、`nanosleep` 和 `clock_nanosleep` 的行为
- checkpoint/restore forensics
- elapsed-time telemetry 和基于 uptime 的 heuristics

因此，虽然这通常不是你首先 abuse 的 namespace，但它绝对可以解释 assessment 期间出现的“impossible” timing behavior。

## Abuse

这里通常没有直接的 breakout primitive，但被修改的 clock behavior 仍然有助于理解 execution environment、识别 advanced runtime features，以及发现基于 timer 的逻辑——这类逻辑使用 monotonic clocks 而不是 wall clock time 进行测量：
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
如果你正在比较两个进程，这里的差异有助于解释异常的 timing 行为、checkpoint/restore 产物，或特定环境下的日志不一致。

与攻击者相关的实际角度：

- 混淆使用 monotonic clocks 实现的 backoff、sleep 或 watchdog 逻辑
- 解释为什么 `/proc/uptime` 和 timer 驱动的行为与主机侧的 wall-clock 预期不一致
- 识别 CRIU/checkpoint-restore 工作流及其他高级 runtime 功能
- 发现某些环境，在这些环境中，使用 `nsenter -T -t <pid> -- ...` 加入目标 time namespace，可能会复现容器本地的 timer 行为，以便进行调试或 post-exploitation

影响：

- 几乎总是用于 reconnaissance 或了解环境
- 有助于解释 logging、uptime 或 checkpoint/restore 异常
- 有助于分析基于 monotonic time 的 sleep、重试和 timer
- 通常本身不是直接的 container-escape 机制

需要注意的重要滥用细节是：time namespaces 不会虚拟化 `CLOCK_REALTIME`，因此它们本身不能让攻击者伪造主机 wall clock，也不能直接破坏系统范围内的证书过期检查。它们的价值主要在于混淆基于 monotonic time 的逻辑、复现特定环境中的 bug，或理解高级 runtime 行为。

## Checks

这些检查主要用于确认 runtime 是否正在使用 private time namespace，以及它是否实际设置了非零 offset。
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
这里有什么值得注意：

- 在许多环境中，这些值不会立即构成安全发现，但它们可以告诉你是否启用了某种 specialized runtime feature。
- 如果 `time_for_children` 与 `time` 不同，调用方可能已经准备了一个仅供子进程使用的 time namespace，但自身尚未进入其中。
- 如果 `date` 与主机一致，而基于 monotonic/boottime 的值不一致，那么你看到的很可能是 time namespacing，而不是 wall-clock tampering。
- 如果你正在比较两个进程，这里的差异可能解释令人困惑的 timing 或 checkpoint/restore 行为。

对于大多数 container breakout，time namespace 并不是你首先会调查的控制机制。不过，完整的 container-security 章节仍应提及它，因为它是现代 kernel model 的一部分，并且偶尔会在高级 runtime 场景中发挥作用。

## References

- [1] [Linux `time_namespaces(7)` 手册页](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces：针对 CLOCK_MONOTONIC / CLOCK_BOOTTIME 的每容器时钟偏移 - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
