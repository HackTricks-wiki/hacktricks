# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

Time namespace 会虚拟化选定的单调时钟，而不是 host wall clock。实际上，这意味着为 **`CLOCK_MONOTONIC`** 和 **`CLOCK_BOOTTIME`** 提供私有偏移，以及与之密切相关的 **`CLOCK_MONOTONIC_COARSE`**、**`CLOCK_MONOTONIC_RAW`** 和 **`CLOCK_BOOTTIME_ALARM`** 视图。它不会虚拟化 **`CLOCK_REALTIME`**，因此 `date` 和证书过期逻辑仍会观察 host wall clock，除非其他机制产生干扰。

其主要用途是让进程在不改变 host 的全局时间视图的情况下，观察受控的已流逝时间偏移。这对于 checkpoint/restore 工作流、确定性测试和高级 runtime 行为都很有用。它通常不像 mount 或 user namespaces 那样属于核心 isolation 控制，但仍有助于使进程环境更加自包含。

从 offensive 角度看，该 namespace 通常更适用于 **reconnaissance、timer skew 和 runtime understanding**，而不是直接 breakout。不过它仍然很重要，因为越来越多的 container runtimes 和 checkpoint/restore 工作流现在能够显式请求它。

## 实验

如果 host kernel 和 userspace 支持它，可以使用以下方式检查该 namespace：
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
支持情况因 kernel 和工具版本而异，因此本页面更侧重于理解其机制，而不是期待它在每个 lab 环境中都可见。重要的观察点是：`date` 仍应反映 host 的 wall clock，而基于 monotonic/boottime 的值才会在配置非零 offset 时发生变化。

### Creation Nuance

与 mount、PID 或 network namespaces 相比，time namespaces 稍有不同：

- `unshare(CLONE_NEWTIME)` 会为**未来的子进程**创建新的 time namespace。
- 调用该函数的 task 仍留在其当前的 time namespace 中。
- 因此，在调试 runtime setup 时，`/proc/<pid>/ns/time_for_children` 往往比 `/proc/<pid>/ns/time` 更值得关注。

写入窗口也很特殊。必须在新的 time namespace 完全填充运行中的 task 之前，将 `/proc/<pid>/timens_offsets` 中的 offset 写入；实际上，runtime 会在 namespace 创建后、启动最终 payload 前的短暂 setup 窗口内完成此操作。一旦其中已有 task 正在运行，后续写入就会因 `EACCES` 失败。这也是低级 runtime 将 time-namespace setup 作为早期 bootstrap 步骤处理的原因，而不是尝试从一个已经启动的 container process 内部修改 offset。

### Time Offsets

Linux time namespaces 通过 `/proc/<pid>/timens_offsets` 暴露每个 namespace 的 offset。其格式是一组 clock 名称或 ID，以及相对于 initial time namespace 的秒/纳秒 delta。

实际上，最可靠的面向用户的 workflow 是让 `unshare` 代你写入这些 offset：
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
重要的一点不是确切的命令语法，而是其行为：容器可以在不更改主机实际时钟的情况下，观察到不同的类似 uptime 的视图。

### `unshare` Helper Flags

较新的 `util-linux` 版本提供了便捷 flags，可在创建 namespace 时自动写入偏移量：
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
这些 flags 主要是为了提升可用性，但也让人们更容易在文档、test harnesses 和 runtime wrappers 中识别该功能。

## Runtime Usage

Time namespaces 比 mount 或 PID namespaces 更新，且使用范围也不如后者广泛。OCI Runtime Specification v1.1 增加了对 `time` namespace 和 `linux.timeOffsets` 字段的显式支持，现代 runtimes 可以将这些数据映射到 kernel bootstrap flow 中。一个最小的 OCI 片段如下：
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
这很重要，因为它将时间命名空间化从一种小众的内核原语，变成了运行时可以通过可移植方式请求的功能。这也解释了为什么运行时内部需要一个明确的同步步骤：必须先将偏移量写入 `/proc/<pid>/timens_offsets`，然后容器 payload 才能完全进入新的命名空间。

像 CRIU 这样的 checkpoint/restore 堆栈，是这项功能存在的主要现实原因之一。如果没有时间命名空间，恢复暂停的 workload 时，单调时钟和启动时间时钟就会因为 workload 被挂起期间经过的时间而发生跳变。

## 安全影响

与其他命名空间类型相比，以时间命名空间为核心的经典 breakout 故事更少。这里的风险通常不是时间命名空间直接启用了逃逸，而是读者完全忽略了它，从而无法发现高级运行时可能如何塑造进程行为。

在专门的环境中，被修改的单调时钟或启动时间视图可能会影响：

- timeout 和 retry 行为
- watchdog 和 lease 逻辑
- `timerfd`、`nanosleep` 和 `clock_nanosleep` 的行为
- checkpoint/restore 取证
- elapsed-time telemetry 和基于 uptime 的启发式判断

因此，虽然这通常不是你首先会利用的命名空间，但它绝对可以解释评估期间出现的“impossible” timing 行为。

## 滥用

这里通常不存在直接的 breakout 原语，但修改后的时钟行为仍可用于理解执行环境、识别高级运行时功能，以及发现那些使用单调时钟而不是 wall clock time 进行计时的基于 timer 的逻辑：
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
如果你正在比较两个进程，这里的差异有助于解释异常的时间行为、checkpoint/restore 产物，或特定环境下的日志不一致。

与攻击者实际相关的角度：

- 混淆使用 monotonic clocks 实现的退避、休眠或 watchdog 逻辑
- 解释为什么 `/proc/uptime` 和由 timer 驱动的行为与主机端的 wall-clock 预期不一致
- 识别 CRIU/checkpoint-restore 工作流及其他高级 runtime 功能
- 发现加入目标 time namespace 后，使用 `nsenter -T -t <pid> -- ...` 可能复现 container 本地 timer 行为的环境，用于调试或 post-exploitation

影响：

- 几乎总是用于 reconnaissance 或了解环境
- 有助于解释 logging、uptime 或 checkpoint/restore 异常
- 有助于分析基于 monotonic time 的休眠、重试和 timer
- 通常本身不是直接的 container-escape 机制

需要注意的滥用细节是：time namespaces 不会虚拟化 `CLOCK_REALTIME`，因此它们本身不能让攻击者伪造主机 wall clock，也不能直接破坏系统范围内的 certificate-expiry checks。它们的主要价值在于混淆基于 monotonic time 的逻辑、复现特定环境下的 bug，或了解高级 runtime 行为。

## 检查

这些检查主要用于确认 runtime 是否实际使用了 private time namespace，以及是否真正设置了非零 offset。
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
这里有什么值得关注：

- 在许多环境中，这些值不会立即构成安全发现，但它们可以告诉你是否启用了某种 specialized runtime feature。
- 如果 `time_for_children` 与 `time` 不同，调用者可能已经准备了一个仅供子进程使用的 time namespace，但自身尚未进入其中。
- 如果 `date` 与主机匹配，但基于 monotonic/boottime 的值不匹配，那么你看到的很可能是 time namespacing，而不是 wall-clock 篡改。
- 如果你正在比较两个进程，这些差异可能解释令人困惑的计时行为或 checkpoint/restore 行为。

对于大多数 container breakout，time namespace 并不是你首先要调查的控制机制。不过，完整的 container-security 部分仍应提及它，因为它是现代 kernel 模型的一部分，并且偶尔会在高级 runtime 场景中发挥作用。

## 参考资料

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
