# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

time namespace 会虚拟化选定的 monotonic-style clocks，而不是 host wall clock。实际这意味着为 **`CLOCK_MONOTONIC`** 和 **`CLOCK_BOOTTIME`** 提供私有偏移量，以及紧密相关的 **`CLOCK_MONOTONIC_COARSE`**、**`CLOCK_MONOTONIC_RAW`** 和 **`CLOCK_BOOTTIME_ALARM`** 视图。它不会虚拟化 **`CLOCK_REALTIME`**，所以 `date` 和证书过期逻辑仍然会看到 host wall clock，除非有其他机制干预。

其主要目的是让进程在不改变 host 的全局时间视图的情况下，观察受控的 elapsed-time 偏移。这对 checkpoint/restore workflows、确定性测试以及高级 runtime 行为很有用。它通常不像 mount 或 user namespaces 那样是显眼的隔离控制，但它仍有助于让进程环境更加 self-contained。

从攻击角度看，这个 namespace 通常对 **reconnaissance、timer skew 和 runtime understanding** 比对直接 breakout 更相关。不过它仍然很重要，因为越来越多的 container runtimes 和 checkpoint/restore workflows 现在可以显式请求它。

## Lab

如果 host kernel 和 userspace 支持它，你可以用以下方式检查这个 namespace：
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
支持情况会因 kernel 和工具版本而异，所以这一页更侧重于理解机制，而不是期望在每个 lab 环境里都能看到它。关键观察是，`date` 仍然应该反映 host wall clock，而基于 monotonic/boottime 的值才是在配置了非零偏移时会变化的那些。

### Creation Nuance

Time namespaces 和 mount、PID 或 network namespaces 相比，稍微有点特殊：

- `unshare(CLONE_NEWTIME)` 会为**未来的 children** 创建一个新的 time namespace。
- 调用的 task 会留在它当前的 time namespace 中。
- 因此，在调试 runtime setup 时，`/proc/<pid>/ns/time_for_children` 往往比 `/proc/<pid>/ns/time` 更有意思。

写入窗口也很特殊。`/proc/<pid>/timens_offsets` 中的偏移必须在新的 time namespace 还没有被运行中的 tasks 完整填充之前写入；实际上，runtimes 会在 namespace 创建和启动最终 payload 之间的这个短暂 setup 窗口里完成这一步。一旦某个 task 已经在里面运行，后续写入就会失败并返回 `EACCES`。这也是为什么低层 runtimes 会把 time-namespace setup 作为早期 bootstrap 步骤来处理，而不是尝试在已经启动的 container process 内部去修补 offsets。

### Time Offsets

Linux time namespaces 通过 `/proc/<pid>/timens_offsets` 暴露每个 namespace 的 offsets。其格式是一组 clock 名称或 ID，再加上相对于初始 time namespace 的 second/nanosecond delta。

在实践中，最可靠的面向用户的 workflow 是让 `unshare` 替你写入这些 offsets：
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
关键点不是确切的命令语法，而是行为：容器可以观察到不同的类似 uptime 的视图，而不会改变主机的 wall clock。

### `unshare` Helper Flags

较新的 `util-linux` 版本提供了便捷标志，会在 namespace 创建期间自动写入偏移量：
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
这些 flags 主要是可用性改进，但它们也让在文档、测试 harnesses 和 runtime wrappers 中更容易识别该特性。

## Runtime Usage

Time namespaces 比 mount 或 PID namespaces 更新，也没有那么普遍被使用。OCI Runtime Specification v1.1 为 `time` namespace 和 `linux.timeOffsets` 字段增加了显式支持，现代 runtimes 可以将这些数据映射到内核 bootstrap flow 中。一个最小的 OCI 片段如下：
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
这很重要，因为它把 time namespacing 从一种小众的 kernel primitive 变成了 runtimes 可以便携请求的东西。这也解释了为什么 runtime internals 需要一个显式的同步步骤：在 container payload 完全进入新的 namespace 之前，必须先把 offset 写入 `/proc/<pid>/timens_offsets`。

像 CRIU 这样的 checkpoint/restore stacks 是这种机制存在的主要现实原因之一。没有 time namespaces，恢复一个暂停的 workload 会让 monotonic 和 boot-time clocks 按照该 workload 挂起期间经过的时间发生跳变。

## Security Impact

与其他 namespace 类型相比，围绕 time namespace 的经典 breakout 故事要少得多。这里的风险通常不是 time namespace 直接导致 escape，而是读者完全忽略它，因此错过了先进 runtimes 可能正在如何塑造 process behavior。

在 specialized environments 中，改变后的 monotonic 或 boottime 视图可能会影响：

- timeout 和 retry behavior
- watchdogs 和 lease logic
- `timerfd`, `nanosleep`, 和 `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry 和基于 uptime 的 heuristics

所以，虽然这通常不是你最先去 abuse 的 namespace，但它完全可以解释 assessment 期间那些“impossible”的 timing behavior。

## Abuse

这里通常没有直接的 breakout primitive，但改变后的 clock behavior 仍然可能对理解 execution environment、识别 advanced runtime features，以及发现那些按 monotonic clocks 而不是 wall clock time 计时的 timer-based logic 很有用:
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
如果你在比较两个进程，这里的差异可以帮助解释奇怪的计时行为、checkpoint/restore 产物，或环境特定的日志不一致。

对攻击者更实用的角度：

- 干扰使用 monotonic clocks 实现的 backoff、sleep 或 watchdog 逻辑
- 解释为什么 `/proc/uptime` 和基于 timer 的行为会与主机侧的 wall-clock 预期不一致
- 识别 CRIU/checkpoint-restore 工作流和其他高级运行时特性
- 发现可通过 `nsenter -T -t <pid> -- ...` 加入目标 time namespace 的环境，以便在调试或 post-exploitation 时复现容器内的 timer 行为

影响：

- 几乎总是 reconnaissance 或环境理解
- 有助于解释 logging、uptime 或 checkpoint/restore 异常
- 有助于分析基于 monotonic-time 的 sleeps、retries 和 timers
- 通常本身不是直接的 container-escape 机制

重要的 abuse 细节是，time namespaces 不会虚拟化 `CLOCK_REALTIME`，因此它们本身并不能让攻击者伪造主机 wall clock，或直接在系统范围内破坏 certificate-expiry 检查。它们的价值主要在于混淆基于 monotonic-time 的逻辑、复现环境特定 bug，或理解高级运行时行为。

## Checks

这些检查主要是为了确认运行时是否真的在使用 private time namespace，以及它是否实际设置了非零偏移。
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
这里有意思的是：

- 在很多环境中，这些值不会直接导致安全告警，但它们会告诉你是否启用了某种专门的 runtime 功能。
- 如果 `time_for_children` 与 `time` 不同，调用方可能已经准备了一个仅供子进程使用的 time namespace，但它自己并没有进入该 namespace。
- 如果 `date` 与主机一致，但基于 monotonic/boottime 的值不一致，那么你很可能看到的是 time namespacing，而不是对 wall-clock 的篡改。
- 如果你在比较两个进程，这里的差异可能解释一些令人困惑的 timing 或 checkpoint/restore 行为。

对于大多数 container breakout，time namespace 不是你首先要检查的控制项。尽管如此，一个完整的 container-security 部分仍然应该提到它，因为它是现代 kernel 模型的一部分，并且在高级 runtime 场景中偶尔会很重要。

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
