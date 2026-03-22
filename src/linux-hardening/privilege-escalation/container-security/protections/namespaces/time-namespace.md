# 时间命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

time namespace 虚拟化选定的时钟，特别是 `CLOCK_MONOTONIC` 和 `CLOCK_BOOTTIME`。它比 mount、PID、network 或 user namespaces 更新且更专用，在讨论 container hardening 时很少是操作者首先想到的点。即便如此，它属于现代 namespace 家族，概念上值得理解。

主要目的是让进程在不改变主机全局时间视图的情况下，观察某些时钟的受控偏移。这对 checkpoint/restore 工作流、确定性测试和一些高级运行时行为很有用。它通常不像 mount 或 user namespaces 那样作为显著的隔离控制，但仍有助于使进程环境更为自包含。

## 实验

如果主机内核和 userspace 支持，你可以用下面的方式检查该命名空间：
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
支持情况因内核和工具版本而异，因此本页更侧重于理解该机制，而不是期望它在每个实验环境中都可见。

### 时间偏移

Linux 的时间命名空间为 `CLOCK_MONOTONIC` 和 `CLOCK_BOOTTIME` 虚拟化偏移量。当前每个命名空间的偏移通过 `/proc/<pid>/timens_offsets` 暴露，在支持的内核上，拥有相关命名空间内 `CAP_SYS_TIME` 的进程也可以修改它：
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
该文件包含纳秒级的增量。将 `monotonic` 调整两天会改变该命名空间内类似 uptime 的观测，而不会改变宿主机的 wall clock。

### `unshare` 辅助标志

较新的 `util-linux` 版本提供可自动写入偏移量的便捷标志：
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
这些标志主要是可用性方面的改进，但它们也使在文档和测试中更容易识别该功能。

## 运行时使用

time 命名空间比 mount 或 PID 命名空间更新，且不那么普遍被使用。OCI Runtime Specification v1.1 为 `time` 命名空间和 `linux.timeOffsets` 字段添加了显式支持，较新的 `runc` 版本实现了模型的那一部分。一个最小的 OCI 片段如下：
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
这很重要，因为它把 time namespacing 从一种小众的内核原语，变成 runtimes 可以以可移植的方式请求的功能。

## 安全影响

与其他 namespace 类型相比，围绕 time namespace 的经典 breakout 故事较少。这里的风险通常不是 time namespace 会直接导致 escape，而是读者完全忽略它，从而错过高级 runtimes 如何可能影响进程行为。在特殊环境中，改变的时钟视图可能会影响 checkpoint/restore、observability 或 forensic 假设。

## 滥用

通常这里没有直接的 breakout primitive，但改变的时钟行为仍然有助于了解执行环境并识别高级 runtimes 的特性：
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
如果你在比较两个进程，这里的差异可以帮助解释异常的时序行为、checkpoint/restore 产生的遗留问题，或是特定环境下的日志不匹配。

影响：

- 几乎总是用于侦察或理解运行环境
- 有助于解释日志、uptime 或 checkpoint/restore 异常
- 通常自身并不是直接的 container-escape 机制

重要的滥用细节是 time namespaces 并不会虚拟化 `CLOCK_REALTIME`，因此它们本身并不能让攻击者伪造主机的 host wall clock 或直接破坏全系统范围内的证书到期检查。它们的价值主要在于混淆基于单调时间的逻辑、重现特定环境的 bug，或理解高级运行时行为。

## Checks

这些检查主要用于确认运行时是否正在使用私有的 time namespace。
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
值得注意的是：

- 在许多环境中，这些值不会立即导致安全发现，但它们可以告诉你是否启用了某种专用的运行时特性。
- 如果你在比较两个进程，这里的差异可能能解释令人困惑的时序或 checkpoint/restore 行为。

对于大多数 container breakouts，time namespace 并不是你首先会调查的控制项。不过，完整的 container-security 部分仍应提及它，因为它是现代内核模型的一部分，并且在高级运行时场景中偶尔会产生作用。
{{#include ../../../../../banners/hacktricks-training.md}}
