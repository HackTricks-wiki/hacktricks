# 时间命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

时间命名空间对选定的时钟进行虚拟化，尤其是 **`CLOCK_MONOTONIC`** 和 **`CLOCK_BOOTTIME`**。它比 mount、PID、network 或 user 命名空间更新、更专用，在讨论容器加固时很少是操作者首先想到的内容。即便如此，它属于现代命名空间家族的一部分，值得在概念上理解。

其主要用途是在不改变宿主机全局时间视图的情况下，让进程观察某些时钟的受控偏移。这对于 checkpoint/restore 工作流、确定性测试和一些高级运行时行为很有用。它通常不像 mount 或 user 命名空间那样是显著的隔离控制，但它仍有助于使进程环境更自包含。

## 实验

如果宿主机的内核和 userspace 支持，你可以使用以下命令检查该命名空间：
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Support varies by kernel and tool versions, so this page is more about understanding the mechanism than expecting it to be visible in every lab environment.

### Time Offsets

Linux 时间命名空间将 `CLOCK_MONOTONIC` 和 `CLOCK_BOOTTIME` 的偏移量虚拟化。当前每个命名空间的偏移量通过 `/proc/<pid>/timens_offsets` 暴露，在支持的内核上，这个文件也可以被在相应命名空间内拥有 `CAP_SYS_TIME` 的进程修改：
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
该文件包含纳秒级的增量。将 `monotonic` 调整两天会改变该命名空间内类似 uptime 的观测，而不会更改主机的实时时钟。

### `unshare` 辅助选项

较新的 `util-linux` 版本提供便捷选项，可自动写入偏移量：
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
这些标志主要是可用性改进，但它们也使在文档和测试中识别该功能更容易。

## 运行时使用

time 命名空间比 mount 或 PID 命名空间更新且使用得不那么普遍。OCI Runtime Specification v1.1 为 `time` namespace 和 `linux.timeOffsets` 字段增加了显式支持，较新的 `runc` 发行实现了模型的那部分。一个最小的 OCI 片段如下所示：
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
这很重要，因为它将时间命名空间从一个小众的内核原语变成了运行时可以可移植地请求的功能。

## Security Impact

围绕时间命名空间的经典突破故事比其他类型的命名空间要少。这里的风险通常不是时间命名空间直接导致逃逸，而是读者完全忽视它，从而错过高级运行时可能如何塑造进程行为的线索。在特定环境中，改变的时钟视图可能会影响检查点/恢复、可观测性或取证假设。

## Abuse

这里通常没有直接的突破原语，但改变的时钟行为仍然可用于了解执行环境并识别高级运行时特性：
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
如果你在比较两个进程，这里的差异可以帮助解释奇怪的时间行为、检查点/恢复（checkpoint/restore）产生的痕迹，或特定环境下的日志不匹配。

影响：

- 几乎总是用于侦察或了解环境
- 有助于解释日志、正常运行时间 (uptime) 或检查点/恢复异常
- 本身通常不是直接的容器逃逸机制

重要的滥用细节是，时间命名空间不会虚拟化 `CLOCK_REALTIME`，因此它们本身不能让攻击者伪造主机的墙钟或直接破坏系统范围内的证书到期检查。它们的价值主要在于混淆基于单调时间的逻辑、重现特定环境的错误，或理解高级运行时行为。

## Checks

这些检查主要用于确认运行时是否根本在使用私有时间命名空间。
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
What is interesting here:

- 在许多环境中，这些值通常不会导致立即的安全发现，但它们能告诉你是否启用了某个专用的 runtime 功能。
- 如果你在比较两个进程，这里的差异可能解释令人困惑的计时或 checkpoint/restore 行为。

对于大多数 container breakouts，time namespace 并不是你首先会调查的控制项。尽管如此，完整的 container-security 部分仍应提到它，因为它是现代 kernel 模型的一部分，并且在高级 runtime 场景中偶尔会产生影响。
