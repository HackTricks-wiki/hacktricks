# IPC 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

IPC 命名空间隔离了 **System V IPC objects** 和 **POSIX message queues**。这包括共享内存段、信号量和消息队列，这些对象在主机上本会被无关进程看到。实际上，这可以防止容器随意附加到属于其他工作负载或主机的 IPC 对象。

与 mount、PID 或 user namespaces 相比，IPC 命名空间通常较少被讨论，但这并不意味着它不重要。共享内存和相关的 IPC 机制可能包含非常有用的状态。如果主机的 IPC 命名空间被暴露，工作负载可能会看到本不应跨越容器边界的进程间协调对象或数据。

## 工作原理

当运行时创建一个新的 IPC 命名空间时，进程会获得自己隔离的 IPC 标识符集合。这意味着像 `ipcs` 这样的命令只会显示该命名空间中可用的对象。如果容器加入了主机的 IPC 命名空间，这些对象就会成为共享的全局视图的一部分。

这在应用或服务大量使用共享内存的环境中特别重要。即便容器无法仅通过 IPC 直接突破隔离，命名空间也可能 leak 信息或导致跨进程干扰，从而为后续攻击提供实质性的帮助。

## 实验

你可以通过以下方式创建一个私有的 IPC 命名空间：
```bash
sudo unshare --ipc --fork bash
ipcs
```
并将运行时行为与以下内容进行比较：
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker 和 Podman 默认隔离 IPC。Kubernetes 通常会为 Pod 提供其自己的 IPC namespace，该 namespace 在同一 Pod 的容器之间共享，但默认不会与主机共享。可以启用与主机共享 IPC，但应将其视为对隔离的实质性削弱，而不是一个不起眼的运行时选项。

## Misconfigurations

明显的错误是 `--ipc=host` 或 `hostIPC: true`。这可能是为了与旧版软件兼容或方便起见，但它会显著改变信任模型。另一个常见问题是简单地忽视 IPC，因为它看起来不如 host PID 或 host networking 那样显著。实际上，如果工作负载涉及浏览器、数据库、科学计算或其他大量使用共享内存的软件，IPC 的攻击面可能非常重要。

## Abuse

当与主机共享 IPC 时，攻击者可能会检查或干扰共享内存对象，获得关于主机或相邻工作负载行为的新见解，或将那里学到的信息与进程可见性和 ptrace-style 能力结合起来。IPC 共享通常是一个辅助性的弱点，而不是完整的越狱路径，但辅助性弱点很重要，因为它们会缩短并稳定真实的攻击链。

第一个有用的步骤是枚举所有可见的 IPC 对象：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
如果与主机共享 IPC 命名空间，大型共享内存段或有趣的对象所有者可以立即揭示应用程序行为：
```bash
ipcs -m -p
ipcs -q -p
```
在某些环境中，/dev/shm 的内容本身会泄露值得检查的文件名、工件或令牌：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC 共享本身很少会立即赋予 host root，但它可能会暴露数据和协调通道，从而使后续的进程攻击变得容易得多。

### 完整示例: `/dev/shm` 机密恢复

最现实的滥用场景通常是数据窃取，而不是直接逃逸。如果暴露了 host IPC 或广泛的共享内存布局，敏感工件有时可以被直接恢复：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impact:

- 从共享内存中提取遗留的秘密或会话材料
- 获取对主机上当前运行的应用程序的洞察
- 为后续的 PID-namespace 或 ptrace-based 攻击提供更精准的定位

IPC 共享因此更应被理解为一种 **attack amplifier**，而不是独立的 host-escape primitive。

## Checks

这些命令用于判断工作负载是否具有私有的 IPC 视图、是否可以看到有意义的共享内存或消息对象，以及 `/dev/shm` 本身是否暴露有用的工件。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
值得注意的是：

- 如果 `ipcs -a` 显示由意外的用户或服务拥有的对象，命名空间可能并不像预期的那样隔离。
- 较大或异常的共享内存段通常值得进一步调查。
- 广泛的 `/dev/shm` 挂载并不一定是漏洞，但在某些环境中会泄露文件名、工件和临时秘密。

IPC 很少像更大型的命名空间类型那样受到关注，但在大量使用 IPC 的环境中，与主机共享它确实是一个重大的安全决策。
