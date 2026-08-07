# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

IPC namespace 隔离 **System V IPC objects** 和 **POSIX message queues**。其中包括共享内存段、信号量以及消息队列；否则，这些对象可能会被主机上无关的进程访问。实际上，这可以防止容器随意连接到属于其他工作负载或主机的 IPC 对象。

与 mount、PID 或 user namespaces 相比，IPC namespace 讨论得通常较少，但这并不意味着它无关紧要。共享内存及相关 IPC 机制可能包含非常有价值的状态信息。如果主机的 IPC namespace 暴露出来，工作负载可能会看到原本不应跨越容器边界的进程间协调对象或数据。

## 操作

当 runtime 创建一个新的 IPC namespace 时，进程会获得一组独立隔离的 IPC 标识符。这意味着，`ipcs` 等命令只会显示该 namespace 中可用的对象。如果容器加入主机 IPC namespace，这些对象就会成为共享全局视图的一部分。

这一点在应用程序或服务大量使用共享内存的环境中尤其重要。即使容器无法仅通过 IPC 直接逃逸，该 namespace 也可能泄露信息，或实现跨进程干扰，从而为后续攻击提供实质性帮助。

## 实验

你可以使用以下命令创建一个私有 IPC namespace：
```bash
sudo unshare --ipc --fork bash
ipcs
```
并比较运行时行为与：
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## 运行时使用

Docker 和 Podman 默认会隔离 IPC。Kubernetes 通常会为 Pod 分配其自身的 IPC namespace；同一 Pod 中的容器共享该 namespace，但默认不会与 host 共享。可以共享 host IPC，但这应被视为隔离性的实质性降低，而不是一个次要的运行时选项。

## 配置错误

最明显的错误是 `--ipc=host` 或 `hostIPC: true`。这样做可能是为了兼容 legacy software 或图方便，但它会大幅改变信任模型。另一个反复出现的问题是直接忽略 IPC，因为它看起来没有 host PID 或 host networking 那么严重。实际上，如果 workload 处理 browsers、databases、scientific workloads，或其他大量使用 shared memory 的 software，IPC attack surface 可能非常重要。

## 滥用

当共享 host IPC 时，攻击者可能检查或干扰 shared memory objects，了解 host 或相邻 workload 的行为，或将从中获取的信息与 process visibility 和 ptrace-style capabilities 结合起来。IPC sharing 通常是辅助性弱点，而不是完整的 breakout path，但辅助性弱点很重要，因为它们会缩短并稳定真实的 attack chains。

第一个有用步骤是枚举当前到底能看到哪些 IPC objects：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
如果共享了 host 的 IPC namespace，大型 shared-memory segments 或有趣的对象所有者可能会立即暴露应用行为：
```bash
ipcs -m -p
ipcs -q -p
```
在某些环境中，`/dev/shm` 的内容本身会 leak 出值得检查的文件名、artifacts 或 tokens：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing 通常不会单独立即给予 host root 权限，但它可能暴露数据和协调通道，使后续的进程攻击变得更加容易。

### 完整示例：`/dev/shm` Secret Recovery

最现实的完整滥用场景是数据窃取，而不是直接逃逸。如果 host IPC 或广泛共享的内存布局被暴露，有时可以直接恢复敏感 artifacts：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
影响：

- 从共享内存中提取遗留的 secrets 或 session material
- 了解主机上当前处于活动状态的应用程序
- 为后续基于 PID-namespace 或 ptrace 的攻击提供更好的目标定位

因此，与其将 IPC sharing 视为一种独立的 host-escape primitive，不如将其理解为一种 **attack amplifier**。

## 检查

这些命令旨在确认 workload 是否具有私有的 IPC 视图、是否可以看到有意义的共享内存或消息对象，以及 `/dev/shm` 本身是否暴露了有用的 artifacts。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
这里有什么值得关注：

- 如果 `ipcs -a` 显示出由非预期用户或服务拥有的对象，则该命名空间可能没有实现预期的隔离。
- 大型或异常的共享内存段通常值得进一步调查。
- 广泛挂载的 `/dev/shm` 并不一定是 bug，但在某些环境中，它会 leak 文件名、artifacts 和临时 secrets。

IPC 很少像更重要的命名空间类型那样受到关注，但在大量使用 IPC 的环境中，与主机共享 IPC 绝对是一项安全决策。

{{#include ../../../../../banners/hacktricks-training.md}}
