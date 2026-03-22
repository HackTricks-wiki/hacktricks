# IPC 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

IPC 命名空间隔离 **System V IPC objects** 和 **POSIX message queues**。这包括共享内存段、信号量和消息队列，这些在主机上本会在不相关的进程之间可见。从实际角度来看，这可以防止容器随意附加到属于其他工作负载或主机的 IPC 对象。

与 mount、PID 或 user 命名空间相比，IPC 命名空间通常较少被讨论，但这并不等于它无关紧要。共享内存和相关的 IPC 机制可能包含非常有用的状态。如果主机 IPC 命名空间被暴露，工作负载可能会获得对进程间协调对象或那些原本不应跨容器边界的数据的可见性。

## 工作原理

当运行时创建一个新的 IPC 命名空间时，进程会获得自己隔离的一组 IPC 标识符。这意味着诸如 `ipcs` 之类的命令只会显示该命名空间中可用的对象。如果容器改为加入主机的 IPC 命名空间，则这些对象会成为共享全局视图的一部分。

这在应用或服务大量使用共享内存的环境中特别重要。即使容器仅靠 IPC 本身无法直接 breakout，命名空间也可能 leak 信息或启用跨进程干扰，从而实质性地帮助后续攻击。

## 实验

可以使用以下命令创建一个私有 IPC 命名空间：
```bash
sudo unshare --ipc --fork bash
ipcs
```
并将运行时行为与以下进行比较：
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## 运行时使用

Docker 和 Podman 默认隔离 IPC。Kubernetes 通常会给 Pod 自己的 IPC namespace，Pod 中的容器共享该 namespace，但默认不会与 host 共享。可以配置与 host 共享 IPC，但这应被视为对隔离性的实质性降低，而不是一个次要的运行时选项。

## 误配置

明显的错误是 `--ipc=host` 或 `hostIPC: true`。这可能是为了兼容遗留软件或出于方便，但它会显著改变信任模型。另一个经常出现的问题是简单地忽略 IPC，因为它比 host PID 或 host networking 看起来不那么严重。实际上，如果工作负载处理浏览器、数据库、科学计算或其他大量使用共享内存的软件，IPC 攻击面可能非常相关。

## 滥用

当 host IPC 被共享时，攻击者可能会检查或干扰共享内存对象，获得对 host 或相邻工作负载行为的新洞见，或者将那里学到的信息与进程可见性和类似 ptrace 的能力结合起来。IPC 共享通常是一个辅助性弱点，而不是完整的突破路径，但辅助性弱点很重要，因为它们会缩短并稳定真实的攻击链。

首要有用的步骤是枚举哪些 IPC 对象是可见的：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
如果共享主机的 IPC 命名空间，较大的共享内存段或有趣的对象所有者可以立即揭示应用程序的行为：
```bash
ipcs -m -p
ipcs -q -p
```
在某些环境中，`/dev/shm` 的内容本身会泄露值得检查的文件名、痕迹或令牌：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC 共享本身很少会直接提供即时的 host root，但它可能暴露数据和协调通道，从而使后续的进程攻击变得容易得多。

### 完整示例：`/dev/shm` 秘密恢复

最现实的完整滥用场景通常是数据窃取，而不是直接逃逸。如果暴露了 host IPC 或广泛的 shared-memory 布局，有时可以直接恢复敏感工件：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
影响:

- 从共享内存中提取遗留的敏感信息或会话材料
- 洞察主机上当前活跃的应用程序
- 为后续基于 PID-namespace 或 ptrace 的攻击提供更精准的目标定位

因此，IPC 共享更应被理解为一个**攻击放大器**，而不是一个独立的主机逃逸原语。

## 检查

这些命令用于判断工作负载是否拥有私有的 IPC 视图、是否可以看到有意义的共享内存或消息对象，以及 `/dev/shm` 本身是否暴露有用的工件。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
这里值得注意的点：

- 如果 `ipcs -a` 显示由意外的用户或服务拥有的对象，说明该 namespace 可能并不像预期那样隔离。
- 大型或异常的共享内存段通常值得进一步调查。
- 一个广泛的 `/dev/shm` 挂载并不一定是漏洞，但在某些环境中它会 leaks 文件名、工件和临时秘密。

IPC 很少像更大的 namespace 类型那样受到那么多关注，但在大量使用它的环境中，与宿主机共享它确实是一个重大的安全决策。
{{#include ../../../../../banners/hacktricks-training.md}}
