# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

IPC namespace 隔离 **System V IPC objects** 和 **POSIX message queues**。其中包括 shared memory segments、semaphores 以及 message queues；否则，这些对象可能会被主机上彼此无关的进程看到。实际上，这可以防止 container 轻易连接到属于其他 workloads 或主机的 IPC objects。

与 mount、PID 或 user namespaces 相比，IPC namespace 受到的讨论通常较少，但这并不意味着它无关紧要。Shared memory 及相关 IPC mechanisms 可能包含非常有用的状态信息。如果 host IPC namespace 被暴露，workload 可能获得对进程间协调对象或数据的可见性，而这些对象或数据原本并不 intended to cross the container boundary。

## 操作

当 runtime 创建一个全新的 IPC namespace 时，进程会获得一组独立隔离的 IPC identifiers。这意味着诸如 `ipcs` 之类的命令只会显示该 namespace 中可用的 objects。如果 container 转而加入 host IPC namespace，这些 objects 就会成为共享 global view 的一部分。

这一点在应用或服务大量使用 shared memory 的环境中尤其重要。即使 container 无法仅通过 IPC 直接 break out，namespace 也可能 leak 信息，或启用跨进程干扰，从而实质性地帮助后续攻击。

## 实验

你可以使用以下命令创建一个 private IPC namespace：
```bash
sudo unshare --ipc --fork bash
ipcs
```
并比较运行时行为：
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime 使用

Docker 和 Podman 默认会隔离 IPC。Kubernetes 通常会为 Pod 提供独立的 IPC namespace，该 namespace 由同一 Pod 中的容器共享，但默认不会与 host 共享。可以共享 host IPC，但这应被视为隔离性明显降低，而不是一个次要的 runtime 选项。

## Misconfigurations

最明显的错误是 `--ipc=host` 或 `hostIPC: true`。这样做可能是为了兼容 legacy software，或出于便利，但它会实质性地改变 trust model。另一个常见问题是忽略 IPC，因为它看起来没有 host PID 或 host networking 那么严重。实际上，如果 workload 处理 browsers、databases、scientific workloads，或其他大量使用 shared memory 的 software，IPC surface 可能非常重要。

## Abuse

共享 host IPC 时，attacker 可能检查或干扰 shared memory objects，进一步了解 host 或相邻 workload 的行为，或将从中获得的信息与 process visibility 和 ptrace-style capabilities 结合起来。IPC sharing 通常是 supporting weakness，而不是完整的 breakout path，但 supporting weaknesses 很重要，因为它们会缩短并稳定真实的 attack chains。

第一步通常是枚举到底能看到哪些 IPC objects：
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
如果共享宿主机的 IPC namespace，大型共享内存段或有趣的对象所有者可以立即揭示应用程序行为：
```bash
ipcs -m -p
ipcs -q -p
```
在某些环境中，`/dev/shm` 的内容本身会 leak 出值得检查的文件名、artifacts 或 tokens：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing 很少会单独立即提供 host root，但它可能暴露数据和协调通道，使后续的进程攻击变得容易得多。

### 完整示例：`/dev/shm` Secret Recovery

最现实的完整滥用场景是数据窃取，而不是直接 escape。如果暴露了主机 IPC 或广泛的共享内存布局，有时可以直接恢复敏感 artifacts：
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
影响：

- 提取留存在共享内存中的 secrets 或 session material
- 了解当前在 host 上运行的 applications
- 为后续基于 PID-namespace 或 ptrace 的 attacks 提供更好的 targeting 信息

因此，与其将 IPC sharing 视为一种独立的 host-escape primitive，不如将其理解为一种 **attack amplifier**。

## 检查

这些命令旨在确认 workload 是否拥有独立的 IPC 视图、是否可见有意义的 shared-memory 或 message objects，以及 `/dev/shm` 本身是否暴露了有用的 artifacts。
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
这里有哪些值得关注的地方：

- 如果 `ipcs -a` 显示出由意外用户或服务拥有的对象，则该 namespace 可能没有预期的隔离程度。
- 大型或异常的 shared memory 段通常值得进一步跟进。
- 宽泛的 `/dev/shm` 挂载并不一定是 bug，但在某些环境中，它会 leak 文件名、artifacts 和临时 secrets。

IPC 很少像更重要的 namespace 类型那样受到关注，但在大量使用 IPC 的环境中，与 host 共享 IPC 绝对是一项 security 决策。
{{#include ../../../../../banners/hacktricks-training.md}}
