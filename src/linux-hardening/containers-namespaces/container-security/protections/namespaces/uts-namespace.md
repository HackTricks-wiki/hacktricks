# UTS 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

UTS 命名空间隔离进程所看到的 **hostname** 和 **NIS domain name**。乍看之下，与 mount、PID 或 user 命名空间相比，这似乎微不足道，但它正是 container 能够呈现为独立主机的原因之一。在该命名空间内，workload 可以看到一个仅属于该命名空间的 hostname，并且有时可以修改它，而不是修改整台机器的全局 hostname。

单独来看，这通常不是 breakout 的核心。然而，一旦共享 host UTS 命名空间，权限足够高的进程就可能影响与主机身份相关的设置，这在运维层面可能很重要，偶尔也会带来安全影响。

## 实验

你可以使用以下命令创建 UTS 命名空间：
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
主机名更改仅在该命名空间内有效，不会更改主机的全局主机名。这是对隔离属性的一个简单但有效的演示。

## 运行时使用

普通容器会获得一个隔离的 UTS 命名空间。Docker 和 Podman 可通过 `--uts=host` 加入主机的 UTS 命名空间，其他运行时和编排系统中也可能存在类似的主机共享模式。不过，大多数情况下，私有 UTS 隔离只是正常容器设置的一部分，几乎不需要操作员关注。

## 安全影响

尽管 UTS 命名空间通常不是最危险的共享对象，但它仍然有助于维护容器边界的完整性。如果主机的 UTS 命名空间暴露，并且进程拥有必要的权限，则可能能够修改与主机名相关的信息。这可能影响监控、日志记录、运维假设，或基于主机身份数据做出信任决策的脚本。

## 滥用

如果共享了主机的 UTS 命名空间，实际需要关注的问题是：进程是否能够修改主机身份设置，而不仅仅是读取这些设置：
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
如果容器还具有必要的权限，请测试是否可以更改 hostname：
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
这主要是一个完整性和运行影响问题，而不是一次完整的 escape，但它仍然表明 container 可以直接影响 host-global 属性。

影响：

- host identity 篡改
- 误导信任 hostname 的日志、监控或自动化
- 通常单独不会导致 full escape，除非与其他弱点结合

在 Docker-style 环境中，一个实用的 host-side detection pattern 是：
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
显示 `UTSMode=host` 的容器正在共享主机的 UTS namespace；如果它们同时具有可调用 `sethostname()` 或 `setdomainname()` 的 capabilities，则应进行更仔细的审查。

## 检查

以下命令足以确认 workload 是拥有自己的 hostname 视图，还是正在共享主机的 UTS namespace。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
这里有哪些值得关注的地方：

- 将 namespace 标识符与 host 进程进行匹配，可能表明存在 host UTS sharing。
- 如果更改 hostname 的影响范围超出 container 本身，说明该 workload 对 host identity 的影响超出了应有范围。
- 这通常比 PID、mount 或 user namespace 问题的优先级更低，但仍能确认进程实际隔离的程度。

在大多数环境中，UTS namespace 最好被视为一种辅助隔离层。它很少是 breakout 中最先排查的对象，但仍然是 container view 整体一致性与安全性的一部分。
{{#include ../../../../../banners/hacktricks-training.md}}
