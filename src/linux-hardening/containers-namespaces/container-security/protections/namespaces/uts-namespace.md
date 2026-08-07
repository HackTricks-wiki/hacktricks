# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

UTS namespace 隔离进程所看到的 **hostname** 和 **NIS domain name**。乍看之下，与 mount、PID 或 user namespaces 相比，这似乎微不足道，但它正是 container 能够表现得像独立主机的组成部分之一。在该 namespace 内，workload 可以看到一个属于该 namespace 的 hostname，并且有时可以修改它，而不是修改整台机器的全局 hostname。

单独来看，这通常不是 breakout 的核心。然而，一旦共享 host UTS namespace，权限足够高的进程就可能影响与主机身份相关的设置，这在运维层面可能很重要，偶尔也会带来安全影响。

## Lab

你可以使用以下命令创建一个 UTS namespace：
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
主机名更改仅在该 namespace 中保持本地化，不会改变主机的全局主机名。这是 isolation 属性的一个简单但有效的演示。

## Runtime Usage

普通 containers 会获得隔离的 UTS namespace。Docker 和 Podman 可通过 `--uts=host` 加入主机 UTS namespace，其他 runtimes 和 orchestration systems 中也可能存在类似的 host-sharing 模式。不过，大多数情况下，private UTS isolation 只是正常 container setup 的一部分，几乎不需要 operator 关注。

## Security Impact

尽管 UTS namespace 通常不是最危险的可共享 namespace，但它仍有助于维护 container boundary 的完整性。如果 host UTS namespace 暴露，且进程拥有必要的 privileges，则可能能够修改主机的 hostname 相关信息。这可能影响 monitoring、logging、operational assumptions，或基于主机 identity data 做出 trust decisions 的 scripts。

## Abuse

如果共享 host UTS namespace，实际需要关注的问题是：进程是否能够修改主机 identity settings，而不仅仅是读取它们：
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
如果 container 也具有必要的 privilege，请测试是否可以更改 hostname：
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
这主要是一个完整性和运行影响问题，而不是完整的 escape，但它仍然表明 container 可以直接影响 host 全局属性。

影响：

- host identity 篡改
- 混淆信任 hostname 的日志、监控或自动化流程
- 通常单独不会导致完整的 escape，除非与其他弱点结合

在 Docker-style 环境中，一个有用的 host-side 检测模式是：
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
显示 `UTSMode=host` 的容器正在共享主机的 UTS namespace；如果它们还具备能够调用 `sethostname()` 或 `setdomainname()` 的 capabilities，则应进行更仔细的审查。

## 检查

以下命令足以确认 workload 是否拥有独立的 hostname 视图，或是否正在共享主机的 UTS namespace。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
这里有哪些值得关注的地方：

- 将 namespace 标识符与 host 进程进行匹配，可能表明存在 host UTS 共享。
- 如果更改 hostname 会影响的不只是 container 本身，则说明该 workload 对 host identity 的影响超出了应有范围。
- 与 PID、mount 或 user namespace 问题相比，这通常属于较低优先级的发现，但仍能确认该进程实际隔离的程度。

在大多数环境中，UTS namespace 最好被视为一种辅助隔离层。它很少是 breakout 调查中首先追查的对象，但仍然是 container 视图整体一致性与安全性的一部分。

{{#include ../../../../../banners/hacktricks-training.md}}
