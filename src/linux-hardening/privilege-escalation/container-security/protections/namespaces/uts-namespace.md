# UTS 命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

UTS 命名空间将进程看到的 **主机名** 和 **NIS 域名** 隔离开来。乍看之下，与挂载、PID 或用户命名空间相比这似乎微不足道，但它是使容器看起来像独立主机的一部分。在该命名空间内，工作负载可以看到并有时更改一个对该命名空间本地的主机名，而不是机器全局的主机名。

单独来看，这通常不是 breakout 故事的核心。不过，一旦共享了宿主机 UTS 命名空间，具有足够权限的进程可能会影响宿主机身份相关的设置，这在运维上可能有影响，有时也会带来安全方面的后果。

## 实验

你可以使用以下命令创建一个 UTS 命名空间：
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
主机名更改仅限于该命名空间，不会修改主机的全局主机名。这是对隔离属性的一个简单但有效的演示。

## 运行时使用

普通容器会获得一个独立的 UTS 命名空间。Docker 和 Podman 可以通过 `--uts=host` 加入主机的 UTS 命名空间，其他运行时和编排系统也可能出现类似的主机共享模式。然而，大多数情况下，私有的 UTS 隔离只是常规容器配置的一部分，几乎不需要运维人员干预。

## 安全影响

尽管 UTS 命名空间通常不是最危险的共享对象，但它仍影响容器边界的完整性。如果主机的 UTS 命名空间被暴露并且进程拥有必要的权限，可能能够修改与主机主机名相关的信息。这可能影响监控、日志、运行时假设，或基于主机身份数据做出信任决策的脚本。

## 滥用

如果主机的 UTS 命名空间被共享，实际的问题是进程是否能修改主机身份设置，而不仅仅是读取它们：
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
如果容器也具有必要的权限，测试是否可以更改主机名：
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
这主要是一个完整性和操作影响问题，而不是完全逃逸，但它仍然表明容器可以直接影响主机全局属性。

Impact:

- 主机身份篡改
- 使依赖主机名的日志、监控或自动化产生混淆
- 通常单独并不会导致完全逃逸，除非与其他弱点结合

On Docker-style environments, a useful host-side detection pattern is:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
显示 `UTSMode=host` 的容器正在与主机共享 UTS 命名空间，如果它们还具有允许调用 `sethostname()` 或 `setdomainname()` 的 capabilities，则应更仔细地审查。

## Checks

这些命令足以查看工作负载是否拥有自己的主机名视图，或正在共享主机的 UTS 命名空间。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
有趣的点：

- 将命名空间标识符与主机进程匹配可能表明存在主机 UTS 共享。
- 如果更改 hostname 会影响到不仅仅是 container 本身，则该 workload 对主机身份的影响力超出了应有的范围。
- 通常这类问题的优先级低于 PID、mount 或 user namespace 问题，但它仍然可以确认进程的实际隔离程度。

在大多数环境中，UTS namespace 最好被视为一个辅助隔离层。它很少是你在 breakout 中首先追踪的对象，但它仍然是容器视图整体一致性和安全性的一部分。
{{#include ../../../../../banners/hacktricks-training.md}}
