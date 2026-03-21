# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

UTS namespace 隔离了进程看到的 **hostname** 和 **NIS domain name**。乍一看这相比于 mount、PID 或 user namespaces 似乎微不足道，但它是让容器看起来像独立主机的一部分。在该 namespace 内，工作负载可以看到并有时更改一个对该 namespace 本地而非整台机器全局的 hostname。

单独看，它通常不是 breakout 故事的核心。不过，一旦共享了 host UTS namespace，具有足够权限的进程可能会影响主机身份相关的设置，这在运维上有影响，有时也会带来安全方面的影响。

## 实验

你可以使用以下命令创建 UTS namespace：
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
主机名的更改仅局限于该命名空间，不会更改主机的全局主机名。这是隔离特性的一个简单但有效的示例。

## 运行时用法

普通容器会获得一个隔离的 UTS 命名空间。Docker 和 Podman 可以通过 `--uts=host` 加入主机的 UTS 命名空间，类似的主机共享模式也可能出现在其他运行时和编排系统中。不过在大多数情况下，私有 UTS 隔离只是正常容器设置的一部分，几乎不需要操作者额外关注。

## 安全影响

尽管 UTS 命名空间通常不是最危险的共享对象，但它仍影响容器边界的完整性。如果主机的 UTS 命名空间被暴露，且进程具有必要的权限，则它可能能够修改与主机主机名相关的信息。这可能影响监控、日志、运维假设，或基于主机身份数据做出信任决策的脚本。

## 滥用

如果主机 UTS 命名空间被共享，实际的问题是进程是否能够修改主机身份设置，而不仅仅是读取它们：
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
如果容器也具有必要的权限，测试是否可以更改主机名:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
这主要是一个完整性和运行影响的问题，而不是一次完全 escape，但它仍然表明容器可以直接影响主机级别的属性。

影响：

- 主机身份篡改
- 使依赖主机名的日志、监控或自动化产生混淆
- 单独通常不会导致完全 escape，除非与其他漏洞结合

在 Docker-style 环境中，一个有用的主机端检测模式是：
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers showing `UTSMode=host` are sharing the host UTS namespace and should be reviewed more carefully if they also carry capabilities that let them call `sethostname()` or `setdomainname()`.

## 检查

这些命令足以判断工作负载是否有自己的主机名视图，或是否在共享宿主机的 UTS namespace。
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- 将命名空间标识符与主机进程匹配可能表明与主机共享 UTS namespace。
- 如果更改主机名影响到容器本身以外的范围，那么该工作负载对主机身份的影响超过了应有的程度。
- 这通常比 PID、mount 或 user namespace 的问题优先级要低，但它仍然能确认进程实际的隔离程度。

在大多数环境中，UTS namespace 最好被视为一个辅助性的隔离层。它很少是你在容器逃逸中首先追查的对象，但它仍然是容器视图整体一致性与安全性的一部分。
