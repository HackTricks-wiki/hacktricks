# 트래픽 캡처, 방화벽 및 아웃바운드 트래픽 점검

{{#include ../../banners/hacktricks-training.md}}

[로컬 리스너와 Unix 소켓](local-network-and-socket-triage.md)을 찾은 후, 어떤 인터페이스로 트래픽이 전달되는지, 어떤 방화벽 또는 프록시 규칙이 연결 가능성에 영향을 미치는지 확인하세요. 루프백 전용 서비스도 다른 호스트에서 접근할 수 없더라도 민감한 HTTP 헤더를 전달할 수 있습니다.

## 캡처 권한을 확인하고 인터페이스 선택하기

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap`은 현재 사용자에게 sudo 권한이 없어도 패킷 캡처 기능을 보유하고 있을 수 있습니다. 실행 파일의 실제 capabilities와 그룹 권한을 확인하세요. 필요한 최소한의 인터페이스, 캡처 시간, 필터를 사용하세요. 캡처 데이터에 자격 증명이나 개인 정보가 포함될 수 있습니다.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow`는 평문 TCP 스트림을 재구성하고, `tshark`는 캡처에서 필드를 필터링하고 추출할 수 있습니다. TLS 트래픽을 복호화하려면 엔드포인트 키가 필요하거나, 연결 전에 `SSLKEYLOGFILE`을 사용하도록 설정된 지원 클라이언트가 필요합니다. [로컬 네트워크 triage 페이지](local-network-and-socket-triage.md#tls-key-logging)에서 해당 절차를 확인할 수 있습니다. 암호화된 캡처를 읽을 수 있는 평문으로 취급하지 마세요.

저장된 인시던트 아티팩트에 따라 판단이 달라질 수 있습니다. [Linux core dump는 프로세스 메모리의 이미지](https://man7.org/linux/man-pages/man5/core.5.html)이므로 세션 키가 남아 있을 수 있습니다. 읽을 수 있는 덤프와 패킷 캡처가 동일한 프로세스와 세션에서 생성됐다면 분석가는 해당 트래픽을 복호화할 수 있을지도 모릅니다. 먼저 아티팩트 경로와 권한을 확인한 다음, 프로세스 ID, 캡처 시간, 프로토콜, 키 형식을 각각 검증하세요. 복호화된 트래픽이나 복구된 아카이브는 정보 노출 단서일 뿐, 다른 계정에 접근했다는 증거는 아닙니다. 일부 SSH 키 자료라도 해당 계정의 SSH 정책에서 허용되는지 확인하려면 먼저 재구성한 뒤 대응하는 공개 키와 일치시켜야 합니다. 광범위한 열거 출력에 core 내용이나 캡처 페이로드를 덤프하지 마세요.

## 방화벽 계층 식별

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables`와 `iptables`는 UFW나 firewalld 같은 배포판 래퍼를 통해 노출될 수 있습니다. 활성 규칙과 래퍼의 영구 설정을 확인하세요. 한 표현에 표시된 규칙이 다른 도구에서 생성되었을 수 있습니다. 특정 규칙 때문에 서비스가 차단되었다고 판단하기 전에 인터페이스, 방향, 소스, 대상, 프로토콜, 포트, 연결 상태를 확인하세요. 구체적인 예시는 [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes)를 참조하세요.

## egress 및 proxy 동작 테스트

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS 실패와 TCP, TLS 또는 proxy 실패를 구분하세요. 평가와 관련된 특정 대상 및 프로토콜을 테스트하세요. ICMP 연결 가능성이 TCP 또는 UDP가 허용된다는 뜻은 아닙니다. proxy가 구성되어 있다면, 의도한 proxy 경유 요청과 해당 `no_proxy` 규칙을 적용해 동일한 대상에 보낸 요청을 비교하세요. 로컬 포트 포워딩으로 loopback 서비스가 다른 곳에서 접근 가능해질 수도 있으므로, 방화벽 관점과 실제 노출 상태가 다르면 활성 리스너와 SSH 터널을 검토하세요.
{{#include ../../banners/hacktricks-training.md}}
