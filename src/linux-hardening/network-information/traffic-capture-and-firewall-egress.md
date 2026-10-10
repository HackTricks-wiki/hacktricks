# 트래픽 캡처, 방화벽 및 송신 트래픽 점검

{{#include ../../banners/hacktricks-training.md}}

[로컬 리스너와 Unix 소켓](local-network-and-socket-triage.md)을 찾은 뒤, 어떤 인터페이스가 해당 트래픽을 전달하는지, 그리고 어떤 방화벽 또는 프록시 규칙이 접근성에 영향을 미치는지 확인하세요. 루프백에서만 동작하는 서비스라도 다른 호스트에서 접근할 수 없더라도 민감한 HTTP 헤더를 전달할 수 있습니다.

## 캡처 권한을 확인하고 인터페이스 선택하기

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

현재 사용자에게 sudo 권한이 없어도 `dumpcap`에 패킷 캡처 기능이 있을 수 있습니다. 실행 파일의 실제 capabilities와 그룹 권한을 확인하세요. 유용한 범위 내에서 인터페이스, 캡처 시간, 필터를 최소화하세요. 캡처 데이터에는 자격 증명이나 개인 정보가 포함될 수 있습니다.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow`는 일반 텍스트 TCP 스트림을 재구성하고, `tshark`는 캡처에서 필드를 필터링하고 추출할 수 있습니다. TLS 트래픽을 복호화하려면 엔드포인트 키가 있거나, 연결 전에 `SSLKEYLOGFILE`을 사용하도록 설정된 지원 클라이언트가 필요합니다. [로컬 네트워크 triage 페이지](local-network-and-socket-triage.md#tls-key-logging)에서 해당 절차를 확인할 수 있습니다. 암호화된 캡처를 읽을 수 있는 일반 텍스트로 취급하지 마세요.

저장된 인시던트 아티팩트가 있다면 판단이 달라질 수 있습니다. [Linux core dump는 프로세스 메모리의 이미지](https://man7.org/linux/man-pages/man5/core.5.html)이므로 세션 키가 남아 있을 수 있습니다. 읽을 수 있는 덤프와 패킷 캡처가 동일한 프로세스와 세션에서 나온 것이라면 분석가가 해당 트래픽을 복호화할 수 있습니다. 먼저 아티팩트 경로와 권한을 확인한 뒤, 프로세스 ID, 캡처 시간, 프로토콜, 키 형식을 각각 검증하세요. 복호화된 트래픽이나 복구된 아카이브는 정보 노출 가능성을 나타내는 단서일 뿐, 다른 계정에 접근했다는 증거는 아닙니다. 일부 SSH 키 자료를 복구했더라도 이를 재구성하고 해당 공개 키와 대조한 뒤, 그 계정의 SSH 정책에서 허용되는지 확인해야 합니다. 광범위한 열거 결과에 core 내용이나 캡처 페이로드를 덤프하지 마세요.

## 방화벽 계층 식별

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` 및 `iptables`는 UFW 또는 firewalld와 같은 배포판 래퍼를 통해 노출될 수 있습니다. 활성 규칙과 래퍼의 영구 저장된 구성을 확인하세요. 한 표현에서 보이는 규칙이 다른 도구에 의해 생성되었을 수 있습니다. 특정 규칙이 서비스를 차단한다고 판단하기 전에 인터페이스, 방향, 소스, 대상, 프로토콜, 포트 및 연결 상태를 확인하세요. 집중된 예시는 [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes)를 참조하세요.

## egress 및 프록시 동작 테스트

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

DNS 오류를 TCP, TLS 또는 proxy 오류와 구분하세요. 평가와 관련된 대상과 프로토콜을 구체적으로 테스트하세요. ICMP 연결이 가능하다고 해서 TCP 또는 UDP가 허용되는 것은 아닙니다. proxy가 구성되어 있다면, 의도한 proxy 경유 요청과 해당 `no_proxy` 규칙이 적용된 동일 대상에 대한 요청을 비교하세요. 로컬 포트 포워딩으로 loopback 서비스에 다른 위치에서 접근할 수도 있으므로, 방화벽 상태와 실제 노출이 일치하지 않으면 활성 listener와 SSH tunnel을 검토하세요.
{{#include ../../banners/hacktricks-training.md}}
