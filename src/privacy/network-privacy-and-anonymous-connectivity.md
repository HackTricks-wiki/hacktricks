# 네트워크 프라이버시 및 익명 연결

{{#include ../banners/hacktricks-training.md}}

네트워크 프라이버시는 라우팅 결정이지 완전한 신원 보호가 아닙니다. 경로를 선택할 때 **출발지**, **목적지**, **콘텐츠**, **타이밍** 중 어떤 정보를 누구에게 숨길지 고려하세요.

정규화된 인벤토리—각 액세스 경로 유형의 `Pros`, `Cons`, 단계별 `Procedure`, `Detection`—는 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)에서 확인하세요. 이 페이지에서는 일반적으로 배포할 수 있는 옵션을 자세히 살펴봅니다.

## 각 관찰자가 보통 볼 수 있는 정보

| 경로 | 로컬 네트워크 / ISP | 중개자 | 목적지 | 주요 한계 | 상대 속도 |
|---|---|---|---|---|---|
| 직접 HTTPS | 출발지, 목적지 메타데이터, 타이밍/트래픽 양 | 호스팅/CDN은 연결을 확인 | 출발지 IP, 브라우저/앱 데이터 | 출발지 IP 프라이버시를 제공하지 않음 | 가장 빠름 |
| 상용 VPN | 출발지가 VPN에 연결된 사실. 일반적으로 목적지 메타데이터는 보이지 않음 | VPN은 출발지와 목적지 메타데이터를 확인 | VPN 출구 IP | 한 제공자가 상관관계 분석 지점이 됨 | 대체로 빠름 |
| 자체 호스팅 VPN/VPS | 출발지가 VPS에 연결된 사실 | 호스트/계정/결제/제어 영역 로그 | VPS 출구 IP | 임대한 서버/계정의 소유자에게 쉽게 연결될 수 있음 | 대체로 빠름 |
| Tor Browser | 출발지가 Tor/bridge에 연결된 사실. 타이밍/트래픽 양 | 각 릴레이는 제한된 일부 정보만 확인 | Tor 출구, 브라우저 데이터 | 느림. 계정/엔드포인트/상관관계 위험 | 보통/느림 |
| Tails/Whonix | 유사한 Tor 경로, 더 강력한 라우팅 경계 | 동일한 Tor 한계 | Tor 출구/앱 데이터 | 운영 실수와 호스트/하드웨어는 여전히 위험 요소 | 보통/느림 |
| 공용 게스트 Wi-Fi + HTTPS | 장소 운영자는 로컬 장치/타이밍과 목적지를 확인 | 장소의 ISP는 메타데이터를 확인 | 게스트 공용 IP | 물리적 위치/캡티브 포털/장치 상관관계 | 빠름/가변적 |
| 셀룰러 핫스팟 | 통신사는 가입자/장치/위치와 목적지를 확인 | 사용 중인 경우 VPN/Tor | 통신사, VPN 또는 Tor 출구 IP | 모바일 가입 정보와 위치는 지속적으로 사용할 수 있는 식별자 | 빠름/가변적 |
| Mixnet | 액세스 네트워크는 mixnet 사용 사실과 타이밍/트래픽 양을 확인 | 여러 믹싱 노드 | 게이트웨이/출구 | 생태계가 초기 단계이며 지연 시간과 대역폭 비용이 큼 | 가장 느림 |

HTTPS는 전송 중 콘텐츠를 보호하지만 모든 메타데이터를 보호하지는 않습니다. EFF에 따르면 페이지 경로, 자격 증명, 메시지가 암호화되어 있어도 도메인, 시간, 트래픽 크기는 중개자에게 계속 보일 수 있습니다.<sup>[[1]](#references)</sup>

암호화된 오버레이가 자동으로 익명 네트워크가 되는 것은 아닙니다. Yggdrasil의 직접 피어는 서로의 IP 주소를 볼 수 있습니다.<sup>[[20]](#references)</sup> Yggdrasil의 [userspace forwarding and SOCKS transport](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack)는 터널링 옵션이지 출발지 익명성 계층이 아닙니다.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN: 신뢰가 집중되는 빠른 프라이버시 옵션

VPN은 액세스 ISP로부터 목적지 메타데이터를 숨기거나, 신뢰할 수 없는 네트워크에서 첫 번째 홉을 보호하거나, 참여 작업에 사용할 고정된 출구 주소를 제공하거나, 사설 네트워크에 접속할 때 유용합니다. 하지만 **사용자를 익명으로 만들지는 않습니다**. VPN은 출발지 연결을 확인하고 목적지 메타데이터를 관찰할 수 있으며, 계정, 쿠키, GPS, 지문, 결제 정보도 그대로 남습니다.<sup>[[1]](#references)</sup>

### 제공업체 평가 체크리스트

1. **소유권 및 관할권:** 법인, 모회사, 운영 국가, 인프라 하청업체, 적용되는 법적 절차를 확인합니다.
2. **수집 데이터:** 계정/청구 정보, 출발지 IP, 연결 타임스탬프, 대역폭, 충돌 텔레메트리, DNS 쿼리, 목적지 로그를 구분합니다. “브라우징 로그를 남기지 않음”이 “데이터를 수집하지 않음”을 뜻하지는 않습니다.
3. **보존 및 삭제:** 정확한 보존 기간과 백업, 사기 방지 시스템, 데이터 처리업체에도 같은 일정이 적용되는지 확인합니다.
4. **증거:** 범위, 날짜, 결과, 개선 조치가 명시된 공개 감사, 재현 가능하거나 공개된 클라이언트, 투명성 보고서, 문서화된 사고를 우선합니다.
5. **프로토콜 및 클라이언트:** 유지 관리되는 WireGuard, OpenVPN 또는 다른 검토된 프로토콜, 자동 업데이트, DNS 및 IPv6 처리, kill switch, 플랫폼별 leak 테스트를 확인합니다.
6. **비즈니스 모델:** 무료 또는 저가 서비스의 운영 자금이 어떻게 마련되는지 파악합니다. 앱 스토어에 등록되어 있다는 사실만으로 신뢰할 수 있는 운영을 입증할 수는 없습니다.
7. **결제 적합성:** 대체 결제 수단을 사용하면 VPN에 공개되는 청구 정보를 줄일 수 있지만, 연결 때마다 관찰되는 출발지 IP를 없애지는 못합니다.

### VPN 구성 및 확인

1. 제공업체/조직의 공식 출처에서 서명된 클라이언트를 설치합니다.
2. 문서화된 경로가 VPN을 우회해야 하는 경우가 아니라면 **full tunnel**을 선택합니다. Split tunneling은 상관관계 분석과 leak 경로를 만듭니다.
3. fail-closed/always-on 동작을 활성화하고 재연결 중에는 트래픽을 차단합니다.
4. DNS를 터널로 보내고 IPv4와 IPv6를 모두 테스트합니다. 안전하게 터널링할 수 없고 기능 손실을 감수할 수 있는 경우에만 프로토콜을 비활성화합니다.
5. 절전/복귀, 네트워크 전환, 캡티브 포털 로그인, 터널 충돌, 핫스팟 테더링을 테스트합니다. NCSC는 일부 플랫폼에서 테더링된 클라이언트가 휴대전화의 VPN을 우회할 수 있다고 경고합니다.<sup>[[2]](#references)</sup>
6. 조직이 관리하는 테스트 엔드포인트를 사용해 관찰된 IPv4, IPv6, DNS 리졸버, 연결 타이밍을 기록합니다. 민감한 참여 작업에서 무작위 “leak test” 사이트를 사용하지 마세요.
7. 클라이언트, OS, 네트워크 또는 정책을 변경한 후 다시 테스트합니다.

### 악성 LAN에서의 라우팅 우회

운영체제가 패킷을 VPN으로 암호화하기 **전에** 경로를 선택하므로, 일부 패킷이 VPN을 우회해도 VPN이 “연결됨”으로 표시될 수 있습니다. TunnelCrack은 일반적인 라우팅 예외를 악용하는 두 가지 방법을 시연했습니다. **LocalNet**은 인터넷 목적지가 직접 연결된 서브넷에 있는 것처럼 보이게 하고, **ServerIP**는 VPN 게이트웨이의 이름 확인을 스푸핑하여 대상 주소에 VPN 전송에 필요한 평문 네트워크 예외를 적용합니다. 이는 WireGuard, OpenVPN, IPsec, TLS의 취약점이 아니라 클라이언트/라우팅 실패입니다. HTTPS 페이로드는 종단 간 암호화된 상태로 유지되지만, 로컬 관찰자는 목적지/타이밍 메타데이터와 평문 프로토콜 데이터를 복구할 수 있습니다.<sup>[[18]](#references)</sup>

TunnelVision은 DHCP 옵션 121을 통해 같은 사전 암호화 원리를 적용합니다. 악성 또는 침해된 DHCP 서버는 VPN의 포괄 경로보다 더 구체적인 클래스리스 경로를 설치해 임의의 호스트나 범위에 물리 인터페이스를 선택할 수 있습니다. VPN 제어 채널은 계속 연결된 상태일 수 있으므로, 터널 연결 해제만 감지하는 kill switch는 작동하지 않을 수 있고, 단일 공용 “IP leak” 확인으로는 선택적 우회를 발견하지 못할 수도 있습니다.<sup>[[19]](#references)</sup>

물리 인터페이스에서 DHCP와 인증된 VPN 전송만 허용하는 패킷 필터 kill switch를 사용하면 fail-closed 동작으로 만들 수 있지만, 표적 경로 주입은 여전히 선택적 서비스 거부 사이드 채널을 만들 수 있습니다. 영향이 큰 Linux 워크로드에는 애플리케이션 네임스페이스에 물리 인터페이스나 평문 네트워크 기본 경로가 없는 더 강력한 [워크로드별 경로 강제 네트워크 네임스페이스 패턴](advanced-network-privacy-architectures.md#enforce-the-route-per-workload)을 우선 사용합니다.<sup>[[19]](#references)</sup>

#### 자체 관리 랩에서 확인

라우팅 및 패킷 필터 구현은 플랫폼마다 다르고 제품 전반에 대한 주장은 시간이 지나면 오래될 수 있으므로, 자체 관리 AP, DHCP 서버, VPN 엔드포인트, 목적지에서 정확한 클라이언트/OS/버전을 테스트합니다. 엔드포인트와 테스트 서버 양쪽에서 패킷을 캡처하세요. 출구 IP 확인 웹사이트만으로는 모든 목적지가 터널을 통과한다는 사실을 입증할 수 없습니다.<sup>[[18]](#references)[[19]](#references)</sup>

1. VPN에 연결하고 VPN 서버 주소를 기록한 다음 모든 IPv4/IPv6 라우팅 테이블과 정책 라우팅 규칙을 저장합니다. Windows에서는 `route print`, macOS에서는 `netstat -rn`, Linux에서는 아래 명령을 사용합니다.
2. 여러 자체 관리 목적지 IP에 대해 선택된 경로를 조회합니다. 문서화된 VPN 전송 엔드포인트를 제외하면 다음 홉/인터페이스는 터널이어야 합니다.
3. TunnelVision 테스트에서는 통제된 DHCP 네트워크에서 임대를 갱신하고, 자체 관리 테스트 목적지에만 적용되는 옵션 121 경로를 설치합니다. 테스트 통과 조건은 트래픽이 터널링되거나 차단되는 것이며, 물리 인터페이스를 통해 목적지 트래픽으로 나가서는 안 됩니다.
4. LocalNet 테스트에서는 클라이언트에 `203.0.113.0/24`와 같은 랩 전용 공용 문서화 서브넷을 할당하고, 해당 서브넷 안에 자체 관리 테스트 목적지를 둡니다. LAN 액세스를 활성화해도 인터넷 목적지로 분류되는 트래픽이 터널을 우회하지 않는지 확인합니다.
5. ServerIP 테스트에서는 VPN 연결 전에 통제된 DNS가 자체 관리 VPN 호스트 이름을 자체 관리 테스트 목적지로 확인하도록 설정하고, 랩 게이트웨이는 VPN 전송을 실제 자체 관리 VPN 엔드포인트로 전달하도록 합니다. 클라이언트는 스푸핑된 주소로 향하는 관련 없는 애플리케이션 트래픽을 예외 처리해서는 안 됩니다.
6. “local network access”를 활성화한 경우와 비활성화한 경우 모두 테스트합니다. 재연결, 절전/복귀, 네트워크 전환, VPN 프로세스 충돌 후에도 테스트를 반복합니다. IPv4, IPv6, DNS를 각각 확인합니다.
7. 물리 인터페이스 캡처를 확인합니다. DHCP 및 VPN 서버로 향하는 암호화된 패킷만 있어야 하며, 자체 관리 테스트 목적지로 직접 향하는 패킷이 있어서는 안 됩니다. 또한 사용자의 확인 메시지나 연결 복구 후 차단된 우회가 조용히 일반 연결로 전환되지 않는지 확인합니다.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: 더 강력한 웹 비연결성

Tor는 여러 릴레이를 거치는 회로를 구성하므로, 일반적으로 어느 한 릴레이도 출발지와 목적지를 모두 알지 못합니다. 목적지에는 사용자의 IP가 아니라 Tor exit가 표시되고, 로컬 네트워크에는 일반적으로 Tor 연결이 표시됩니다.<sup>[[3]](#references)</sup> Tor는 지연 시간이 짧은 TCP 애플리케이션용으로 설계되었으므로 속도가 느리고, 양쪽 끝을 모두 상관 분석할 수 있는 공격자로부터의 보호를 보장하지 않습니다.<sup>[[4]](#references)</sup>

### 안전한 Tor Browser 사용 절차

1. Tor Browser는 Tor Project 또는 공식 미러에서만 다운로드하고, 가능하면 서명을 확인합니다.
2. 일반 브라우저에서 Tor SOCKS 포트를 지정해 사용하는 대신 **Tor Browser**를 사용합니다. 일반 브라우저는 DNS/WebRTC와 식별 가능한 상태를 leak할 수 있습니다.<sup>[[5]](#references)</sup>
3. 기본 크기, 글꼴, 확장 프로그램 및 개인정보 보호 설정을 유지합니다. 추가 애드온은 브라우저를 더 고유하게 만들 수 있습니다.<sup>[[6]](#references)</sup>
4. 기능이 더 많이 제한되는 것을 감수할 수 있다면 보안 수준을 **Safer** 또는 **Safest**로 설정합니다.
5. 직접 Tor 연결이 차단되거나 일반 릴레이 IP가 로컬에서 노출되는 것이 허용되지 않는 경우 bridge를 사용합니다. Bridge는 쉽게 인식되는 것을 줄여 주지만 트래픽 분석을 없애지는 않습니다.<sup>[[7]](#references)</sup>
6. 신원을 식별할 수 있는 계정에 로그인하거나 식별 정보를 제공하지 말고, 다운로드한 활성 문서를 외부 네트워크에 연결된 애플리케이션에서 열지 않습니다.
7. 각 신원에 별도의 세션/컨텍스트를 사용합니다. “New circuit”은 브라우저/애플리케이션 신원을 지우는 것과 다릅니다. 상황에 따라 **New Identity**를 사용하거나 격리된 환경을 재시작합니다.
8. 인증된 HTTPS 또는 인증된 onion service를 우선 사용합니다. Tor exit는 암호화되지 않은 HTTP 트래픽을 볼 수 있습니다.

### Tor와 VPN 함께 사용하기

두 가지를 결합한다고 해서 자동으로 더 안전해지는 것은 아닙니다. Tor 앞에 VPN을 두면 ISP로부터 직접적인 Tor 릴레이 연결을 숨길 수 있지만 VPN은 출발지를 알게 됩니다. VPN 앞에 Tor를 두면 VPN이 Tor 이후 활동을 지속적으로 볼 수 있고 익명성 집합이 줄어들 수 있습니다. 잘못 구성하면 leak이 발생할 수 있습니다. Tor Project는 명확한 위협 모델을 가진 고급 사용자만 이러한 조합을 사용하도록 권고합니다.<sup>[[8]](#references)</sup>

## 공용 및 게스트 Wi-Fi

현대적인 HTTPS 덕분에 수동적으로 감시하는 주변 사용자는 일반적으로 제대로 암호화된 웹 콘텐츠를 읽을 수 없지만, 게스트 Wi-Fi는 익명성을 보장하지 않습니다. 장소 운영자는 연결 시간, 기기 식별자, 캡티브 포털 데이터, 목적지 및 DHCP 세부 정보를 기록할 수 있습니다. 카메라, 구매 내역, 교통수단 및 물리적 관찰을 통해 사용자를 식별할 수도 있습니다. 이름이 비슷한 가짜 핫스팟은 포털 인증 정보를 탈취하거나 암호화되지 않은 트래픽을 조작할 수 있습니다.<sup>[[9]](#references)</sup>

### 합법적인 게스트 네트워크 사용 절차

1. 게스트용으로 제공된 네트워크 또는 소유자가 명시적으로 사용을 허가한 네트워크만 이용합니다. 직원에게 정확한 SSID와 포털 이용 절차를 확인합니다.
2. 도착 전에 엔드포인트와 여행용 라우터를 업데이트합니다. 파일/프린터 공유, 인바운드 검색, 자동 연결 및 저장된 네트워크 검색을 비활성화합니다.
3. OS의 비공개/무작위 Wi-Fi 주소 기능을 활성화합니다. 최신 Apple 시스템은 개방형/취약한 네트워크에서 주소를 순환해 사용할 수 있으며, 최신 Android의 무작위화는 일반적으로 SSID별로 지속됩니다. 이는 로컬 식별자 하나만 줄여 줍니다.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. 권한이 높은 워크스테이션과 게스트 네트워크 사이에 조직이 관리하는 여행용 라우터 또는 신뢰도가 낮은 브리지 기기를 사용하는 것이 좋습니다. 이렇게 하면 방화벽/VPN 정책을 한곳에서 적용할 수 있지만, 장소 운영자로부터 라우터를 숨기지는 못합니다.<sup>[[12]](#references)</sup>
5. 지정된 신뢰도가 낮은 기기/브라우저를 통해서만 캡티브 포털을 완료합니다. 익명 컨텍스트라고 여겨지는 환경에서 개인 정보나 재사용 중인 인증 정보를 입력하지 않습니다. 연결이 설정되면 포털 브라우저를 닫습니다.
6. 민감한 활동을 하기 전에 전체 터널 VPN 또는 Tor를 시작하고, 실패 시 연결이 차단되는지 확인합니다.
7. 사용 후 네트워크를 삭제하고 포털 계정/데이터 보존 정책을 검토합니다.

{% hint style="danger" %}
이웃의 Wi-Fi를 크래킹하거나, 포털을 우회하거나, 유출된 게스트 인증 정보를 사용하거나, 다른 게스트의 접속을 복제하거나, 카페에 Raspberry Pi를 숨기는 행위는 무단 활동이지 개인정보 보호 기법이 아닙니다. 안전한 대안은 합법적인 게스트 네트워크, 고객이 승인한 사이트 또는 부동산 소유자의 서면 동의를 받아 설치하고 회수하는 문서화된 drop node입니다.
{% endhint %}

## 여행용 라우터

여행용 라우터는 워크스테이션을 적대적인 로컬 브로드캐스트로부터 격리하고, 방화벽을 적용하며, 일관된 내부 SSID를 제공하고, VPN을 자동으로 재연결할 수 있습니다. 하지만 **익명성을 보장하지는 않습니다**. 업스트림 네트워크는 라우터의 무선 식별자와 트래픽 타이밍을 볼 수 있으며, VPN 제공업체는 터널의 출발지를 알 수 있습니다.

- 지원되는 OpenWrt/공급업체 펌웨어를 사용하고 사용하지 않는 서비스를 제거합니다.
- 고유한 암호를 사용하는 Ethernet 또는 전용 관리 SSID를 통해 관리합니다.
- WAN 측 관리, UPnP, WPS, 파일 공유 및 요청하지 않은 인바운드 트래픽을 비활성화합니다.
- 지원되고 허용되는 경우에만 무작위/비공개 WAN MAC을 사용합니다.
- DNS와 IPv6를 포함해 라우터에서 VPN 정책을 적용하고 터널이 실패하면 외부 트래픽을 차단합니다.
- 휴대폰 핫스팟이 테더링 기기의 트래픽을 휴대폰 VPN을 통해 터널링한다고 가정하지 말고 직접 테스트합니다.

## 셀룰러, SIM 및 eSIM

셀룰러는 편리하지만 익명성은 보장하지 않습니다. 통신 사업자는 가입자/기기 식별자와 네트워크 연결로 추정되는 위치를 보유합니다. eSIM도 여전히 모바일 가입 서비스입니다. 선불 요금제가 미등록 상태를 의미하지는 않습니다. 요건은 국가마다 다르고 변경될 수 있습니다.<sup>[[13]](#references)</sup>

운용 시 유의 사항:

- 허구의 가입자를 만들려는 목적이 아니라 개인 데이터 노출을 줄이는 목적으로 별도의 지원되는 기기를 사용합니다.
- 개인 휴대폰과 함께 “별도” 기기를 계속 휴대하지 않습니다. 위협 모델에 동일 장소에 있었다는 사실이 포함된다면 특히 유의합니다.
- 사용하지 않는 셀룰러, Wi-Fi, Bluetooth 및 위치 접근을 비활성화합니다. 전원을 끄는 것이 UI 토글보다 강력한 무선 차단 방법입니다.
- 민감한 트래픽은 승인된 VPN/Tor 경로로 보내되, 통신 사업자가 가입 정보/기기 위치 및 터널 엔드포인트를 여전히 알고 있음을 고려합니다.
- 국가 규제 기관이나 현지 법률 전문가에게 최신 등록 및 보존 규정을 확인합니다. 온라인의 “익명 SIM 국가” 목록에 의존하지 않습니다.

## DNS 및 TLS 메타데이터

- **DoH/DoT/DoQ**는 클라이언트와 리졸버 사이의 DNS를 암호화해 로컬에서의 간단한 열람이나 수정은 막지만, 리졸버는 여전히 쿼리와 전송 식별자를 볼 수 있습니다. 신뢰 대상이 바뀔 뿐 익명성이 생기는 것은 아닙니다.<sup>[[14]](#references)</sup>
- **ODoH**는 프록시를 추가해 프록시와 대상이 공모하지 않는다는 가정하에 리졸버가 클라이언트 IP를 알 필요가 없게 합니다. 트래픽 분석은 명시적으로 범위에 포함되지 않습니다.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**는 클라이언트, DNS 및 서버가 지원하는 경우 TLS 핸드셰이크에서 내부 서버 이름을 보호할 수 있습니다. 목적지 IP, 타이밍, 트래픽 양 및 엔드포인트는 여전히 노출됩니다.<sup>[[16]](#references)</sup>
- VPN 또는 Tor 환경이 올바르게 구성되어 있다면 DNS는 해당 환경에서 지원하는 경로를 따라야 합니다. 별도의 리졸버를 추가하면 새로운 관찰자나 지문이 생길 수 있습니다.

### 암호화된 DNS/ECH 확인 절차

1. DNS를 VPN/Tor 환경, OS 또는 애플리케이션 중 어디에서 제어할지 결정합니다. 관련 없는 리졸버를 여러 개 쌓는 대신 의도한 **한** 계층에서 구성합니다.
2. 공개된 개인정보 보호/보존 정책을 기준으로 리졸버를 선택하고, 플랫폼에서 지원한다면 엄격한 암호화 모드를 활성화합니다. 기회적 대체 방식은 평문으로 조용히 되돌아갈 수 있습니다.
3. 직접 관리하는 권한 있는 테스트 영역에서 고유한 하위 도메인을 조회하고, 권한 있는 로그에서 의도한 재귀 리졸버가 확인되는지 점검합니다.
4. 권한이 있는 상태에서 테스트 기기의 트래픽만 캡처합니다. 접속 네트워크가 평문 DNS를 읽을 수 없는지 확인하되, 암호화된 리졸버/터널 엔드포인트는 볼 수 있음을 고려합니다.
5. 암호화된 리졸버가 차단되거나 연결되지 않는 경우를 테스트합니다. 통과 조건은 선택한 연결 차단 동작 또는 문서화된 대체 동작이지, 실수로 평문 쿼리가 전송되는 것이 아닙니다.
6. ECH의 경우, 제어 가능한 ECH 지원 호스트를 사용하고 클라이언트/서버 진단 정보를 확인해 **내부** ClientHello가 수락되었는지 확인합니다. HTTPS 레코드가 제공된다는 사실만으로 ECH 성공이 입증되지는 않습니다.
7. 네트워크 변경, 캡티브 포털 사용, 브라우저 업데이트 및 VPN 재연결 후 다시 테스트합니다. 이후 관리자가 우회를 만들지 않도록 DNS/ECH를 어느 구성 요소가 담당하는지 기록합니다.

## Mixnet

Nym 또는 Katzenpost 같은 Mixnet은 고정 크기 패킷, 지연, 재정렬 및 커버 트래픽을 추가해 타이밍 상관 분석에 대응합니다. 이러한 특성은 지연 시간과 대역폭 비용을 발생시키며, 독립적으로 검증된 배포 규모의 근거는 제한적입니다. 현재의 소비자용 Mixnet은 Tor/VPN보다 빠르거나 보장된 대체재가 아니라 **초기 단계/지연 시간이 긴 옵션**으로 간주합니다.<sup>[[17]](#references)</sup>

### 평가 절차

1. 유지 관리되는 클라이언트와 정확히 지원되는 애플리케이션을 확인합니다. 문서화되지 않은 프록시를 통해 임의의 브라우저/시스템 트래픽을 강제로 보내지 않습니다.
2. 진입 노드, mix 노드, 게이트웨이, 목적지 및 공모 가정에 대한 최신 위협 모델을 읽습니다.
3. 별도의 테스트 환경에 공식 서명된 소스에서 설치하고, 소유한 무해한 엔드포인트만 사용합니다.
4. 전달 지연 시간, 메시지 크기 제한, 안정성, 재전송 및 게이트웨이를 사용할 수 없을 때의 동작을 측정합니다.
5. 로컬 트래픽과 소유한 엔드포인트를 검사해 의도한 경로와 출발지를 확인합니다. 응답에도 동일한 개인정보 보호 설계가 적용되는지 확인합니다.
6. 종료/실패 동작을 테스트합니다. 애플리케이션이 인터넷에 직접 연결하는 방식으로 조용히 대체해서는 안 됩니다.
7. 속도를 높이기 위해 커버 트래픽을 비활성화하거나, 지연을 줄이거나, 특이한 고정 경로를 선택하지 않습니다. 이러한 변경은 명시된 익명성 모델을 무효화할 수 있습니다.
8. 특정 배포, 독립적인 분석 및 운용 신뢰성이 결과의 중요도에 부합할 때까지 실험 단계로 유지합니다.

## 네트워크 사전 점검 목록

- [ ] 접속 네트워크, 대상, 날짜 및 출발지 인프라에 대한 승인이 포함되어 있습니다.
- [ ] 엔드포인트에 관련 없는 신원이나 활성 동기화 세션이 없습니다.
- [ ] IPv4, IPv6, DNS 및 재연결 동작이 계획과 일치합니다.
- [ ] 제어된 DHCP/로컬 서브넷 경로 주입으로 테스트 트래픽이 물리 인터페이스로 이동할 수 없습니다.
- [ ] 목적지에는 예상된 egress만 표시됩니다.
- [ ] 캡티브 포털 및 핫스팟 동작을 민감한 트래픽 없이 테스트했습니다.
- [ ] 로컬 공유/검색 및 자동 네트워크 연결이 비활성화되어 있습니다.
- [ ] 관찰자 표와 남아 있는 트래픽 상관 분석 위험을 수용했습니다.
- [ ] 제공업체 정책, 데이터 보존 및 비상 연락처가 최신 상태입니다.

지식 분할 릴레이, 경로 강제 워크로드, 플러그형 전송, onion service, I2P 및 일회용 원격 브라우저에 대해서는 [고급 네트워크 개인정보 보호 아키텍처](advanced-network-privacy-architectures.md)를 참조하세요.



## References

- [1] [EFF — 나에게 적합한 VPN 선택하기](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — 기기 보안 지침: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor가 제공하는 개인정보 보호 및 익명성](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor 간단 소개](https://spec.torproject.org/intro/)
- [5] [Tor Project — 다른 브라우저에서 Tor 사용하기](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser의 플러그인 및 애드온](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor 차단 해제하기](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPN과 함께 Tor Browser 사용하기](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — 공용 Wi-Fi 네트워크는 안전한가요?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple 기기의 Wi-Fi 개인정보 보호](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC 무작위화 구현하기](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — 보안 권한 워크스테이션 원칙](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — 의무적 SIM 등록: 정책 및 규제 관점](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS 개인정보 보호 서비스 운영자를 위한 권고 사항](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — 위협 모델](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — 터널 우회: 라우팅 테이블 악용을 통한 VPN 클라이언트 트래픽 leak](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: 공격자가 라우팅 기반 VPN을 드러내 VPN leak을 일으키는 방법](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil FAQ: Yggdrasil은 익명인가요?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
