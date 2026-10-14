# 공격 인프라 및 귀속 회피

{{#include ../banners/hacktricks-training.md}}

운영자는 단일 프록시만으로 의미 있는 익명성을 확보하는 경우가 드뭅니다. 실제 캠페인은 **분리 그래프**를 구축합니다. 운영자는 액세스 노드에 접속하고, 경유 노드는 해당 노드를 출구 노드로부터 숨기며, 리디렉터는 실제 C2를 보호하고, 일회용 이름은 공개 엣지를 가리킵니다.

각 경로의 정규화된 장단점, 배포 및 탐지 정보를 보려면 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)를 참조하세요. 이 페이지에서는 공격자 관점의 인프라 구성에 대해 더 자세히 다룹니다.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

대상이 마지막으로 관찰한 주소는 경로의 증거일 뿐, 누가 키보드를 조작했는지에 대한 증명은 아닙니다. MITRE는 주요 구성 요소를 Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568), Web Service (T1102)에 대응시킵니다.<sup>[[1]](#references)</sup>

## 인프라 유형

| 유형 | 공격자가 사용하는 이유 | 지속적으로 노출되는 정보 | 방어자가 활용할 최선의 단서 |
|---|---|---|---|
| 임대형 VPS/cloud | 빠르고 예측 가능하며 라우팅이 가능하고 재구축이 쉬움 | 테넌트, 결제 정보, 콘솔, 소스 로그인 및 이미지 이력 | 계정/컨트롤 플레인 이벤트 및 반복되는 서버 fingerprint |
| 상용 VPN/Tor | 대규모 공유 egress 집합, 서버 관리 불필요 | 제공업체/가시성 관리자의 관찰 정보 및 종단 간 타이밍 | 대상에서의 동작, endpoint 증거 및 흐름 상관분석 |
| 주거용/모바일 proxy | 소비자 ASN 및 지리적 위치의 개연성 | 브로커/고객 기록, proxyware 또는 감염된 호스트의 동작 | 비현실적인 이동, proxy 프로토콜 및 세션별 주소 변경 |
| 침해된 서버/router/IoT | 피해자의 평판과 관할권을 빌림 | 임플란트, 관리 흐름 및 반복되는 상위 컨트롤러 | 단일 출구 IP가 아닌 기기 텔레메트리 및 ORB 토폴로지 |
| CDN/redirector | 공개 edge와 백엔드 C2를 분리 | TLS/HTTP 문법, 인증서, 라우팅 및 cloud 계정 아티팩트 | edge와 origin 간 상관관계 및 요청 형태의 군집화 |
| 합법적인 웹 서비스 | 허용된 GitHub/cloud/social 트래픽에 섞임 | API token, 테넌트/객체 식별자 및 비정상적인 프로세스 계보 | endpoint 프로세스와 서비스/API 의미 |
| 물리/셀룰러/위성 경로 | 겉으로 드러나는 물리적 출발지를 바꿈 | RF, 통신사, 가입자, 기기 및 위치 기록 | 무선/물리적 증거와 네트워크 증거의 결합 |

## 운영형 relay box 네트워크

**ORB 네트워크**는 중간 서비스로 사용되는 관리형 proxy fleet입니다. Mandiant는 이를 임대 서버로 구성된 프로비저닝 네트워크, 침해된 router/IoT로 구성된 비프로비저닝 네트워크, 그리고 하이브리드 네트워크로 구분합니다. 성숙한 토폴로지는 네 가지 논리적 역할로 구성됩니다.<sup>[[2]](#references)</sup>

1. **관리 서버(ACOS):** 인벤토리, 자격 증명, 상태 및 라우팅 정책을 관리합니다.
2. **액세스/relay 노드:** 고객 또는 운영자를 인증하며, 변경되는 mesh로 들어가는 안정적인 진입점입니다.
3. **Traversal 노드:** 하나 이상의 임대 또는 침해된 시스템이 불투명한 연결을 relay합니다.
4. **출구/스테이징 노드:** 정찰, 악용 또는 C2 대상에 최종 출발지 주소를 제시합니다.

mesh는 국가, ASN, 지연 시간 또는 가용성에 따라 출구를 선택하고 상태가 나쁜 노드를 교체할 수 있습니다. 여러 위협 그룹이 동일한 네트워크를 임대할 수도 있습니다. Mandiant는 일부 ORB에서 IPv4 주소가 연관된 기간이 불과 31일인 사례를 관찰했습니다. 따라서 오래된 IP 목록을 차단하기보다 **네트워크 자체를 진화하는 행위자 유사 개체로 취급할 것**을 권고합니다.<sup>[[2]](#references)</sup>

### 이점과 leak되는 정보

- 대상에는 지리적으로 가까우며 주거용으로 보이는 출구가 표시될 수 있습니다.
- 출구는 대상과 직전 홉을 볼 수 있지만, 반드시 운영자를 식별할 수 있는 것은 아닙니다.
- 액세스 서비스는 고객과 경로 요청을 확인합니다. 독립적으로 관리되는 mesh는 고객과 출구를 분리할 수 있지만, 강력한 제3자 기록을 남깁니다.
- IP가 교체되더라도 반복되는 포트, handshake 순서, 서버 배너, 인증서, 가동 시간대 및 컨트롤러 간 관계를 통해 fleet이 드러날 수 있습니다.
- 침해된 router에는 endpoint 텔레메트리가 없는 경우가 많지만, ISP에는 여전히 가입자 및 흐름 데이터가 있습니다. 장비를 압수하면 임플란트/설정 아티팩트가 노출됩니다.

{% hint style="info" %}
승인된 훈련에서는 조직 소유 VM 또는 router로 토폴로지를 재현하고 컨트롤러의 attribution map을 보관하세요. 공개 proxy나 제3자 기기를 끌어들이지 마세요. [실습 가이드](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)는 중간 장비에 피해를 주지 않고도 방어자에게 보이는 동일한 홉 구조를 구성합니다.
{% endhint %}

## 주거용 및 모바일 proxy 네트워크

주거용 proxy 서비스는 세션에 소비자 broadband 주소를 할당하고, 모바일 proxy는 통신사 NAT pool을 통해 egress합니다. 공급원은 명시적으로 등록된 기기, 소비자 애플리케이션에 번들된 SDK/proxyware, 재판매업체 또는 malware일 수 있습니다. 이러한 출처는 서로 동등하지 않습니다. 충분한 정보를 바탕으로 한 동의가 없다면 개인정보 보호 서비스는 침해된 인프라가 됩니다.

회전 방식은 탐지에 영향을 줍니다.

- **요청별 회전**은 상위 계층의 신원이 유지되는 동안 IP 및 ASN/지리적 위치가 빠르게 불연속적으로 바뀌게 합니다.
- **고정 세션**은 출구를 몇 분 또는 몇 시간 동안 유지해 일반 가입자처럼 보이게 합니다.
- **backconnect gateway**는 고객에게 하나의 브로커 endpoint를 보여주고 내부적으로 출구를 선택합니다.
- **모바일 pool**은 다수의 실제 가입자를 소수의 통신사 NAT 주소 뒤에 배치하므로 IP 차단 비용이 커집니다.

방어자는 IP를 인증된 세션, TLS/client fingerprint, HTTP 순서, 기기 cookie 및 동작과 연관지어 분석해야 합니다. 상위 계층의 모든 특성이 동일한 상태에서 현지 주거용 로그인으로 보이는 연결이 다른 국가에서 이어진다면, 평판 정보만 사용할 때보다 더 강한 증거가 됩니다. 반대로 주소 공유와 모바일 핸드오프는 정상적인 변동을 일으킬 수 있으므로 주거용/proxy 분류만으로 단정하지 마세요.

### Proxyware 컨트롤 플레인과 리셀러 중복

주거용 pool을 단순한 출구 목록으로 모델링하지 마세요. IPIDEA 생태계 분석에서는 재사용 가능한 **2단계 컨트롤 플레인**이 드러났습니다. 내장 SDK가 먼저 기기/등록 메타데이터를 Tier One 도메인에 보고하고, 그곳에서 스케줄링 정보와 Tier Two `connect`/`proxy` IP:port 쌍을 받습니다. 노드는 주기적으로 Tier Two connect 포트를 확인해 인코딩된 작업을 가져오고, 대응하는 proxy 포트에 두 번째 연결을 연 다음 제공된 바이트를 요청된 대상으로 relay합니다. 명목상 서로 다른 SDK와 proxy 브랜드는 별도의 검색 도메인을 사용했지만, 공통 소유권 및 리셀러 관계를 통해 공유 Tier Two 인프라와 중복되는 출구 pool로 연결되었습니다.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

이 방식은 residential IP block보다 더 오래 지속되는 추적 단서를 제공합니다:<sup>[[13]](#references)</sup>

- 예상치 못한 유틸리티, VPN, 게임 또는 임베디드 장치 프로세스가 안정적인 device ID/customer key를 전송하고 변경되는 서버 목록을 받습니다.
- 엔드포인트가 특이한 포트의 direct IP를 폴링한 다음, 새 destination socket을 열기 직전에 같은 주소의 다른 포트에 연결합니다.
- 겉보기에는 서로 다른 여러 브랜드가 Tier Two 주소, 프로토콜 문법, SDK 코드 또는 exit-node 중복을 공유합니다.
- 서로 다른 Tier One 도메인에 접속하는 각기 다른 애플리케이션이 동일한 Tier Two pool의 주소를 받습니다.

이러한 중복은 attribution에도 한계를 둡니다. 한 vendor의 광고된 pool에 IP가 포함되어 있다는 사실만으로는 해당 시점에 어떤 reseller, 고객 또는 threat actor가 그 IP를 사용했는지 입증되지 않습니다. flow timestamp, process lineage, Tier One 응답 본문, Tier Two task identifier를 보존하세요.<sup>[[13]](#references)</sup> 승인된 exercise에서는 조직 소유 엔드포인트에서만 이 계층 구조를 모방하세요. 소비자 장치나 제3자 proxyware를 등록하지 마세요.

## Multi-hop proxy chains

MITRE는 external proxy와 **multi-hop proxies (T1090.003)**를 구분합니다. 중요한 것은 hop의 수가 아니라 지식과 관리 권한의 분리입니다.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

한 당사자가 A와 B를 모두 운영하면 공유 로그나 트래픽 타이밍으로 회로를 재구성할 수 있습니다. 동일한 endpoint/account에서 상용 VPN을 순차적으로 추가해도 지연만 늘어날 뿐, 공통된 신원 정보와 결제 정보, 타이밍 증거는 그대로 남을 수 있습니다. Tor는 독립적으로 선택된 릴레이와 공통 클라이언트 설계를 통해 이 문제를 줄이지만, 저지연 인터랙티브 네트워크는 양쪽 끝을 모두 측정하는 관찰자에 대한 저항성을 보장할 수 없습니다.

흔한 실패 원인으로는 DNS 또는 IPv6 우회, 애플리케이션의 자체 소켓 연결, 릴레이에 직접 도달하는 관리 트래픽, 동기화된 활동, 재사용된 SSH 키, 식별 가능한 계정에 로그인하는 행위가 있습니다. 올바른 검증 방법은 실패 테스트입니다. 모든 릴레이를 차례로 중단하고, 워크로드가 일반 연결 경로로 대체될 수 없음을 확인해야 합니다.

### 터널 붕괴 및 upstream 유출

릴레이 아키텍처는 실패할 때 흔히 가장 쉽게 출처가 드러납니다. Unit 42는 피해자 측 VPS, 릴레이 VPS, residential proxy, Tor 및 기타 proxy 서비스를 사용하는 다중 계층 첩보 경로를 문서화했습니다. 터널이 누락되거나 붕괴되자 숨겨진 upstream 인프라가 릴레이 및 피해자 측 시스템에 직접 연결되었습니다. 같은 조사에서는 upstream 인프라에 잠시 노출된 X.509 certificate를 계층 간 연결 고리로도 활용했습니다.<sup>[[14]](#references)</sup>

**data plane**(`victim <-> exit`)과 **control plane**(`operator/upstream -> relay administration`)을 분리하세요. 소유한 모든 계층에서 인바운드 및 인증 로그, certificate 이력, 짧은 실패 연결을 보존하세요. 성공한 C2 세션만 기록해서는 안 됩니다. 릴레이 장애 중에만 나타나거나 여러 피해자 측 노드를 직접 관리하는 소스는 일반적인 exit보다 upstream 후보일 가능성이 높지만, 해당 소스의 ASN/geolocation은 여전히 가설일 뿐 운영자의 신원에 대한 증거는 아닙니다.

승인된 실습 환경에서는 워크로드가 fail closed하도록 해야 합니다. Linux network namespace에 격리된 워크로드의 경우 첫 번째 경로는 tunnel을 사용해야 합니다. tunnel을 제거한 뒤에는 물리 uplink를 선택하는 대신 요청과 경로 조회가 모두 실패해야 합니다.

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS와 IPv6에 대해 테스트를 반복하고 각 relay 경계에서 테스트하세요. probe가 하나라도 성공하면 정책 라우팅이나 방화벽을 수정하기 전에 실제 인터페이스/소스 주소를 기록하세요. 이 관찰 결과가 조사자가 보게 될 attribution leak입니다.

## Redirector tiers and traffic shaping

공개 **redirector**는 작전별 문법에 일치하는 트래픽을 받아 보호된 team server로 전달합니다. 그 밖의 트래픽은 거부하거나 무해한 콘텐츠를 제공할 수 있습니다.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

여러 계층을 두면 노출을 제한할 수 있습니다. 공개 도메인이 burn되더라도 팀 서버까지 노출될 필요는 없습니다. CDN은 anycast 용량과 신뢰도 높은 외부 도메인을 제공하지만, CDN 계정과 edge 로그는 귀속 추적 지점이 됩니다. TLS fingerprints, 인증서 이력, 특징적인 경로/헤더 순서, 응답 크기, 리디렉션 동작, origin allowlist를 통해 서로 관련 없어 보이는 front를 묶을 수 있습니다.

탐지를 위해 정규화 전에 reverse-proxy 필드를 기록하고, SNI/Host/authority를 비교하며, 드문 헤더 조합을 검사하고, 응답 본문과 TLS fingerprints를 군집화하고, 설정이 겹치는지 cloud/CDN 감사 로그를 검색하세요. 승인된 red team은 실제 브랜드를 모방하거나 관련 없는 제3자 뒤에 자격 증명 수집 기능을 두지 않아야 합니다.

## Domain fronting 및 domainless fronting

기존 방식의 **domain fronting (T1090.004)**에서는 TLS 연결이 허용된 front 도메인을 SNI에 알리는 한편, 암호화된 HTTP `Host` 또는 HTTP/2 `:authority`는 다른 back-end 도메인을 요청합니다. 협조하는 CDN은 내부 값에 따라 라우팅합니다. TLS 복호화를 할 수 없는 네트워크 관찰자는 front를 보지만, CDN은 두 값을 모두 확인하고 origin도 볼 수 있습니다. domainless 변형에서는 SNI가 비어 있고 다른 라우팅 필드가 목적지를 선택할 수 있습니다.<sup>[[4]](#references)</sup>

이것은 마법 같은 위장이 아닙니다. 중개자가 의도적이든 실수로든 불일치를 허용하고 내부 이름을 라우팅할 수 있을 때만 작동합니다. 주요 제공업체들은 계정 간 fronting을 제한했습니다. Encrypted ClientHello (ECH)는 경로상의 관찰자가 볼 수 있는 내용을 바꾸지만, CDN, endpoint 또는 애플리케이션 기록을 지우지는 않습니다.

탐지 지점은 다음과 같습니다.

- endpoint 프로세스 계보와 해당 애플리케이션이 예상하지 않는 목적지
- 법적으로 허용되고 가능한 경우, TLS inspection을 통한 SNI와 HTTP authority 불일치
- 한 tenant/front가 다른 authority/origin으로 라우팅되는 모습을 보여주는 CDN 로그
- 일반적으로 상호작용형인 서비스에 대한 비정상적으로 오래 지속되거나 주기적인 세션
- front 도메인이 바뀌어도 일정한 암호화된 흐름 크기와 주기

안전한 실습 환경에서는 소유한 reverse proxy에서 라우팅 불일치를 시뮬레이션하며, 공개 CDN을 악용하지 않습니다.

## 동적 해석: DDNS, DGA 및 fast flux

동적 해석은 논리적 서비스를 고정된 인프라와 분리합니다.

- **DDNS:** 인증된 클라이언트가 주소가 바뀐 후에도 안정적인 이름을 업데이트합니다.
- **DGA:** endpoint와 controller가 시간/키 seed로 후보 도메인 이름을 생성하고, 운영자는 그중 일부만 등록합니다.
- **Fast flux:** 이름이 빠르게 바뀌는 여러 침해된/proxy 주소를 반환하며, TTL이 짧은 경우가 많습니다.
- **Double flux:** 서비스 주소와 권한 있는 name server 주소가 모두 바뀌어 제어 계층도 숨깁니다.

Fast flux는 적대적으로 사용되는 부하 분산 패턴이지, 단순히 “DNS 응답이 많다”는 뜻이 아닙니다. 강한 증거를 확보하려면 짧은 TTL, 많은 고유 주소, 넓은 ASN/지역 분포, 짧은 노드 수명, 반복되는 애플리케이션 동작, 의심스러운 등록 이력을 함께 확인해야 합니다. CDN도 이런 특징 중 몇 가지를 정상적으로 보입니다. MITRE는 DNS 동작을 프로세스 및 후속 연결과 연관 지을 것을 권장합니다.<sup>[[5]](#references)</sup>

DGA는 어휘 엔트로피, 자음/숫자 패턴, NXDOMAIN 급증, 동시에 처음 관측된 도메인, 프로세스 맥락을 통해 탐지할 수 있습니다. 단어 목록 기반 DGA와 생성형 모델은 단순한 엔트로피 규칙을 무력화하므로, 전체 fleet에 걸친 시간적 군집화와 endpoint 계보가 더 중요합니다.

## 침해된 도메인과 domain shadowing

공격자는 registrar/DNS 계정을 탈취하거나, 방치된 하위 도메인을 인수하거나, 그 외에는 평판이 좋은 도메인 아래에 레코드를 추가할 수 있습니다. **Domain shadowing**은 정상적인 apex를 유지하면서 공격자가 제어하는 다수의 하위 도메인이 바뀌는 전달 또는 C2 호스트를 가리키게 합니다. 이를 통해 도메인의 사용 연식과 평판을 이용하고 도메인 단위 차단을 피할 수 있습니다.<sup>[[6]](#references)</sup>

방어자는 registrar와 권한 있는 DNS 감사 로그, MFA, registry/registrar 잠금, 새 delegation/API token/name server에 대한 경보, certificate transparency 모니터링, DNS가 참조하는 cloud 리소스 목록을 확보해야 합니다. 하위 도메인의 해석 및 인증서 이력은 apex의 평판과 별도로 조사하세요.

## Web 서비스와 dead-drop resolver

**Dead-drop resolver (T1102.001)**는 합법적인 게시물, 프로필, 문서, repository, cloud object 또는 blockchain 필드 안에 현재 C2를 가리키는 인코딩된 포인터를 저장합니다. Malware는 공개 object를 가져와 도메인/IP를 디코딩하고 다음 단계에 연결합니다. 양방향 변형은 서비스 API를 통해 명령이나 파일을 주고받습니다.<sup>[[7]](#references)</sup>

GitHub에 특화된 한 resolver 변형은 인증된 repository 채널에 문제가 생겼을 때만 Issues Search API를 사용합니다. 클라이언트는 현재 날짜, repository, issue 유형에 일치하는 issue를 검색하고, 각 issue의 comments URL을 따라간 다음 `<!--`와 `-->` 표시자 사이에서 ciphertext를 추출합니다. 호스트별 날짜 기반 복호화 후 `Owner`, `LicRepo`, `LicToken` 같은 필드가 기본 repository owner, 경로, token을 대체합니다. 이를 통해 운영자는 클라이언트를 교체하지 않고 자격 증명과 endpoint를 변경할 수 있습니다. issue comment는 resolver이고, repository 파일은 tasking 채널로 남습니다.<sup>[[15]](#references)</sup>

이 방식은 복원력을 높이고 정적 바이너리 분석으로 back-end C2를 알아내기 어렵게 합니다. 동시에 안정적인 object, tenant, repository, API, 접근 패턴 식별자를 만듭니다. 방어자는 다음을 연계해야 합니다.

1. 서비스에 접속한 프로세스
2. 정확한 API 경로/object 및 응답 hash
3. 디코딩 또는 문자열 처리 활동
4. 얼마 지나지 않아 발생한 새 outbound 연결
5. fleet 내 다른 곳에서 반복되는 동일한 동작

GitHub, cloud storage 또는 social media를 전부 차단하는 것은 대개 현실적이지 않습니다. 서비스 인식형 egress 정책과 프로세스 수준의 상관 분석이 도메인만 차단하는 것보다 효과적입니다.

## 페르소나, 계정, 조달 구획

페르소나, 복구 이메일, 전화번호, 결제 수단, 브라우저 또는 관리자 IP가 구획 간 연결고리가 되면 인프라 익명성은 무너집니다. 국가와 연계된 작전은 사용하기 훨씬 전부터 social profile, 이메일 정체성, cloud 계정을 준비해 왔습니다. ATT&CK는 이를 Establish Accounts (T1585)로 기록하며, social, email, cloud 하위 기법을 포함합니다.<sup>[[8]](#references)</sup>

방어자나 조사관은 다음 정보를 바탕으로 그래프를 구성합니다.

- 생성 및 최초 로그인 시각, locale, time zone, 작업 일정
- 복구 필드, MFA 장치, 신분증, 결제 수단
- 브라우저/TLS fingerprints 및 출발 네트워크 이력
- avatar 재사용, 이미지 출처, 문체, social graph의 성장
- 공유되는 도메인 등록자, name server, 인증서, analytics ID 또는 repository commit
- 공개 relay 아키텍처를 우회하는 management-plane 작업

승인된 red team의 경우, synthetic persona를 작전 통제자에게 문서화하고, 조직 소유의 복구/결제 채널을 사용하며, 무관한 실제 인물을 사칭하지 않고, 사전에 폐기 계획을 세워야 합니다. SOC가 알아채지 못하더라도 작전은 책임 추적이 가능해야 합니다.

## 위협 모델링을 위한 새로운 복합 패턴

다음은 **방어자 주도의 조합**이며, 특정 행위자가 각 설계를 그대로 배포했다는 주장이 아닙니다. 이미 관측된 기본 요소를 결합한 것으로, purple-team 가설로 활용할 수 있습니다.

### 비대칭 단방향 tasking

명령은 공개형, broadcast 또는 append-only 출처를 통해 도착하고, 결과는 지연 후 관련 없는 채널을 통해 나갑니다. 기본 요소의 예로는 web-service 단방향 통신과 dead drop이 있습니다. 분리하면 단일 흐름이 양방향처럼 보이지 않고 단순한 요청/응답 상관 분석도 어렵게 됩니다.<sup>[[9]](#references)</sup>

**탐지:** object 수준의 읽기를 보존한 다음, 더 넓은 시간 범위에서 프로세스 상태 변경과 이후 outbound 전송을 연계합니다. 즉각적인 응답이 없어도 드문 프로세스가 동일한 공개 object를 읽는지 추적하세요.

### 다단계 채널 승격

조용한 첫 번째 단계는 시스템을 조사하고, 일부 시스템만 관련 없는 두 번째 단계 채널로 승격합니다. 두 번째 endpoint, protocol, process는 첫 번째와 인프라를 공유하지 않을 수 있습니다. 이 방식은 성능이 높은 인프라의 노출을 제한하며, ATT&CK T1104에 명시적으로 모델링되어 있습니다.<sup>[[10]](#references)</sup>

**탐지:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`을 연계하고, 첫 번째 도메인을 차단한 뒤 사건을 종결하지 마세요.

### 교차 protocol relay 변환

서로 다른 hop은 패킷을 투명하게 전달하는 대신 HTTPS, QUIC, WebSocket, DNS, SSH 또는 message-queue API 간에 변환합니다. 변환은 단일 end-to-end protocol fingerprint를 없애지만, 독특한 타이밍, buffering, 의미 변환을 보이는 gateway를 만듭니다. Protocol tunneling (T1572)은 proxy 및 서비스 사칭과 결합될 수 있습니다.<sup>[[11]](#references)</sup>

**탐지:** 한 protocol을 받고 밀접하게 연관된 바이트/시간 동작으로 다른 protocol을 시작하는 gateway 호스트를 찾습니다. endpoint의 의도와 실제 전달되는 protocol을 비교하세요.

### Edge 장치의 수동 활성화

Beacon을 보내는 대신 implant가 router/VPN에 이미 도달하는 트래픽을 모니터링하고 magic value, source-port 패턴 또는 인증된 token이 있을 때만 활성화됩니다. 정상 트래픽은 실제 서비스로 계속 전달됩니다. ATT&CK는 이를 Traffic Signaling (T1205)이라 부르며, 문서화된 network-device 및 APT 사례가 있습니다.<sup>[[12]](#references)</sup>

**탐지:** firmware/file 무결성, 승인된 조사 중의 raw packet capture, 예상치 못한 socket filter, 서비스 동작의 차이를 확인합니다. 주기적인 beacon이 없다고 해서 edge 장치가 깨끗하다는 뜻은 아닙니다.

### Serverless 및 일회성 origin 교체

front는 안정적인 논리적 정체성을 유지하면서 수명이 짧은 function/container가 여러 region/account에서 개별 단계를 처리합니다. 이 방식은 디스크에 남는 시간과 고정 origin IP를 줄이지만, control-plane 생성 정보, image/layer, role, secret, request ID, billing telemetry가 지속적인 연결 그래프가 됩니다.

**탐지:** workload 외부에 cloud 감사 로그와 invocation 로그를 보존하고, deployment template, role, environment key, front-to-origin 관계를 군집화합니다.

### Privacy 계층의 다양성

작전은 단일한 동질적 경로를 의도적으로 피할 수 있습니다. 예를 들어 한 채널은 임대 relay를, tasking은 공개 object를, exit는 소유한 lab cellular link를, 관리는 별도의 조직 네트워크를 사용할 수 있습니다. 한 제공업체의 침해가 미치는 가치는 줄어들지만, 계층 간 타이밍 및 운영 실수 위험은 커집니다.

**탐지:** identity, DNS, SaaS, network, cloud 센서 전반의 작전 타임라인을 구성합니다. 동일한 지표가 아니라 동기화된 상태 전환을 찾으세요.

### 분산형 또는 transparency log dead drop

공격자는 지속성이 높은 공개 append-only 시스템, content-addressed store 또는 transparency형 feed에 작은 암호화 포인터를 넣을 수 있습니다. 공개 object는 복원력이 높지만, 정확한 index/content hash와 클라이언트의 polling 동작은 안정적인 식별자가 됩니다.

**탐지:** 전체 API/object 식별자와 응답 hash를 기록하고, 불변 object를 polling한 뒤 디코딩 또는 새 연결을 수행하는 비표준 프로세스에 경보를 설정합니다.

### 지연된 store-and-forward 작전

상호작용형 C2는 강한 타이밍 상관관계를 만듭니다. store-and-forward 설계는 암호화된 작업을 모아 처리하고, 몇 분 또는 몇 시간 뒤 다른 queue나 물리적 전송을 통해 결과를 반환합니다. 응답성은 떨어지지만 end-to-end 타이밍 상관관계는 약해집니다.

**탐지:** 상관 분석 시간 범위를 늘리고, 주기적인 queue 접근을 모델링하며, endpoint staging을 조사합니다. 일괄 처리는 신호를 패킷 타이밍에서 예약된 프로세스/파일 동작으로 옮길 뿐, 없애지는 않습니다.

## 설계 검토: 관찰자 관점에서 생각하기

배포 전과 로그 수집 후에 각 경로에 대해 다음 표를 작성하세요.

| 계층 | 출발지를 보는가? | 목적지를 보는가? | 내용을 보는가? | 안정적인 식별자 | 보존/법적 책임 주체 |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

일반적인 제공업체 하나가 모든 항목을 파악할 수 있다면, 아키텍처는 target으로부터는 은폐를 제공하더라도 강력한 분리는 제공하지 못합니다. 내부 통제자가 어떤 활동을 어떤 engagement와 연결할 수 없다면 전문적인 red teaming에 적합하지 않습니다.

## References

- [1] [MITRE ATT&CK — 인프라 확보 (T1583), 인프라 침해 (T1584), Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus 첩보 행위자들이 ORB 네트워크를 사용](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — 인프라 침해: 도메인 (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — 계정 생성 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 세계 최대 residential proxy 네트워크의 교란](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Shadow Campaigns: 글로벌 첩보 활동의 실체 파악](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel 캠페인, 이라크 인프라를 표적으로 삼다](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
