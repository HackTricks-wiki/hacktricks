# 공격 인프라와 귀속 회피

{{#include ../banners/hacktricks-training.md}}

운영자는 단일 proxy만으로 의미 있는 익명성을 얻는 경우가 드뭅니다. 실제 캠페인에서는 **분리 그래프**를 구축합니다. 운영자는 access node에 접속하고, traversal node는 exit에서 access node를 숨기며, redirector는 실제 C2를 보호하고, 일회용 도메인 이름은 공개 edge를 가리킵니다.

모든 경로를 정규화된 장단점/배포/탐지 관점에서 살펴보려면 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)를 참고하세요. 이 페이지에서는 적대적 인프라를 조합하는 방법을 더 자세히 다룹니다.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

타깃이 마지막으로 확인한 주소는 따라서 경로의 증거이지, 누가 키보드를 조작했는지에 대한 증명은 아닙니다. MITRE는 주요 구성 요소를 Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568), Web Service (T1102)에 대응시킵니다.<sup>[[1]](#references)</sup>

## 인프라 유형

| 유형 | 공격자가 사용하는 이유 | 지속적으로 노출되는 정보 | 방어자의 최선의 추적 지점 |
|---|---|---|---|
| 임대 VPS/cloud | 빠르고 예측 가능하며 라우팅이 가능하고, 쉽게 재구축할 수 있음 | 테넌트, 결제, 콘솔, 소스 로그인 및 이미지 이력 | 계정/컨트롤 플레인 이벤트와 반복되는 서버 지문 |
| 상용 VPN/Tor | 대규모 공유 egress 집합, 서버 관리 불필요 | 제공업체/감시자의 가시성과 종단 간 타이밍 | 대상 동작, 엔드포인트 증거 및 플로 상관관계 |
| 주거용/모바일 proxy | 소비자 ASN과 지리적 개연성 | 브로커/고객 기록, proxyware 또는 감염된 호스트의 동작 | 비현실적인 이동, proxy 프로토콜 및 세션별 주소 변경 |
| 침해된 서버/라우터/IoT | 피해자의 평판과 관할권을 빌림 | 임플란트, 관리 플로 및 반복적으로 나타나는 상위 컨트롤러 | 단일 exit IP가 아닌 디바이스 텔레메트리와 ORB 토폴로지 |
| CDN/redirector | 공개 edge와 백엔드 C2를 분리 | TLS/HTTP 문법, 인증서, 라우팅 및 cloud 계정 아티팩트 | edge와 origin 간 상관관계 및 요청 형태 클러스터링 |
| 합법적인 웹 서비스 | 허용된 GitHub/cloud/social 트래픽에 섞임 | API 토큰, 테넌트/객체 식별자 및 비정상적인 프로세스 계보 | 엔드포인트 프로세스와 서비스/API 의미 |
| 물리/셀룰러/위성 경로 | 겉으로 드러나는 물리적 출발지를 바꿈 | RF, 통신사, 가입자, 디바이스 및 위치 기록 | 무선/물리 증거와 네트워크 증거의 결합 |

## 운영형 릴레이 박스 네트워크

**ORB network**는 중간 서비스로 사용되는 관리형 proxy fleet입니다. Mandiant는 이를 임대 서버로 구성된 프로비저닝 네트워크, 침해된 라우터/IoT로 구성된 비프로비저닝 네트워크, 그리고 하이브리드 네트워크로 나눕니다. 성숙한 토폴로지에는 네 가지 논리적 역할이 있습니다.<sup>[[2]](#references)</sup>

1. **관리 서버(ACOS):** 인벤토리, 자격 증명, 상태 및 라우팅 정책을 관리합니다.
2. **액세스/릴레이 노드:** 고객 또는 운영자를 인증하며, 계속 바뀌는 mesh로 들어가는 안정적인 진입점입니다.
3. **Traversal 노드:** 하나 이상의 임대 또는 침해된 시스템이 불투명한 연결을 릴레이합니다.
4. **Exit/staging 노드:** 정찰, 익스플로잇 또는 C2 대상에 마지막 출발지 주소로 나타납니다.

mesh는 국가, ASN, 지연 시간 또는 가용성에 따라 exit를 선택하고, 상태가 좋지 않은 노드를 교체할 수 있습니다. 여러 위협 그룹이 같은 네트워크를 임대할 수도 있습니다. Mandiant는 일부 ORB에서 IPv4 주소가 연관된 기간이 불과 31일에 그치는 경우를 관찰했습니다. 따라서 오래된 IP 목록을 차단하기보다 **네트워크 자체를 변화하는 행위자 유사 개체로 취급할 것**을 권고합니다.<sup>[[2]](#references)</sup>

### 이 방식이 제공하는 이점과 leak되는 정보

- 타깃에는 지리적으로 가까우며 주거용인 것처럼 보이는 exit가 나타날 수 있습니다.
- exit는 타깃과 직전 hop을 볼 수 있지만, 반드시 운영자를 식별할 수 있는 것은 아닙니다.
- 액세스 서비스는 고객과 경로 요청을 확인할 수 있습니다. 독립적으로 관리되는 mesh는 고객과 exit를 분리할 수 있지만, 강력한 상대방 기록을 남깁니다.
- IP가 바뀌어도 반복되는 포트, handshake 순서, 서버 배너, 인증서, 가동 시간대 및 컨트롤러 관계를 통해 fleet이 드러날 수 있습니다.
- 침해된 라우터에는 엔드포인트 텔레메트리가 없는 경우가 많지만, ISP는 여전히 가입자 및 플로 데이터를 보유합니다. 압수 시 임플란트/설정 아티팩트가 노출됩니다.

{% hint style="info" %}
승인된 연습에서는 조직 소유 VM 또는 라우터를 사용해 토폴로지를 재현하고 컨트롤러의 귀속 정보를 기록해 두세요. 개방형 proxy나 제3자 디바이스를 동원하지 마세요. [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)는 중간자를 피해 입히지 않으면서 동일한 방어자 관점의 hop 구조를 구성합니다.
{% endhint %}

## 주거용 및 모바일 proxy 네트워크

주거용 proxy 서비스는 소비자용 broadband 주소에 세션을 할당하고, 모바일 proxy는 통신사 NAT pool을 통해 egress합니다. 공급원에는 명시적으로 등록된 어플라이언스, 소비자 애플리케이션에 번들로 포함된 SDK/proxyware, 재판매업체 또는 malware가 있을 수 있습니다. 이러한 출처는 서로 동등하지 않습니다. 충분한 정보를 바탕으로 한 동의가 없다면 개인정보 보호 서비스는 침해된 인프라가 됩니다.

회전 방식은 탐지에 영향을 줍니다.

- **요청별 회전**은 상위 계층의 신원이 그대로인 상태에서 IP와 ASN/지리 정보가 급격히 달라지게 합니다.
- **sticky session**은 몇 분 또는 몇 시간 동안 exit를 유지해 일반 가입자처럼 보이게 합니다.
- **backconnect gateway**는 고객에게 단일 브로커 엔드포인트를 노출하고, 내부적으로 exit를 선택합니다.
- **모바일 pool**은 다수의 실제 가입자를 소수의 통신사 NAT 주소 뒤에 두므로, IP 차단의 비용이 커집니다.

방어자는 IP를 인증된 세션, TLS/클라이언트 지문, HTTP 순서, 디바이스 쿠키 및 동작과 연관 지어야 합니다. 다른 모든 상위 계층 특성이 그대로인데 현지 주거용 로그인으로 보이는 접속 직후 다른 국가에서 접속하면, 평판 정보만으로 판단하는 것보다 더 강한 근거가 됩니다. 반대로 주소 공유와 모바일 핸드오프로 인해 정상적인 주소 변경도 발생하므로, 주거용/proxy 분류를 단정적인 판단으로 취급해서는 안 됩니다.

### Proxyware 컨트롤 플레인과 재판매업체 간 중복

주거용 pool을 단순한 exit 목록으로 모델링하지 마세요. IPIDEA 생태계 분석을 통해 재사용되는 **2계층 컨트롤 플레인**이 드러났습니다. 내장 SDK는 먼저 디바이스/등록 메타데이터를 Tier One 도메인에 보고하고, 스케줄링 정보와 Tier Two `connect`/`proxy` IP:port 쌍을 받습니다. 노드는 주기적으로 Tier Two connect 포트를 확인해 인코딩된 작업을 받고, 연결된 proxy 포트로 두 번째 연결을 열어 제공된 바이트를 요청된 대상으로 릴레이합니다. 명목상 서로 다른 SDK와 proxy 브랜드는 별도의 검색 도메인을 사용했지만, 공통 소유권과 재판매업체 관계를 통해 공유 Tier Two 인프라와 중복되는 exit pool로 이어졌습니다.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

이는 주거용 IP 블록보다 더 지속성 있는 헌팅 기준점을 제공합니다:<sup>[[13]](#references)</sup>

- 예상치 못한 유틸리티, VPN, 게임 또는 임베디드 장치 프로세스가 안정적인 장치 ID/고객 키를 전송하고 변경되는 서버 목록을 받음;
- 엔드포인트가 비정상 포트의 직접 IP를 폴링한 다음, 새 대상 소켓을 열기 직전에 같은 주소의 다른 포트에 연결함;
- 여러 개의 서로 다른 브랜드가 Tier Two 주소, 프로토콜 문법, SDK 코드 또는 출구 노드 중복을 공유함;
- 서로 다른 Tier One 도메인에 접속하는 별개의 애플리케이션이 같은 Tier Two 풀의 주소를 받음.

이 중복은 attribution에도 한계를 둡니다. 어떤 IP가 한 공급업체의 공개 풀에 포함된 것을 확인해도, 해당 시점에 어떤 재판매업체, 고객 또는 위협 행위자가 사용했는지는 입증되지 않습니다. 플로 타임스탬프, 프로세스 계보, Tier One 응답 본문 및 Tier Two 작업 식별자를 보존하세요.<sup>[[13]](#references)</sup> 승인된 훈련에서는 조직 소유 엔드포인트만 사용해 이 계층 구조를 모사하세요. 소비자 장치나 제3자 proxyware를 등록해서는 안 됩니다.

## Multi-hop proxy chains

MITRE는 external proxies와 **multi-hop proxies (T1090.003)**를 구분합니다. 중요한 속성은 홉 수가 아니라 지식과 관리의 분리입니다.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

한 주체가 A와 B를 모두 운영한다면, 공유 로그나 흐름 타이밍을 통해 회로를 재구성할 수 있습니다. 같은 엔드포인트/계정에서 상업용 VPN을 순차적으로 추가하면 지연 시간은 늘어날 수 있지만, 공통 신원 정보, 결제 정보, 타이밍 증거는 그대로 남을 수 있습니다. Tor는 독립적으로 선택된 릴레이와 공유 클라이언트 설계를 통해 이 문제를 줄이지만, 저지연 인터랙티브 네트워크는 양쪽 끝을 모두 관찰하는 감시자에 대한 저항성을 보장할 수 없습니다.

일반적인 실패 원인은 DNS 또는 IPv6 우회, 자체 소켓을 여는 애플리케이션, 릴레이에 직접 연결되는 관리 트래픽, 동기화된 활동, 재사용된 SSH 키, 식별 가능한 계정 로그인 등입니다. 올바른 검증 방법은 실패 테스트입니다. 모든 릴레이를 차례로 중단하고, 워크로드가 평문 경로로 대체 연결될 수 없음을 확인해야 합니다.

### Tunnel collapse and upstream leakage

릴레이 아키텍처는 실패할 때 흔히 가장 쉽게 추적됩니다. Unit 42는 피해자에 가까운 VPS, 릴레이 VPS, 주거용 프록시, Tor 및 기타 프록시 서비스를 이용한 다중 계층 첩보 경로를 문서화했습니다. 터널이 누락되거나 붕괴했을 때는 숨겨진 상류 인프라가 릴레이 및 피해자에 가까운 시스템에 직접 연결되었습니다. 같은 조사에서는 상류 인프라에 잠시 노출된 X.509 인증서를 계층 간 연결 고리로도 활용했습니다.<sup>[[14]](#references)</sup>

**데이터 플레인**(`victim <-> exit`)과 **컨트롤 플레인**(`operator/upstream -> relay administration`)을 분리하세요. 성공한 C2 세션뿐만 아니라, 소유한 모든 계층의 인그레스 및 인증 로그, 인증서 이력, 짧게 실패한 연결도 보관하세요. 릴레이 장애 중에만 나타나거나 여러 피해자에 가까운 노드를 직접 관리하는 소스는 일반 출구보다 상류 후보일 가능성이 높지만, 해당 소스의 ASN/지리적 위치는 여전히 가설일 뿐 운영자의 신원을 증명하지는 않습니다.

승인된 실습 환경에서는 워크로드가 fail closed하도록 설정해야 합니다. Linux 네트워크 네임스페이스에서 격리된 워크로드의 첫 번째 경로는 터널을 사용해야 합니다. 터널을 제거한 뒤에는 물리적 업링크를 선택하는 대신 요청과 경로 조회가 모두 실패해야 합니다:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS와 IPv6에 대해, 그리고 각 relay 경계에서 테스트를 반복하세요. 프로브가 하나라도 성공하면 policy routing이나 firewall을 수정하기 전에 실제 interface/source address를 기록하세요. 조사자가 확인할 수 있는 attribution leak이 바로 그 관찰 결과입니다.

## Redirector tiers and traffic shaping

공개 **redirector**는 작업별 문법과 일치하는 트래픽을 받아 보호된 team server로 전달합니다. 그 외의 트래픽은 거부하거나 무해한 콘텐츠를 제공할 수 있습니다.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

여러 계층을 두면 노출을 제한할 수 있습니다. 공개 도메인이 burn되더라도 팀 서버까지 노출될 필요는 없습니다. CDN은 anycast 용량과 평판이 좋은 외부 도메인을 제공하지만, CDN 계정과 엣지 로그가 attribution 지점이 됩니다. TLS fingerprints, 인증서 이력, 고유한 경로/헤더 순서, 응답 크기, 리디렉션 동작, origin allowlist를 통해 서로 무관해 보이는 front를 하나로 묶을 수 있습니다.

탐지를 위해 정규화 전에 reverse-proxy 필드를 기록하고, SNI/Host/authority를 비교하고, 드문 헤더 조합을 검사하고, 응답 본문과 TLS fingerprints를 클러스터링하고, 클라우드/CDN 감사 로그에서 설정이 겹치는지 검색하세요. 승인된 red team의 경우 실제 브랜드를 모방하거나, 무관한 제3자 뒤에 credential 수집 기능을 두지 마세요.

## Domain fronting과 domainless fronting

기존의 **domain fronting (T1090.004)**에서는 TLS 연결이 SNI에 허용된 front domain을 알리는 반면, 암호화된 HTTP `Host` 또는 HTTP/2 `:authority`는 다른 back-end domain을 요청합니다. 협조하는 CDN은 내부 값을 기준으로 라우팅합니다. TLS 복호화를 하지 않는 네트워크 관찰자는 front만 보지만, CDN은 두 값과 origin을 모두 확인할 수 있습니다. domainless 변형에서는 SNI가 비어 있고 다른 라우팅 필드가 목적지를 선택할 수 있습니다.<sup>[[4]](#references)</sup>

이는 마법 같은 사칭 기법이 아닙니다. 중개자가 의도적으로 또는 실수로 불일치를 허용하고 내부 이름을 라우팅할 수 있을 때만 작동합니다. 주요 제공업체는 계정 간 fronting을 제한했습니다. Encrypted ClientHello (ECH)는 경로상의 관찰자가 볼 수 있는 정보를 바꾸지만 CDN, endpoint 또는 애플리케이션 기록을 없애지는 않습니다.

탐지 지점은 다음과 같습니다.

- endpoint 프로세스의 부모 관계와 해당 애플리케이션에 예상되지 않는 목적지
- TLS inspection이 합법적이고 가능한 경우 SNI와 HTTP authority의 불일치
- 한 tenant/front가 다른 authority/origin으로 라우팅되는 것을 보여주는 CDN 로그
- 일반적으로 상호작용형인 서비스에 대한 비정상적인 장기 세션 또는 주기적 세션
- front domain이 바뀌어도 일정하게 유지되는 암호화된 flow 크기와 주기

안전한 실습 환경에서는 소유한 reverse proxy에서 라우팅 불일치를 시뮬레이션하며, 공개 CDN을 악용하지 않습니다.

## 동적 해석: DDNS, DGA, fast flux

동적 해석은 논리적 서비스를 고정된 인프라로부터 분리합니다.

- **DDNS:** 인증된 클라이언트가 주소 변경 후에도 안정적인 이름을 유지하도록 해당 이름을 업데이트합니다.
- **DGA:** endpoint와 controller가 시간/키 seed로부터 후보 domain name을 산출하고, 운영자는 그중 일부만 등록합니다.
- **Fast flux:** 이름이 빠르게 바뀌는 침해된/proxy 주소 집합을 반환하며, TTL이 낮은 경우가 많습니다.
- **Double flux:** 서비스 주소와 권한 name-server 주소가 모두 순환해 control layer까지 숨깁니다.

Fast flux는 적대적으로 사용되는 부하 분산 패턴이지, 단순히 “DNS 응답이 많다”는 뜻이 아닙니다. 낮은 TTL, 높은 고유 주소 수, 넓은 ASN/지역 분포, 짧은 노드 수명, 반복되는 애플리케이션 동작, 의심스러운 등록 이력이 함께 나타날 때 더 강한 증거가 됩니다. CDN도 이러한 속성 중 여러 가지를 정상적으로 보일 수 있습니다. MITRE는 DNS 동작을 프로세스 및 이후 연결과 연관 지을 것을 권장합니다.<sup>[[5]](#references)</sup>

DGA는 어휘적 entropy, 자음/숫자 패턴, NXDOMAIN 급증, 동기화된 최초 관측 domain, 프로세스 context를 통해 탐지할 수 있습니다. 단어 목록 기반 DGA와 생성형 모델은 단순한 entropy 규칙을 무력화하므로, fleet 전반의 시간 기반 클러스터링과 endpoint 계보가 더 중요해집니다.

## 침해된 domain과 domain shadowing

공격자는 registrar/DNS 계정을 탈취하거나, 방치된 하위 도메인을 인수하거나, 평판이 좋은 기존 domain 아래에 레코드를 추가할 수 있습니다. **Domain shadowing**은 정당한 apex를 그대로 두면서 공격자가 제어하는 다수의 하위 도메인을 변경되는 delivery 또는 C2 host로 연결합니다. 이 방식은 domain의 연식과 평판을 빌려 domain 전체를 차단하는 조치를 피할 수 있습니다.<sup>[[6]](#references)</sup>

방어자는 registrar 및 authoritative-DNS 감사 로그, MFA, registry/registrar 잠금, 새 delegation/API token/name server에 대한 경보, certificate-transparency 모니터링, DNS에서 참조하는 클라우드 리소스 목록을 관리해야 합니다. 하위 도메인의 해석 결과와 인증서 이력은 apex의 평판과 별도로 조사하세요.

## Web 서비스와 dead-drop resolver

**Dead-drop resolver (T1102.001)**는 합법적인 게시물, 프로필, 문서, repository, 클라우드 객체 또는 blockchain 필드에 현재 C2를 가리키는 인코딩된 포인터를 저장합니다. Malware는 공개 객체를 가져와 domain/IP를 디코딩한 다음 다음 단계에 접속합니다. 양방향 변형은 서비스 API를 통해 명령이나 파일을 주고받습니다.<sup>[[7]](#references)</sup>

GitHub 전용 resolver 변형 중 하나는 인증된 repository 채널이 실패했을 때만 Issues Search API를 사용합니다. 클라이언트는 현재 날짜, repository, issue 유형과 일치하는 issue를 검색하고 각 issue의 comments URL을 따라가 `<!--`와 `-->` 표시자 사이의 ciphertext를 추출합니다. host별 날짜 기반 복호화를 거친 뒤 `Owner`, `LicRepo`, `LicToken` 같은 필드가 기본 repository owner, 경로, token을 대체합니다. 이 방식으로 운영자는 클라이언트를 교체하지 않고 credential과 endpoint를 순환할 수 있습니다. issue comment는 resolver이고 repository 파일은 tasking 채널로 남습니다.<sup>[[15]](#references)</sup>

Android 변형은 시작 시 공개 Telegram 페이지 두 개 중 하나를 선택하고 APK에 삽입된 표시자 두 개 사이의 ciphertext를 추출합니다. 이 값은 Base64URL로 디코딩한 뒤 AES-128-CBC로 복호화합니다. `SHA-256(marker)`의 처음 16바이트가 key이고 나머지 16바이트가 IV입니다. 평문은 Telegram 페이지 URL이 아니라 실제 C2 base URL입니다. 해석을 재현할 때는 페이지 콘텐츠와 정확한 표시자를 보존하세요. 공개 페이지를 변경하면 APK를 다시 빌드하지 않고도 endpoint를 바꿀 수 있습니다.<sup>[[16]](#references)</sup>

이 방식은 복원력을 제공하고 정적 binary 분석에서 back-end C2를 숨깁니다. 동시에 안정적인 객체, tenant, repository, API, 접근 패턴 식별자를 만듭니다. 방어자는 다음 정보를 결합해야 합니다.

1. 서비스에 접속한 프로세스
2. 정확한 API 경로/객체와 응답 hash
3. 디코딩 또는 문자열 처리 활동
4. 그 직후의 새로운 outbound 연결
5. fleet 내 다른 시스템에서도 나타나는 동일한 동작

GitHub, 클라우드 스토리지 또는 소셜 미디어를 모두 차단하는 것은 대개 현실적이지 않습니다. 서비스 인식형 egress 정책과 프로세스 수준의 상관 분석이 domain만 차단하는 것보다 효과적입니다.

## Persona, 계정, 조달 compartment

Persona, 복구 이메일, 전화번호, 결제 수단, 브라우저 또는 admin IP가 compartment 사이의 연결 고리가 되면 인프라 익명성은 실패합니다. 국가 연계 작전은 실제 사용 전에 소셜 프로필, 이메일 정체성, 클라우드 계정을 오래전부터 구축해 왔습니다. ATT&CK는 이를 Establish Accounts (T1585)로 기록하며, 소셜, 이메일, 클라우드 하위 기법을 포함합니다.<sup>[[8]](#references)</sup>

방어자 또는 조사자는 다음 정보를 바탕으로 그래프를 구성합니다.

- 생성 및 최초 로그인 시간, locale, 시간대, 작업 일정
- 복구 정보, MFA 기기, 신분 증명 문서, 결제 수단
- 브라우저/TLS fingerprints와 출발지 네트워크 이력
- 아바타 재사용, 이미지 출처, 작성 스타일, 소셜 그래프 성장 양상
- 공유되는 domain 등록자, name server, 인증서, analytics ID 또는 repository commit
- 공개 relay 아키텍처를 우회하는 management-plane 동작

승인된 red team의 경우 합성 persona를 exercise controller에 문서화하고, 조직 소유의 복구/결제 채널을 사용하고, 관련 없는 실제 인물을 사칭하지 않으며, 사전에 폐기 계획을 마련해야 합니다. SOC는 계속 눈치채지 못할 수 있지만, 작전을 책임 소재가 불분명한 상태로 만들어서는 안 됩니다.

## 위협 모델링을 위한 새로운 복합 패턴

다음은 **방어자 주도의 조합**이며, 특정 공격자가 정확히 이 설계를 배포했다는 주장이 아닙니다. 이미 관측된 기본 기법을 결합한 것으로, purple team 가설로 활용할 수 있습니다.

### 비대칭 단방향 tasking

명령은 공개, broadcast 또는 append-only 소스를 통해 들어오고, 결과는 지연 후 관련 없는 채널을 통해 나갑니다. 기본 기법의 예로 web-service one-way communication과 dead drop이 있습니다. 채널을 분리하면 단일 flow가 양방향으로 보이지 않아 단순한 요청/응답 상관 분석을 어렵게 합니다.<sup>[[9]](#references)</sup>

**탐지:** 객체 수준의 읽기를 보존한 다음, 더 넓은 시간 범위에 걸쳐 프로세스 상태 변경과 이후 outbound 전송을 연관 지으세요. 즉각적인 응답이 없더라도 드문 프로세스가 동일한 공개 객체를 읽는지 조사하세요.

### 다단계 채널 승격

조용한 첫 단계가 inventory를 수행한 뒤, 선택된 시스템만 관련 없는 두 번째 단계 채널로 승격합니다. 두 번째 endpoint, protocol, process는 첫 번째 단계와 인프라를 공유하지 않을 수 있습니다. 이렇게 하면 고급 인프라의 노출을 제한할 수 있으며, 이는 ATT&CK T1104에 명시적으로 모델링되어 있습니다.<sup>[[10]](#references)</sup>

**탐지:** `첫 번째 network process -> 다운로드/설정된 상태 -> 새 process 또는 injection -> 관련 없는 목적지`를 연결하세요. 첫 번째 domain을 차단한 뒤 사건을 종결하지 마세요.

### 프로토콜 간 relay 변환

서로 다른 hop은 패킷을 투명하게 전달하는 대신 HTTPS, QUIC, WebSocket, DNS, SSH 또는 message-queue API 간에 변환합니다. 변환은 end-to-end 프로토콜 fingerprint 하나로 식별하기 어렵게 만들지만, 고유한 타이밍, buffering, 의미 변환을 보이는 gateway를 만듭니다. Protocol tunneling (T1572)은 proxy 및 서비스 사칭과 결합될 수 있습니다.<sup>[[11]](#references)</sup>

**탐지:** 한 protocol을 받고 다른 protocol을 시작하면서 바이트/시간 동작이 밀접하게 연동되는 gateway host를 찾으세요. endpoint의 의도와 실제 전송되는 protocol을 비교하세요.

### Edge device에서의 수동 활성화

Beacon을 보내는 대신 implant가 router/VPN에 이미 도달하는 트래픽을 모니터링하고 magic value, source-port 패턴 또는 인증 token이 나타날 때만 활성화됩니다. 정상 트래픽은 실제 서비스로 계속 전달됩니다. ATT&CK는 이를 Traffic Signaling (T1205)이라고 하며, 문서화된 network-device 및 APT 사례가 있습니다.<sup>[[12]](#references)</sup>

**탐지:** firmware/file 무결성, 승인된 조사 중 raw packet capture, 예상하지 못한 socket filter, 서비스 동작의 차이를 점검하세요. 주기적인 beacon이 없다고 해서 edge device가 깨끗하다는 뜻은 아닙니다.

### Serverless 및 ephemeral origin 순환

Front는 안정적인 논리적 정체성을 유지하는 한편, 수명이 짧은 function/container가 여러 region/account에서 각 단계를 처리합니다. 이렇게 하면 디스크에 남는 흔적과 고정 origin IP를 줄일 수 있지만, control-plane 생성 정보, image/layer, role, secret, request ID, billing telemetry가 지속적인 관계 그래프를 만듭니다.

**탐지:** 클라우드 감사 및 invocation 로그를 workload 외부에 보존하세요. 배포 템플릿, role, 환경 key, front와 origin 간 관계를 클러스터링하세요.

### Privacy layer 다양화

작전은 하나의 동일한 연결 경로를 의도적으로 피할 수 있습니다. 예를 들어 한 채널은 임대한 relay를 사용하고, tasking은 공개 객체를 사용하고, exit는 소유한 실습용 cellular link를 사용하고, 관리는 별도의 조직 네트워크를 사용할 수 있습니다. 이렇게 하면 한 제공업체가 침해되었을 때의 영향은 줄어들지만, 계층 간 타이밍 및 운영 실수 위험은 커집니다.

**탐지:** identity, DNS, SaaS, network, cloud sensor 전반의 campaign timeline을 구성하세요. 동일한 지표보다 동기화된 상태 변화를 검색하세요.

### Decentralized 또는 transparency-log dead drop

공격자는 내구성이 있는 공개 append-only 시스템, content-addressed store 또는 transparency와 유사한 feed 어디에나 작은 암호화 포인터를 둘 수 있습니다. 공개 객체는 복원력이 있지만, 정확한 index/content hash와 클라이언트의 polling 동작은 안정적인 식별자가 됩니다.

**탐지:** 전체 API/객체 식별자와 응답 hash를 기록하세요. 비표준 프로세스가 변경 불가능한 객체를 polling한 뒤 디코딩하거나 새 연결을 시작하는 경우 경보를 생성하세요.

### 지연된 store-and-forward 작전

Interactive C2는 강한 타이밍 상관관계를 만듭니다. Store-and-forward 설계는 암호화된 작업을 모아 몇 분 또는 몇 시간 뒤 다른 queue나 물리적 전송을 통해 결과를 반환합니다. 응답성을 희생하는 대신 end-to-end 타이밍 상관관계를 약화합니다.

**탐지:** 상관 분석 시간 범위를 늘리고, 주기적인 queue 접근을 모델링하고, endpoint staging을 살펴보세요. Batching은 신호를 패킷 타이밍에서 예약된 프로세스/파일 동작으로 옮길 뿐, 없애지는 않습니다.

## 설계 검토: 관찰자 관점에서 생각하기

각 경로에 대해 배포 전과 수집 후에 다음 표를 작성하세요.

| Layer | 출발지를 확인할 수 있는가? | 목적지를 확인할 수 있는가? | 콘텐츠를 확인할 수 있는가? | 안정적인 식별자 | 보존/법적 책임 주체 |
|---|---:|---:|---:|---|---|
| 로컬 네트워크/carrier | | | | | |
| 진입/access 서비스 | | | | | |
| traversal 운영자 | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| 대상 | | | | | |
| 계정/결제 제공업체 | | | | | |

일반적인 제공업체 하나가 모든 항목을 채울 수 있다면, 이 아키텍처는 대상에게 활동을 숨길 수는 있지만 견고한 분리를 제공하지는 못합니다. 내부 controller가 활동을 특정 engagement에 연결할 수 없다면, 전문적인 red teaming에 적합하지 않습니다.

## References

- [1] [MITRE ATT&CK — 인프라 확보 (T1583), 인프라 침해 (T1584), Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — 중국 연계 첩보 행위자들이 ORB 네트워크를 사용](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — 다중 hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — 인프라 침해: Domain (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — 계정 생성 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: 단방향 통신 (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — 다단계 채널 (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 세계 최대 residential proxy network 교란](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — 그림자 작전: 전 세계 첩보 활동의 실체 밝히기](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel 캠페인, 이라크 인프라 겨냥](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI가 오버레이를 만들고, 피해자는 PIN을 잃다](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
