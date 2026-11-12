# 공격 인프라 및 귀속 회피

{{#include ../banners/hacktricks-training.md}}

운영자는 단일 proxy만으로 의미 있는 익명성을 확보하는 경우가 드뭅니다. 실제 캠페인에서는 **분리 그래프**를 구축합니다. 운영자는 access node에 접속하고, traversal node는 exit에서 해당 노드를 숨기며, redirector는 실제 C2를 보호하고, 폐기 가능한 이름은 공개 edge를 가리킵니다.

각 경로의 정규화된 장단점, 배포 및 탐지 정보를 확인하려면 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)를 참고하세요. 이 페이지에서는 공격 인프라의 구성 방법을 더 자세히 살펴봅니다.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

대상이 마지막으로 확인한 주소는 따라서 경로의 증거이지, 키보드를 누가 제어했는지에 대한 증명은 아닙니다. MITRE는 주요 구성 요소를 Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568), Web Service (T1102)에 매핑합니다.<sup>[[1]](#references)</sup>

## 인프라 유형

| 유형 | 행위자가 사용하는 이유 | 지속적으로 남는 노출 정보 | 방어자의 최선의 추적 지점 |
|---|---|---|---|
| 임대 VPS/cloud | 빠르고 예측 가능하며 라우팅이 쉽고 재구축이 간편함 | 테넌트, 결제, 콘솔, 소스 로그인 및 이미지 이력 | 계정/제어 플레인 이벤트 및 반복되는 서버 fingerprint |
| 상용 VPN/Tor | 규모가 큰 공유 egress 집합, 서버 관리 불필요 | 공급자/가시성 및 종단 간 타이밍 | 대상 동작, endpoint 증거 및 흐름 상관관계 |
| 주거용/모바일 proxy | 소비자 ASN 및 지역적 개연성 | 브로커/고객 기록, proxyware 또는 감염된 호스트의 동작 | 불가능한 이동, proxy 프로토콜 및 세션별 주소 변경 |
| 침해된 서버/router/IoT | 피해자의 평판 및 관할권을 빌림 | implant, 관리 흐름 및 반복되는 상위 컨트롤러 | 단일 exit IP가 아닌 장치 원격 측정 및 ORB 토폴로지 |
| CDN/redirector | 공개 edge와 백엔드 C2를 분리 | TLS/HTTP 문법, 인증서, 라우팅 및 cloud 계정 아티팩트 | edge와 origin 간 상관관계 및 요청 형태 클러스터링 |
| 합법적인 웹 서비스 | 허용된 GitHub/cloud/social 트래픽에 섞임 | API 토큰, 테넌트/객체 식별자 및 비정상적인 프로세스 계보 | endpoint 프로세스와 서비스/API 의미 |
| 물리/셀룰러/위성 경로 | 겉으로 보이는 물리적 출발지를 바꿈 | RF, 통신사, 가입자, 장치 및 위치 기록 | 무선/물리적 증거와 네트워크 증거의 결합 |

## 운영형 릴레이 박스 네트워크

**ORB network**는 중계 서비스로 사용되는 관리형 proxy fleet입니다. Mandiant는 이를 임대 서버로 구성된 프로비저닝 네트워크, 침해된 router/IoT로 구성된 비프로비저닝 네트워크, 그리고 하이브리드 네트워크로 나눕니다. 성숙한 토폴로지에는 네 가지 논리적 역할이 있습니다:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** 자산 목록, 자격 증명, 상태 및 라우팅 정책을 관리합니다.
2. **Access/relay node:** 고객이나 운영자를 인증합니다. 변화하는 mesh에 안정적으로 진입하는 지점입니다.
3. **Traversal nodes:** 하나 이상의 임대 시스템 또는 침해된 시스템이 불투명한 연결을 중계합니다.
4. **Exit/staging node:** 정찰, 악용 또는 C2 대상에 최종 소스 주소를 제시합니다.

mesh는 국가, ASN, 지연 시간 또는 가용성을 기준으로 exit를 선택하고 상태가 나쁜 노드를 교체할 수 있습니다. 여러 위협 그룹이 같은 네트워크를 임대할 수 있습니다. Mandiant는 일부 ORB에서 IPv4 주소가 연관된 기간이 짧게는 31일에 불과한 사례를 관찰했습니다. 따라서 오래된 IP 목록을 차단하기보다 **네트워크를 진화하는 행위자 유사 개체로 취급**할 것을 권고합니다.<sup>[[2]](#references)</sup>

### 이점과 노출 정보

- 대상은 지리적으로 가깝고 겉보기에는 주거용인 exit를 볼 수 있습니다.
- exit는 대상과 직전 홉을 볼 수 있지만, 반드시 운영자를 볼 수 있는 것은 아닙니다.
- access 서비스는 고객과 경로 요청을 볼 수 있습니다. 독립적으로 관리되는 mesh는 고객을 exit와 분리할 수 있지만, 강력한 거래 기록을 남깁니다.
- 반복되는 포트, handshake 순서, 서버 배너, 인증서, 가동 시간대 및 컨트롤러 관계를 통해 IP가 바뀌더라도 fleet이 드러날 수 있습니다.
- 침해된 router에는 endpoint 원격 측정 정보가 없는 경우가 많지만, ISP에는 가입자 및 흐름 데이터가 남아 있습니다. 압수 시 implant/configuration 아티팩트가 드러납니다.

{% hint style="info" %}
승인된 실습에서는 조직 소유 VM이나 router로 토폴로지를 재현하고 컨트롤러의 attribution map을 보관하세요. 개방형 proxy나 제3자 장치를 동원하지 마세요. [실습 가이드](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)는 중개자를 피해자로 만들지 않고도 방어자에게 동일한 홉 구조를 보여줍니다.
{% endhint %}

## 주거용 및 모바일 proxy 네트워크

주거용 proxy 서비스는 소비자 광대역 주소에 세션을 할당하고, 모바일 proxy는 통신사 NAT 풀을 통해 egress합니다. 공급원에는 명시적으로 등록된 장치, 소비자 애플리케이션에 포함된 SDK/proxyware, 재판매업자 또는 malware가 포함될 수 있습니다. 이러한 출처는 서로 동등하지 않습니다. 충분한 설명에 근거한 동의가 없으면 개인정보 보호 서비스는 침해된 인프라가 됩니다.

회전 방식은 탐지에 영향을 줍니다.

- **요청별 회전**은 상위 계층의 식별 정보는 그대로인 상태에서 IP 및 ASN/지역이 빠르게 바뀌게 합니다.
- **고정 세션**은 몇 분에서 몇 시간 동안 exit를 유지해 일반 가입자처럼 보입니다.
- **backconnect gateway**는 고객에게 하나의 브로커 endpoint만 노출하고 내부적으로 exit를 선택합니다.
- **모바일 풀**은 다수의 실제 가입자를 소수의 통신사 NAT 주소 뒤에 두므로, IP 차단에 큰 비용이 들 수 있습니다.

방어자는 IP를 인증된 세션, TLS/client fingerprint, HTTP 순서, 장치 cookie 및 동작과 연관 지어야 합니다. 모든 상위 계층 특성이 동일한데 주거용 IP에서 현지 로그인이 발생한 뒤 다른 국가에서 접속하면, 평판만 확인하는 것보다 강한 근거가 됩니다. 반대로 주소 공유와 모바일 handoff로 인해 정상적인 주소 변경이 발생할 수 있으므로, 주거용/proxy 분류만으로 판정해서는 안 됩니다.

### Proxyware 제어 플레인과 재판매업자 간 중복

주거용 풀을 단순한 exit 목록으로 모델링하지 마세요. IPIDEA 생태계 분석에서는 재사용 가능한 **2계층 제어 플레인**이 드러났습니다. 내장된 SDK가 먼저 장치/등록 메타데이터를 Tier One 도메인에 보고하고, 스케줄링 정보와 Tier Two `connect`/`proxy` IP:port 쌍을 받습니다. 노드는 주기적으로 Tier Two connect 포트에서 인코딩된 작업을 확인하고, 쌍을 이루는 proxy 포트에 두 번째 연결을 열어 제공된 바이트를 요청된 대상으로 중계합니다. 명목상 서로 다른 SDK와 proxy 브랜드는 별도의 탐색 도메인을 사용했지만, 공동 소유 및 재판매업자 관계로 인해 공유 Tier Two 인프라와 겹치는 exit 풀로 이어졌습니다.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

이는 residential IP block보다 더 지속성 높은 hunting pivot을 제공합니다:<sup>[[13]](#references)</sup>

- 예상치 못한 utility, VPN, game 또는 embedded-device 프로세스가 안정적인 device ID/customer key를 보내고 변경되는 server list를 받음
- endpoint가 비정상 포트의 direct IP를 폴링한 다음, 새 destination socket을 열기 직전에 같은 주소의 다른 포트에 연결함
- 겉보기에는 서로 다른 여러 브랜드가 Tier Two 주소, protocol grammar, SDK 코드 또는 exit-node 중복을 공유함
- 서로 다른 Tier One 도메인에 연결하는 별개의 애플리케이션이 동일한 Tier Two pool의 주소를 받음

이러한 중복은 attribution도 제한합니다. 한 vendor가 광고하는 pool에서 IP를 확인했다고 해서 관련 시점에 어떤 reseller, customer 또는 threat actor가 해당 IP를 사용했는지는 입증되지 않습니다. flow timestamp, process lineage, Tier One response body 및 Tier Two task identifier를 보존하세요.<sup>[[13]](#references)</sup> 승인된 exercise에서는 organization 소유 endpoint만 사용해 이 계층 구조를 모방하세요. consumer device나 third-party proxyware는 절대 등록하지 마세요.

## Multi-hop proxy chains

MITRE는 external proxy와 **multi-hop proxy (T1090.003)**를 구분합니다. 중요한 속성은 hop 수가 아니라 지식과 관리의 분리입니다.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

한 주체가 A와 B를 모두 운영하면, 공유 로그나 흐름 타이밍을 통해 회로를 재구성할 수 있습니다. 동일한 엔드포인트/계정에서 상업용 VPN을 순차적으로 추가하면 지연 시간은 늘어날 수 있지만, 공통된 신원 정보, 결제 정보, 타이밍 증거는 그대로 남을 수 있습니다. Tor는 독립적으로 선택된 릴레이와 공유 클라이언트 설계를 통해 이 문제를 줄이지만, 저지연 대화형 네트워크는 양쪽 끝을 모두 측정하는 관찰자에 대한 저항을 보장할 수 없습니다.

흔히 발생하는 실패 사례는 DNS 또는 IPv6 우회, 애플리케이션이 자체 소켓을 여는 경우, 관리 트래픽이 릴레이에 직접 도달하는 경우, 동기화된 활동, SSH 키 재사용, 식별 가능한 계정에 로그인하는 경우입니다. 올바른 검증 방법은 실패 테스트입니다. 모든 릴레이를 차례로 중지하고 워크로드가 평문 경로로 우회할 수 없음을 확인해야 합니다.

### 터널 붕괴 및 상위 인프라 누출

릴레이 아키텍처는 장애가 발생할 때 attribution이 가장 쉬운 경우가 많습니다. Unit 42는 피해자 측 VPS, 릴레이 VPS, 주거용 프록시, Tor 및 기타 프록시 서비스를 사용하는 다계층 첩보 경로를 문서화했습니다. 터널이 생략되거나 붕괴되었을 때, 숨겨진 상위 인프라가 릴레이 및 피해자 측 시스템에 직접 연결되었습니다. 같은 조사에서는 상위 인프라에 잠시 노출된 X.509 인증서를 계층 간 피벗에도 사용했습니다.<sup>[[14]](#references)</sup>

**데이터 플레인**(`victim <-> exit`)과 **제어 플레인**(`operator/upstream -> relay administration`)을 분리하세요. 소유한 각 계층의 인그레스 및 인증 로그, 인증서 이력, 짧은 실패 연결을 보존하세요. 성공한 C2 세션만 보존해서는 안 됩니다. 릴레이 장애 중에만 나타나거나 여러 피해자 측 노드를 직접 관리하는 소스는 일반적인 exit보다 상위 인프라 후보일 가능성이 높습니다. 하지만 ASN/지리적 위치 정보는 여전히 가설일 뿐, 운영자의 신원을 입증하지는 않습니다.

승인된 랩에서는 워크로드가 fail closed 방식으로 동작하도록 해야 합니다. Linux 네트워크 네임스페이스에 격리된 워크로드의 첫 번째 경로는 터널을 사용해야 합니다. 터널을 제거한 뒤에는 물리 업링크를 선택하는 대신 요청과 경로 조회가 모두 실패해야 합니다:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS와 IPv6에 대해, 그리고 각 relay 경계에서 테스트를 반복합니다. 프로브가 하나라도 성공하면, policy routing이나 방화벽을 복구하기 전에 실제 인터페이스/소스 주소를 기록합니다. 이 관측 결과가 조사자가 확인하게 될 attribution leak입니다.

## Redirector 계층 및 트래픽 셰이핑

공개 **redirector**는 작전별 문법에 맞는 트래픽을 받아 보호된 팀 서버로 전달합니다. 그 외의 트래픽은 거부하거나 무해한 콘텐츠를 제공할 수 있습니다.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

여러 계층을 사용하면 노출을 제한할 수 있습니다. 공개 도메인이 소진되어도 팀 서버까지 노출될 필요는 없습니다. CDN은 anycast 용량과 신뢰도 높은 외부 도메인을 제공하지만, CDN 계정과 edge 로그는 attribution 지점이 됩니다. TLS fingerprints, 인증서 이력, 특징적인 경로/헤더 순서, 응답 크기, 리디렉션 동작, origin allowlists를 이용하면 겉보기에 무관한 프런트들을 묶어낼 수 있습니다.

탐지를 위해 정규화 전에 reverse-proxy 필드를 기록하고, SNI/Host/authority를 비교하며, 드문 헤더 조합을 검사하고, 응답 본문과 TLS fingerprints를 클러스터링하며, cloud/CDN audit logs에서 설정이 겹치는 부분을 검색합니다. 승인된 red team에서는 실제 브랜드를 모방하거나 무관한 제3자 뒤에 자격 증명 수집 기능을 두지 않습니다.

## Domain fronting 및 domainless fronting

기존 **domain fronting (T1090.004)**에서는 TLS 연결이 허용된 프런트 도메인을 SNI에 표시하는 한편, 암호화된 HTTP `Host` 또는 HTTP/2 `:authority`는 다른 백엔드 도메인을 요청합니다. 협력하는 CDN은 내부 값에 따라 트래픽을 라우팅합니다. TLS 복호화를 하지 않는 네트워크 관찰자에게는 프런트만 보이지만, CDN은 두 값과 origin을 모두 볼 수 있습니다. domainless 변형에서는 SNI가 비어 있고 다른 라우팅 필드가 대상지를 선택할 수 있습니다.<sup>[[4]](#references)</sup>

이는 마법 같은 사칭이 아닙니다. 중개자가 의도적이든 실수로든 불일치를 허용하고 내부 이름을 라우팅할 수 있을 때만 작동합니다. 주요 provider들은 계정 간 fronting을 제한해 왔습니다. Encrypted ClientHello (ECH)는 경로상의 관찰자가 볼 수 있는 내용을 바꾸지만 CDN, endpoint 또는 애플리케이션 기록을 없애지는 않습니다.

탐지 지점은 다음과 같습니다.

- endpoint 프로세스 계보와 해당 애플리케이션에서 예상하지 못한 대상지
- TLS inspection이 법적으로 허용되고 가능한 경우 SNI와 HTTP authority 간 불일치
- 한 tenant/front가 다른 authority/origin으로 라우팅되는 것을 보여주는 CDN logs
- 일반적으로 상호작용형인 서비스에 대한 비정상적으로 오래 지속되거나 주기적인 세션
- front 도메인이 바뀌어도 유지되는 암호화된 흐름의 크기와 주기

안전한 실습 환경에서는 소유한 reverse proxy에서 라우팅 불일치를 시뮬레이션하며, 공개 CDN을 악용하지 않습니다.

## 동적 해석: DDNS, DGA 및 fast flux

동적 해석은 논리적 서비스를 고정된 인프라와 분리합니다.

- **DDNS:** 인증된 클라이언트가 주소 변경 후 안정적인 이름을 업데이트합니다.
- **DGA:** endpoint가 seed를 바탕으로 도메인 이름을 파생합니다. seed는 흔히 시간이나 키를 사용하지만, 변경 가능한 공개 콘텐츠를 사용하는 경우도 있습니다. 운영자는 활성 이름에 대한 DNS를 설정합니다.<sup>[[17]](#references)</sup>
- **Fast flux:** 이름이 빠르게 바뀌는, 침해된 주소 또는 proxy 주소 집합을 반환하며 TTL이 낮은 경우가 많습니다.
- **Double flux:** 서비스 주소와 authoritative name-server 주소가 모두 순환하여 제어 계층도 숨깁니다.

Fast flux는 적대적으로 사용되는 부하 분산 패턴이지 단순히 “DNS 응답이 많다”는 뜻이 아닙니다. 낮은 TTL, 높은 고유 주소 수, 넓은 ASN/지리적 분산, 짧은 노드 수명, 반복되는 애플리케이션 동작, 의심스러운 등록 이력을 조합하면 더 강한 증거가 됩니다. CDN도 이러한 특성 중 일부를 정당하게 공유합니다. MITRE는 DNS 동작을 프로세스 및 후속 연결과 연관 지을 것을 권장합니다.<sup>[[5]](#references)</sup>

DGA는 어휘적 엔트로피, 자음/숫자 패턴, NXDOMAIN 급증, 동기화된 최초 관측 도메인, 프로세스 맥락을 통해 탐지할 수 있습니다. 단어 목록 기반 DGA와 생성 모델은 단순한 엔트로피 규칙을 우회하므로, 전체 fleet을 대상으로 한 시간적 클러스터링과 endpoint 계보가 더 중요합니다.

### 단어 목록 DGA용 변경 가능한 이미지 seed

DGA가 시간에 의존할 필요는 없습니다. 한 loader는 공개 Telegram 채널 페이지를 가져와 `tgme_page_photo_image` 요소의 `src`를 읽고, 해당 프로필 이미지를 다운로드한 다음 디코딩된 픽셀이 아니라 **파일의 마지막 50바이트**를 해시합니다. 네 개의 해시 seed가 형용사, 명사, 동사, 숫자를 각각 선택합니다. 이미지를 바꾸면 새 클라이언트를 배포하지 않고도 파생된 DNS 이름을 변경할 수 있습니다. 양쪽에서 다운로드한 이미지의 정확한 바이트와 동일한 단어 목록 순서를 사용해야 합니다. 이미지를 다시 인코딩하거나 목록 순서를 바꾸면 다른 이름이 생성됩니다.<sup>[[17]](#references)</sup>

클라이언트에서 복구한 단어 목록을 사용하면 이름 선택 단계를 재현할 수 있습니다. 소스의 바이트 단위 해시는 64-bit 누산기, multiplier `0x1000193`, 각 구성 요소별 별도 seed를 사용합니다.<sup>[[17]](#references)</sup>

<details>
<summary>이미지 seed를 사용한 단어 목록 이름 선택 재현</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

[dead-drop resolver](#web-services-and-dead-drop-resolvers)가 엔드포인트 자체를 게시하는 것과 달리, 여기서 공개 객체는 변경 가능한 시드만 제공하며 클라이언트가 로컬에서 엔드포인트를 도출합니다.

그런 다음 생성된 이름을 `https://dns.google/resolve?name=<domain>&type=TXT`를 통해 DNS TXT 레코드로 조회합니다. 클라이언트는 JSON 응답의 `data` 필드를 Base64 디코딩하고, 내장된 공개 키로 Ed25519 서명을 검증한 후에만 명령을 AES-ECB로 복호화합니다. 관찰된 평문은 메서드 선택자와 암호화된 페이로드의 URL로 시작합니다. 서명 검증이 있으므로 TXT 레코드를 조회할 수 있다는 사실만으로는 승인된 tasking을 제공할 수 없습니다.<sup>[[17]](#references)</sup>

## 침해된 도메인과 도메인 섀도잉

공격자는 registrar/DNS 계정을 탈취하거나, 방치된 하위 도메인을 인수하거나, 그 밖에는 평판이 좋은 도메인 아래에 레코드를 추가할 수 있습니다. **Domain shadowing**은 정상적인 apex 도메인을 유지하면서 공격자가 제어하는 다수의 하위 도메인을 변경되는 delivery 또는 C2 호스트로 연결합니다. 도메인의 사용 연한과 평판을 이용하며 도메인 전체를 대상으로 하는 차단을 피할 수 있습니다.<sup>[[6]](#references)</sup>

방어자는 registrar 및 authoritative DNS 감사 로그, MFA, registry/registrar 잠금, 새 위임/API token/name server에 대한 경보, certificate transparency 모니터링, DNS에서 참조하는 cloud 리소스 목록을 확보해야 합니다. 하위 도메인의 해석 및 인증서 이력을 apex 도메인의 평판과 별도로 조사하세요.

## 웹 서비스와 dead-drop resolver

**dead-drop resolver (T1102.001)**는 정상적인 게시물, 프로필, 문서, 저장소, cloud 객체 또는 blockchain 필드에 현재 C2를 가리키는 인코딩된 포인터를 저장합니다. Malware는 공개 객체를 가져와 도메인/IP를 디코딩한 뒤 다음 단계를 호출합니다. 양방향 변형은 서비스 API를 통해 명령이나 파일을 주고받습니다.<sup>[[7]](#references)</sup>

GitHub에 특화된 resolver 변형 중 하나는 인증된 저장소 채널이 실패할 때만 Issues Search API를 사용합니다. 클라이언트는 현재 날짜, 저장소, issue 유형과 일치하는 issue를 검색하고, 각 issue의 comments URL을 따라가 `<!--`와 `-->` 표시자 사이에 있는 암호문을 추출합니다. 호스트별로 날짜에서 파생된 복호화를 거친 후 `Owner`, `LicRepo`, `LicToken` 같은 필드가 기본 저장소 소유자, 경로, token을 대체합니다. 이를 통해 운영자는 클라이언트를 교체하지 않고도 인증 정보와 엔드포인트를 교체할 수 있습니다. issue 댓글은 resolver 역할을 하고 저장소 파일은 tasking 채널로 남습니다.<sup>[[15]](#references)</sup>

Android 변형은 시작 시 공개 Telegram 페이지 두 개 중 하나를 선택하고, APK에 포함된 표시자가 두 번 나타나는 위치 사이에서 암호문을 추출합니다. 값을 Base64URL 디코딩한 뒤 AES-128-CBC로 복호화합니다. `SHA-256(marker)`의 처음 16바이트가 키이고 나머지 16바이트가 IV입니다. 평문은 Telegram 페이지 URL이 아니라 실제 C2 기본 URL입니다. 해석 방식을 재현할 때는 페이지 콘텐츠와 정확한 표시자를 그대로 유지하세요. 공개 페이지를 변경하면 APK를 다시 빌드하지 않고도 엔드포인트를 교체할 수 있습니다.<sup>[[16]](#references)</sup>

이 방식은 복원력을 높이고 정적 바이너리 분석에서 백엔드 C2를 숨깁니다. 또한 안정적인 객체, tenant, 저장소, API 및 접근 패턴 식별자를 만듭니다. 방어자는 다음 항목을 연관 분석해야 합니다.

1. 서비스에 접속한 프로세스
2. 정확한 API 경로/객체와 응답 hash
3. 디코딩 또는 문자열 처리 활동
4. 그 직후 발생한 새 아웃바운드 연결
5. 플릿 내 다른 곳에서 나타나는 동일한 동작

모든 GitHub, cloud storage 또는 소셜 미디어를 차단하는 것은 현실적으로 어려운 경우가 많습니다. 서비스 인식형 egress 정책과 프로세스 수준의 상관 분석은 도메인만 차단하는 방식보다 효과적입니다.

## 페르소나, 계정 및 조달 구획

페르소나, 복구 이메일, 전화번호, 결제 수단, 브라우저 또는 관리자 IP가 구획 사이를 연결하면 인프라 익명성이 무너집니다. 국가 연계 작전은 계정 사용 훨씬 전부터 소셜 프로필, 이메일 신원, cloud 계정을 준비해 왔습니다. ATT&CK는 이를 Establish Accounts (T1585)로 기록하며, 소셜, 이메일, cloud 하위 기술을 포함합니다.<sup>[[8]](#references)</sup>

방어자나 조사자는 다음 정보를 바탕으로 그래프를 만듭니다.

- 생성 및 최초 로그인 시간, 로케일, 시간대, 작업 일정
- 복구 정보, MFA 장치, 신원 문서, 결제 수단
- 브라우저/TLS fingerprint 및 출발지 네트워크 이력
- 아바타 재사용, 이미지 출처, 문체, 소셜 그래프의 성장
- 공유된 도메인 등록자, name server, 인증서, 분석 ID 또는 저장소 commit
- 공개 relay 아키텍처를 우회하는 관리 평면 작업

인가된 red team의 경우, 합성 페르소나는 연습 통제 담당자에게 문서화해야 합니다. 조직 소유의 복구/결제 채널을 사용하고, 관련 없는 실제 인물을 사칭하지 않으며, 계획된 폐기 절차를 마련해야 합니다. SOC가 이를 파악하지 못할 수는 있지만, 작전이 책임 소재를 알 수 없는 상태가 되어서는 안 됩니다.

## 위협 모델링에 활용할 새로운 복합 패턴

다음은 **방어자 주도의 조합**이며, 특정 행위자가 각각의 정확한 설계를 배포했다는 주장이 아닙니다. 이미 관찰된 기본 요소를 결합한 것으로, purple-team 가설로 유용합니다.

### 비대칭 단방향 tasking

명령은 공개된, broadcast 또는 append-only 소스를 통해 들어오고, 결과는 지연 후 관련 없는 채널을 통해 나갑니다. 기본 요소의 예로는 웹 서비스 단방향 통신과 dead drop이 있습니다. 경로를 분리하면 하나의 흐름이 양방향으로 보이지 않으며 단순한 요청/응답 상관 분석도 어렵게 됩니다.<sup>[[9]](#references)</sup>

**탐지:** 객체 수준의 읽기를 보존한 뒤, 더 넓은 시간 범위에서 프로세스 상태 변경과 이후의 아웃바운드 전송을 상호 연관시키세요. 즉각적인 응답이 없더라도 동일한 공개 객체를 읽는 드문 프로세스를 찾아보세요.

### 다단계 채널 승격

조용한 1단계는 인벤토리를 수집하고 선택된 시스템만 관련 없는 2단계 채널로 승격합니다. 두 번째 엔드포인트, 프로토콜, 프로세스는 첫 번째와 인프라를 공유하지 않을 수 있습니다. 이렇게 하면 유능한 인프라의 노출을 줄일 수 있으며, ATT&CK에서는 이를 T1104로 명시적으로 모델링합니다.<sup>[[10]](#references)</sup>

**탐지:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`을 연관 분석하세요. 첫 번째 도메인을 차단한 뒤 사건을 종결하지 마세요.

### 교차 프로토콜 relay 변환

각 hop은 패킷을 투명하게 전달하는 대신 HTTPS, QUIC, WebSocket, DNS, SSH 또는 message-queue API를 서로 변환합니다. 변환은 단일 종단 간 프로토콜 fingerprint를 없애지만, 독특한 타이밍, 버퍼링, 의미 변환을 보이는 gateway를 만듭니다. Protocol tunneling (T1572)은 프록시 및 서비스 사칭과 결합될 수 있습니다.<sup>[[11]](#references)</sup>

**탐지:** 한 프로토콜을 수신하고 긴밀하게 연계된 바이트/시간 동작으로 다른 프로토콜을 시작하는 gateway 호스트를 찾으세요. 엔드포인트가 의도한 동작과 실제로 전달된 프로토콜을 비교하세요.

### 엣지 장치의 수동 활성화

beacon을 보내는 대신, implant는 router/VPN에 이미 도달하는 트래픽을 모니터링하고 magic value, source-port 패턴 또는 인증된 token이 있을 때만 활성화됩니다. 정상 트래픽은 실제 서비스로 계속 전달됩니다. ATT&CK는 이를 Traffic Signaling (T1205)이라 부르며, 문서화된 네트워크 장치 및 APT 사례가 있습니다.<sup>[[12]](#references)</sup>

**탐지:** 펌웨어/파일 무결성, 인가된 hunt 중의 raw packet capture, 예상치 못한 socket filter, 차등적인 서비스 동작을 확인하세요. 주기적인 beacon이 없다고 해서 엣지 장치가 깨끗하다는 뜻은 아닙니다.

### Serverless 및 임시 origin 교체

front는 안정적인 논리적 식별자를 유지하면서 수명이 짧은 function/container가 여러 region/account에서 개별 단계를 처리합니다. 이로써 디스크에 남는 기간과 고정 origin IP를 줄일 수 있지만, control-plane 생성 정보, image/layer, role, secret, 요청 ID, billing 텔레메트리가 지속적으로 남는 그래프가 됩니다.

**탐지:** cloud 감사 및 invocation 로그를 workload 외부에 보존하세요. 배포 템플릿, role, 환경 키, front와 origin 간 관계를 그룹화하세요.

### 프라이버시 계층의 다양성

작전은 의도적으로 하나의 동질적인 체인을 피할 수 있습니다. 예를 들어 한 채널은 임대 relay를 사용하고, tasking은 공개 객체를 사용하며, exit은 자체 소유 lab cellular link를 사용하고, 관리는 별도의 조직 네트워크를 사용합니다. 이렇게 하면 한 provider가 침해되어도 그 영향은 줄지만, 계층 간 타이밍 및 운영 실수의 위험은 커집니다.

**탐지:** 신원, DNS, SaaS, 네트워크, cloud 센서를 아우르는 캠페인 타임라인을 만드세요. 동일한 지표가 아니라 동기화된 상태 전환을 검색하세요.

### 탈중앙화 또는 transparency log dead drop

공격자는 영구적인 공개 append-only 시스템, content-addressed store 또는 transparency 유사 피드 어디에나 작은 암호화 포인터를 저장할 수 있습니다. 공개 객체는 복원력이 높지만, 정확한 색인/content hash와 클라이언트의 polling 동작은 안정적인 식별자가 됩니다.

**탐지:** 전체 API/객체 식별자와 응답 hash를 기록하세요. 디코딩이나 새 연결에 앞서 변경 불가능한 객체를 polling하는 비표준 프로세스에 경보를 설정하세요.

### 지연된 store-and-forward 작전

대화형 C2는 강한 타이밍 상관 관계를 만듭니다. store-and-forward 설계는 암호화된 작업을 묶어 저장하고, 몇 분 또는 몇 시간 뒤 다른 queue나 물리적 전송을 통해 결과를 반환합니다. 종단 간 타이밍 상관을 약화하는 대신 응답성을 희생합니다.

**탐지:** 상관 분석 시간 범위를 늘리고 주기적인 queue 접근을 모델링하며 엔드포인트의 staging을 살펴보세요. batching은 신호를 패킷 타이밍에서 예약된 프로세스/파일 동작으로 옮길 뿐, 없애지 않습니다.

## 설계 검토: 관찰자 관점으로 생각하기

배포 전과 데이터 수집 후 각 경로에 대해 이 표를 작성하세요.

| 계층 | 출발지를 볼 수 있나? | 목적지를 볼 수 있나? | 콘텐츠를 볼 수 있나? | 안정적인 식별자 | 보존 기간/법적 책임자 |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

일반적인 provider 하나가 모든 열을 채울 수 있다면, 이 아키텍처는 target으로부터는 은폐할 수 있지만 견고한 분리는 제공하지 못합니다. 내부 통제 담당자가 활동을 engagement와 연결할 수 없다면 전문 red teaming에 적합하지 않습니다.

## References

- [1] [MITRE ATT&CK — 인프라 획득 (T1583), 인프라 침해 (T1584), 프록시 (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — 중국 연계 첩보 행위자들이 ORB 네트워크를 사용](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — 다중 hop 프록시 (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — 도메인 프론팅 (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — 인프라 침해: 도메인 (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — 웹 서비스: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — 계정 생성 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — 웹 서비스: 단방향 통신 (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — 다단계 채널 (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 세계 최대 주거용 프록시 네트워크 차단](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — 그림자 캠페인: 글로벌 첩보 활동의 실체를 밝히다](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Campaign, 이라크 인프라를 표적으로 삼다](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI가 오버레이를 만들고, 피해자는 PIN을 잃다](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — 서명된 ChatGPT 및 Claude 바이너리를 통해 배포된 과거의 수법](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
