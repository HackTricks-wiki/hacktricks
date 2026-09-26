# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

운영자는 단일 proxy만으로 의미 있는 익명성을 확보하는 경우가 드뭅니다. 실제 campaign에서는 **분리 그래프**를 구축합니다. 운영자는 access node에 도달하고, traversal node는 exit에서 해당 node를 숨기며, redirector는 실제 C2를 보호하고, 일회용 name은 public edge를 가리킵니다.

모든 경로를 정규화된 장단점/배포/탐지 관점에서 확인하려면 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)를 사용하세요. 이 페이지에서는 adversarial infrastructure 구성에 대해 더 자세히 다룹니다.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
따라서 target이 마지막으로 본 address는 경로에 대한 증거이지, keyboard를 누가 조작했는지에 대한 증거는 아니다. MITRE는 주요 구성 요소를 Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) 및 Web Service (T1102)에 매핑한다.<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | 행위자가 사용하는 이유 | 지속적으로 남는 노출 | Defender의 최적 pivot |
|---|---|---|---|
| Rented VPS/cloud | 빠르고 예측 가능하며 routable하고 쉽게 재구축할 수 있음 | tenant, billing, console, source-login 및 image 이력 | account/control-plane 이벤트와 반복되는 server fingerprint |
| Commercial VPN/Tor | 대규모 shared egress 집합을 제공하며 server administration이 필요 없음 | provider/guard 가시성과 end-to-end timing | destination behavior, endpoint evidence 및 flow correlation |
| Residential/mobile proxy | consumer ASN과 지리적 개연성을 제공 | broker/customer 기록, proxyware 또는 infected-host 동작 | impossible travel, proxy protocols 및 session별 address churn |
| Compromised server/router/IoT | victim의 reputation과 관할권을 빌림 | implant, management flow 및 반복되는 upstream controller | 하나의 exit IP가 아닌 device telemetry와 ORB topology |
| CDN/redirector | public edge와 back-end C2를 분리 | TLS/HTTP grammar, certificate, routing 및 cloud-account artifacts | edge-to-origin correlation 및 request-shape clustering |
| Legitimate web service | 허용된 GitHub/cloud/social traffic에 섞임 | API token, tenant/object identifiers 및 비정상적인 process lineage | endpoint process와 service/API semantics |
| Physical/cellular/satellite path | 겉보기 물리적 출발지를 변경 | RF, carrier, subscriber, device 및 location records | radio/physical evidence와 network evidence의 결합 |

## Operational relay box networks

**ORB network**는 중간 service로 사용되는 managed proxy fleet이다. Mandiant는 이를 leased server로 구성된 provisioned network, compromised router/IoT로 구성된 non-provisioned network, 그리고 hybrid로 구분한다. 성숙한 topology에는 네 가지 논리적 역할이 있다.<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory, credentials, health 및 routing policy를 유지한다.
2. **Access/relay node:** customer 또는 operator를 authenticate하며, 변화하는 mesh로 들어가는 안정적인 entry이다.
3. **Traversal nodes:** 하나 이상의 leased 또는 compromised system이 opaque connection을 relay한다.
4. **Exit/staging node:** reconnaissance, exploitation 또는 C2 target에 최종 source address를 표시한다.

mesh는 country, ASN, latency 또는 availability를 기준으로 exit를 선택하고, 상태가 좋지 않은 node를 rotate할 수 있다. 여러 threat group이 동일한 network를 rent할 수 있다. Mandiant는 일부 ORB에서 IPv4 address가 최단 31일 동안만 연결된 상태로 유지되는 것을 관찰했으며, 따라서 오래된 IP 목록을 차단하기보다 **network를 변화하는 actor와 유사한 entity로 취급할 것**을 권고한다.<sup>[[2]](#references)</sup>

### 이것이 제공하는 것과 이것이 leak하는 것

- target은 지리적으로 가깝고 겉보기에는 residential인 exit를 볼 수 있다.
- exit는 target과 직전 hop을 보지만, 반드시 operator를 보는 것은 아니다.
- access service는 customer와 route request를 볼 수 있다. 독립적으로 관리되는 mesh는 customer를 exit와 분리할 수 있지만, 강력한 counterparty record를 남긴다.
- 반복되는 port, handshake order, server banner, certificate, uptime window 및 controller relationship은 IP가 rotate되는 동안에도 fleet을 노출할 수 있다.
- compromised router에는 endpoint telemetry가 없는 경우가 많지만, 해당 router의 ISP에는 여전히 subscriber 및 flow data가 있다. 압수되면 implant/configuration artifacts가 노출된다.

{% hint style="info" %}
권한이 부여된 exercise에서는 organization이 소유한 VM 또는 router로 topology를 재현하고 controller의 attribution map을 보관한다. open proxy 또는 third-party device를 모집하지 않는다. [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)는 intermediary를 victim으로 만들지 않고 동일한 defender-visible hop structure를 생성한다.
{% endhint %}

## Residential and mobile proxy networks

Residential proxy service는 session을 consumer broadband address에 할당하고, mobile proxy는 carrier NAT pool을 통해 egress한다. 공급원은 명시적으로 등록된 appliance, consumer application에 포함된 SDK/proxyware, reseller 또는 malware일 수 있다. 이러한 출처는 동일하지 않다. informed consent가 없으면 privacy service는 compromised infrastructure로 변한다.

Rotation mode는 detection에 영향을 준다.

- **per-request rotation**은 빠른 IP 및 ASN/geography discontinuity를 만들지만, higher-layer identity는 안정적으로 유지한다.
- **sticky sessions**는 exit를 수분 또는 수시간 동안 유지하여 일반적인 subscriber와 유사하게 보인다.
- **backconnect gateways**는 customer에게 하나의 broker endpoint만 노출하고 내부적으로 exit를 선택한다.
- **mobile pools**는 다수의 실제 subscriber를 소수의 carrier NAT address 뒤에 배치하므로, IP block의 비용이 커진다.

Defender는 IP를 authenticated session, TLS/client fingerprint, HTTP ordering, device cookie 및 behavior와 correlate해야 한다. 겉보기에는 local인 residential login 이후 모든 higher-layer feature가 동일한 상태에서 다른 country가 나타난다면, 이는 reputation만 사용하는 것보다 강한 신호다. 반대로 address sharing과 mobile handoff는 정상적인 churn을 만들 수 있으므로, residential/proxy classification을 verdict로 취급해서는 안 된다.

### Proxyware control planes와 reseller overlap

residential pool을 단순한 exit 목록으로 모델링해서는 안 된다. IPIDEA ecosystem에 대한 분석은 재사용 가능한 **two-tier control plane**을 드러냈다. embedded SDK는 먼저 device/enrollment metadata를 Tier One domain에 보고하고, scheduling 및 Tier Two `connect`/`proxy` IP:port pair를 수신한다. node는 encoded task를 받기 위해 주기적으로 Tier Two connect port를 poll하고, 연결된 proxy port에 두 번째 connection을 open한 뒤, 제공된 bytes를 요청된 destination으로 relay한다. 명목상 서로 다른 SDK와 proxy brand는 별도의 discovery domain을 보유했지만, common ownership 및 reseller relationship을 통해 shared Tier Two infrastructure와 겹치는 exit pool로 수렴했다.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
이는 residential IP block보다 더 지속적인 hunting pivot을 생성한다:<sup>[[13]](#references)</sup>

- 예상치 못한 utility, VPN, game 또는 embedded-device process가 안정적인 device ID/customer key를 전송하고 변경되는 server list를 수신한다.
- endpoint가 비정상적인 port의 direct IP를 polling한 다음, 새로운 destination socket을 열기 직전에 동일한 address의 다른 port에 연결한다.
- 여러 apparent brand가 Tier Two address, protocol grammar, SDK code 또는 exit-node overlap을 공유한다.
- 서로 다른 Tier One domain에 접속하는 별개의 application이 동일한 Tier Two pool에서 address를 수신한다.

이러한 overlap은 attribution도 제한한다. 한 vendor의 advertised pool에 있는 IP를 확인하는 것만으로는 해당 시점에 어떤 reseller, customer 또는 threat actor가 이를 사용했는지 입증할 수 없다. flow timestamp, process lineage, Tier One response body 및 Tier Two task identifier를 보존하라.<sup>[[13]](#references)</sup> authorized exercise에서는 organization-owned endpoint만 사용해 이 hierarchy를 모방하라. consumer device 또는 third-party proxyware를 절대 enroll하지 마라.

## Multi-hop proxy chains

MITRE는 external proxy와 **multi-hop proxies (T1090.003)**를 구분한다. 중요한 속성은 hop 수가 아니라 knowledge와 administration의 분리다.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
한 당사자가 A와 B를 모두 운영하는 경우, 공유 로그나 트래픽 흐름 타이밍을 통해 circuit을 재구성할 수 있습니다. 동일한 endpoint/account에서 상용 VPN을 순차적으로 추가하면 latency는 증가할 수 있지만, 공통된 identity, 결제 정보 및 timing 증거는 그대로 남을 수 있습니다. Tor는 독립적으로 선택된 relay와 공유 client 설계를 사용하여 이 문제를 완화하지만, low-latency interactive network는 양쪽 끝을 모두 측정하는 observer에 대한 저항성을 보장할 수 없습니다.

일반적인 실패는 DNS 또는 IPv6 bypass, 애플리케이션이 자체 socket을 여는 경우, management traffic이 relay에 직접 도달하는 경우, 동기화된 활동, 재사용된 SSH key, 식별 가능한 account로 로그인하는 경우입니다. 올바른 검증은 failure test입니다. 모든 relay를 차례로 중지하고 workload가 clear path로 fallback할 수 없음을 확인해야 합니다.

### Tunnel collapse and upstream leakage

relay architecture는 실패할 때 attribution 가능성이 가장 높아지는 경우가 많습니다. Unit 42는 victim-facing VPS, relay VPS, residential proxy, Tor 및 기타 proxy service를 사용하는 multi-tier espionage path를 문서화했습니다. tunnel이 누락되거나 collapse되었을 때, 숨겨진 upstream infrastructure가 relay 및 victim-facing system에 직접 연결되었습니다. 동일한 조사에서는 upstream infrastructure에 잠시 노출된 X.509 certificate도 tier 간 pivot으로 사용되었습니다.<sup>[[14]](#references)</sup>

**data plane** (`victim <-> exit`)을 **control plane** (`operator/upstream -> relay administration`)과 분리하여 유지하세요. 모든 자체 운영 tier에서 ingress 및 authentication log, certificate history, 그리고 성공한 C2 session뿐 아니라 짧은 실패 connection도 보관하세요. relay outage 중에만 나타나거나 여러 victim-facing node를 직접 관리하는 source는 일반적인 exit보다 강력한 upstream 후보이지만, 해당 source의 ASN/geolocation은 여전히 가설일 뿐 operator identity의 증거는 아닙니다.

authorized lab에서는 workload가 fail closed하도록 구성해야 합니다. Linux network namespace에서 격리된 workload의 경우, 첫 번째 route는 tunnel을 사용해야 합니다. tunnel을 제거한 후에는 physical uplink를 선택하는 대신 request와 route lookup이 모두 실패해야 합니다.
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
DNS와 IPv6에 대해, 그리고 각 relay 경계에서 테스트를 반복한다. 어떤 probe라도 성공하면 policy routing 또는 firewall을 수정하기 전에 실제 interface/source address를 기록한다. 해당 관찰 결과가 investigator가 확인할 수 있는 attribution leak이다.

## Redirector tiers and traffic shaping

공개 **redirector**는 operation-specific grammar와 일치하는 traffic을 받아 보호된 team server로 전달한다. 그 외의 모든 traffic은 거부하거나 무해한 content를 제공할 수 있다.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
여러 계층을 사용하면 노출을 제한할 수 있습니다. public domain을 소진해도 team server까지 노출될 필요는 없습니다. CDN은 anycast 용량과 신뢰도 높은 외부 domain을 제공하지만, CDN account와 edge logs가 attribution 지점이 됩니다. TLS fingerprints, certificate histories, 고유한 paths/header order, response sizes, redirect behavior 및 origin allowlists를 통해 겉보기에 무관한 front들을 하나의 cluster로 묶을 수 있습니다.

탐지를 위해 normalization 전에 reverse-proxy fields를 기록하고, SNI/Host/authority를 비교하며, 드문 header 조합을 검사하고, response bodies와 TLS fingerprints를 cluster화하며, cloud/CDN audit logs에서 configuration overlap을 검색합니다. 승인된 red team에서는 실제 brand를 복제하거나 관련 없는 third party 뒤에 credential collection을 배치하지 않아야 합니다.

## Domain fronting and domainless fronting

일반적인 **domain fronting (T1090.004)**에서는 TLS connection이 SNI에 허용된 front domain을 표시하는 반면, 암호화된 HTTP `Host` 또는 HTTP/2 `:authority`는 다른 back-end domain을 요청합니다. 협력하는 CDN은 내부 값을 기준으로 routing합니다. TLS decryption이 없는 network observer는 front만 볼 수 있지만, CDN은 두 값과 origin을 모두 확인합니다. Domainless 변형에서는 SNI가 비어 있고 다른 routing field가 destination을 선택할 수 있습니다.<sup>[[4]](#references)</sup>

이는 마법 같은 impersonation이 아닙니다. intermediary가 의도적이거나 우연히 불일치를 허용하고 내부 이름을 routing할 수 있을 때만 작동합니다. 주요 provider들은 cross-account fronting을 제한했습니다. Encrypted ClientHello (ECH)는 on-path observer가 볼 수 있는 정보를 바꾸지만 CDN, endpoint 또는 application records를 제거하지는 않습니다.

탐지 지점은 다음과 같습니다.

- 해당 application에서 예상되지 않는 endpoint process ancestry 및 destination;
- TLS inspection이 합법적이고 가능한 경우 SNI와 HTTP authority의 불일치;
- 하나의 tenant/front가 다른 authority/origin으로 routing되는 것을 보여주는 CDN logs;
- 일반적으로 interactive한 service에 대한 비정상적인 장기 또는 주기적 sessions;
- 변경되는 front domains를 가로질러 안정적인 encrypted flow sizes 및 cadence.

안전한 lab에서는 소유한 reverse proxy에서 routing mismatch를 시뮬레이션하며, public CDN을 악용하지 않습니다.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution은 논리적 service를 고정된 infrastructure와 분리합니다.

- **DDNS:** 인증된 client가 address 변경 후에도 안정적인 name을 업데이트합니다.
- **DGA:** endpoint와 controller가 time/key seed에서 candidate domain names를 함께 도출하며, operator는 그중 일부만 등록합니다.
- **Fast flux:** name이 빠르게 변경되는 compromised/proxy addresses 집합을 반환하며, 대개 짧은 TTL을 사용합니다.
- **Double flux:** service addresses와 authoritative name-server addresses를 모두 교체하여 control layer까지 숨깁니다.

Fast flux는 단순히 “많은 DNS answers”가 아니라, adversarial하게 사용되는 load-distribution pattern입니다. 더 강한 증거는 짧은 TTL, 높은 unique-address count, 넓은 ASN/geography 분산, 짧은 node lifetime, 반복되는 application behavior 및 의심스러운 registration history를 결합합니다. CDN도 이러한 속성 중 여러 가지를 합법적으로 공유합니다. MITRE는 DNS behavior를 process 및 이후 connections와 상관분석할 것을 권장합니다.<sup>[[5]](#references)</sup>

DGA는 lexical entropy, consonant/digit patterns, NXDOMAIN bursts, 동기화된 first-seen domains 및 process context를 통해 탐지할 수 있습니다. Wordlist DGAs와 generative models는 단순한 entropy 규칙을 우회하므로 fleet 전체의 temporal clustering과 endpoint lineage가 더욱 중요해집니다.

## Compromised domains and domain shadowing

Actor는 registrar/DNS account를 hijack하거나, dangling subdomain을 takeover하거나, 그 외에는 신뢰할 수 있는 domain 아래에 records를 추가할 수 있습니다. **Domain shadowing**은 legitimate apex를 유지하면서 attacker-controlled subdomains를 대량으로 생성하여 변경되는 delivery 또는 C2 hosts를 가리키게 합니다. 이는 domain의 age와 reputation을 빌리고 domain-wide blocking을 회피할 수 있습니다.<sup>[[6]](#references)</sup>

Defender에게는 registrar 및 authoritative-DNS audit logs, MFA, registry/registrar locks, 새로운 delegations/API tokens/name servers에 대한 alerts, certificate-transparency monitoring, 그리고 DNS가 참조하는 cloud resources inventory가 필요합니다. Subdomain의 resolution과 certificate history는 apex reputation과 독립적으로 조사해야 합니다.

## Web services and dead-drop resolvers

**Dead-drop resolver (T1102.001)**는 legitimate post, profile, document, repository, cloud object 또는 blockchain field 내부에 현재 C2를 가리키는 encoded pointer를 저장합니다. Malware는 public object를 가져와 domain/IP를 decode한 후 다음 stage에 접속합니다. Bidirectional 변형은 service APIs를 통해 commands 또는 files를 교환합니다.<sup>[[7]](#references)</sup>

이는 복원력을 제공하고 static binary analysis에서 back-end C2를 숨깁니다. 동시에 안정적인 object, tenant, repository, API 및 access-pattern identifiers를 생성합니다. Defender는 다음 항목을 연결해야 합니다.

1. service에 접속한 process;
2. 정확한 API path/object 및 response hash;
3. decoding 또는 string-processing activity;
4. 곧이어 발생한 새로운 outbound connection; 그리고
5. fleet의 다른 곳에서 나타나는 동일한 behavior.

모든 GitHub, cloud storage 또는 social media를 차단하는 것은 거의 실행 가능하지 않습니다. Service-aware egress policy와 process-level correlation이 domain-only blocking보다 효과적입니다.

## Personas, accounts and procurement compartments

Persona, recovery email, phone, payment, browser 또는 admin IP가 compartments를 연결하면 infrastructure anonymity는 실패합니다. State-linked operations는 사용하기 훨씬 전부터 social profiles, email identities 및 cloud accounts를 구축해 왔습니다. ATT&CK는 이를 Establish Accounts (T1585)로 기록하며, social, email 및 cloud sub-techniques를 포함합니다.<sup>[[8]](#references)</sup>

Defender 또는 investigator는 다음 항목으로 graph를 구축합니다.

- creation 및 first-login time, locale, time zone 및 working schedule;
- recovery fields, MFA devices, identity documents 및 payment instruments;
- browser/TLS fingerprints 및 source-network history;
- avatar 재사용, image provenance, writing style 및 social-graph growth;
- 공유되는 domain registrant, name server, certificate, analytics ID 또는 repository commit;
- public relay architecture를 우회하는 management-plane actions.

승인된 red team의 경우 synthetic personas를 exercise controller에게 문서화하고, organization이 소유한 recovery/payment channels를 사용하며, 실제 관련 없는 사람을 impersonate하지 않고, 계획된 retirement 절차를 마련해야 합니다. SOC가 계속 blind 상태일 수는 있지만, operation이 책임 소재를 잃어서는 안 됩니다.

## Emerging compound patterns to threat-model

다음은 **defender-driven compositions**이며, 특정 actor가 각각의 정확한 design을 배포했다는 주장이 아닙니다. 이미 관찰된 primitives를 결합한 것으로, 유용한 purple-team hypotheses입니다.

### Asymmetric one-way tasking

Commands는 public, broadcast 또는 append-only source를 통해 도착하고, results는 지연 후 관련 없는 channel을 통해 나갑니다. Primitive의 예로 web-service one-way communication과 dead drops가 있습니다. 분리하면 단일 flow가 bidirectional로 보이는 것을 방지하고 단순한 request/response correlation을 방해합니다.<sup>[[9]](#references)</sup>

**Detection:** object-level reads를 보존한 다음 process state changes와 이후 outbound transfers를 더 넓은 시간 범위에서 상관분석합니다. 즉시 reply가 뒤따르지 않더라도 동일한 public object를 읽는 드문 process를 hunt합니다.

### Multi-stage channel promotion

조용한 first stage가 inventory를 수행한 뒤 선택된 system만 관련 없는 second-stage channel로 promote합니다. 두 번째 endpoint, protocol 및 process는 첫 번째와 infrastructure를 전혀 공유하지 않을 수 있습니다. 이는 capable infrastructure의 노출을 제한하며 ATT&CK T1104로 명시적으로 모델링됩니다.<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`을 연결합니다. 첫 번째 domain을 차단한 뒤 incident를 종료하지 마십시오.

### Cross-protocol relay translation

서로 다른 hops는 packets를 투명하게 forwarding하는 대신 HTTPS, QUIC, WebSocket, DNS, SSH 또는 message-queue API를 서로 변환합니다. Translation은 단일 end-to-end protocol fingerprint를 제거하지만, distinctive timing, buffering 및 semantic conversion을 가진 gateways를 생성합니다. Protocol tunneling (T1572)은 proxies 및 service impersonation과 결합될 수 있습니다.<sup>[[11]](#references)</sup>

**Detection:** 하나의 protocol을 수신하고 다른 protocol을 시작하며 byte/time behavior가 긴밀하게 결합된 gateway hosts를 찾습니다. Endpoint intent를 실제로 전달된 protocol과 비교합니다.

### Passive activation on edge devices

Beaconing 대신 implant는 router/VPN에 이미 도달하는 traffic을 모니터링하고 magic value, source-port pattern 또는 authenticated token이 있을 때만 activate합니다. Normal traffic은 실제 service로 계속 전달됩니다. ATT&CK는 이를 Traffic Signaling (T1205)이라고 부르며, network-device 및 APT examples가 문서화되어 있습니다.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, 승인된 hunt 중 raw packet capture, 예상하지 못한 socket filters 및 differential service behavior를 검사합니다. 주기적인 beacon이 없다고 해서 edge device가 clean하다는 뜻은 아닙니다.

### Serverless and ephemeral origin rotation

Front는 안정적인 logical identity를 유지하는 동안, short-lived functions/containers가 여러 regions/accounts에서 개별 stages를 처리합니다. 이는 disk lifetime과 고정된 origin IPs를 줄이지만, control-plane creation, image/layer, role, secret, request ID 및 billing telemetry가 지속적인 graph가 됩니다.

**Detection:** cloud audit 및 invocation logs를 workload 외부에 보존하고, deployment templates, roles, environment keys 및 front-to-origin relationships를 cluster화합니다.

### Privacy-layer diversity

Operation은 의도적으로 하나의 homogeneous chain을 피할 수 있습니다. 예를 들어 한 channel은 leased relay를 사용하고, tasking은 public object를 사용하며, exit은 소유한 lab cellular link에서 나오고, administration은 별도의 organization network를 사용합니다. 이는 하나의 provider가 compromise되는 것의 가치를 줄이지만 cross-layer timing 및 operational-error risk를 증가시킵니다.

**Detection:** identity, DNS, SaaS, network 및 cloud sensors 전반에서 campaign timelines를 구축합니다. 동일한 indicators가 아니라 synchronized state transitions를 검색합니다.

### Decentralized or transparency-log dead drops

Actor는 durable public append-only system, content-addressed store 또는 transparency-like feed 어디에든 작은 encrypted pointer를 배치할 수 있습니다. Public object는 복원력이 있지만, 정확한 index/content hash와 client polling behavior가 안정적인 identifiers가 됩니다.

**Detection:** 전체 API/object identifiers와 response hashes를 기록하고, immutable objects를 polling한 뒤 decoding 또는 새로운 connections를 수행하는 nonstandard processes에 alert를 생성합니다.

### Delayed store-and-forward operations

Interactive C2는 강한 timing correlation을 생성합니다. Store-and-forward design은 encrypted jobs를 batch 처리하고 몇 분 또는 몇 시간 후 다른 queue나 physical transfer를 통해 results를 반환합니다. 이는 responsiveness를 희생하여 end-to-end timing correlation을 약화합니다.

**Detection:** correlation windows를 늘리고, periodic queue access를 모델링하며, endpoint staging을 검사합니다. Batching은 signal을 packet timing에서 scheduled process/file behavior로 이동시킬 뿐 제거하지 않습니다.

## Design review: think in observers

모든 path에 대해 deployment 전과 collection 후 다음 table을 작성합니다.

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

하나의 일반적인 provider가 모든 column을 채울 수 있다면, 해당 architecture는 target으로부터의 concealment는 제공하지만 강력한 separation은 제공하지 않습니다. 어떠한 internal controller도 activity를 engagement에 매핑할 수 없다면, professional red teaming에 적합하지 않습니다.

## References

- [1] [MITRE ATT&CK — Infrastructure 획득 (T1583), Infrastructure Compromise (T1584) 및 Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors가 ORB networks를 사용](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastructure Compromise: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Accounts 수립 (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — 세계 최대 residential proxy network 방해](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Global Espionage uncovering](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
