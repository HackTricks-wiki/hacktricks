# Offensive Infrastructure and Attribution Evasion

Operator는 단일 proxy만으로 의미 있는 익명성을 확보하는 경우가 드뭅니다. 실제 campaign은 **separation graph**를 구축합니다. Operator는 access node에 접속하고, traversal node는 exit에서 해당 node를 숨기며, redirector는 실제 C2를 보호하고, disposable name은 public edge를 가리킵니다.

모든 경로를 정규화된 장단점/배포/탐지 관점에서 확인하려면 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)를 사용하세요. 이 페이지에서는 adversarial infrastructure 구성에 대해 더 자세히 다룹니다.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
따라서 target이 마지막으로 본 address는 경로에 대한 증거이지, keyboard를 누가 조작했는지에 대한 증거는 아니다. MITRE는 주요 구성 요소를 Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568), Web Service (T1102)에 매핑한다.<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | Why an actor uses it | Durable exposure | Defender's best pivot |
|---|---|---|---|
| Rented VPS/cloud | 빠르고 예측 가능하며 routable하고 쉽게 재구축할 수 있음 | tenant, billing, console, source-login 및 image history | account/control-plane events 및 반복되는 server fingerprint |
| Commercial VPN/Tor | 대규모 shared egress set; server administration 불필요 | provider/guard visibility 및 end-to-end timing | destination behavior, endpoint evidence 및 flow correlation |
| Residential/mobile proxy | consumer ASN 및 지리적 개연성 확보 | broker/customer records; proxyware 또는 infected-host behavior | impossible travel, proxy protocols 및 session별 address churn |
| Compromised server/router/IoT | victim reputation 및 jurisdiction을 빌림 | implant, management flow 및 반복되는 upstream controller | 단일 exit IP가 아닌 device telemetry 및 ORB topology |
| CDN/redirector | public edge와 back-end C2를 분리 | TLS/HTTP grammar, certificate, routing 및 cloud-account artifacts | edge-to-origin correlation 및 request-shape clustering |
| Legitimate web service | 허용된 GitHub/cloud/social traffic에 섞임 | API token, tenant/object identifiers 및 unusual process lineage | endpoint process와 service/API semantics |
| Physical/cellular/satellite path | 겉으로 보이는 physical origin을 변경 | RF, carrier, subscriber, device 및 location records | radio/physical 및 network evidence 결합 |

## Operational relay box networks

**ORB network**는 중간 서비스로 사용되는 managed proxy fleet이다. Mandiant는 이를 leased server로 구성된 provisioned networks, compromised router/IoT로 구성된 non-provisioned networks, 그리고 hybrids로 구분한다. 성숙한 topology에는 네 가지 logical role이 있다:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory, credentials, health 및 routing policy를 유지한다.
2. **Access/relay node:** customer 또는 operator를 authenticate하며, 변화하는 mesh로 들어가는 안정적인 entry이다.
3. **Traversal nodes:** 하나 이상의 leased 또는 compromised system이 opaque connection을 relay한다.
4. **Exit/staging node:** reconnaissance, exploitation 또는 C2 target에 최종 source address를 제시한다.

mesh는 country, ASN, latency 또는 availability를 기준으로 exit를 선택하고 상태가 좋지 않은 node를 rotate할 수 있다. 여러 threat group이 동일한 network를 rent할 수 있다. Mandiant는 일부 ORB에 연결된 IPv4 address가 31일 정도만 유지되는 것을 관찰했으며, 따라서 오래된 IP 목록을 차단하기보다는 **network를 변화하는 actor와 유사한 entity로 취급할 것**을 권고한다.<sup>[[2]](#references)</sup>

### What this buys—and what it leaks

- target은 지리적으로 가까우며 겉보기에는 residential일 수 있는 exit를 본다.
- exit는 target과 직전 hop을 보지만, 반드시 operator를 보는 것은 아니다.
- access service는 customer와 route request를 본다. 독립적으로 관리되는 mesh는 customer를 exit와 분리할 수 있지만, 강력한 counterparty record를 남긴다.
- 반복되는 port, handshake order, server banner, certificate, uptime window 및 controller relationship은 IP가 rotate되는 동안에도 fleet을 드러낼 수 있다.
- compromised router에는 endpoint telemetry가 없는 경우가 많지만, 해당 router의 ISP에는 여전히 subscriber 및 flow data가 있으며, 압수 시 implant/configuration artifact가 노출된다.

{% hint style="info" %}
authorized exercise에서는 organization이 소유한 VM 또는 router로 topology를 재현하고 controller의 attribution map을 보관한다. open proxy나 third-party device를 모집하지 않는다. [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)는 intermediary를 victim으로 만들지 않고 defender에게 동일하게 보이는 hop structure를 생성한다.
{% endhint %}

## Residential and mobile proxy networks

Residential proxy service는 session을 consumer broadband address에 할당하며, mobile proxy는 carrier NAT pool을 통해 egress한다. Supply는 명시적으로 등록된 appliance, consumer application에 포함된 SDK/proxyware, reseller 또는 malware에서 비롯될 수 있다. 이러한 origin은 서로 동일하지 않다. informed consent가 없으면 privacy service는 compromised infrastructure로 변한다.

Rotation mode는 detection에 영향을 준다.

- **per-request rotation**은 higher-layer identity가 안정적으로 유지되는 동안 IP 및 ASN/geography가 빠르게 불연속적으로 바뀌게 한다.
- **sticky sessions**는 exit를 수분 또는 수시간 동안 유지하여 일반적인 subscriber처럼 보이게 한다.
- **backconnect gateways**는 customer에게 하나의 broker endpoint를 노출하고 내부적으로 exit를 선택한다.
- **mobile pools**는 다수의 실제 subscriber를 소수의 carrier NAT address 뒤에 배치하므로, IP block의 비용이 커진다.

Defender는 IP를 authenticated session, TLS/client fingerprint, HTTP ordering, device cookie 및 behavior와 correlate해야 한다. 겉보기에는 local인 residential login 이후 모든 higher-layer feature가 동일한 상태에서 다른 country가 나타난다면 reputation만으로 판단하는 것보다 더 강한 신호다. 반대로 address sharing 및 mobile handoff는 정상적인 churn을 만들 수 있으므로 residential/proxy classification을 verdict로 취급해서는 안 된다.

## Multi-hop proxy chains

MITRE는 external proxy와 **multi-hop proxy (T1090.003)**를 구분한다. 중요한 특성은 hop count가 아니라 knowledge와 administration의 분리다.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
한 당사자가 A와 B를 운영하면 공유 로그 또는 flow timing을 통해 circuit을 재구성할 수 있습니다. 동일한 endpoint/account에서 순차적으로 상용 VPN을 추가하면 latency가 증가할 수 있지만, 공통된 identity, 결제 정보 및 timing 증거는 그대로 남을 수 있습니다. Tor는 독립적으로 선택된 relay와 공유 client 설계를 통해 이 문제를 완화하지만, low-latency interactive network는 양쪽 끝을 모두 측정하는 observer에 대한 저항성을 보장할 수 없습니다.

일반적인 실패 원인은 DNS 또는 IPv6 bypass, 애플리케이션이 자체 socket을 여는 경우, management traffic이 relay에 직접 도달하는 경우, 동기화된 activity, 재사용된 SSH key, 그리고 식별 가능한 account에 로그인하는 경우입니다. 올바른 검증 방법은 failure test입니다. 각 relay를 차례로 중지하고 workload가 clear path로 fallback할 수 없음을 입증해야 합니다.

## Redirector tiers and traffic shaping

공개 **redirector**는 operation별 grammar와 일치하는 traffic을 수신하여 보호된 team server로 전달합니다. 그 외의 모든 traffic은 거부하거나 무해한 content를 제공할 수 있습니다.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
여러 계층을 사용하면 노출을 제한할 수 있습니다. 공개 도메인을 소각해도 team server가 노출될 필요는 없습니다. CDN은 anycast 용량과 평판이 좋은 외부 도메인을 제공하지만, CDN account와 edge 로그가 attribution 지점이 됩니다. TLS fingerprints, certificate histories, 고유한 paths/header order, response sizes, redirect behavior 및 origin allowlists를 통해 서로 무관해 보이는 front들을 하나의 그룹으로 묶을 수 있습니다.

탐지를 위해 normalization 전에 reverse-proxy fields를 기록하고, SNI/Host/authority를 비교하며, 드문 header 조합을 검사하고, response bodies와 TLS fingerprints를 cluster하고, configuration overlap을 확인하기 위해 cloud/CDN audit logs를 검색합니다. 승인된 red teams의 경우 실제 brand를 복제하거나 무관한 third party 뒤에 credential collection을 배치하지 않아야 합니다.

## Domain fronting and domainless fronting

고전적인 **domain fronting (T1090.004)**에서는 TLS connection이 SNI에 허용된 front domain을 알리는 반면, 암호화된 HTTP `Host` 또는 HTTP/2 `:authority`는 다른 back-end domain을 요청합니다. 협력하는 CDN은 내부 값에 따라 routing합니다. TLS decryption을 수행하지 않는 network observer는 front만 보지만, CDN은 두 값과 origin을 모두 확인합니다. Domainless variant에서는 SNI가 비어 있고 다른 routing field가 destination을 선택할 수 있습니다.<sup>[[4]](#references)</sup>

이는 마법 같은 impersonation이 아닙니다. intermediary가 불일치를 의도적으로 또는 우연히 허용하고 내부 이름을 routing할 방법을 알고 있을 때만 작동합니다. 주요 provider들은 cross-account fronting을 제한했습니다. Encrypted ClientHello (ECH)는 on-path observer가 볼 수 있는 내용을 변경하지만 CDN, endpoint 또는 application records를 제거하지는 않습니다.

탐지 지점은 다음과 같습니다.

- 해당 application에서 예상되지 않는 endpoint process ancestry 및 destination;
- TLS inspection이 합법적이고 이용 가능한 경우 SNI와 HTTP authority의 불일치;
- 한 tenant/front가 다른 authority/origin으로 routing되는 것을 보여 주는 CDN logs;
- 일반적으로 interactive한 service에 대한 비정상적으로 장시간 지속되거나 주기적인 sessions;
- front domains가 변경되는 동안에도 유지되는 encrypted flow sizes와 cadence.

안전한 lab에서는 소유한 reverse proxy에서 routing mismatch를 simulation하며, public CDN을 abuse하지 않습니다.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution은 논리적 service를 고정된 infrastructure에서 분리합니다.

- **DDNS:** 인증된 client가 address 변경 후에도 stable name을 유지하도록 이를 update합니다.
- **DGA:** endpoint와 controller가 모두 time/key seed에서 candidate domain names를 도출하며, operator는 그중 일부만 register합니다.
- **Fast flux:** name이 빠르게 변경되는 compromised/proxy addresses 집합을 반환하며, 흔히 낮은 TTL을 사용합니다.
- **Double flux:** service addresses와 authoritative name-server addresses가 모두 rotation되어 control layer까지 숨깁니다.

Fast flux는 단순히 “많은 DNS answers”가 아니라 adversarial하게 사용되는 load-distribution pattern입니다. 더 강한 증거는 낮은 TTL, 높은 unique-address count, 넓은 ASN/geography dispersion, 짧은 node lifetime, 반복되는 application behavior 및 의심스러운 registration history를 결합합니다. CDN도 이러한 특성 중 일부를 정당하게 공유합니다. MITRE는 DNS behavior를 process 및 이후 connections와 상관 분석할 것을 권장합니다.<sup>[[5]](#references)</sup>

DGA는 lexical entropy, consonant/digit patterns, NXDOMAIN bursts, synchronized first-seen domains 및 process context를 통해 탐지할 수 있습니다. Wordlist DGAs와 generative models는 단순한 entropy 규칙을 우회하므로 fleet-wide temporal clustering과 endpoint lineage가 더욱 중요해집니다.

## Compromised domains and domain shadowing

Actor는 registrar/DNS account를 hijack하거나, dangling subdomain을 takeover하거나, 그 외에는 평판이 좋은 domain 아래에 records를 추가할 수 있습니다. **Domain shadowing**은 정상적인 apex를 유지하면서 공격자가 제어하는 다수의 subdomains가 변경되는 delivery 또는 C2 hosts를 가리키도록 합니다. 이를 통해 domain의 연식과 reputation을 빌리고 domain-wide blocking을 회피할 수 있습니다.<sup>[[6]](#references)</sup>

Defenders는 registrar 및 authoritative-DNS audit logs, MFA, registry/registrar locks, 새로운 delegations/API tokens/name servers에 대한 alerts, certificate-transparency monitoring, 그리고 DNS가 참조하는 cloud resources inventory를 확보해야 합니다. Subdomain의 resolution과 certificate history는 apex reputation과 별도로 조사합니다.

## Web services and dead-drop resolvers

**Dead-drop resolver (T1102.001)**는 합법적인 post, profile, document, repository, cloud object 또는 blockchain field 내부에 현재 C2를 가리키는 encoded pointer를 저장합니다. Malware는 public object를 가져와 domain/IP를 decode한 다음 다음 stage에 접속합니다. Bidirectional variants는 service APIs를 통해 commands 또는 files를 교환합니다.<sup>[[7]](#references)</sup>

이는 복원력을 제공하고 static binary analysis에서 back-end C2를 숨깁니다. 동시에 안정적인 object, tenant, repository, API 및 access-pattern identifiers를 생성합니다. Defenders는 다음 항목을 연결해야 합니다.

1. service에 접속한 process;
2. 정확한 API path/object 및 response hash;
3. decoding 또는 string-processing activity;
4. 그 직후의 새로운 outbound connection; 그리고
5. fleet의 다른 위치에서 나타나는 동일한 behavior.

모든 GitHub, cloud storage 또는 social media를 차단하는 것은 대체로 실현 가능하지 않습니다. Service-aware egress policy와 process-level correlation이 domain-only blocking보다 효과적입니다.

## Personas, accounts and procurement compartments

Persona, recovery email, phone, payment, browser 또는 admin IP가 compartments를 연결하면 infrastructure anonymity는 무너집니다. State-linked operations는 사용하기 훨씬 전부터 social profiles, email identities 및 cloud accounts를 육성해 왔으며, ATT&CK는 이를 Establish Accounts (T1585)로 기록하고 social, email 및 cloud sub-techniques를 포함합니다.<sup>[[8]](#references)</sup>

Defender 또는 investigator는 다음 항목으로 graph를 구축합니다.

- creation 및 first-login time, locale, time zone 및 working schedule;
- recovery fields, MFA devices, identity documents 및 payment instruments;
- browser/TLS fingerprints 및 source-network history;
- avatar reuse, image provenance, writing style 및 social-graph growth;
- shared domain registrant, name server, certificate, analytics ID 또는 repository commit;
- public relay architecture를 우회하는 management-plane actions.

승인된 red team의 경우 synthetic personas를 exercise controller에게 문서화하고, organization-owned recovery/payment channels를 사용하며, 실제로 관련 없는 사람을 impersonate하지 않고, 계획된 retirement 절차를 마련해야 합니다. SOC가 계속 blind 상태일 수는 있지만, operation이 accountability를 잃어서는 안 됩니다.

## Emerging compound patterns to threat-model

다음은 **defender-driven compositions**이며, 특정 actor가 각각의 정확한 design을 배포했다는 주장이 아닙니다. 이미 관찰된 primitives를 결합한 것으로, 유용한 purple-team hypotheses입니다.

### Asymmetric one-way tasking

Commands는 public, broadcast 또는 append-only source를 통해 도착하고, results는 delay 후 무관한 channel을 통해 나갑니다. Primitive의 예로 web-service one-way communication과 dead drops가 있습니다. 분리는 단일 flow가 bidirectional처럼 보이는 것을 방지하고 단순한 request/response correlation을 방해합니다.<sup>[[9]](#references)</sup>

**Detection:** object-level reads를 보존한 다음, 더 넓은 window에서 process state changes와 이후 outbound transfers를 correlation합니다. 즉각적인 reply가 없더라도 동일한 public object를 읽는 드문 process를 hunt합니다.

### Multi-stage channel promotion

조용한 first stage는 inventory를 수행하고 선택된 systems만 무관한 second-stage channel로 promotion합니다. 두 번째 endpoint, protocol 및 process는 첫 번째 infrastructure와 아무런 공통점이 없을 수 있습니다. 이는 capable infrastructure의 노출을 제한하며 ATT&CK T1104로 명시적으로 model됩니다.<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`을 연결합니다. 첫 번째 domain을 blocking한 뒤 incident를 종료하지 마십시오.

### Cross-protocol relay translation

서로 다른 hops는 packets를 transparent하게 forwarding하는 대신 HTTPS, QUIC, WebSocket, DNS, SSH 또는 message-queue API를 translate합니다. Translation은 단일 end-to-end protocol fingerprint를 제거하지만, 고유한 timing, buffering 및 semantic conversion을 보이는 gateways를 생성합니다. Protocol tunneling (T1572)은 proxies 및 service impersonation과 결합될 수 있습니다.<sup>[[11]](#references)</sup>

**Detection:** 하나의 protocol을 수신하고 다른 protocol을 시작하며 byte/time behavior가 긴밀하게 결합된 gateway hosts를 찾습니다. Endpoint intent와 실제로 전달된 protocol을 비교합니다.

### Passive activation on edge devices

Beaconing 대신 implant는 router/VPN에 이미 도달하는 traffic을 모니터링하고 magic value, source-port pattern 또는 authenticated token이 있을 때만 activation합니다. 정상 traffic은 실제 service로 계속 전달됩니다. ATT&CK는 이를 Traffic Signaling (T1205)이라 부르며, network-device 및 APT examples가 문서화되어 있습니다.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, 승인된 hunt 중 raw packet capture, 예상하지 못한 socket filters 및 differential service behavior를 확인합니다. 주기적인 beacon이 없다고 해서 edge device가 clean하다는 뜻은 아닙니다.

### Serverless and ephemeral origin rotation

Front는 안정적인 논리적 identity를 유지하는 동시에, 단기간 생존하는 functions/containers가 여러 regions/accounts에서 개별 stages를 처리합니다. 이는 disk lifetime과 고정된 origin IPs를 줄이지만, control-plane creation, image/layer, role, secret, request ID 및 billing telemetry가 지속적인 graph가 됩니다.

**Detection:** workload 외부에 cloud audit 및 invocation logs를 보존하고, deployment templates, roles, environment keys 및 front-to-origin relationships를 cluster합니다.

### Privacy-layer diversity

Operation은 의도적으로 하나의 homogeneous chain을 피할 수 있습니다. 예를 들어 한 channel은 leased relay를 사용하고, tasking은 public object를 사용하며, exit는 owned lab cellular link에서 제공되고, administration은 별도의 organization network를 사용합니다. 이는 하나의 provider가 compromise되었을 때의 가치를 줄이지만 cross-layer timing과 operational-error risk를 증가시킵니다.

**Detection:** identity, DNS, SaaS, network 및 cloud sensors 전반에서 campaign timelines를 구축합니다. 동일한 indicators가 아니라 synchronized state transitions를 검색합니다.

### Decentralized or transparency-log dead drops

Actor는 내구성 있는 public append-only system, content-addressed store 또는 transparency-like feed에 작은 encrypted pointer를 배치할 수 있습니다. Public object는 resilient하지만 정확한 index/content hash와 client polling behavior가 stable identifiers가 됩니다.

**Detection:** 전체 API/object identifiers와 response hashes를 기록하고, immutable objects를 polling한 뒤 decoding 또는 새로운 connections를 수행하는 nonstandard processes에 alert를 생성합니다.

### Delayed store-and-forward operations

Interactive C2는 강한 timing correlation을 생성합니다. Store-and-forward design은 encrypted jobs를 batch하고, 몇 분 또는 몇 시간 후 다른 queue나 physical transfer를 통해 results를 반환합니다. 이는 responsiveness를 희생하는 대신 end-to-end timing correlation을 약화시킵니다.

**Detection:** correlation windows를 늘리고, periodic queue access를 model하며, endpoint staging을 검사합니다. Batching은 signal을 packet timing에서 scheduled process/file behavior로 이동시킬 뿐, signal 자체를 제거하지는 않습니다.

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

하나의 일반적인 provider가 모든 column을 채울 수 있다면, 해당 architecture는 target으로부터의 concealment은 제공하지만 robust separation은 제공하지 않습니다. 어떠한 internal controller도 activity를 engagement로 되돌려 mapping할 수 없다면, professional red teaming에 부적합합니다.

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
