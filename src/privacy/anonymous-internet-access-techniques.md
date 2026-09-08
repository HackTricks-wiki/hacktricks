# Anonymous Internet Access Technique Catalog

{{#include ../banners/hacktricks-training.md}}

이 문서는 표준 access-path 목록이다. 모든 vendor 이름이 아니라 protocol 및 운영 **family**를 다룬다. 어떤 Internet 경로도 anonymity를 보장하지 않는다. account, browser, endpoint, timing, payment, cloud-control-plane 및 물리적 증거가 겉보기에는 완벽한 경로도 무력화할 수 있다.

모든 항목은 같은 필드를 사용한다. “Procedure”는 합법적인 배포 또는 소유한 lab에서의 emulation을 의미한다. 실제 technique이 router compromise, access 탈취 또는 비동의 intermediary 악용을 요구하는 경우, 재현에서는 exercise 소유 시스템으로 대체한다.

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | 공유 public address | subscriber 간 ambiguity | high | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | 빠른 source-address 분리 | high | deployable |
| Multi-hop/split relay, MASQUE | 최종 proxy | knowledge split 또는 full-IP tunnel | high/moderate | 신뢰된 relay로 deployable |
| Tor, bridge, onion service | exit 또는 onion identity | 다자간 경로와 공통 browser | moderate | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay 또는 timing resistance | low/variable | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request partitioning | high | 지원 application만 |
| Public Wi-Fi, travel router | venue/tunnel address | 위치/access-path 변경 | high | permission required |
| Cellular/eSIM, satellite | carrier/provider address | 독립적인 물리 uplink | high/variable | subscription/provider가 관찰 |
| Remote browser/jump host | remote workspace | endpoint 및 egress 분리 | high | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network appearance | high | consent/provenance 중요 |
| ORB/compromised relay | 다른 victim의 address | origin concealment 및 차용 reputation | high | owned-lab reproduction only |
| CDN/fronting/redirector | CDN/front address | back-end infrastructure 보호 | high | provider/owner approval required |
| Fast flux/DGA/dead drop | rotating node/service | infrastructure discovery resistance | variable | owned-lab reproduction only |
| Drop/nearest-neighbor | target 인접 local address | geographic/network boundary 통과 | high | owned-site lab only |
| Store-and-forward/offline | gateway 또는 physical receiver | interactive timing linkage 감소 | low | application-specific |
| Pluggable/refraction transport | Tor entry 또는 cooperating diversion proxy | censorship-resistant reachability | variable | 지원 client 또는 research lab |
| IPFS gateway/PIR/remote fetcher | gateway 또는 application service | publisher/query/request partitioning | variable | 제한된 application만 |
| Anycast/QUIC/MPTCP | stable broker 또는 multiple subflows | rendezvous 및 session continuity | high | availability용이지 anonymity용 아님 |
| CI/CD automation runner | hosted runner address | disposable accountable egress | high | owned workflow only |
| Non-IP local first hop | organization gateway | sensor에서 Internet stack 제거 | low | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** 여러 사용자가 하나의 public address를 공유하며, access provider가 subscriber-side address와 port를 public tuple로 매핑한다.

**Pros:** 빠르고 특수 client가 필요 없다. destination 측 IP만으로는 household, venue 또는 carrier pool 정도만 식별할 수 있다.

**Cons:** provider는 subscriber/port/time 매핑을 보관할 수 있다. account와 fingerprint는 여전히 남으며, 다른 사용자가 address reputation을 훼손할 수 있다.

**Procedure:** (1) authorized access가 NAT/CGNAT를 사용하는지 확인한다. (2) owned endpoint에서 정확한 public IP와 source port를 기록한다. (3) application identity를 분리한다. (4) shared addressing를 privacy control로 취급하지 않는다. (5) ISP가 destination을 알면 안 되는 경우 더 강한 경로를 사용한다.

**Detection:** destination은 IP만이 아니라 source port와 정확한 시간을 보관해야 한다. Provider는 NAT allocation log를 상관 분석하고, investigator는 account/device/browser 증거를 결합한다.

## Commercial VPN

**Mechanics:** 암호화된 full-tunnel connection이 VPN에서 종료되고 destination에는 VPN의 egress가 보인다. VPN은 일반적으로 source, timing 및 destination을 연결할 수 있다.

**Pros:** 빠르고 간단하다. local passive observation을 방어하며, 안정적 또는 공유 exit를 제공한다. 통제된 red-team egress에 적합하다.

**Cons:** trust가 집중된다. billing/login telemetry, kill-switch/DNS/IPv6 failure가 존재하며 shared exit는 reputation 차단을 자주 받는다.

**Procedure:** (1) provider, owner, jurisdiction, retention 및 assessment policy를 확인한다. (2) 서명된 공식 client를 설치한다. (3) full tunnel, always-on 및 fail-closed를 활성화한다. (4) DNS와 IPv6를 의도적으로 route한다. (5) owned endpoint에서 관찰되는 IPv4/IPv6/DNS를 검증한다. (6) tunnel을 중지/재연결하고 clear fallback이 없는지 확인한다.<sup>[[1]](#references)</sup>

**Detection:** local network는 VPN infrastructure로 향하는 긴 encrypted flow를 볼 수 있다. Provider는 authentication/connection record를 보유하며, destination은 ASN/reputation과 account, TLS/browser 및 behavior correlation을 사용한다.

## Self-hosted VPN or rented VPS egress

**Mechanics:** operator가 WireGuard/OpenVPN gateway를 관리하거나 rented server를 통해 traffic을 forward한다.

**Pros:** 예측 가능한 높은 속도, allowlist에 넣기 쉬운 고정 address, custom logging/firewall 및 우수한 incident control을 제공한다.

**Cons:** anonymity set이 작다. cloud tenant, payment, source login, API 및 image history가 operator와 연결되며, 새로 생성된 특징적인 server는 쉽게 cluster화된다.

**Procedure:** (1) engagement 전용 organization project를 만든다. (2) 지원되는 image와 fixed address를 provision한다. (3) management를 MFA/key-based administration으로 제한한다. (4) full-tunnel egress와 DNS를 구성한다. (5) 가능한 경우 범위가 지정된 destination만 허용한다. (6) leak/failure 동작을 테스트한다. (7) controller audit record를 보관한다. (8) teardown 시 credential과 resource를 제거한다.

**Detection:** hosting ASN, first-seen address, certificate/service fingerprint 및 scanning behavior를 상관 분석한다. cloud owner는 control-plane, console, billing 및 flow log를 사용한다.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** application이 proxy에 TCP stream 개설을 요청한다. SOCKS는 version에 따라 name resolution과 UDP도 전달할 수 있으며, SSH는 하나의 encrypted session 내부에서 stream을 forward한다.

**Pros:** 가볍고 application별로 적용 가능하며 빠르다. chaining 및 segmented network 접근에 유용하다.

**Cons:** application이 우회할 수 있고 DNS가 leak될 수 있다. Proxy는 인접 endpoint를 보며 browser state는 남는다. Open proxy는 trap이거나 compromised system일 수 있다.

**Procedure:** (1) owned host에 proxy를 배포한다. (2) authentication을 요구하고 source/destination을 제한한다. (3) disposable application profile 하나를 구성한다. (4) 필요한 경우 remote DNS resolution을 보장한다. (5) owned DNS/HTTP endpoint로 확인한다. (6) workload의 direct egress를 차단한다. (7) proxy credential을 검사하고 교체한다.

**Detection:** tunnel-capable process, CONNECT/SOCKS negotiation, 긴 SSH session 및 application과 맞지 않는 destination을 식별한다. Proxy log는 stream을 재구성한다.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** website가 destination을 fetch하고 link/form을 자체 origin을 통해 rewrite하거나, extension이 browser request를 proxy로 보낸다. Destination에는 service가 보이지만 service는 TLS 종료 후 plaintext를 보고 content를 주입하거나 보관할 수 있다.

**Pros:** system-wide client가 필요 없고 간단한 browsing에 빠르며 VPN 설치가 불가능한 환경에서도 작동한다.

**Cons:** proxy가 credential/content를 읽고 download를 rewrite하며 user를 fingerprint할 수 있다. Script/WebSocket/download가 우회할 수 있고 browser extension은 광범위한 privilege를 가진다. Anonymity set이 작고 차단이 잦다.

**Procedure:** (1) authorized testing에는 organization-operated proxy만 사용한다. (2) personal account가 없는 disposable browser로 격리한다. (3) password 입력과 민감한 download를 금지한다. (4) owned page의 모든 subresource가 proxy를 통해 resolve되는지 확인한다. (5) WebSocket, download 및 form 동작을 테스트한다. (6) 사용 후 extension/profile을 제거한다.

**Detection:** destination은 proxy를 기록한다. Enterprise proxy/DNS와 extension inventory가 service를 식별하며, content-security/reporting 또는 owned canary subresource가 direct bypass를 드러낸다. Proxy log는 user session과 target을 매핑한다.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** entry는 source를 보고 하나 이상의 traversal relay가 이를 exit와 분리하며, exit는 destination을 본다.

**Pros:** 일반적인 relay 하나가 양쪽을 모두 알 필요가 없다. 한 node의 failure/seizure로 드러나는 정보가 줄고 geography를 유연하게 선택할 수 있다.

**Cons:** 동일한 administration/log가 split을 무력화한다. Latency, timing correlation, failure 및 DNS route가 증가하며 같은 account/payment가 모든 hop을 연결할 수 있다.

**Procedure:** (1) 각 hop이 제거하는 observer를 정의한다. (2) 분리가 중요하면 독립적으로 관리되는 owned/approved relay를 사용한다. (3) workload에서 entry-only access를 강제한다. (4) 각 relay가 다음 hop에만 접근하도록 한다. (5) 모든 layer의 log를 확인한다. (6) 각 hop을 중지하고 fail-closed를 확인한다. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)로 재현한다.

**Detection:** 인접 NetFlow의 timing/volume, 반복되는 proxy handshake 및 공통 controller infrastructure를 상관 분석한다. Exit만으로 operator geography를 추론하지 않는다.

## Split-knowledge application relay and OHTTP

**Mechanics:** client가 stateless HTTP message를 gateway에 암호화하고 relay를 통해 전송한다. Relay는 client IP를 보지만 request는 보지 못하며, gateway는 request를 보지만 일반적으로 relay IP만 본다.

**Pros:** 지원 request에 대해 강력하고 audit 가능한 privacy partition을 제공하며 general anonymity network보다 overhead가 낮다.

**Cons:** 임의 browsing에는 사용할 수 없다. Cookie/authentication이 다시 연결할 수 있고, relay/gateway collusion과 traffic analysis가 남는다. Application이 구현해야 한다.

**Procedure:** (1) RFC 9458을 명시적으로 지원하는 application을 선택한다. (2) 공식 configuration path를 통해 gateway key를 확인한다. (3) 안정적인 per-user field를 피한다. (4) 지원되는 stateless request만 전송한다. (5) relay, gateway 및 target log를 비교한다. (6) direct fallback 없이 key rotation/failure를 테스트한다.<sup>[[2]](#references)</sup>

**Detection:** Enterprise endpoint는 initiating process와 OHTTP relay를 노출한다. Gateway는 malformed/replayed traffic을 탐지하며 timing과 stable payload/account field가 request를 연결할 수 있다.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUIC가 UDP 또는 IP packet을 proxy를 통해 전달한다. 현대적인 VPN과 유사한 tunnel을 구현하고 transport를 HTTP/3와 혼합할 수 있지만 proxy는 여전히 observer다.<sup>[[3]](#references)</sup>

**Pros:** 효율적인 multiplexing/roaming, UDP 또는 full IP 지원, 현대적인 HTTP infrastructure를 통한 배포가 가능하다.

**Cons:** anonymity network가 아니다. Proxy/account는 source와 destination을 보며 QUIC/HTTP fingerprint와 well-known path가 endpoint/provider에 보인다.

**Procedure:** (1) RFC 9298/9484 지원을 문서화한 client/service를 사용한다. (2) proxy certificate/configuration을 authenticate한다. (3) 허용할 target route를 정의한다. (4) path 내부에서 encrypted DNS를 활성화한다. (5) owned endpoint로 UDP, TCP, IPv6 및 failover를 검증한다. (6) proxy request 및 flow log를 검사한다.

**Detection:** endpoint는 client process와 virtual interface를 본다. Network는 proxy로 향하는 지속적인 QUIC/TLS를 분류할 수 있으며 proxy log는 CONNECT target/path와 assigned route를 노출한다.

## Tor Browser

**Mechanics:** Tor는 guard, middle 및 exit relay를 선택한다. Layered encryption은 각 relay가 보는 정보를 제한하며 Tor Browser는 fingerprinting 저항을 목표로 표준화된 browser를 제공한다.

**Pros:** 큰 public anonymity set, 양쪽을 모두 아는 일반 relay가 없음, server를 운영하지 않아도 destination unlinkability를 제공한다.

**Cons:** 느리고 TCP 중심이며 exit reputation/block이 존재한다. Login과 disclosure는 user를 식별하고 low-latency timing correlation은 남는다.

**Procedure:** (1) project에서 Tor Browser를 download하고 검증한다. (2) default를 유지하고 extension을 피한다. (3) 적절한 security level을 선택한다. (4) 별도 identity/session을 만든다. (5) identifying account와 외부 active document를 피한다. (6) HTTPS 또는 authenticated onion service를 사용한다. (7) owned endpoint에서만 exit를 확인한다.<sup>[[4]](#references)</sup>

**Detection:** bridge/transport를 사용하지 않으면 local network가 알려진 guard traffic을 식별할 수 있다. Destination은 exit와 Tor Browser behavior를 보며 end-to-end observer는 timing/volume을 상관 분석한다.

## Tor bridges and pluggable transports

**Mechanics:** non-public bridge가 public guard를 대체한다. obfs4, Snowflake 또는 WebTunnel은 첫 hop transport를 변경하여 단순 차단/probing을 어렵게 한다.

**Pros:** censorship을 우회하고 명확한 public-relay destination을 숨기며 entry 이후 Tor circuit을 유지한다.

**Cons:** transport pattern/bridge discovery가 가능하고 성능이 변동한다. Account 또는 global timing에 대한 보호는 추가하지 않는다.

**Procedure:** (1) 먼저 direct Tor를 시도한다. (2) Tor Browser Connection 설정에서 내장 지원 transport를 선택하거나 공식 bridge를 요청한다. (3) random binary/list를 사용하지 않는다. (4) 연결 후 benign test를 실행한다. (5) reconnect와 clock을 테스트한다. (6) 나머지 browser 설정은 표준으로 유지한다.<sup>[[5]](#references)</sup>

**Detection:** Censor는 destination discovery, protocol/flow classification 및 active probing을 사용한다. Defender는 circumvention 사용과 compromise를 구분하고 endpoint process/context에 의존해야 한다.

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor는 access ISP로부터 direct Tor 사용을 숨기지만 VPN에는 source가 노출된다. Tor-before-VPN은 VPN에 post-Tor traffic을 제공하고 안정적인 customer/tunnel identity를 노출하는 경우가 많다.

**Pros:** 올바르게 설계하면 특정 observer를 제거하며 한 layer를 차단하는 network에 접근할 수 있다.

**Cons:** 복잡성, 흔하지 않은 fingerprint, leak, 감소한 anonymity set 및 false confidence가 발생한다. Tor Project는 이를 advanced 조합으로 취급한다.<sup>[[6]](#references)</sup>

**Procedure:** (1) 제거되는 observer와 새로 도입되는 observer를 작성한다. (2) disposable environment를 사용한다. (3) 의도한 outer path만 수립한다. (4) firewall route를 강제한다. (5) DNS/IPv4/IPv6 및 각 failure order를 확인한다. (6) 두 provider의 visibility를 비교한다. (7) 측정 가능한 이점이 없으면 stack을 폐기한다.

**Detection:** local/VPN/Tor observer는 서로 다른 인접 layer를 본다. Timing은 end-to-end로 남으며 unusual nested tunnel fingerprint와 provider account가 session을 연결할 수 있다.

## Onion service

**Mechanics:** client와 service가 모두 rendezvous로 향하는 Tor circuit을 만들어 service IP를 숨기고 exit를 피한다.

**Pros:** source와 service location 보호, end-to-end onion authentication, public inbound port 불필요 및 선택적 client authorization을 제공한다.

**Cons:** update/analytics/error를 통해 origin이 leak될 수 있다. Onion key가 중요하며 application identity/timing과 host compromise가 남는다.

**Procedure:** (1) application을 격리하고 loopback/socket에만 bind한다. (2) 지원되는 Tor를 설치한다. (3) 공식 지침에 따라 v3 onion service를 구성한다. (4) stable identity가 필요할 때만 key를 보호/backup한다. (5) closed use에는 client authorization을 추가한다. (6) third-party fetch를 제거한다. (7) 외부에서 origin에 접근할 수 없는지 검증한다.<sup>[[7]](#references)</sup>

**Detection:** Host/network defender는 Tor process/configuration과 outbound circuit을 발견한다. Application error, DNS, certificate 또는 third-party resource가 origin을 노출할 수 있다.

## I2P internal services

**Mechanics:** I2P는 overlay 내부 destination을 위해 별도의 단방향 inbound/outbound tunnel을 사용한다. Public-Internet outproxy는 trust point를 추가한다.

**Pros:** decentralized internal publishing, 공식 exit dependency 없음, inbound/outbound path 분리를 제공한다.

**Cons:** 일반 web의 대체재가 아니며 ecosystem이 작다. 장기 peer behavior가 존재하고 outproxy는 public browsing을 관찰할 수 있다.

**Procedure:** (1) 공식 source에서 설치한다. (2) dedicated context를 사용한다. (3) integration/bandwidth stabilization을 허용한다. (4) owned I2P-native service에 접근한다. (5) 명시적으로 필요하지 않으면 outproxy를 피한다. (6) shutdown 시 direct fallback이 없는지 확인한다. (7) local peer와 service log를 검사한다.<sup>[[8]](#references)</sup>

**Detection:** Local network는 장기 peer traffic과 bootstrap behavior를 본다. Endpoint는 router/application process를 노출하며 outproxy는 exit를 기록한다.

## Mixnets

**Mechanics:** fixed-size packet, batching, delay, reordering 및 cover traffic이 timing correlation을 줄이며 gateway가 application을 연결한다.

**Pros:** low-latency proxy보다 timing analysis에 강하고 asynchronous message/transaction에 유용하다.

**Cons:** latency와 bandwidth overhead, 작은 deployment 및 application 제한이 있다. Gateway/account metadata가 남을 수 있다.

**Procedure:** (1) 유지 관리되는 client와 지원 application을 선택한다. (2) 실제 threat model을 읽는다. (3) 별도 compartment에 설치한다. (4) owned endpoint로 benign data를 전송한다. (5) latency/reliability와 reply path를 측정한다. (6) gateway failure를 테스트한다. (7) 속도를 위해 delay/cover traffic을 비활성화하지 않는다.<sup>[[9]](#references)</sup>

**Detection:** Endpoint는 client를 식별한다. Access network는 gateway/packet cadence를 분류할 수 있으며 gateway와 exit는 인접 role을 관찰한다. 광범위한 correlation에는 더 긴 statistical window가 필요하다.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet은 peer를 통해 publish/search/download request를 route하고 anonymity level에 따라 cover traffic을 추가할 수 있다. 자체 문서는 default level 1에서 cover traffic이 요구되지 않으며 강력한 traffic analysis가 origin을 식별할 수 있다고 경고한다.<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing과 조정 가능한 cover-traffic requirement를 제공한다.

**Cons:** 일반적인 anonymous web access가 아니다. Performance/storage cost와 peer 및 traffic-analysis 제한이 있으며 GNUnet VPN 문서는 IP overlay가 충분한 anonymity를 제공하지 않는다고 설명한다.

**Procedure:** (1) 유지 관리되는 공식 build를 설치한다. (2) test peer를 격리한다. (3) bandwidth/storage를 제한한다. (4) 선택한 anonymity level로 무해한 unique test file을 publish한다. (5) 다른 owned peer에서 retrieve한다. (6) cover-traffic과 latency를 기록한다. (7) IP VPN component가 동등한 anonymity를 제공한다고 주장하지 않는다.

**Detection:** Peer bootstrap, overlay traffic, local datastore/process 및 file identifier가 노출된다. 광범위한 observer는 cover traffic과 traffic volume을 분석할 수 있다.

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ는 resolver까지 암호화한다. ODoH는 proxy와 resolver 사이에서 client address와 query를 분리하며 ECH는 inner TLS ClientHello/server name을 암호화한다.

**Pros:** 일부 local observer에서 plaintext DNS/SNI를 제거하고 ODoH는 source/query knowledge를 분할한다.

**Cons:** IP-anonymity path가 아니다. Resolver/proxy/server는 각자의 role을 보유하며 destination IP/timing/volume과 endpoint는 남는다. Fallback은 leak될 수 있다.

**Procedure:** (1) OS, application 또는 tunnel 중 DNS를 관리할 주체를 선택한다. (2) strict encrypted mode 또는 지원되는 ODoH를 활성화한다. (3) unique owned domain을 테스트한다. (4) local capture로 clear query가 없는지 확인한다. (5) resolver failure 시 의도한 동작을 검증한다. (6) ECH에서는 server diagnostic이 inner ClientHello acceptance를 보이는지 확인한다.<sup>[[11]](#references)</sup>

**Detection:** Endpoint/resolver log가 query를 노출한다. Network는 encrypted-resolver endpoint와 destination flow를 식별하며 ECH state는 path에서 숨겨져도 endpoint/CDN에는 보인다.

## Split-provider privacy relay

**Mechanics:** iCloud Private Relay와 같은 product는 client를 아는 ingress와 destination을 아는 독립 운영 egress를 사용하며 coarse region을 처리한다.

**Pros:** 낮은 마찰의 split knowledge, 빠른 속도, 지원 traffic에 통합된 DNS/web protection을 제공한다.

**Cons:** Product/application 범위가 제한된다. Account/platform provider는 customer를 식별하며 임의의 system anonymity가 아니다. Collusion/legal 및 timing risk가 남는다.

**Procedure:** (1) 지원되는 정확한 application과 traffic type을 확인한다. (2) 적절한 경우 dedicated platform context에서 feature를 활성화한다. (3) region behavior를 선택한다. (4) Safari/DNS와 unsupported application을 별도로 테스트한다. (5) destination address를 검사한다. (6) network switching/failure를 테스트한다.<sup>[[12]](#references)</sup>

**Detection:** Access는 ingress를 보고 destination은 egress를 본다. Platform/relay log와 account record는 각 layer를 연결하며 unsupported application은 일반 경로를 노출한다.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** Browsing/tool execution이 remote system에서 실행된다. Destination에는 remote system의 egress가 보이고 workspace provider에는 operator connection과 control plane이 보인다.

**Pros:** 빠르고 위험한 content를 격리하며 안정적인 controlled egress, disposable state 및 강한 organizational audit을 제공한다.

**Cons:** Provider/admin은 session/account를 관찰할 수 있다. Screen/clipboard/file channel이 leak될 수 있고 remote browser fingerprint가 unique할 수 있다. Workspace owner에게는 anonymous가 아니다.

**Procedure:** (1) engagement마다 organization-owned workspace 하나를 만든다. (2) MFA를 요구하고 administration을 제한한다. (3) clipboard/upload/download를 비활성화하거나 제한한다. (4) approved fixed egress를 사용한다. (5) personal IdP/sync를 사용하지 않는다. (6) 검토한 evidence만 export한다. (7) 일정에 따라 workspace와 credential을 제거한다.

**Detection:** Provider와 IdP log가 user를 session에 매핑한다. Destination은 workspace egress/browser를 cluster화하며 enterprise defender는 remote-control protocol과 anomalous cloud session을 식별한다.

## Public or guest Wi-Fi

**Mechanics:** Traffic은 venue NAT 또는 해당 장소에서 시작된 tunnel을 통해 exit한다.

**Pros:** 빠르고 shared non-home address를 제공하며 dedicated infrastructure가 필요 없다.

**Cons:** Venue association/DHCP/portal, camera, purchase 및 location evidence가 남는다. Hostile peer/AP, 약관 및 물리적 위험도 있다.

**Procedure:** (1) guest에게 제공된 access를 받고 staff와 SSID를 확인한다. (2) patch된 low-trust device를 사용한다. (3) sharing/auto-join을 비활성화하고 private MAC을 활성화한다. (4) reused identity 없이 portal을 완료한다. (5) fail-closed VPN/Tor path를 시작한다. (6) tethered traffic을 확인한다. (7) network를 forget한다.

**Detection:** Venue는 AP, MAC, DHCP, portal 및 시간을 상관 분석한다. Destination에는 venue/tunnel이 보이며 investigator는 physical 및 device evidence를 결합한다. Access control을 우회하지 않는다.

## Travel router

**Mechanics:** Operator-owned router가 venue Wi-Fi/Ethernet에 연결되고 tunnel policy가 강제된 isolated internal network를 제공한다.

**Pros:** Workstation을 격리하고 central kill switch/DNS와 일관된 client network를 제공하며 privileged endpoint를 local broadcast에서 보호한다.

**Cons:** Router가 stable radio/DHCP fingerprint가 되고 attack surface를 추가한다. Captive portal과 tethering은 tunnel을 우회할 수 있다.

**Procedure:** (1) 지원 firmware를 update한다. (2) 고유 management credential을 설정하고 WAN admin/WPS/UPnP를 비활성화한다. (3) 허용되는 경우 private upstream MAC을 구성한다. (4) 별도 internal SSID를 만든다. (5) full-tunnel DNS/IPv6 firewall policy를 강제한다. (6) portal, reconnect 및 tunnel failure를 테스트한다.

**Detection:** Venue는 router association과 traffic shape를 보며 local RF/DHCP fingerprinting으로 식별할 수 있다. VPN provider는 venue source를 본다.

## Cellular, prepaid SIM and eSIM

**Mechanics:** Modem이 carrier radio access를 사용하고 일반적으로 carrier NAT를 통과한다. VPN/Tor layer는 destination-visible exit를 변경할 수 있다.

**Pros:** local wired/Wi-Fi network와 독립적이고 mobile이며 빠르다. Authorized drop의 backhaul에 유용하다.

**Cons:** Carrier는 subscriber/eSIM, IMSI, IMEI, cell, time 및 assigned port를 안다. Registration law는 다르며 personal phone과의 co-location이 device를 연결한다.

**Procedure:** (1) 필요한 정확한 정보로 합법적으로 service를 얻는다. (2) organization-owned 별도 modem/device를 사용한다. (3) exercise controller에 기록한다. (4) 관련 없는 radio/account를 비활성화한다. (5) approved tunnel을 수립한다. (6) tethered client가 실제로 tunnel을 따르는지 테스트한다. (7) 이동 전에 provider와 retention 가정을 확인한다.<sup>[[13]](#references)</sup>

**Detection:** Carrier record와 RF location, enterprise USB/PCI/MDM inventory 및 rogue-hotspot survey, destination/tunnel timing을 사용한다.

## Satellite Internet and satellite downlink abuse

**Mechanics:** 정상 service는 registered terminal/provider를 사용한다. 과거 one-way DVB-S abuse에서는 beam 내부 receiver가 legitimate subscriber에게 전달된 unencrypted downlink traffic을 관찰하고 outbound request에는 다른 path를 사용할 수 있었다.

**Pros:** 넓은 footprint와 independent last mile을 제공한다. 역사적인 one-way abuse는 C2를 subscriber geography로 잘못 귀속시킬 수 있었다.

**Cons:** Equipment/RF/provider record, latency와 coverage 문제가 있다. Modern bidirectional system은 다르며 outbound path와 asymmetric routing이 증거로 남는다.

**Procedure:** 합법적인 access에는 owned terminal을 등록하고 필요하면 traffic을 tunnel한다. 역사적인 Turla behavior를 emulation하려면 RF-free lab에서 synthetic one-way packet capture를 replay하고 request를 하지 않은 host에 reply가 전달된 것을 analyst가 탐지하는지 테스트한다. Live satellite traffic을 intercept하지 않는다.<sup>[[14]](#references)</sup>

**Detection:** Provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency 및 malware configuration을 사용한다.

## Residential/mobile proxy or consented proxyware

**Mechanics:** Backconnect gateway가 sticky 또는 rotating 방식으로 consumer broadband/mobile exit를 할당한다. Supply는 consensual, deceptively bundled 또는 malicious할 수 있다.

**Pros:** 빠르고 geography를 선택할 수 있으며 consumer ASN이 일부 hosting block을 피하고 큰 pool을 제공한다.

**Cons:** Provenance/consent와 legal risk, broker visibility, infected exit로 인한 피해, rotation anomaly 및 높은 비용/불안정성이 있다.

**Procedure:** emulation에는 문서화되고 informed-consent를 받은 organization-owned agent만 사용한다. (1) test endpoint를 enroll한다. (2) owner/IP를 inventory한다. (3) gateway를 구성한다. (4) sticky/per-request mode를 전환한다. (5) owned target에만 전송한다. (6) gateway/exit/target log를 비교한다. (7) 모든 agent를 제거한다.

**Detection:** Impossible travel, 빠른 IP/ASN 변경 중에도 유지되는 browser/account, backconnect protocol, proxyware process/network artifact 및 broker/controller 관계를 탐지한다.

## ORB, botnet and compromised edge-device relays

**Mechanics:** Leased 또는 compromised router/IoT/server가 fleet으로 관리되는 access, traversal 및 exit role을 구성한다. 여러 APT customer가 공유할 수 있다.

**Pros:** 차용한 reputation/geography, 짧은 수명의 exit, resilient multi-hop mesh 및 약한 actor-to-IP link를 제공한다.

**Cons:** Criminal victimization, implant/controller 및 fleet pattern, intermediary seizure, 불안정한 성능과 operator/customer service record가 존재한다.

**Procedure:** 실제 device를 compromise하지 않는다. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)을 사용한다. (1) isolated entry/transit/target network를 만든다. (2) owned dual-homed relay container를 연결한다. (3) 하나의 test port만 forward한다. (4) benign request를 보낸다. (5) target이 exit만 보는지 확인한다. (6) exit를 교체한다. (7) 이름이 지정된 모든 asset을 teardown한다.<sup>[[15]](#references)</sup>

**Detection:** Topology, port/service, controller relation, implant fingerprint 및 node lifecycle을 추적한다. Edge configuration/flow/integrity telemetry를 centralize하며 exit IP를 actor와 동일시하지 않는다.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** Public edge가 특정 grammar와 일치하는 traffic만 forward한다. Fronting은 intermediary가 허용할 때 benign outer SNI와 다른 inner HTTP authority 또는 blank SNI를 사용한다.

**Pros:** Back-end를 숨기고 보호하며 fast global edge, shared service와의 blending 및 빠른 cutover를 제공한다.

**Cons:** CDN은 모든 routing과 tenant를 본다. 많은 provider가 cross-tenant fronting을 금지한다. SNI/Host/process/flow와 account artifact가 남고 configuration reuse가 campaign을 cluster화한다.

**Procedure:** [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging)를 사용하여 owned reverse proxy에서만 재현한다. Local certificate/edge를 만들고, mismatched Host 하나를 owned target으로 route하고, SNI와 Host를 log한 뒤 normal/mismatched request를 전송하고 container를 제거한다.<sup>[[16]](#references)</sup>

**Detection:** Endpoint 또는 terminating edge에서 SNI/ECH/Host/`:authority`를 비교한다. Initiating process, tenant/origin, request grammar 및 flow cadence를 결합한다.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS는 stable name을 update한다. DGA는 변경되는 candidate name을 계산하고 fast flux는 낮은 TTL로 service address를 rotation한다. Double flux는 name server도 rotation한다.

**Pros:** Resilient discovery, 빠른 infrastructure replacement 및 다수의 node 뒤에 controller 은닉을 제공한다.

**Cons:** DNS가 centralized telemetry를 만든다. Entropy/NXDOMAIN/churn, 낮은 TTL과 광범위한 ASN pattern이 나타나며 registration과 authoritative infrastructure가 남는다.

**Procedure:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry)를 사용한다. Owned zone이 RFC 5737 address를 5초 TTL로 반환하도록 설정하고 반복 query하며 synthetic epoch를 변경하고 analytics를 검증한다. Test record를 third party로 향하게 하지 않는다.<sup>[[17]](#references)</sup>

**Detection:** Sliding-window unique answer/ASN, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal cluster 및 process follow-on을 탐지한다. Context를 고려하여 legitimate CDN을 제외한다.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** Public post, repository, document, object 또는 feed에 encoded current endpoint 또는 task가 포함된다. Client는 다른 channel로 result를 반환할 수 있다.

**Pros:** 높은 reputation의 허용된 service, TLS 및 binary 변경 없는 endpoint rotation을 제공한다. Asymmetric tasking은 단순 flow correlation을 어렵게 한다.

**Cons:** Stable object/account/API identifier, provider record, endpoint decode/follow-on sequence가 남는다. Content는 seize 또는 변경될 수 있다.

**Procedure:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence)를 사용한다. Owned container 하나에 encoded pointer를 host하고 short-lived client에서 fetch/decode한 뒤 두 번째 owned service에 contact한다. 두 log를 보존하고 teardown한다.

**Detection:** Unusual process → stable object read → decode → new destination sequence를 상관 분석한다. Content를 hash/preserve하고 domain만이 아니라 전체 object path를 보관한다.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** Function/short-lived job이 provider NAT 또는 front 뒤에서 실행된다. Logical service는 안정적이지만 instance와 address는 rotation한다.

**Pros:** 빠른 deployment/destruction, provider-scale shared egress, 적은 local disk 및 elastic regional routing을 제공한다.

**Cons:** Tenant, role, API, image, secret, invocation, billing 및 front-to-origin log가 지속된다. Cold-start와 platform fingerprint 및 provider policy도 남는다.

**Procedure:** (1) organization-owned exercise tenant를 사용한다. (2) owned endpoint에만 request하는 benign function을 배포한다. (3) project/role/image/config를 기록한다. (4) 여러 instance에서 invoke한다. (5) target IP와 audit/request ID를 비교한다. (6) log retention을 테스트한다. (7) function, role 및 secret을 제거한다.

**Detection:** Cloud audit/invocation log, unusual role creation, stable request grammar를 가진 shared egress, image/layer 및 secret reuse, front-origin correlation을 사용한다.

## Authorized on-site drop

**Mechanics:** Inventory된 소형 computer가 local wired/Wi-Fi와 outbound VPN/cellular rendezvous를 사용하여 local source로 나타난다.

**Pros:** Realistic internal-origin testing, 높은 속도, NAC/physical inventory/egress control 테스트가 가능하다.

**Cons:** Physical discovery/theft, serial/MAC/USB/DHCP/PoE/RF와 camera evidence가 남으며 분실 시 credential이 노출될 수 있다.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)를 따른다. (1) 정확한 서면 placement authority를 얻는다. (2) serial, MAC, photo, location 및 retrieval time을 기록한다. (3) signed minimal image와 short-lived mutual credential을 사용한다. (4) outbound-only destination/capability를 제한한다. (5) server-side quarantine과 bandwidth limit을 추가한다. (6) SOC visibility와 loss response를 테스트한다. (7) 회수하고 필요한 evidence를 보존한 뒤 합의된 lifecycle policy에 따라 sanitize한다. 비동의 venue에 숨기지 않는다.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera 및 physical inspection을 사용한다.

## Nearest-neighbor wireless pivot

**Mechanics:** Actor가 target의 radio range 안에 있는 host를 제어한 뒤 target Wi-Fi credential을 사용하여 원격으로 boundary를 넘는다. APT28이 이 방법으로 nearby compromised organization을 사용했다.<sup>[[18]](#references)</sup>

**Pros:** Operator가 이동할 필요가 없고 target에는 local radio source가 보이며 Internet entry에만 적용된 control을 우회한다.

**Cons:** Nearby compromised/owned dual-radio host와 유효한 access가 필요하다. RADIUS/NAC/AP 및 neighbor endpoint evidence와 signal/device anomaly가 남는다.

**Procedure:** [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot)로만 재현한다. Owned pivot을 neighbor와 target lab SSID에 연결하고 하나의 service만 forward하며 두 AP/pivot log를 수집한다. 이후 EAP-TLS/device posture를 활성화하고 두 번째 시도가 실패하는지 확인한다.

**Detection:** RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login 및 physical presence를 상관 분석한다. Nearby endpoint에서 simultaneous radio, forwarding 및 tunnel을 탐색한다.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** Traffic이 하나의 interactive Internet session이 아니라 local peer, asynchronous gateway, removable media 또는 scheduled queue를 통과한다.

**Pros:** Disruption/censorship 중에도 작동하고 delayed/batched delivery가 단순 timing을 약화한다. Local communication에는 central last mile이 필요 없다.

**Cons:** 높은 latency, 작은 anonymity set, custody/physical metadata, malicious peer가 존재한다. 결국 traffic을 관찰하는 gateway에 도달한다.

**Procedure:** (1) isolated owned three-node mesh 또는 file queue를 구축한다. (2) Content를 end-to-end encryption/authentication한다. (3) Origin에서 direct Internet route를 제거한다. (4) Controlled delay 후 benign file을 relay한다. (5) Gateway만 owned destination에 contact하는지 확인한다. (6) Custody/timestamp를 비교한다. (7) 필요한 evidence를 보존하고 승인된 closeout에서 temporary media/queue를 sanitize한다.

**Detection:** Endpoint file/process activity, peer-radio link, removable-media audit, queue/gateway periodicity 및 content identifier를 사용한다. Interactive-flow analysis 대신 더 긴 correlation window를 사용한다.

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN)은 public relay address를 할당하고 client와 peer 사이에 UDP, TCP 또는 TLS traffic을 전달한다. ICE policy는 direct candidate를 노출하지 않고 relay 사용을 강제할 수 있다. TURN은 reachability를 해결할 뿐 general anonymity를 제공하지 않는다. Server는 client를 authenticate하고 allocation, peer, time 및 volume을 관찰한다.<sup>[[19]](#references)</sup>

**Pros:** 널리 구현되었고 restrictive NAT를 처리하며 mobile WebRTC를 지원한다. Relay-only policy가 올바르면 peer는 client의 direct transport address를 받지 않는다.

**Cons:** TURN operator는 양쪽 인접 측을 모두 본다. Application identity, media fingerprint 및 signaling이 남는다. Relay-only는 bandwidth와 latency 비용이 있으며 잘못 구성하면 host 또는 server-reflexive candidate가 수집된다.

**Procedure:** (1) TLS와 short-lived credential을 사용하는 organization-owned TURN service를 배포한다. (2) realm, peer, port, quota 및 expiration을 제한한다. (3) Test application을 relay-only ICE로 설정한다. (4) Owned peer에 call한다. (5) `getStats()`와 packet capture로 relay candidate만 media를 전달했는지 확인한다. (6) Relay를 중지하고 direct fallback이 없는지 확인한다. (7) Engagement 동안 allocation log를 보존한다.

**Detection:** Signaling, browser process 및 TURN allocation이 session을 relay에 연결한다. Network는 TURN port 또는 TLS endpoint로 향하는 지속적인 flow를 관찰하며 peer는 allocated relay를 본다. **Captured node:** Application state와 ephemeral TURN credential이 realm과 rendezvous service를 드러낼 수 있다. Per-device short-lived credential을 사용하고 operator authentication은 controller에만 둔다.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** NAT 뒤의 node가 organization-controlled broker에 authenticated connection을 시작한다. Operator는 broker에 별도로 authenticate하며 broker는 좁은 management channel을 authorize한다. Inbound port forwarding이나 direct operator-to-node route가 필요 없다.

**Pros:** NAT와 captive last mile 뒤에서도 안정적이고 central revocation/audit을 제공한다. Field-node address 변경에 operator discovery가 필요 없으며 operator identity와 node credential을 분리한다.

**Cons:** Broker가 중요한 correlation point가 된다. Periodic keepalive가 식별 가능하고 broad tunnel은 unsafe pivot이 될 수 있다. Broker가 손실되면 management가 종료된다.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous)를 따른다. Scoped device identity 하나를 발급하고 owned broker 및 approved management service만 허용한다. Authenticated keepalive, fail-closed routing을 강제하고 address change와 reboot recovery를 테스트한 뒤 loss drill에서 identity를 revoke한다. WireGuard는 실제로 필요할 때 broadly useful NAT interval로 25초 persistent keepalive를 문서화한다.<sup>[[20]](#references)</sup>

**Detection:** Broker와 identity-provider log가 양쪽을 매핑한다. Access network는 반복되는 encrypted destination/cadence를 보며 endpoint inventory는 overlay agent를 보여준다. **Captured node:** Device key, broker name, tunnel address 및 cached task data가 노출된다고 가정한다. Operator private key, personal account 또는 reusable controller token을 포함하지 않아야 한다.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** Field workload가 authenticated mailbox를 polling하여 signed, pre-approved job을 받고 제한된 result를 post한다. Operator는 별도 control plane으로 queue에 기록하며 둘 사이에 interactive socket이 없다.

**Pros:** Intermittent link를 견디고 timing/addressing을 분리한다. Quota와 schema로 capability를 제한할 수 있으며 central audit/revocation이 쉽다.

**Cons:** Polling cadence와 stable object/queue name이 fingerprint가 된다. Provider log가 producer와 consumer를 연결하고 control이 지연되며 queued data가 exercise를 노출할 수 있다.

**Procedure:** (1) Engagement queue 하나와 device identity 하나를 만든다. (2) Signed schema와 benign, 명시적으로 범위가 지정된 job을 정의한다. (3) Message TTL, 최대 result size 및 rate를 설정한다. (4) Node가 자신의 queue만 pull하고 result prefix에만 write하도록 한다. (5) Offline accumulation, duplicate delivery 및 revocation을 테스트한다. (6) Immutable access log를 중앙화한다. (7) Retention requirement 충족 후 queue를 삭제한다.

**Detection:** Unusual process의 periodic API call, stable bucket/object/queue path, 동일한 user-agent/TLS behavior 및 fetch-then-new-connection sequence를 탐색한다. **Captured node:** Local cache가 pending job과 object name을 드러낼 수 있다. Cache는 encrypted, bounded, disposable하게 유지하고 authoritative controller log는 보존한다.

## Dual-uplink failover and connection migration

**Mechanics:** Approved field node가 venue Ethernet/Wi-Fi와 organization cellular처럼 독립된 두 uplink를 보유하고 overlay 또는 message broker를 통해 route 변경 중에도 control session을 유지한다. 이는 anonymity가 아니라 availability engineering이다.

**Pros:** Provider, AP 또는 captive-portal 하나의 failure를 견디고 maintenance를 지원하며 의심스러운 path를 신속히 격리한다.

**Cons:** 두 provider가 두 location/account record를 만든다. 동시 사용은 correlation을 쉽게 하며 failover 중 route/DNS leak이 발생할 수 있다. Cellular co-location evidence도 남는다.

**Procedure:** (1) 두 organization-owned interface와 provider를 등록한다. (2) Owned endpoint에 deterministic route priority와 health check를 설정한다. (3) DNS와 management를 overlay에 bind한다. (4) Secondary path가 inbound traffic을 받지 않게 한다. (5) 각 path를 분리하고 session recovery, source policy 및 direct destination access가 없는지 확인한다. (6) 계획되지 않은 path change를 alert한다. (7) Data use와 roaming limit을 문서화한다.

**Detection:** AS간 동일한 device certificate, request grammar 및 timing을 상관 분석한다. Local inventory는 두 radio를 보고 carrier/venue는 자체 record를 보관한다. **Captured node:** 두 SIM/device identifier와 known SSID가 노출될 수 있다. Organization asset을 사용하고 personal device와 함께 두거나 pairing하지 않는다.

## Organization private APN or managed cellular tunnel

**Mechanics:** Carrier private APN이 enrolled SIM을 private routed domain에 배치하거나 enterprise gateway로 traffic을 tunnel한다. Device를 public mobile Internet에서 분리하지만 carrier 또는 contracting organization으로부터 숨기지는 않는다.

**Pros:** Stable private addressing, carrier-level enrollment/traffic policy 및 public inbound exposure 방지를 제공한다. Authorized remote appliance에 유용하다.

**Cons:** Subscriber, IMSI/IMEI, cell 및 billing attribution이 강력하다. Procurement lead time/cost, carrier/gateway outage가 존재하며 operator에게 anonymous가 아니다.

**Procedure:** (1) Assessment organization 명의로 APN을 계약한다. (2) Registered SIM과 gateway prefix만 whitelist한다. (3) Application-layer mutual authentication을 추가한다. (4) APN route를 rendezvous와 update service로 제한한다. (5) SIM removal, roaming, public-Internet breakout 및 revocation을 테스트한다. (6) Carrier/gateway record를 모니터링한다. (7) Closeout 시 모든 SIM을 cancel 또는 quarantine한다.

**Detection:** Carrier inventory/cell telemetry, APN gateway flow, SIM/IMEI mismatch 및 enterprise asset record를 사용한다. **Captured node:** Storage가 encrypted여도 SIM과 modem이 contract를 식별한다. Capture resilience는 deniability가 아니라 빠른 suspension과 좁은 authorization을 의미한다.

## Long-range point-to-point wireless bridge

**Mechanics:** Directional Wi-Fi 또는 licensed/unlicensed point-to-point radio가 owner-approved 두 site를 연결하고 remote site에서 Internet egress를 제공한다. Commercial proxy 없이 apparent IP location을 이동할 수 있다.

**Pros:** 높은 throughput, intermediate wired carrier와 독립된 경로, 제어 가능한 RF/routing 및 segmentation/remote-site monitoring 테스트를 제공한다.

**Cons:** Line-of-sight, spectrum, landlord 및 regulatory constraint가 있다. Distinctive RF emission과 hardware가 존재하고 두 endpoint가 physical evidence가 된다. Weather/power/alignment가 stability에 영향을 준다.

**Procedure:** (1) 두 site의 written permission을 얻고 spectrum/power rule을 확인한다. (2) 승인된 parameter 밖으로 transmit하지 않고 path를 survey한다. (3) Authenticated encryption과 management VLAN을 사용한다. (4) Bridge를 owned rendezvous 또는 test subnet으로 제한한다. (5) Failover, alignment, power recovery 및 RF containment를 테스트한다. (6) 두 radio를 label/inventory한다. (7) Exercise 후 제거하고 configuration reset을 확인한다.

**Detection:** RF survey, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic 및 remote-site egress log를 사용한다. **Captured node:** Configuration이 peer와 management domain을 드러낸다. Unique exercise credential을 사용하고 personal management account를 두지 않으며 peer key를 빠르게 revoke한다.

## Consented cooperative or community exit

**Mechanics:** Volunteer 또는 partner organization이 published policy에 따라 relay를 알고 운영한다. Traffic은 shared community pool에서 exit하며 coordination layer가 abuse와 revocation을 관리한다.

**Pros:** Diverse non-cloud network, proxyware보다 안전한 명시적 consent, trust를 분산하는 shared governance를 제공한다. Research와 censorship-resilience study에 유용하다.

**Cons:** 작은 pool과 membership record가 anonymity를 줄인다. Exit operator는 complaint를 받고 traffic metadata를 관찰한다. Malicious participant, variable uptime 및 jurisdiction 차이도 존재한다.

**Procedure:** (1) Acceptable-use 및 logging policy를 publish한다. (2) 각 operator로부터 informed opt-in을 받는다. (3) Unique relay identity를 발급하고 destination/rate를 제한한다. (4) Abuse handling과 one-action revocation을 제공한다. (5) Testing 중 owned endpoint로 authorized traffic만 보낸다. (6) Churn과 correlation exposure를 측정한다. (7) Consent 종료 시 relay를 clean하게 제거한다.

**Detection:** Membership/control-plane record, relay certificate, common software fingerprint 및 exit behavior가 pool을 식별한다. **Captured node:** Relay configuration이 cooperative를 식별할 수 있지만 client identity를 포함해서는 안 된다. Client-to-session accountability는 access control하에 authorized controller에 보관한다.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extension은 temporary interface identifier를 만들어 모든 outbound connection에서 stable address가 재사용되지 않게 한다. Provider prefix 변경이 rotation을 추가할 수 있지만 delegated prefix, subscriber record 및 upper-layer fingerprint는 남는다.<sup>[[21]](#references)</sup>

**Pros:** Stable interface identifier에 의한 장기 passive tracking을 줄이며 common operating system에 내장되고 relay overhead가 없다.

**Cons:** Source anonymity가 아니다. ISP와 local network는 여전히 prefix/device를 알고 DNS, account 및 browser state가 session을 연결한다. Address churn은 allowlist와 logging을 복잡하게 한다.

**Procedure:** (1) Owned client에서 현재 stable/temporary address를 확인한다. (2) Third-party spoofing 대신 OS 지원 privacy-address default를 활성화한다. (3) Address lifetime 동안 owned IPv6 endpoint에 반복 요청한다. (4) Inbound service가 의도한 stable address에만 bind되는지 확인한다. (5) DHCPv6/RA/neighbor와 정확한 endpoint log를 보관한다. (6) 모든 IPv6 address에 대해 VPN/firewall behavior를 테스트한다.

**Detection:** 하나의 address를 하나의 device로 취급하지 말고 delegated prefix, layer-2 identity, neighbor discovery, account 및 endpoint telemetry를 상관 분석한다. **Captured node:** Network profile과 interface identifier는 남는다. Temporary addressing는 하나의 passive identifier를 막을 뿐 forensic attribution을 막지 못한다.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** Pluggable transport는 첫 Tor connection의 appearance 또는 bridge 도달 방식을 변경한다. Snowflake는 short-lived volunteer WebRTC proxy를 사용하고 WebTunnel은 일반 HTTPS와 유사하며 obfs4는 단순 protocol identification과 active probing을 방어하고 meek은 지원 web infrastructure를 통해 relay한다. 이는 Tor로 들어가는 censorship-circumvention transport이지 추가적인 end-to-end anonymity layer가 아니다.<sup>[[22]](#references)</sup>

**Pros:** Direct Tor 또는 known relay가 차단된 경우 유용하다. Snowflake는 stable public bridge address를 피하며 maintained Tor client에 통합된다. Destination에는 여전히 일반적인 Tor 특성이 전달된다.

**Cons:** 성능이 낮거나 변동한다. Broker/front/bridge와 local network는 서로 다른 metadata를 관찰한다. Transport fingerprint와 blocking은 가능하며 volunteer proxy는 Tor를 대체하지 않고 application plaintext를 신뢰해서도 안 된다.

**Procedure:** (1) 공식 Tor Browser 또는 지원 Tor client를 설치하고 검증한다. (2) Connection/Bridges에서 내장 transport를 선택한다. (3) Owned diagnostic page에만 연결한다. (4) Page가 Snowflake/WebTunnel peer가 아닌 Tor exit를 보는지 확인한다. (5) Bootstrap과 performance를 비교한다. (6) Transport를 실패시키고 client가 조용히 direct connection하지 않는지 확인한다. (7) Test 후 표준 지원 configuration으로 돌아간다.

**Detection:** Censor는 destination allowlist, TLS/WebRTC behavior, broker discovery 및 flow analysis를 결합할 수 있다. Endpoint는 Tor와 transport configuration을 노출한다. **Capture-resilient OPSEC:** Standard client를 사용하고 personal browser state를 복사하지 않으며 bridge/broker history가 복구될 수 있다고 가정한다. **Monitoring:** Tor bootstrap log, 예상치 못한 direct DNS/connection attempt 및 controller-owned page observation을 감시한다. Transport failure는 discovery의 증거가 아니다.

## Refraction networking or decoy routing

**Mechanics:** Cooperating network operator가 허용된 decoy로 향하는 것처럼 보이는 traffic에서 covert signal을 탐지하고 flow를 circumvention proxy로 divert한다. Deployment에는 network path 내부 infrastructure가 필요하며 client가 innocent website를 선택하는 것만으로 만들 수 없다.<sup>[[23]](#references)</sup>

**Pros:** Apparent destination을 차단하려면 censor가 collateral damage를 감수해야 할 수 있다. Public bridge address를 배포할 필요가 없으며 on-path-assisted circumvention의 research model로 유용하다.

**Cons:** Specialized ISP/transit participation이 필요하다. Deployability와 performance는 routing에 의존한다. Client-to-decoy flow와 proxy-side activity가 남고 global 또는 cooperating observer는 timing을 상관 분석할 수 있다.

**Procedure:** Uninvolved network를 통해 signal하지 않는다. Isolated lab에서 재현한다. (1) owned client, router, decoy 및 proxy namespace를 만든다. (2) benign tagged test request를 사용한다. (3) owned router가 해당 tag만 proxy로 redirect하게 한다. (4) pre/post-routing tuple과 request ID를 log한다. (5) ordinary/signaled flow를 비교한다. (6) false positive와 removal을 테스트한다. (7) lab route를 제거한다.

**Detection:** Authorized network operator는 routing divergence, unusual client hello/tag behavior 및 decoy-versus-back-end flow discrepancy를 검사할 수 있다. **Capture-resilient OPSEC:** Research client에는 test key와 documentation address만 둔다. **Monitoring:** Signed lab-router decision과 proxy arrival을 비교하며 production transit provider를 probe하여 signaling 탐지 여부를 확인하지 않는다.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway가 IPFS content identifier (CID)를 cache 또는 peer에서 retrieve하고 검증 가능한 content를 client에 반환한다. Original publisher에는 final reader가 아니라 gateway 또는 다른 peer가 보일 수 있으며 gateway는 reader IP와 requested CID를 본다. Native peer-to-peer retrieval은 client를 peer와 DHT/routing participant에 노출한다.<sup>[[24]](#references)</sup>

**Pros:** Cache가 publisher와 reader를 분리하고 immutable content는 hash로 검증할 수 있다. Replicated data는 한 host의 failure를 견디며 HTTP client에는 native peer stack이 필요 없다.

**Cons:** Public CID와 gateway log가 interest를 노출한다. 첫 retrieval timing은 publisher와 reader를 연결할 수 있으며 malicious web content와 path-style same-origin hazard가 존재한다. Public gateway는 best-effort이며 abuse를 금지한다.

**Procedure:** (1) Owned private IPFS swarm 또는 gateway에 harmless test file을 publish한다. (2) CID를 기록한다. (3) Subdomain isolation을 사용하여 별도 owned HTTP gateway로 retrieve한다. (4) Byte를 CID와 비교한다. (5) Caching 후 반복한다. (6) Publisher, peer 및 gateway log를 비교한다. (7) Retention 종료 시 unpin하고 test content를 제거한다.

**Detection:** Gateway는 source/CID를 기록하고 DHT/peer connection은 retrieval을 드러낸다. Endpoint history와 file hash가 content를 식별한다. **Capture-resilient OPSEC:** Read-only field client에 private publishing key를 저장하지 않고 content addressing 전에 민감한 content를 암호화한다. **Monitoring:** 예상치 못한 pinning, peer-set change, allowlist 밖 CID request 또는 gateway account notice를 alert한다.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR)은 명시된 single- 또는 multi-server threat model에서 client가 선택한 index를 server에 cryptographically hide한 채 database에서 하나의 record를 retrieve하게 한다. Bounded dataset의 query selection을 보호하지만 general web access나 IP anonymity는 아니다.<sup>[[25]](#references)</sup>

**Pros:** 강력한 application-specific query privacy와 측정 가능한 leakage model을 제공한다. Key directory, blocklist 또는 작은 public database에 유용하며 정확한 lookup term을 공개할 필요를 줄인다.

**Cons:** Computation/bandwidth overhead가 있다. Server는 relay와 결합하지 않으면 connection time/IP를 알며 dataset version, response size 및 application state가 user를 분리할 수 있다. Implementation maturity는 다양하다.

**Procedure:** (1) Synthetic owned database에 audited PIR implementation을 배포한다. (2) Dataset version과 parameter를 publish한다. (3) 동일한 request size로 여러 index를 retrieve한다. (4) Local에서 correctness를 검증한다. (5) Server log를 비교하고 index가 없는지 확인한다. (6) Malicious/truncated response와 version mismatch를 테스트한다. (7) 이를 anonymous browsing이라고 부르지 말고 정확한 privacy assumption을 문서화한다.

**Detection:** Network는 service 사용과 volume을 보고 endpoint telemetry는 client와 final record 사용을 노출한다. Compromised server는 dataset 또는 timing을 조작할 수 있다. **Capture-resilient OPSEC:** Client에는 public database parameter와 bounded cache만 둔다. **Monitoring:** Signed dataset root, fixed request shape, error-rate 변화 및 server-key rotation을 검증한다.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** Remote service가 URL을 fetch/render하고 screenshot, metadata 또는 sanitized content를 반환한다. Destination에는 fetcher address가 보이고 service에는 requester, URL 및 result가 보인다. Link-preview bot, security scanner 또는 third-party URL fetcher의 abuse는 authorized proxy 사용이 아니다.

**Pros:** Workstation에서 active content를 격리한다. Destination에는 controlled fetcher fingerprint가 전달되며 file type, size, destination 및 rendering limit을 강제할 수 있다. Disposable execution environment를 사용한다.

**Cons:** Service가 request를 완전히 알고 account/API/billing record를 보유한다. SSRF와 data-exfiltration risk가 있고 script, authentication 및 interactive site가 작동하지 않을 수 있다. Unique URL은 requester와 fetch를 연결한다.

**Procedure:** (1) Owned test domain만 strict allowlist에 둔 organization-owned fetcher를 배포한다. (2) Private, link-local, metadata 및 unapproved redirect address를 차단한다. (3) Method, redirect, byte 및 render time을 제한한다. (4) Credential/cookie를 제거한다. (5) Owned URL을 submit한다. (6) Requester, fetcher 및 target log를 비교한다. (7) Render instance를 제거하고 policy에 따라 central audit을 보존한다.

**Detection:** Target은 service ASN/fingerprint를 보고 provider/controller log는 requester와 URL을 연결한다. Endpoint process/API call은 submission을 보여준다. **Capture-resilient OPSEC:** Arbitrary destination authority가 없는 short-lived project token 하나를 사용한다. **Monitoring:** Allowlist denial, redirect violation, controller job ID 없는 fetch 및 provider abuse notice를 alert한다.

## Anycast rendezvous pool

**Mechanics:** 여러 organization-controlled node가 하나의 stable service address를 advertise/front하고 routing이 가까운 instance를 선택한다. Anycast는 availability를 높이고 individual back-end를 client에게 숨길 수 있지만 operator가 모든 instance를 제어하며 service address는 stable하다.<sup>[[26]](#references)</sup>

**Pros:** Resilient regional ingress, 한 instance failure 시 field reconfiguration 불필요, DDoS/load distribution 및 known node 간 session 이동을 위한 central policy를 제공한다.

**Cons:** BGP/CDN과 provider record가 organization을 식별한다. Path change는 stateful session을 중단할 수 있고 client location별 monitoring이 다르다. Stable address 하나는 쉽게 차단되거나 reputation cluster가 된다.

**Procedure:** Provider-supported organization project 또는 isolated routing lab을 사용한다. (1) 동일한 authenticated health endpoint 두 개를 배포한다. (2) 문서화된 service address 하나를 노출한다. (3) Session state를 edge가 아니라 broker에 보관한다. (4) 한 node를 withdraw하고 reconnection을 검증한다. (5) Certificate, policy 및 log consistency를 테스트한다. (6) unauthorized origin/region을 alert한다. (7) Closeout에서 advertisement와 credential을 제거한다.

**Detection:** BGP/RPKI/history, provider tenancy, certificate 및 identical service behavior가 pool을 식별한다. **Capture-resilient OPSEC:** Edge에는 regional service identity만 두고 operator 또는 fleet-enrollment key를 두지 않는다. **Monitoring:** Authorized monitor로 모든 region을 probe하고 route origin과 configuration digest를 비교하며 unexpected origin을 incident로 취급한다.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection ID는 NAT rebinding 또는 address change 중 client session을 유지할 수 있다. Multipath TCP는 여러 subflow를 통해 하나의 reliable byte stream을 전달한다. Wi-Fi/cellular 전환의 continuity를 향상하지만 common peer에는 이전/새 path가 모두 노출되어 cross-path correlation이 쉬워질 수 있다.<sup>[[27]](#references)</sup>

**Pros:** Uplink 변경 중 빠른 recovery, application session 재시작 불필요, MPTCP의 resilience/throughput 결합 및 approved field node 지원을 제공한다.

**Cons:** Anonymity가 아니다. Peer는 migration/subflow를 보며 connection identifier와 simultaneous traffic이 path를 연결한다. Middlebox/carrier 지원은 다르고 provider record가 증가한다.

**Procedure:** (1) Owned field client와 rendezvous 사이에서만 지원 transport를 활성화한다. (2) IP와 독립적으로 application을 authenticate한다. (3) Approved Wi-Fi에서 bounded transfer를 시작한다. (4) Organization cellular로 전환한다. (5) Path validation, data integrity 및 clear/direct fallback 부재를 확인한다. (6) Idle timeout과 복귀를 테스트한다. (7) 모든 path transition의 broker record를 보존한다.

**Detection:** Peer는 address migration 또는 MPTCP subflow를 직접 관찰한다. Access provider는 각자의 부분을 보고 connection ID, TLS identity 및 timing이 양쪽을 연결한다. **Capture-resilient OPSEC:** Device-scoped session material만 저장하고 resumable state를 빠르게 expire한다. **Monitoring:** Impossible path change, 동시에 사용된 unauthorized network, migration storm 및 quarantine 후 resumption을 alert한다.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** Organization-owned workflow가 hosted runner에서 bounded network check를 실행한다. Destination에는 cloud runner address가 보이고 platform에는 repository, actor, workflow, token, log 및 billing attribution이 남는다. 이는 accountable egress를 가진 remote execution이지 provider로부터의 anonymity가 아니다.<sup>[[28]](#references)</sup>

**Pros:** Disposable clean environment, reproducible job definition, inbound connection 불필요, geographic availability check 및 강한 controller audit을 제공한다.

**Cons:** Platform과 organization이 initiator를 식별한다. Broad workflow token과 untrusted pull request는 위험하며 shared IP reputation과 secret/target data를 보존하는 log/artifact가 존재한다.

**Procedure:** (1) Private organization repository와 assessment environment를 만든다. (2) Owned endpoint에 대한 manually approved fixed benign job만 허용한다. (3) Minimal read-only workflow permission을 사용하고 production secret을 두지 않는다. (4) Check를 실행한다. (5) Workflow, provider 및 target record를 비교한다. (6) Artifact에 credential이 없는지 확인한다. (7) Environment token을 삭제하고 필요한 audit을 보존한다.

**Detection:** Provider audit와 workflow log가 직접 attribution을 제공한다. Target은 runner ASN/range와 stable request grammar를 식별한다. **Capture-resilient OPSEC:** Field-device, signing, wallet 또는 cloud-administrator secret을 runner variable에 두지 않는다. **Monitoring:** Branch/environment approval을 요구하고 workflow edit, fork execution, secret read 및 unexpected destination을 alert한다.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio 또는 serial/optical link가 nearby sensor에서 owner-approved Internet gateway로 bounded message를 전달한다. Field device 자체에는 Internet route가 없고 gateway만 egress다. Radio range와 protocol limit 때문에 이는 telemetry/store-and-forward 설계이며 interactive anonymous Internet이 아니다.

**Pros:** 가장 작은 field device에서 Internet stack과 credential을 제거하고 low power를 사용한다. Gateway에 policy를 centralize하며 임시 dead zone을 연결할 수 있다.

**Cons:** RF/physical discovery, pairing 및 device identifier가 남는다. Bandwidth/range가 작고 gateway가 모든 message를 연결한다. Spectrum/encryption restriction은 다르며 capture 시 queued data가 노출될 수 있다.

**Procedure:** (1) Site와 spectrum 승인을 얻는다. (2) Unique key로 owned sensor 하나와 owned gateway 하나를 pairing한다. (3) Signed fixed-size message type, TTL 및 rate를 정의한다. (4) Sensor에 default IP route를 주지 않는다. (5) Gateway가 owned collector로만 forward하게 한다. (6) Replay, range loss 및 gateway outage를 테스트한다. (7) 두 device를 inventory하고 회수한다.

**Detection:** RF survey, pairing database, physical inspection 및 gateway process/flow log가 path를 드러낸다. **Capture-resilient OPSEC:** Sensor에는 pairwise key와 bounded encrypted queue만 두고 operator, Wi-Fi, cellular 또는 controller credential은 두지 않는다. **Monitoring:** New peer, sequence rollback, key failure, unusual RF rate 및 unregistered gateway를 통한 message를 alert한다.

## Capture/compromise exposure matrix

이 표는 위의 모든 family에 capture-resilience check를 적용한다. “Minimize”는 authorized asset에서 secret과 blast radius를 줄인다는 뜻이며 evidence를 삭제하거나 investigation을 숨긴다는 뜻이 아니다.

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known network, DHCP/portal history, MAC, tunnel peer | 별도 organization device; 지원 시 private MAC; personal account 없음; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostname, key, route, log 및 인접 hop | engagement별 identity 하나; 짧은 TTL; 좁은 route; broker-side revocation; master key 없음 |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifier 및 cached request | payload identifier 최소화; approved config pin; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state 및 peer history | standard client; 별도 service key; encrypted minimal state; compromised service identity rotation |
| Remote browser/VDI/jump host | workspace token, clipboard/file 및 remote tenant | gateway의 phishing-resistant MFA; transfer channel 비활성화; 빠른 session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider 및 대략적 location | organization contract; personal co-location 없음; 좁은 APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | consented/owned node만; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API token, deployment 및 billing reference | dedicated project; least-privilege role; short-lived deploy token; provider audit 중앙 보관 |
| Dead drop, pull mailbox, store-and-forward | object name, queue, cached job/result 및 custody data | signed bounded job; TTL; encrypted cache; 별도 producer identity; immutable server log |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifact | written placement; unique device identity; operator secret 없음; tamper/state telemetry; revoke/recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route 및 uplink profile | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed path |
| IPv6 temporary addressing | profile, prefix history 및 endpoint/application state | anti-tracking으로만 취급; network log 보존; endpoint compartmentation과 결합 |
| Pluggable transport/refraction lab | bridge/broker/decoy setting, Tor state 및 research key | standard client 또는 isolated lab; personal browser state 없음; production signaling 없음 |
| IPFS/PIR/fetcher | requested CID/query, client, cached content, gateway 또는 service token | encrypted bounded cache; public-only parameter; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service node, connection ID, resumable state 및 known path | regional identity만; 짧은 resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, log 및 artifact | least-privilege workflow; production/field/wallet secret 없음; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued message 및 gateway identity | unique pairwise key; fixed message schema; Wi-Fi/cellular/operator credential 없음 |

## Monitoring possible discovery for every access family

Client-side test만으로 investigator 또는 defender가 감시 중인지 증명할 수 없다. Engagement가 소유한 system의 변경을 monitor하고 controller/client와 corroborate하며 observer를 probe하지 말고 중지한다. 아래 row는 위의 모든 technique을 포함한다. [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise)와 결합한다.

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unauthorized network/SIM/device, 설명되지 않은 relocation 또는 provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leak, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback 또는 범위 밖 egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer 또는 provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health 및 owned canary page | personal-account crossover, unexpected non-Tor connection 또는 compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association 및 content hash | unknown peer/gateway, sequence rollback, unauthorized content 또는 missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export 및 cloud audit | unknown login/workflow edit, secret read, unexpected destination 또는 project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature 및 TTL | unknown node/origin/object writer, unsigned/replayed job, lab 밖 topology escape |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use 또는 site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation 및 broker session | impossible migration, simultaneous unauthorized path 또는 revoke 후 session resumption |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root 또는 provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. 제거할 observer와 숨길 data를 지정한다.
2. 이를 제거하는 가장 단순한 family를 선택한다.
3. Source, entry, traversal, exit, DNS, account 및 payment observer를 그린다.
4. 별도의 endpoint/application identity를 사용한다.
5. IPv4, IPv6, DNS, WebRTC/application bypass 및 destination view를 검증한다.
6. 모든 hop을 중단하고 failure가 closed인지 확인한다.
7. 통제하는 모든 component의 log를 비교한다.
8. 남은 timing, provider, endpoint 및 physical link를 기록한다.

## References

- [1] [EFF — 자신에게 적합한 VPN 선택](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — HTTP에서 UDP Proxying](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor 보호 기능](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor 차단 해제](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — VPN과 함께 Tor Browser 사용](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion service 개요](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
{{#include ../banners/hacktricks-training.md}}
