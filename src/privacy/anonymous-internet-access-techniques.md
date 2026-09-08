# Anonymous Internet Access Technique Catalog

이 문서는 표준 access-path inventory입니다. 모든 vendor 이름이 아니라 protocol 및 operational **families**를 다룹니다. 어떤 Internet 경로도 anonymity를 보장하지 않습니다. account, browser, endpoint, timing, payment, cloud-control-plane 및 물리적 증거가 완벽해 보이는 경로도 무력화할 수 있습니다.

모든 항목은 동일한 필드를 사용합니다. “Procedure”는 합법적인 deployment 또는 소유한 lab에서의 emulation을 의미합니다. 실제 technique가 router compromise, access 탈취 또는 동의하지 않은 intermediary 악용에 의존하는 경우, reproduction에서는 exercise 소유 시스템으로 대체합니다.

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | 공유 public address | subscriber 간 모호성 | high | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | 빠른 source-address 분리 | high | deployable |
| Multi-hop/split relay, MASQUE | 최종 proxy | knowledge split 또는 full-IP tunnel | high/moderate | trusted relay를 사용해 deployable |
| Tor, bridge, onion service | exit 또는 onion identity | 다자간 경로와 공통 browser | moderate | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay 또는 timing 저항 | low/variable | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request 분할 | high | 지원 application만 |
| Public Wi-Fi, travel router | venue/tunnel address | 위치/access-path 변경 | high | permission required |
| Cellular/eSIM, satellite | carrier/provider address | 독립적인 물리 uplink | high/variable | subscription/provider가 관찰 |
| Remote browser/jump host | remote workspace | endpoint 및 egress 분리 | high | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network처럼 보임 | high | consent/provenance 중요 |
| ORB/compromised relay | 다른 피해자의 address | origin 은닉 및 차용 reputation | high | owned-lab reproduction only |
| CDN/fronting/redirector | CDN/front address | back-end infrastructure 보호 | high | provider/owner 승인 필요 |
| Fast flux/DGA/dead drop | 순환 node/service | infrastructure discovery 저항 | variable | owned-lab reproduction only |
| Drop/nearest-neighbor | target 인접 local address | geographic/network boundary 통과 | high | owned-site lab only |
| Store-and-forward/offline | gateway 또는 physical receiver | interactive timing 연결 감소 | low | application-specific |
| Pluggable/refraction transport | Tor entry 또는 협력 diversion proxy | censorship-resistant reachability | variable | 지원 client 또는 research lab |
| IPFS gateway/PIR/remote fetcher | gateway 또는 application service | publisher/query/request 분할 | variable | bounded application only |
| Anycast/QUIC/MPTCP | stable broker 또는 multiple subflows | rendezvous 및 session continuity | high | availability, not anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | high | owned workflow only |
| Non-IP local first hop | organization gateway | sensor에서 Internet stack 제거 | low | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** 여러 사용자가 하나의 public address를 공유하며, access provider가 subscriber-side address와 port를 public tuple에 매핑합니다.

**Pros:** 빠르고 특별한 client가 필요하지 않습니다. destination 측 IP만으로는 household, venue 또는 carrier pool 정도만 식별할 수 있습니다.

**Cons:** provider는 subscriber/port/time 매핑을 보관할 수 있습니다. account와 fingerprint는 남으며, 다른 사용자가 address reputation을 손상시킬 수 있습니다.

**Procedure:** (1) authorized access가 NAT/CGNAT를 사용하는지 확인합니다. (2) owned endpoint에서 정확한 public IP와 source port를 기록합니다. (3) application identity를 분리합니다. (4) shared addressing를 privacy control로 간주하지 않습니다. (5) ISP가 destination을 알아서는 안 되는 경우 더 강한 경로를 사용합니다.

**Detection:** destination은 IP만이 아니라 source port와 정확한 시간을 보관해야 합니다. provider는 NAT allocation log를 상관 분석하고, investigator는 account/device/browser 증거를 결합합니다.

## Commercial VPN

**Mechanics:** 암호화된 full-tunnel connection이 VPN에서 종료되고 destination에는 VPN의 egress가 보입니다. VPN은 일반적으로 source, timing 및 destination을 연결할 수 있습니다.

**Pros:** 빠르고 단순하며 local passive observation을 방어합니다. 안정적이거나 공유된 exit를 제공하며 controlled red-team egress에 적합합니다.

**Cons:** trust가 집중됩니다. billing/login telemetry, kill-switch/DNS/IPv6 failure가 존재하며 shared exit는 reputation 차단을 자주 받습니다.

**Procedure:** (1) provider, owner, jurisdiction, retention 및 assessment policy를 확인합니다. (2) 서명된 공식 client를 설치합니다. (3) full tunnel, always-on 및 fail-closed 동작을 활성화합니다. (4) DNS와 IPv6를 의도적으로 route합니다. (5) owned endpoint에서 관찰되는 IPv4/IPv6/DNS를 확인합니다. (6) tunnel을 중지하고 재연결하여 clear fallback이 없는지 확인합니다.<sup>[[1]](#references)</sup>

**Detection:** local network는 VPN infrastructure로 향하는 긴 암호화 flow를 확인할 수 있습니다. provider는 authentication/connection record를 보유하며, destination은 ASN/reputation과 account, TLS/browser 및 behavior correlation을 사용합니다.

## Self-hosted VPN or rented VPS egress

**Mechanics:** operator가 WireGuard/OpenVPN gateway를 관리하거나 rented server를 통해 traffic을 forward합니다.

**Pros:** 예측 가능한 높은 속도, allowlist 가능한 고정 address, custom logging/firewall 및 우수한 incident control을 제공합니다.

**Cons:** anonymity set이 작습니다. cloud tenant, payment, source login, API 및 image history가 operator와 연결됩니다. 새롭고 특징적인 server는 쉽게 cluster화됩니다.

**Procedure:** (1) engagement 전용 organization project를 생성합니다. (2) 지원되는 image와 fixed address를 provision합니다. (3) management를 MFA/key-based administration으로 제한합니다. (4) full-tunnel egress와 DNS를 설정합니다. (5) 가능한 경우 scoped destination만 허용합니다. (6) leak/failure 동작을 테스트합니다. (7) controller audit record를 보관합니다. (8) teardown 시 credential과 resource를 폐기합니다.

**Detection:** hosting ASN, first-seen address, certificate/service fingerprint 및 scanning behavior를 상관 분석합니다. cloud owner는 control-plane, console, billing 및 flow log를 사용합니다.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** application이 proxy에 TCP stream을 열도록 요청합니다. SOCKS는 version에 따라 name resolution과 UDP도 전달할 수 있으며, SSH는 하나의 암호화 session 내부에서 stream을 forward합니다.

**Pros:** 가볍고 application별로 적용할 수 있으며 빠릅니다. chaining과 segmented network 접근에 유용합니다.

**Cons:** application이 이를 우회할 수 있습니다. DNS가 leak될 수 있고 proxy는 인접 endpoint를 확인합니다. browser state는 남으며 open proxy는 trap 또는 compromised system일 수 있습니다.

**Procedure:** (1) owned host에 proxy를 deploy합니다. (2) authentication을 요구하고 source/destination을 제한합니다. (3) 하나의 disposable application profile을 설정합니다. (4) 필요한 경우 remote DNS resolution을 보장합니다. (5) owned DNS/HTTP endpoint로 확인합니다. (6) workload의 direct egress를 차단합니다. (7) proxy credential을 검사하고 rotate합니다.

**Detection:** tunnel-capable process, CONNECT/SOCKS negotiation, 긴 SSH session 및 application과 맞지 않는 destination을 식별합니다. proxy log로 stream을 재구성할 수 있습니다.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** website이 destination을 fetch하고 link/form을 자신의 origin을 통해 rewrite하거나, extension이 browser request를 proxy로 보냅니다. destination에는 service가 보이지만 service는 TLS termination 후 plaintext를 읽고 content를 주입하거나 보관할 수 있습니다.

**Pros:** system-wide client가 필요하지 않습니다. 단순 browsing에 빠르고 VPN 설치가 불가능한 환경에서도 작동합니다.

**Cons:** proxy가 credential/content를 읽고 download를 rewrite하며 user를 fingerprint할 수 있습니다. script/WebSocket/download가 우회할 수 있고 browser extension은 광범위한 권한을 가집니다. anonymity set이 작고 자주 차단됩니다.

**Procedure:** (1) authorized testing에는 organization-operated proxy만 사용합니다. (2) personal account가 없는 disposable browser에 격리합니다. (3) password 입력과 민감한 download를 금지합니다. (4) owned page의 모든 subresource가 proxy를 통해 resolve되는지 확인합니다. (5) WebSocket, download 및 form 동작을 테스트합니다. (6) 사용 후 extension/profile을 제거합니다.

**Detection:** destination은 proxy를 log합니다. enterprise proxy/DNS와 extension inventory가 service를 식별합니다. content-security/reporting 또는 owned canary subresource가 direct bypass를 드러낼 수 있으며, proxy log가 user session과 target을 연결합니다.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** entry는 source를 보고 하나 이상의 traversal relay가 이를 exit에서 분리합니다. exit는 destination을 봅니다.

**Pros:** 일반적인 relay 하나가 양쪽을 모두 알 필요가 없습니다. 한 node의 failure/seizure가 드러내는 정보가 줄고 geography를 유연하게 선택할 수 있습니다.

**Cons:** 동일한 administration/log가 분리를 무력화할 수 있습니다. latency, timing correlation, 추가 failure 및 DNS route가 발생하며 동일한 account/payment가 모든 hop을 연결할 수 있습니다.

**Procedure:** (1) 각 hop이 제거할 observer를 정의합니다. (2) 분리가 중요할 때 독립적으로 관리되는 owned/approved relay를 사용합니다. (3) workload에서 entry-only access를 강제합니다. (4) 각 relay가 다음 hop에만 접근할 수 있도록 합니다. (5) 모든 layer의 log를 확인합니다. (6) 각 hop을 중지하고 fail-closed 동작을 확인합니다. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)로 재현합니다.

**Detection:** 인접 NetFlow의 timing/volume, 반복되는 proxy handshake 및 공통 controller infrastructure를 상관 분석합니다. exit로 operator geography를 추론하지 않습니다.

## Split-knowledge application relay and OHTTP

**Mechanics:** client가 stateless HTTP message를 gateway에 암호화하고 relay를 통해 전송합니다. relay는 client IP를 보지만 request는 보지 못합니다. gateway는 request를 보지만 일반적으로 relay IP만 확인합니다.

**Pros:** 지원되는 request에 대해 강력하고 감사 가능한 privacy partition을 제공합니다. general anonymity network보다 overhead가 낮습니다.

**Cons:** 임의 browsing에는 사용할 수 없습니다. cookie/authentication이 다시 연결할 수 있으며 relay/gateway collusion과 traffic analysis가 남습니다. application이 이를 구현해야 합니다.

**Procedure:** (1) RFC 9458을 명시적으로 지원하는 application을 선택합니다. (2) 공식 configuration path로 gateway key를 확인합니다. (3) stable per-user field를 피합니다. (4) 지원되는 stateless request만 전송합니다. (5) relay, gateway 및 target log를 비교합니다. (6) direct fallback 없이 key rotation/failure를 테스트합니다.<sup>[[2]](#references)</sup>

**Detection:** enterprise endpoint는 initiating process와 OHTTP relay를 노출합니다. gateway는 malformed/replayed traffic을 감지할 수 있으며 timing과 stable payload/account field가 request를 연결할 수 있습니다.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUIC가 UDP 또는 IP packet을 proxy를 통해 전달합니다. modern VPN과 유사한 tunnel을 구현하고 transport를 HTTP/3와 섞을 수 있지만 proxy는 여전히 observer입니다.<sup>[[3]](#references)</sup>

**Pros:** 효율적인 multiplexing/roaming, UDP 또는 full IP 지원 및 modern HTTP infrastructure를 통한 deployment를 제공합니다.

**Cons:** anonymity network가 아닙니다. proxy/account는 source와 destination을 확인합니다. QUIC/HTTP fingerprint와 well-known path가 endpoint/provider에 보입니다.

**Procedure:** (1) RFC 9298/9484 지원을 문서화한 client/service를 사용합니다. (2) proxy certificate/configuration을 인증합니다. (3) 허용할 target route를 정의합니다. (4) path 내부에서 encrypted DNS를 활성화합니다. (5) owned endpoint로 UDP, TCP, IPv6 및 failover를 확인합니다. (6) proxy request와 flow log를 검사합니다.

**Detection:** endpoint는 client process와 virtual interface를 확인합니다. network는 proxy로 향하는 지속적인 QUIC/TLS를 분류할 수 있고, proxy log에는 CONNECT target/path와 assigned route가 남습니다.

## Tor Browser

**Mechanics:** Tor는 guard, middle 및 exit relay를 선택하며 layered encryption으로 각 relay가 보는 범위를 제한합니다. Tor Browser는 fingerprinting 저항을 목표로 표준화된 browser를 추가합니다.

**Pros:** 큰 public anonymity set, 양쪽을 모두 아는 일반 relay의 부재 및 server를 운영하지 않아도 되는 destination unlinkability를 제공합니다.

**Cons:** 느리고 TCP 중심입니다. exit reputation/block이 있으며 login과 disclosure가 user를 식별합니다. low-latency timing correlation은 여전히 가능합니다.

**Procedure:** (1) project에서 Tor Browser를 download하고 verify합니다. (2) default를 유지하고 extension을 피합니다. (3) 적절한 security level을 선택합니다. (4) 별도 identity/session을 생성합니다. (5) 식별 가능한 account와 외부 active document를 피합니다. (6) HTTPS 또는 authenticated onion service를 사용합니다. (7) owned endpoint로만 exit를 확인합니다.<sup>[[4]](#references)</sup>

**Detection:** bridge/transport를 사용하지 않으면 local network가 알려진 guard traffic을 식별할 수 있습니다. destination에는 exit와 Tor Browser behavior가 보이며, end-to-end observer는 timing/volume을 상관 분석합니다.

## Tor bridges and pluggable transports

**Mechanics:** non-public bridge가 public guard를 대체합니다. obfs4, Snowflake 또는 WebTunnel은 첫 hop transport를 변경하여 단순 blocking/probing을 어렵게 합니다.

**Pros:** censorship를 우회하고 명백한 public-relay destination을 숨기며, entry 이후에는 Tor circuit을 유지합니다.

**Cons:** transport pattern과 bridge discovery가 가능할 수 있습니다. 성능이 변동하며 account나 global timing에 대한 보호는 추가하지 않습니다.

**Procedure:** (1) 먼저 direct Tor를 시도합니다. (2) Tor Browser Connection 설정에서 built-in supported transport를 선택하거나 공식 bridge를 요청합니다. (3) 무작위 binary/list를 사용하지 않습니다. (4) 연결 후 무해한 test를 실행합니다. (5) reconnect와 clock을 테스트합니다. (6) 다른 browser 설정은 standard로 유지합니다.<sup>[[5]](#references)</sup>

**Detection:** censor는 destination discovery, protocol/flow classification 및 active probing을 사용합니다. defender는 circumvention 사용과 compromise를 구분하고 endpoint process/context에 의존해야 합니다.

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor는 access ISP로부터 direct Tor 사용을 숨기지만 VPN에는 source가 노출됩니다. Tor-before-VPN은 VPN에 post-Tor traffic을 제공하며 안정적인 customer/tunnel identity를 갖는 경우가 많습니다.

**Pros:** 올바르게 설계하면 특정 observer를 제거하며 한 layer를 차단하는 network에 접근할 수 있습니다.

**Cons:** 복잡성, 특이한 fingerprint, leak, 축소된 anonymity set 및 false confidence가 발생합니다. Tor Project는 조합을 advanced technique로 취급합니다.<sup>[[6]](#references)</sup>

**Procedure:** (1) 제거할 observer와 새로 도입되는 observer를 작성합니다. (2) disposable environment를 사용합니다. (3) 의도한 outer path만 설정합니다. (4) firewall route를 강제합니다. (5) DNS/IPv4/IPv6와 각 failure order를 확인합니다. (6) 두 provider의 visibility를 비교합니다. (7) 측정 가능한 이점이 없으면 stack을 폐기합니다.

**Detection:** local/VPN/Tor observer는 서로 다른 인접 layer를 봅니다. timing은 end-to-end로 남고, 비정상적인 nested tunnel fingerprint와 provider account가 session을 연결할 수 있습니다.

## Onion service

**Mechanics:** client와 service가 모두 rendezvous로 향하는 Tor circuit을 구성하여 service IP를 숨기고 exit를 피합니다.

**Pros:** source와 service location 보호, end-to-end onion authentication, public inbound port 불필요 및 선택적 client authorization을 제공합니다.

**Cons:** update/analytics/error를 통해 origin이 leak될 수 있습니다. onion key가 중요하며 application identity/timing과 host compromise는 남습니다.

**Procedure:** (1) application을 격리하고 loopback/socket에만 bind합니다. (2) 지원되는 Tor를 설치합니다. (3) 공식 지침으로 v3 onion service를 설정합니다. (4) stable identity가 필요한 경우에만 key를 보호하고 backup합니다. (5) 폐쇄형 사용에는 client authorization을 추가합니다. (6) third-party fetch를 제거합니다. (7) 외부에서 origin에 접근할 수 없는지 확인합니다.<sup>[[7]](#references)</sup>

**Detection:** host/network defender는 Tor process/configuration과 outbound circuit을 찾을 수 있습니다. application error, DNS, certificate 또는 third-party resource가 origin을 드러낼 수 있습니다.

## I2P internal services

**Mechanics:** I2P는 overlay 내부 destination에 대해 별도의 unidirectional inbound/outbound tunnel을 사용합니다. public-Internet outproxy는 trust point를 추가합니다.

**Pros:** decentralized internal publishing, 공식 exit 의존성 부재 및 분리된 inbound/outbound path를 제공합니다.

**Cons:** general web replacement가 아니며 ecosystem이 작습니다. 장기간 실행되는 peer behavior가 있고 outproxy는 public browsing을 관찰할 수 있습니다.

**Procedure:** (1) 공식 source에서 설치합니다. (2) 전용 context를 사용합니다. (3) integration/bandwidth stabilization을 허용합니다. (4) owned I2P-native service에 접근합니다. (5) 명시적으로 필요하지 않으면 outproxy를 피합니다. (6) shutdown 시 direct fallback이 없는지 확인합니다. (7) local peer와 service log를 검사합니다.<sup>[[8]](#references)</sup>

**Detection:** local network는 long-lived peer traffic과 bootstrap behavior를 봅니다. endpoint는 router/application process를 노출하며, outproxy는 exit를 log합니다.

## Mixnets

**Mechanics:** fixed-size packet, batching, delay, reordering 및 cover traffic으로 timing correlation을 줄이며 gateway가 application을 연결합니다.

**Pros:** low-latency proxy보다 timing analysis에 강하고 asynchronous message/transaction에 유용합니다.

**Cons:** latency와 bandwidth overhead가 크고 deployment와 application 범위가 작습니다. gateway/account metadata가 남을 수 있습니다.

**Procedure:** (1) 유지 관리되는 client와 지원 application을 선택합니다. (2) 실제 threat model을 읽습니다. (3) 별도 compartment에 설치합니다. (4) owned endpoint로 무해한 data를 전송합니다. (5) latency/reliability와 reply path를 측정합니다. (6) gateway failure를 테스트합니다. (7) 속도만을 위해 delay/cover traffic을 비활성화하지 않습니다.<sup>[[9]](#references)</sup>

**Detection:** endpoint는 client를 식별합니다. access network는 gateway/packet cadence를 분류할 수 있고, gateway와 exit는 인접 role을 관찰합니다. 넓은 correlation에는 더 긴 통계 window가 필요합니다.

## GNUnet anonymous file sharing

**Mechanics:** GNUnet은 peer를 통해 publish/search/download request를 route하고 anonymity level에 따라 cover traffic을 추가할 수 있습니다. 자체 documentation은 default level 1에서 cover traffic을 요구하지 않으며 강력한 traffic analysis가 origin을 식별할 수 있다고 경고합니다.<sup>[[10]](#references)</sup>

**Pros:** decentralized하고 application-native인 anonymous sharing 및 조정 가능한 cover-traffic 요구를 제공합니다.

**Cons:** 일반적인 anonymous web access가 아닙니다. 성능/storage 비용, peer 및 traffic-analysis 제한이 있으며 GNUnet VPN documentation은 IP overlay가 좋은 anonymity를 제공하지 않는다고 설명합니다.

**Procedure:** (1) 유지 관리되는 공식 build를 설치합니다. (2) test peer를 격리합니다. (3) bandwidth/storage를 제한합니다. (4) 선택한 anonymity level로 무해하고 고유한 test file을 publish합니다. (5) 다른 owned peer에서 retrieve합니다. (6) cover-traffic과 latency를 기록합니다. (7) IP VPN component가 동등한 anonymity를 제공한다고 주장하지 않습니다.

**Detection:** peer bootstrap, overlay traffic, local datastore/process 및 file identifier가 드러납니다. 광범위한 observer는 cover traffic과 비교하여 traffic volume을 분석할 수 있습니다.

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ는 resolver까지 암호화합니다. ODoH는 proxy와 resolver 사이에서 client address와 query를 분리하며, ECH는 inner TLS ClientHello/server name을 암호화합니다.

**Pros:** 일부 local observer에서 plaintext DNS/SNI를 제거하며 ODoH는 source/query knowledge를 분할합니다.

**Cons:** IP-anonymity path가 아닙니다. resolver/proxy/server는 각각 role을 유지하고 destination IP/timing/volume과 endpoint가 남습니다. fallback은 leak될 수 있습니다.

**Procedure:** (1) OS, application 또는 tunnel 중 누가 DNS를 관리할지 선택합니다. (2) strict encrypted mode 또는 지원되는 ODoH를 활성화합니다. (3) 고유한 owned domain으로 테스트합니다. (4) local capture로 clear query가 없는지 확인합니다. (5) resolver failure 시 의도한 동작을 확인합니다. (6) ECH의 경우 server diagnostic에서 inner ClientHello acceptance를 확인합니다.<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver log에 query가 노출됩니다. network는 encrypted-resolver endpoint와 destination flow를 식별하며, ECH state는 path에서 숨겨져도 endpoint/CDN에 보입니다.

## Split-provider privacy relay

**Mechanics:** iCloud Private Relay와 같은 product는 client를 아는 ingress와 destination을 아는 독립 운영 egress를 사용하며 coarse region을 처리합니다.

**Pros:** 낮은 마찰의 split knowledge, 빠른 속도 및 지원 traffic에 대한 integrated DNS/web protection을 제공합니다.

**Cons:** product/application 범위가 제한됩니다. account/platform provider는 customer를 식별하며 arbitrary system anonymity가 아닙니다. collusion/legal 및 timing risk가 있습니다.

**Procedure:** (1) 지원되는 정확한 application과 traffic type을 확인합니다. (2) 적절한 경우 전용 platform context에서 feature를 활성화합니다. (3) region 동작을 선택합니다. (4) Safari/DNS와 unsupported application을 별도로 테스트합니다. (5) destination address를 검사합니다. (6) network switching/failure를 테스트합니다.<sup>[[12]](#references)</sup>

**Detection:** access에는 ingress가 보이고 destination에는 egress가 보입니다. platform/relay log와 account record는 각 layer를 연결하며 unsupported application은 일반 경로를 노출합니다.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** browsing/tool execution이 remote system에서 수행됩니다. destination에는 remote egress가 보이고 workspace provider에는 operator connection과 control plane이 보입니다.

**Pros:** 빠르고 위험한 content를 격리하며 stable controlled egress, disposable state 및 강력한 organization audit을 제공합니다.

**Cons:** provider/admin이 session/account를 관찰할 수 있습니다. screen/clipboard/file channel이 leak되고 remote browser fingerprint가 고유할 수 있습니다. workspace owner에 대해서는 anonymous가 아닙니다.

**Procedure:** (1) engagement마다 organization-owned workspace 하나를 생성합니다. (2) MFA를 요구하고 administration을 제한합니다. (3) clipboard/upload/download를 비활성화하거나 제한합니다. (4) approved fixed egress를 사용합니다. (5) personal IdP/sync를 사용하지 않습니다. (6) 검토된 evidence만 export합니다. (7) 일정에 따라 workspace와 credential을 폐기합니다.

**Detection:** provider와 IdP log가 user를 session에 연결합니다. destination은 workspace egress/browser를 cluster화하고 enterprise defender는 remote-control protocol과 비정상 cloud session을 식별합니다.

## Public or guest Wi-Fi

**Mechanics:** traffic이 venue NAT 또는 그곳에서 시작된 tunnel을 통해 나갑니다.

**Pros:** 빠르고 shared non-home address를 제공하며 전용 infrastructure가 필요하지 않습니다.

**Cons:** venue association/DHCP/portal, camera, purchase 및 location evidence가 남습니다. hostile peer/AP, terms 및 physical risk도 있습니다.

**Procedure:** (1) guest에게 제공된 access를 얻고 staff와 SSID를 확인합니다. (2) patch된 low-trust device를 사용합니다. (3) sharing/auto-join을 끄고 private MAC을 활성화합니다. (4) reused identity 없이 portal을 완료합니다. (5) fail-closed VPN/Tor path를 시작합니다. (6) tethered traffic을 확인합니다. (7) network를 forget합니다.

**Detection:** venue는 AP, MAC, DHCP, portal 및 time을 상관 분석합니다. destination에는 venue/tunnel이 보이며 investigator는 physical과 device evidence를 결합합니다. access control을 우회하지 않습니다.

## Travel router

**Mechanics:** operator-owned router가 venue Wi-Fi/Ethernet에 연결되고 enforced tunnel policy를 적용한 isolated internal network를 제공합니다.

**Pros:** workstation을 격리하고 central kill switch/DNS, 일관된 client network를 제공하며 privileged endpoint를 local broadcast에서 보호합니다.

**Cons:** router가 stable radio/DHCP fingerprint가 됩니다. attack surface가 증가하고 captive portal과 tethering이 tunnel을 우회할 수 있습니다.

**Procedure:** (1) 지원 firmware를 update합니다. (2) 고유 management credential을 설정하고 WAN admin/WPS/UPnP를 끕니다. (3) 허용되는 경우 private upstream MAC을 설정합니다. (4) 별도 internal SSID를 만듭니다. (5) full-tunnel DNS/IPv6 firewall policy를 강제합니다. (6) portal, reconnect 및 tunnel failure를 테스트합니다.

**Detection:** venue는 router association과 traffic shape를 확인합니다. local RF/DHCP fingerprinting이 식별할 수 있으며 VPN provider에는 venue source가 보입니다.

## Cellular, prepaid SIM and eSIM

**Mechanics:** modem이 carrier radio access와 일반적으로 carrier NAT를 사용합니다. VPN/Tor layer는 destination에 보이는 exit를 변경할 수 있습니다.

**Pros:** local wired/Wi-Fi network와 독립적이고 mobile이며 빠릅니다. authorized drop의 backhaul에 유용합니다.

**Cons:** carrier는 subscriber/eSIM, IMSI, IMEI, cell, time 및 assigned port를 압니다. registration law는 지역마다 다르며 personal phone과의 co-location이 device를 연결합니다.

**Procedure:** (1) 필요한 정확한 정보로 합법적으로 service를 얻습니다. (2) organization-owned 별도 modem/device를 사용합니다. (3) exercise controller에 기록합니다. (4) 관련 없는 radio/account를 끕니다. (5) approved tunnel을 설정합니다. (6) tethered client가 실제로 tunnel을 따르는지 테스트합니다. (7) travel 전에 provider와 retention 가정을 확인합니다.<sup>[[13]](#references)</sup>

**Detection:** carrier record와 RF location, enterprise USB/PCI/MDM inventory 및 rogue-hotspot survey, destination/tunnel timing을 사용합니다.

## Satellite Internet and satellite downlink abuse

**Mechanics:** 일반 service는 registered terminal/provider를 사용합니다. 과거 one-way DVB-S abuse에서는 beam 내부 receiver가 legitimate subscriber에게 향한 unencrypted downlink traffic을 관찰하고, outbound request에는 다른 path를 사용했습니다.

**Pros:** 넓은 coverage, 독립적인 last mile 및 historical one-way abuse를 통한 subscriber geography 오인 가능성이 있었습니다.

**Cons:** equipment/RF/provider record, latency와 coverage 문제가 있습니다. modern bidirectional system은 다르며 outbound path와 asymmetric routing이 여전히 증거로 남습니다.

**Procedure:** 합법적인 access에는 owned terminal을 등록하고 필요에 따라 traffic을 tunnel합니다. historical Turla behavior를 emulation하려면 RF-free lab에서 synthetic one-way packet capture를 replay하고 request를 만들지 않은 host에 대한 reply를 analyst가 탐지하는지 테스트합니다. live satellite traffic은 intercept하지 않습니다.<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency 및 malware configuration을 사용합니다.

## Residential/mobile proxy or consented proxyware

**Mechanics:** backconnect gateway가 consumer broadband/mobile exit를 sticky 또는 rotating 방식으로 할당합니다. supply는 consensual, deceptively bundled 또는 malicious할 수 있습니다.

**Pros:** 빠르고 geographic choice가 가능하며 consumer ASN이 일부 hosting block을 피하고 큰 pool을 제공합니다.

**Cons:** provenance/consent 및 legal risk, broker 관찰, infected exit 피해, rotation anomaly 및 비용/불안정성이 있습니다.

**Procedure:** emulation에는 documented informed-consent organization-owned agent만 사용합니다. (1) test endpoint를 enroll합니다. (2) owner/IP를 inventory합니다. (3) gateway를 설정합니다. (4) sticky/per-request mode를 rotate합니다. (5) owned target에만 전송합니다. (6) gateway/exit/target log를 비교합니다. (7) 모든 agent를 제거합니다.

**Detection:** impossible travel, rapid IP/ASN change에도 유지되는 browser/account, backconnect protocol, proxyware process/network artifact 및 broker/controller relation을 탐지합니다.

## ORB, botnet and compromised edge-device relays

**Mechanics:** leased 또는 compromised router/IoT/server가 fleet으로 access, traversal 및 exit role을 수행합니다. 여러 APT customer가 이를 공유할 수 있습니다.

**Pros:** 차용한 reputation/geography, 단기 exit, resilient multi-hop mesh 및 actor-to-IP 직접 연결 약화를 제공합니다.

**Cons:** criminal victimization, implant/controller와 fleet pattern, intermediary seizure, 불안정한 성능 및 operator/customer record가 남습니다.

**Procedure:** 실제 device를 compromise하지 않습니다. [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)을 사용합니다. (1) isolated entry/transit/target network를 만듭니다. (2) owned dual-homed relay container를 연결합니다. (3) 하나의 test port만 forward합니다. (4) benign request를 보냅니다. (5) target에 exit만 보이는지 확인합니다. (6) exit를 rotate합니다. (7) 이름이 지정된 모든 asset을 teardown합니다.<sup>[[15]](#references)</sup>

**Detection:** topology, port/service, controller relation, implant fingerprint 및 node lifecycle을 추적합니다. edge configuration/flow/integrity telemetry를 centralize하며 exit IP를 actor와 동일시하지 않습니다.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** public edge가 특정 grammar와 일치하는 traffic만 forward합니다. fronting은 intermediary가 허용할 때 benign outer SNI와 다른 inner HTTP authority 또는 blank SNI를 사용합니다.

**Pros:** back-end를 숨기고 보호하며 빠른 global edge, shared service와의 혼합 및 신속한 cutover를 제공합니다.

**Cons:** CDN은 모든 routing과 tenant를 봅니다. 많은 provider가 cross-tenant fronting을 금지합니다. SNI/Host/process/flow와 account artifact가 남고 configuration reuse가 campaign을 연결합니다.

**Procedure:** owned reverse proxy에서만 [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging)로 재현합니다. local certificate/edge를 만들고 mismatched Host 하나를 owned target으로 route하며 SNI와 Host를 log합니다. normal/mismatched request를 전송한 후 container를 제거합니다.<sup>[[16]](#references)</sup>

**Detection:** endpoint 또는 terminating edge에서 SNI/ECH/Host/`:authority`를 비교하고 initiating process, tenant/origin, request grammar 및 flow cadence를 결합합니다.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS는 stable name을 update하고, DGA는 변화하는 candidate name을 생성하며, fast flux는 낮은 TTL로 service address를 rotate합니다. double flux는 name server도 rotate합니다.

**Pros:** resilient discovery, 빠른 infrastructure replacement 및 다수의 node 뒤 controller 은닉을 제공합니다.

**Cons:** DNS가 centralized telemetry를 만들고 entropy/NXDOMAIN/churn이 발생합니다. low TTL, broad ASN pattern, registration 및 authoritative infrastructure가 남습니다.

**Procedure:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry)를 사용합니다. owned zone이 RFC 5737 address를 5초 TTL로 반환하게 하고 반복 query합니다. synthetic epoch를 변경하고 analytics를 검증합니다. test record를 third party로 향하게 하지 않습니다.<sup>[[17]](#references)</sup>

**Detection:** sliding-window unique answer/ASN, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal cluster 및 process follow-on을 사용합니다. context를 통해 legitimate CDN을 제외합니다.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** public post, repository, document, object 또는 feed에 encoded current endpoint나 task가 포함됩니다. client는 다른 channel로 result를 반환할 수 있습니다.

**Pros:** 높은 reputation의 허용 service, TLS 및 binary를 바꾸지 않는 endpoint rotation을 제공합니다. asymmetric tasking은 단순 flow correlation을 방해합니다.

**Cons:** stable object/account/API identifier, provider record, endpoint decode/follow-on sequence가 남습니다. content는 압수되거나 변경될 수 있습니다.

**Procedure:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence)를 사용합니다. owned container 하나에 encoded pointer를 hosting하고 short-lived client에서 fetch/decode합니다. 두 번째 owned service에 접속하고 두 log를 보존한 뒤 teardown합니다.

**Detection:** unusual process → stable object read → decode → new destination sequence를 상관 분석합니다. content를 hash/preserve하고 domain뿐 아니라 full object path를 보관합니다.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** function/short-lived job이 provider NAT 또는 front 뒤에서 실행됩니다. logical service는 stable하지만 instance와 address는 rotate됩니다.

**Pros:** 빠른 deployment/destruction, provider-scale shared egress, 적은 local disk 및 elastic regional routing을 제공합니다.

**Cons:** tenant, role, API, image, secret, invocation, billing 및 front-to-origin log가 durable합니다. cold-start와 platform fingerprint, provider policy도 남습니다.

**Procedure:** (1) organization-owned exercise tenant를 사용합니다. (2) owned endpoint만 요청하는 benign function을 deploy합니다. (3) project/role/image/config를 기록합니다. (4) 여러 instance에서 invoke합니다. (5) target IP와 audit/request ID를 비교합니다. (6) log retention을 테스트합니다. (7) function, role 및 secret을 제거합니다.

**Detection:** cloud audit/invocation log, 비정상 role creation, stable request grammar를 가진 shared egress, image/layer 및 secret reuse, front-origin correlation을 사용합니다.

## Authorized on-site drop

**Mechanics:** inventoried small computer가 local wired/Wi-Fi와 outbound VPN/cellular rendezvous를 사용하여 local source처럼 보입니다.

**Pros:** realistic internal-origin testing, 높은 속도 및 NAC, physical inventory와 egress control testing을 제공합니다.

**Cons:** physical discovery/theft, serial/MAC/USB/DHCP/PoE/RF와 camera evidence가 남습니다. 분실 시 credential이 노출될 수 있습니다.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)를 따릅니다. (1) 정확한 서면 placement authority를 얻습니다. (2) serial, MAC, photo, location 및 retrieval time을 기록합니다. (3) signed minimal image와 short-lived mutual credential을 사용합니다. (4) outbound-only destination/capability를 제한합니다. (5) server-side quarantine와 bandwidth limit을 추가합니다. (6) SOC visibility와 loss response를 테스트합니다. (7) 회수하고 필요한 evidence를 보존한 뒤 합의된 lifecycle policy에 따라 sanitize합니다. 동의하지 않은 venue에 숨기지 않습니다.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera 및 physical inspection을 사용합니다.

## Nearest-neighbor wireless pivot

**Mechanics:** actor가 target radio range 내의 host를 control한 뒤 target Wi-Fi credential을 사용해 원격으로 boundary를 넘습니다. APT28이 인접 compromised organization을 이런 방식으로 사용했습니다.<sup>[[18]](#references)</sup>

**Pros:** operator travel이 필요 없고 target에는 local radio source가 보이며 Internet entry에만 적용된 control을 우회합니다.

**Cons:** nearby compromised/owned dual-radio host와 유효한 access가 필요합니다. RADIUS/NAC/AP 및 neighbor endpoint evidence, signal/device anomaly가 남습니다.

**Procedure:** [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot)에서만 재현합니다. owned pivot을 neighbor 및 target lab SSID에 연결하고 하나의 service만 forward합니다. 두 AP/pivot log를 수집한 뒤 EAP-TLS/device posture를 활성화하고 두 번째 시도가 실패하는지 확인합니다.

**Detection:** RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login 및 physical presence를 상관 분석합니다. nearby endpoint에서 simultaneous radio, forwarding 및 tunnel을 탐색합니다.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** traffic이 하나의 interactive Internet session이 아니라 local peer, asynchronous gateway, removable media 또는 scheduled queue를 통과합니다.

**Pros:** disruption/censorship 상황에서 작동하며 delayed/batched delivery가 단순 timing을 약화시킵니다. local communication에는 central last mile이 필요하지 않습니다.

**Cons:** 높은 latency, 작은 anonymity set, custody/physical metadata, malicious peer가 존재하며 결국 data를 관찰하는 gateway에 도달합니다.

**Procedure:** (1) isolated owned three-node mesh 또는 file queue를 구축합니다. (2) content를 end to end로 encrypt/authenticate합니다. (3) origin에서 direct Internet route를 제거합니다. (4) controlled delay 후 benign file을 relay합니다. (5) gateway만 owned destination에 접속하는지 확인합니다. (6) custody/timestamp를 비교합니다. (7) 필요한 evidence를 보존하고 승인된 closeout에서 temporary media/queue를 sanitize합니다.

**Detection:** endpoint file/process activity, peer-radio link, removable-media audit, queue/gateway periodicity 및 content identifier를 사용합니다. interactive-flow analysis 대신 긴 correlation window를 사용합니다.

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN)는 public relay address를 할당하고 client와 peer 사이에서 UDP, TCP 또는 TLS traffic을 전달합니다. ICE policy는 direct candidate 노출 대신 relay 사용을 강제할 수 있습니다. TURN은 reachability를 해결할 뿐 general anonymity를 제공하지 않습니다. server는 client를 authenticate하고 allocation, peer, time 및 volume을 관찰합니다.<sup>[[19]](#references)</sup>

**Pros:** 널리 구현되고 restrictive NAT를 처리하며 mobile WebRTC를 지원합니다. relay-only policy가 올바르면 peer가 client의 direct transport address를 받지 않습니다.

**Cons:** TURN operator가 양쪽 인접 영역을 모두 봅니다. application identity, media fingerprint 및 signaling이 남습니다. relay-only는 bandwidth와 latency 비용이 있고 잘못된 설정은 host 또는 server-reflexive candidate를 수집할 수 있습니다.

**Procedure:** (1) TLS와 short-lived credential을 사용하는 organization-owned TURN service를 deploy합니다. (2) realm, peer, port, quota 및 expiration을 제한합니다. (3) test application을 relay-only ICE로 설정합니다. (4) owned peer를 호출합니다. (5) `getStats()`와 packet capture로 media가 relay candidate만 사용하는지 확인합니다. (6) relay를 중지하고 direct fallback이 없는지 확인합니다. (7) engagement용 allocation log를 보존합니다.

**Detection:** signaling, browser process 및 TURN allocation이 session을 relay에 연결합니다. network는 TURN port 또는 TLS endpoint로 향하는 지속적인 flow를 관찰하고 peer에는 allocated relay가 보입니다. **Captured node:** application state와 ephemeral TURN credential이 realm 및 rendezvous service를 드러낼 수 있습니다. per-device short-lived credential을 사용하고 operator authentication은 controller에만 유지하여 노출을 줄입니다.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** NAT 뒤 node가 organization-controlled broker에 authenticated connection을 시작합니다. operator는 broker에 별도로 authenticate하며 broker가 좁은 management channel을 authorize합니다. inbound port forwarding이나 direct operator-to-node route가 필요하지 않습니다.

**Pros:** NAT와 captive last mile 뒤에서 안정적이며 central revocation/audit을 제공합니다. field-node address 변경 시 operator discovery가 필요 없고 operator identity와 node credential을 분리합니다.

**Cons:** broker가 중요한 correlation point가 됩니다. periodic keepalive는 식별 가능하고 broad tunnel은 unsafe pivot이 될 수 있습니다. broker가 loss되면 management가 중단됩니다.

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous)를 따릅니다. scoped device identity 하나를 발급하고 owned broker 및 approved management service만 허용합니다. authenticated keepalive, fail-closed routing, address change와 reboot recovery를 테스트하고 loss drill에서 identity를 revoke합니다. WireGuard는 실제로 필요할 때 broadly useful NAT interval로 25초 persistent keepalive를 문서화합니다.<sup>[[20]](#references)</sup>

**Detection:** broker와 identity-provider log가 양쪽을 연결합니다. access network에는 반복되는 encrypted destination/cadence가 보이고 endpoint inventory에는 overlay agent가 나타납니다. **Captured node:** device key, broker name, tunnel address 및 cached task data가 노출된다고 가정합니다. operator private key, personal account 또는 reusable controller token을 포함해서는 안 됩니다.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** field workload가 authenticated mailbox를 polling하여 signed, pre-approved job을 받고 제한된 result를 게시합니다. operator는 별도 control plane을 통해 queue에 기록하며 둘 사이에 interactive socket이 없습니다.

**Pros:** intermittent link를 견디고 timing과 addressing을 분리합니다. quota와 schema로 capability를 제한할 수 있고 central audit/revocation이 쉽습니다.

**Cons:** polling cadence와 stable object/queue name이 system을 fingerprint합니다. provider log가 producer와 consumer를 연결하고 control이 지연됩니다. queued data를 capture하면 exercise가 드러날 수 있습니다.

**Procedure:** (1) engagement queue 하나와 device identity 하나를 생성합니다. (2) benign하고 명시적으로 scoped된 signed job schema를 정의합니다. (3) message TTL, 최대 result size 및 rate를 설정합니다. (4) node가 자신의 queue만 pull하고 result prefix에만 write하도록 합니다. (5) offline accumulation, duplicate delivery 및 revocation을 테스트합니다. (6) immutable access log를 centralize합니다. (7) retention requirement가 충족되면 queue를 삭제합니다.

**Detection:** unusual process의 periodic API call, stable bucket/object/queue path, 동일한 user-agent 또는 TLS behavior 및 fetch-then-new-connection sequence를 탐색합니다. **Captured node:** local cache가 pending job과 object name을 드러낼 수 있습니다. cache는 encrypted, bounded, disposable로 유지하고 authoritative controller log는 보존합니다.

## Dual-uplink failover and connection migration

**Mechanics:** approved field node가 venue Ethernet/Wi-Fi와 organization cellular 같은 두 독립 uplink를 가지며 route 변경 중에도 overlay 또는 message broker를 통해 control session을 유지합니다. 이는 anonymity가 아니라 availability engineering입니다.

**Pros:** 한 provider, AP 또는 captive portal failure를 견디고 planned maintenance를 지원하며 의심되는 path를 빠르게 격리할 수 있습니다.

**Cons:** 두 provider가 두 location/account record를 만듭니다. simultaneous use는 correlation을 쉽게 하고 failover 중 route/DNS leak이 발생할 수 있습니다. cellular co-location evidence도 남습니다.

**Procedure:** (1) 두 organization-owned interface와 provider를 등록합니다. (2) owned endpoint에 deterministic route priority와 health check를 할당합니다. (3) DNS와 management를 overlay에 bind합니다. (4) secondary path가 inbound traffic을 받지 않도록 합니다. (5) 각 path를 분리하고 session recovery, source policy 및 direct destination access 부재를 확인합니다. (6) 계획되지 않은 path 변경에 alert합니다. (7) data use와 roaming limit을 문서화합니다.

**Detection:** ASNs 전체에서 동일한 device certificate, request grammar 및 timing을 상관 분석합니다. local inventory는 두 radio를 확인하고 carrier/venue는 자체 record를 보관합니다. **Captured node:** 두 SIM/device identifier와 known SSID가 보일 수 있습니다. organization asset을 사용하고 personal device와 co-locate/pair하지 않습니다.

## Organization private APN or managed cellular tunnel

**Mechanics:** carrier private APN은 enrolled SIM을 private routed domain에 배치하거나 enterprise gateway로 traffic을 tunnel합니다. device를 public mobile Internet에서 분리하지만 carrier 또는 contracting organization으로부터 숨기지는 않습니다.

**Pros:** stable private addressing, carrier-level enrollment/traffic policy 및 public inbound exposure 회피를 제공합니다. authorized remote appliance에 유용합니다.

**Cons:** subscriber, IMSI/IMEI, cell 및 billing attribution이 강력합니다. procurement lead time/cost, carrier/gateway outage가 있으며 operator에 대해서는 anonymous가 아닙니다.

**Procedure:** (1) assessment organization 명의로 APN을 계약합니다. (2) registered SIM과 gateway prefix만 whitelist합니다. (3) application-layer mutual authentication을 추가합니다. (4) APN route를 rendezvous와 update service로 제한합니다. (5) SIM removal, roaming, public-Internet breakout 및 revocation을 테스트합니다. (6) carrier와 gateway record를 monitoring합니다. (7) closeout 시 모든 SIM을 cancel 또는 quarantine합니다.

**Detection:** carrier inventory와 cell telemetry, APN gateway flow, SIM/IMEI mismatch 및 enterprise asset record를 사용합니다. **Captured node:** storage가 암호화되어도 SIM과 modem이 contract를 식별합니다. capture resilience는 deniability가 아니라 신속한 suspension과 좁은 authorization을 의미합니다.

## Long-range point-to-point wireless bridge

**Mechanics:** directional Wi-Fi 또는 licensed/unlicensed point-to-point radio가 owner-approved 두 site를 연결하고 remote site에서 Internet egress를 제공합니다. commercial proxy 없이 apparent IP location을 이동할 수 있습니다.

**Pros:** 높은 throughput, intermediate wired carrier와 독립적인 연결, 제어 가능한 RF/routing 및 segmentation과 remote-site monitoring 테스트를 제공합니다.

**Cons:** line-of-sight, spectrum, landlord 및 regulatory constraint가 있습니다. distinctive RF emission과 hardware, 두 endpoint의 physical evidence가 남으며 weather/power/alignment가 안정성에 영향을 줍니다.

**Procedure:** (1) 두 site에 대한 서면 permission을 얻고 spectrum/power rule을 확인합니다. (2) approved parameter 밖에서는 transmit하지 않고 path를 survey합니다. (3) authenticated encryption과 management VLAN을 사용합니다. (4) bridge를 owned rendezvous 또는 test subnet으로 제한합니다. (5) failover, alignment, power recovery 및 RF containment를 테스트합니다. (6) 두 radio를 label/inventory합니다. (7) exercise 후 제거하고 configuration reset을 확인합니다.

**Detection:** RF survey, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic 및 remote-site egress log를 사용합니다. **Captured node:** configuration이 peer와 management domain을 드러냅니다. unique exercise credential을 사용하고 personal management account를 두지 않으며 peer key를 신속하게 revoke합니다.

## Consented cooperative or community exit

**Mechanics:** volunteer 또는 partner organization이 published policy에 따라 relay를 알고 실행합니다. traffic은 shared community pool에서 exit하고 coordination layer가 abuse와 revocation을 관리합니다.

**Pros:** 다양한 non-cloud network, proxyware보다 안전한 명시적 consent, trust 분산형 shared governance 및 research/censorship-resilience에 유용합니다.

**Cons:** 작은 pool과 membership record가 anonymity를 줄입니다. exit operator는 complaint와 traffic metadata를 받고 malicious participant, variable uptime 및 jurisdiction 차이가 존재합니다.

**Procedure:** (1) acceptable-use와 logging policy를 공개합니다. (2) 각 operator의 informed opt-in을 얻습니다. (3) unique relay identity를 발급하고 destination/rate를 제한합니다. (4) abuse handling과 one-action revocation을 제공합니다. (5) testing 중 owned endpoint로 authorized traffic만 전송합니다. (6) churn과 correlation exposure를 측정합니다. (7) consent가 끝나면 relay를 cleanly 제거합니다.

**Detection:** membership/control-plane record, relay certificate, common software fingerprint 및 exit behavior가 pool을 식별합니다. **Captured node:** relay configuration이 cooperative를 식별할 수 있지만 client identity를 포함해서는 안 됩니다. client-to-session accountability는 access-controlled authorized controller에 보관합니다.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extension은 temporary interface identifier를 생성하여 모든 outbound connection에서 stable address가 재사용되지 않게 합니다. provider prefix 변경이 rotation을 추가할 수 있지만 delegated prefix, subscriber record 및 upper-layer fingerprint는 남습니다.<sup>[[21]](#references)</sup>

**Pros:** stable interface identifier를 이용한 장기 passive tracking을 줄이고 common operating system에 내장되어 있으며 relay overhead가 없습니다.

**Cons:** source anonymity가 아닙니다. ISP와 local network는 여전히 prefix/device를 알고 DNS, account 및 browser state가 session을 연결합니다. address churn은 allowlist와 logging을 복잡하게 합니다.

**Procedure:** (1) owned client에서 현재 stable/temporary address를 검사합니다. (2) third-party spoofing 대신 OS-supported privacy-address default를 활성화합니다. (3) address lifetime 동안 owned IPv6 endpoint를 반복 요청합니다. (4) inbound service가 의도한 stable address에만 bind되는지 확인합니다. (5) DHCPv6/RA/neighbor 및 정확한 endpoint log를 보존합니다. (6) 모든 IPv6 address에 대한 VPN/firewall 동작을 테스트합니다.

**Detection:** 하나의 address를 하나의 device로 취급하지 말고 delegated prefix, layer-2 identity, neighbor discovery, account 및 endpoint telemetry를 상관 분석합니다. **Captured node:** network profile과 interface identifier는 남습니다. temporary addressing는 하나의 passive identifier를 막을 뿐 forensic attribution을 막지 않습니다.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** pluggable transport는 첫 Tor connection이 보이는 방식 또는 bridge에 도달하는 방식을 변경합니다. Snowflake는 short-lived volunteer WebRTC proxy를 사용하고, WebTunnel은 일반 HTTPS처럼 보이며, obfs4는 단순 protocol identification과 active probing에 저항하고, meek은 지원되는 web infrastructure를 통해 relay합니다. 이는 Tor로 들어가는 censorship-circumvention transport이지 추가적인 end-to-end anonymity layer가 아닙니다.<sup>[[22]](#references)</sup>

**Pros:** direct Tor 또는 known relay가 차단된 경우 유용합니다. Snowflake는 stable public bridge address를 피하고 maintained Tor client에 통합되어 있으며 destination에는 여전히 일반 Tor property가 보입니다.

**Cons:** 성능이 낮거나 변동합니다. broker/front/bridge와 local network가 서로 다른 metadata를 보며 transport fingerprint와 blocking은 여전히 가능합니다. volunteer proxy는 Tor를 대체하지 않으며 application plaintext를 신뢰해서는 안 됩니다.

**Procedure:** (1) 공식 Tor Browser 또는 supported Tor client를 설치하고 verify합니다. (2) Connection/Bridges에서 built-in transport를 선택합니다. (3) owned diagnostic page에만 연결합니다. (4) page에 Snowflake/WebTunnel peer가 아닌 Tor exit가 보이는지 확인합니다. (5) bootstrap과 performance를 비교합니다. (6) transport를 failure시키고 client가 조용히 direct connection하지 않는지 확인합니다. (7) test 후 standard supported configuration으로 돌아갑니다.

**Detection:** censor는 destination allowlist, TLS/WebRTC behavior, broker discovery 및 flow analysis를 결합할 수 있습니다. endpoint는 Tor와 transport configuration을 노출합니다. **Capture-resilient OPSEC:** standard client를 사용하고 personal browser state를 복사하지 않으며 bridge/broker history가 복구될 수 있다고 가정합니다. **Monitoring:** Tor bootstrap log, 예상 밖의 direct DNS/connection attempt 및 controller-side owned-page observation을 확인합니다. transport failure가 discovery의 증거는 아닙니다.

## Refraction networking or decoy routing

**Mechanics:** cooperating network operator가 허용된 decoy로 향하는 것처럼 보이는 traffic에서 covert signal을 탐지하고 flow를 circumvention proxy로 divert합니다. deployment에는 network path 내부의 infrastructure가 필요하며 client가 innocent website을 선택하는 것만으로 생성할 수 없습니다.<sup>[[23]](#references)</sup>

**Pros:** apparent destination을 차단하려면 censor가 collateral damage를 감수해야 할 수 있습니다. public bridge address 배포가 필요 없고 on-path-assisted circumvention의 research model로 유용합니다.

**Cons:** specialized ISP/transit participation이 필요합니다. deployability와 performance는 routing에 의존하며 client-to-decoy flow와 proxy-side activity가 남습니다. global 또는 cooperating observer는 timing을 상관 분석할 수 있습니다.

**Procedure:** 관련 없는 network를 통해 signal하지 않습니다. isolated lab에서 재현합니다. (1) owned client, router, decoy 및 proxy namespace를 생성합니다. (2) benign tagged test request를 사용합니다. (3) owned router가 해당 tag만 proxy로 redirect하게 합니다. (4) pre/post-routing tuple과 request ID를 log합니다. (5) ordinary와 signaled flow를 비교합니다. (6) false positive와 removal을 테스트합니다. (7) lab route를 제거합니다.

**Detection:** authorized network operator는 routing divergence, unusual client hello/tag behavior 및 decoy-versus-back-end flow discrepancy를 검사할 수 있습니다. **Capture-resilient OPSEC:** research client에는 test key와 documentation address만 보관합니다. **Monitoring:** signed lab-router decision과 proxy arrival을 비교하며 production transit provider를 probe하여 signaling 탐지 여부를 확인하지 않습니다.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway가 IPFS content identifier (CID)를 cache 또는 peer에서 retrieve하고 검증 가능한 content를 client에 반환합니다. original publisher는 final reader가 아니라 gateway 또는 다른 peer를 볼 수 있고 gateway는 reader IP와 requested CID를 봅니다. native peer-to-peer retrieval은 client를 peer와 DHT/routing participant에 노출합니다.<sup>[[24]](#references)</sup>

**Pros:** cache가 publisher와 reader를 분리할 수 있고 immutable content는 hash로 검증됩니다. replicated data가 하나의 host failure를 견디며 HTTP client에는 native peer stack이 필요하지 않습니다.

**Cons:** public CID와 gateway log가 interest를 드러냅니다. 최초 retrieval timing이 publisher와 reader를 연결할 수 있고 malicious web content와 path-style same-origin hazard가 있습니다. public gateway는 best-effort이며 abuse를 금지합니다.

**Procedure:** (1) owned private IPFS swarm 또는 owned gateway에 무해한 test file을 publish합니다. (2) CID를 기록합니다. (3) subdomain isolation을 사용하는 별도 owned HTTP gateway로 retrieve합니다. (4) byte를 CID와 비교합니다. (5) caching 후 반복합니다. (6) publisher, peer 및 gateway log를 비교합니다. (7) retention 종료 시 unpin하고 test content를 제거합니다.

**Detection:** gateway는 source/CID를 log합니다. DHT와 peer connection이 retrieval을 드러내며 endpoint history와 file hash가 content를 식별합니다. **Capture-resilient OPSEC:** read-only field client에 private publishing key를 저장하지 않고 content addressing 전에 민감한 content를 encrypt합니다. **Monitoring:** unexpected pinning, peer-set 변경, allowlist 밖 CID request 또는 gateway account notice에 alert합니다.

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR)은 stated single- 또는 multi-server threat model에서 client가 선택한 index를 server에 cryptographically 숨긴 채 database에서 하나의 record를 retrieve하도록 합니다. bounded dataset의 query selection을 보호하지만 general web access나 IP anonymity는 아닙니다.<sup>[[25]](#references)</sup>

**Pros:** 강력한 application-specific query privacy, 측정 가능한 leakage model 및 key directory/blocklist/small public database에 대한 활용성을 제공합니다. 정확한 lookup term을 공개할 필요를 줄일 수 있습니다.

**Cons:** computation/bandwidth overhead가 있습니다. relay와 함께 사용하지 않으면 server는 connection time/IP를 압니다. dataset version, response size 및 application state가 user를 분리할 수 있고 implementation maturity가 다양합니다.

**Procedure:** (1) synthetic owned database에 audited PIR implementation을 deploy합니다. (2) dataset version과 parameter를 공개합니다. (3) 동일한 request size로 여러 index를 retrieve합니다. (4) local에서 correctness를 확인합니다. (5) server log를 비교하고 index가 없는지 확인합니다. (6) malicious/truncated response와 version mismatch를 테스트합니다. (7) 이를 anonymous browsing이라고 부르지 말고 정확한 privacy assumption을 문서화합니다.

**Detection:** network에는 service use와 volume이 보입니다. endpoint telemetry는 client와 final record use를 드러내며 compromised server는 dataset 또는 timing을 조작할 수 있습니다. **Capture-resilient OPSEC:** client에는 public database parameter와 bounded cache만 보관합니다. **Monitoring:** signed dataset root, fixed request shape, error-rate 변경 및 server-key rotation을 검증합니다.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** remote service가 URL을 fetch/render하고 screenshot, metadata 또는 sanitized content를 반환합니다. destination에는 fetcher address가 보이고 service에는 requester, URL 및 result가 보입니다. link-preview bot, security scanner 또는 third-party URL fetcher를 악용하는 것은 authorized proxy use가 아닙니다.

**Pros:** workstation에서 active content를 격리합니다. destination에는 controlled fetcher fingerprint가 보이며 file type, size, destination 및 rendering limit을 강제할 수 있습니다. disposable execution environment를 사용합니다.

**Cons:** service가 request를 완전히 알고 account/API/billing record가 남습니다. SSRF와 data-exfiltration risk가 있고 script, authentication 및 interactive site가 작동하지 않을 수 있습니다. unique URL이 requester와 fetch를 연결합니다.

**Procedure:** (1) owned test domain만 strict allowlist에 포함한 organization-owned fetcher를 deploy합니다. (2) private, link-local, metadata 및 unapproved redirect address를 차단합니다. (3) method, redirect, byte 및 render time을 제한합니다. (4) credential/cookie를 제거합니다. (5) owned URL을 제출합니다. (6) requester, fetcher 및 target log를 비교합니다. (7) render instance를 폐기하고 policy에 따라 central audit를 보존합니다.

**Detection:** target에는 service ASN/fingerprint가 보입니다. provider와 controller log가 requester를 URL에 연결하며 endpoint process/API call이 submission을 보여줍니다. **Capture-resilient OPSEC:** arbitrary destination authority가 없는 short-lived project token 하나만 사용합니다. **Monitoring:** allowlist denial, redirect violation, controller job ID 없는 fetch 및 provider abuse notice를 alert합니다.

## Anycast rendezvous pool

**Mechanics:** organization-controlled 여러 node가 하나의 stable service address를 advertise/front하고 routing이 가까운 instance를 선택합니다. Anycast는 availability를 향상하고 client에서 individual back-end를 숨기지만 operator가 모든 instance를 control하며 service address는 stable합니다.<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress, instance failure 시 field reconfiguration 불필요, DDoS/load distribution 및 known node 간 session 이동을 위한 central policy를 제공합니다.

**Cons:** BGP/CDN과 provider record가 organization을 식별합니다. path change가 stateful session을 중단할 수 있고 client location별 monitoring이 다릅니다. 하나의 stable address는 쉽게 차단되고 reputation cluster가 됩니다.

**Procedure:** provider-supported organization project 또는 isolated routing lab을 사용합니다. (1) 동일한 authenticated health endpoint 두 개를 deploy합니다. (2) 하나의 documented service address를 expose합니다. (3) session state를 edge가 아닌 broker에 유지합니다. (4) 한 node를 withdraw하고 reconnection을 확인합니다. (5) certificate, policy 및 log consistency를 테스트합니다. (6) unauthorized origin/region에 alert합니다. (7) closeout 시 advertisement와 credential을 제거합니다.

**Detection:** BGP/RPKI/history, provider tenancy, certificate 및 동일한 service behavior가 pool을 식별합니다. **Capture-resilient OPSEC:** edge에는 regional service identity만 두고 operator 또는 fleet-enrollment key는 두지 않습니다. **Monitoring:** authorized monitor에서 모든 region을 probe하고 route origin과 configuration digest를 비교합니다. unexpected origin은 incident로 처리합니다.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection ID는 NAT rebinding 또는 address 변경 중 client session을 유지할 수 있습니다. Multipath TCP는 여러 subflow에서 하나의 reliable byte stream을 전달합니다. Wi-Fi/cellular 전환의 continuity를 높이지만 common peer에는 old/new path가 모두 노출되고 cross-path correlation이 쉬워질 수 있습니다.<sup>[[27]](#references)</sup>

**Pros:** uplink 변경 시 빠른 recovery, application session restart 불필요, MPTCP의 resilience/throughput 결합 및 approved field node 지원을 제공합니다.

**Cons:** anonymity가 아닙니다. peer가 migration/subflow를 보고 connection identifier와 simultaneous traffic이 path를 연결합니다. middlebox/carrier support가 다르고 provider record가 늘어납니다.

**Procedure:** (1) owned field client와 rendezvous 사이에서만 supported transport를 활성화합니다. (2) IP와 독립적으로 application을 authenticate합니다. (3) approved Wi-Fi에서 bounded transfer를 시작합니다. (4) organization cellular로 전환합니다. (5) path validation, data integrity 및 clear/direct fallback 부재를 확인합니다. (6) idle timeout과 복귀를 테스트합니다. (7) 모든 path transition의 broker record를 보존합니다.

**Detection:** peer는 address migration 또는 MPTCP subflow를 직접 봅니다. access provider는 자신의 영역을 확인하며 connection ID, TLS identity와 timing이 양쪽을 연결합니다. **Capture-resilient OPSEC:** device-scoped session material만 저장하고 resumable state를 짧게 만료합니다. **Monitoring:** impossible path change, simultaneous unapproved network, migration storm 및 quarantine 후 resumption에 alert합니다.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** organization-owned workflow가 hosted runner에서 bounded network check를 수행합니다. destination에는 cloud runner address가 보이고 platform은 repository, actor, workflow, token, log 및 billing attribution을 보유합니다. 이는 provider로부터의 anonymity가 아니라 accountable egress를 가진 remote execution입니다.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment, reproducible job definition, inbound connection 불필요, geographically distributed availability check 및 강력한 controller audit을 제공합니다.

**Cons:** platform과 organization이 initiator를 식별합니다. broad workflow token과 untrusted pull request는 위험하며 shared IP reputation과 secret/target data를 보존하는 log/artifact가 있습니다.

**Procedure:** (1) assessment용 private organization repository와 environment를 생성합니다. (2) owned endpoint에 대한 manually approved fixed benign job만 허용합니다. (3) minimal read-only workflow permission을 사용하고 production secret을 사용하지 않습니다. (4) check를 실행합니다. (5) workflow, provider 및 target record를 비교합니다. (6) artifact에 credential이 없는지 확인합니다. (7) environment token을 삭제하고 필요한 audit를 보존합니다.

**Detection:** provider audit와 workflow log가 직접 attribution을 제공합니다. target은 runner ASN/range와 stable request grammar를 식별합니다. **Capture-resilient OPSEC:** field-device, signing, wallet 또는 cloud-administrator secret을 runner variable에 넣지 않습니다. **Monitoring:** branch/environment approval을 요구하고 workflow edit, fork execution, secret read 및 unexpected destination에 alert합니다.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio 또는 serial/optical link가 nearby sensor에서 owner-approved Internet gateway로 bounded message를 전달합니다. field device 자체에는 Internet route가 없고 gateway만 egress입니다. radio range와 protocol limit 때문에 이는 telemetry/store-and-forward 설계이지 interactive anonymous Internet이 아닙니다.

**Pros:** 가장 작은 field device에서 Internet stack과 credential을 제거하고 low power를 사용합니다. gateway가 policy를 centralize하며 temporary dead zone을 연결할 수 있습니다.

**Cons:** RF/physical discovery, pairing 및 device identifier가 남습니다. bandwidth/range가 작고 gateway는 모든 message를 연결합니다. spectrum/encryption 제한이 다르며 capture 시 queued data가 노출될 수 있습니다.

**Procedure:** (1) site와 spectrum approval을 얻습니다. (2) unique key로 owned sensor 하나와 gateway 하나를 pair합니다. (3) signed fixed-size message type, TTL 및 rate를 정의합니다. (4) sensor에 default IP route를 주지 않습니다. (5) gateway가 owned collector로만 forward하게 합니다. (6) replay, range loss 및 gateway outage를 테스트합니다. (7) 두 device를 inventory하고 회수합니다.

**Detection:** RF survey, pairing database, physical inspection 및 gateway process/flow log가 path를 드러냅니다. **Capture-resilient OPSEC:** sensor에는 pairwise key와 bounded encrypted queue만 저장하고 operator, Wi-Fi, cellular 또는 controller credential은 저장하지 않습니다. **Monitoring:** new peer, sequence rollback, key failure, unusual RF rate 및 unregistered gateway를 통한 message에 alert합니다.

## Capture/compromise exposure matrix

이 표는 위의 모든 family에 capture-resilience check를 적용합니다. “Minimize”는 authorized asset의 secret과 blast radius를 줄인다는 뜻이며, evidence를 지우거나 investigation을 숨긴다는 의미가 아닙니다.

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | 알려진 network, DHCP/portal history, MAC, tunnel peer | 별도 organization device; 지원 시 private MAC; personal account 없음; controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostname, key, route, log 및 인접 hop | engagement별 identity 하나; short TTL; narrow route; broker-side revocation; master key 없음 |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifier 및 cached request | payload identifier 최소화; approved config pin; bounded cache; strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | 설치 software, bridge/onion material, local state 및 peer history | standard client; 별도 service key; encrypted minimal state; compromised service identity rotate |
| Remote browser/VDI/jump host | workspace token, clipboard/file 및 remote tenant | gateway의 phishing-resistant MFA; transfer channel 비활성화; 신속한 session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider 및 대략적 location | organization contract; personal co-location 없음; narrow APN/overlay policy; provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | consented/owned node만; signed agent; per-node credential; controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API token, deployment 및 billing reference | dedicated project; least-privilege role; short-lived deploy token; provider audit central 보관 |
| Dead drop, pull mailbox, store-and-forward | object name, queue, cached job/result 및 custody data | signed bounded job; TTL; encrypted cache; separate producer identity; immutable server log |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifact | written placement; unique device identity; operator secret 없음; tamper/state telemetry; revoke/recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route 및 uplink profile | outbound-only narrow service; short-lived device credential; independent operator login; fail-closed path |
| IPv6 temporary addressing | profile, prefix history 및 endpoint/application state | anti-tracking으로만 취급; network log 보존; endpoint compartmentation과 결합 |
| Pluggable transport/refraction lab | bridge/broker/decoy setting, Tor state 및 research key | standard client 또는 isolated lab; personal browser state 없음; production signaling 없음 |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway 또는 service token | encrypted bounded cache; public-only parameter; short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service node, connection ID, resumable state 및 알려진 모든 path | regional identity만; 짧은 resumption lifetime; central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, log 및 artifact | least-privilege workflow; production/field/wallet secret 없음; environment approval |
| Non-IP local hop | radio peer, pairwise key, queued message 및 gateway identity | unique pairwise key; fixed message schema; Wi-Fi/cellular/operator credential 없음 |

## Monitoring possible discovery for every access family

client-side test만으로 investigator 또는 defender가 감시 중인지 입증할 수 없습니다. engagement가 소유한 system의 변경을 monitoring하고 controller/client와 corroborate하며 observer를 probe하지 말고 중지합니다. 아래 행은 위의 모든 technique를 포함합니다. [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise)와 함께 사용합니다.

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | 승인되지 않은 network/SIM/device, 설명되지 않는 relocation 또는 provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leak, 새 admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback 또는 범위 밖 egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer 또는 provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health 및 owned canary page | personal-account crossover, 예상 밖 non-Tor connection 또는 compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association 및 content hash | unknown peer/gateway, sequence rollback, unauthorized content 또는 missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export 및 cloud audit | unknown login/workflow edit, secret read, unexpected destination 또는 project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature 및 TTL | unknown node/origin/object writer, unsigned/replayed job, lab 밖 topology escape |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use 또는 site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation 및 broker session | impossible migration, simultaneous unapproved path 또는 revoke 후 session resumption |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root 또는 provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. 제거할 observer와 숨길 data를 명시합니다.
2. 이를 제거하는 가장 단순한 family를 선택합니다.
3. source, entry, traversal, exit, DNS, account 및 payment observer를 그립니다.
4. 별도의 endpoint/application identity를 사용합니다.
5. IPv4, IPv6, DNS, WebRTC/application bypass 및 destination view를 확인합니다.
6. 모든 hop을 중단하고 failure가 closed인지 확인합니다.
7. 제어하는 모든 component의 log를 비교합니다.
8. 남은 timing, provider, endpoint 및 physical link를 기록합니다.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
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
