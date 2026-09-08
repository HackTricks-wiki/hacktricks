# 고급 Network Privacy Architecture

복잡성은 특정 관찰자나 failure mode를 제거할 때만 유용합니다. 고유한 tunnel stack, custom packet shape, 드문 user agent 또는 자주 교체되는 infrastructure는 수천 명이 사용하는 표준 configuration보다 더 강력한 fingerprint가 될 수 있습니다.

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)는 일반적인 `Pros`/`Cons`/`Procedure`/`Detection` 스키마를 제공합니다. 이 페이지에서는 더 복잡한 architecture와 trust boundary를 확장하여 설명합니다.

따라서 advanced goal은 **knowledge의 분리**입니다. 어떤 일반 component도 user identity, destination, plaintext 및 장기적인 activity history를 동시에 보유해서는 안 됩니다. 이것은 invisibility가 아니며, collusion, legal process, endpoint compromise 또는 end-to-end traffic correlation을 통해 여전히 경로를 재구성할 수 있습니다.

## Architecture 선택

| Pattern | 확보되는 Property | 새로운 Trust/Failure | 적합한 사용 |
|---|---|---|---|
| Standard Tor Browser | 공유 browser fingerprint 및 multi-relay path | 낮은 latency로 인해 traffic correlation이 가능함 | 일반적인 anonymous web browsing |
| Tor bridge + pluggable transport | 직접적인 Tor blocking/classification을 어렵게 만듦 | Bridge/transport는 여전히 탐지될 수 있으며, bridge는 source를 파악함 | Censored networks |
| Onion service | Service IP를 숨기고 exit을 방지하며 onion identity를 인증함 | Onion key와 server endpoint가 critical asset이 됨 | Private publishing, intake 또는 administration |
| Independent ingress + egress relays | 일반적으로 어떤 단일 relay도 source와 destination을 동시에 볼 수 없음 | Operators가 collude할 수 있으며, timing이 양쪽을 통과함 | High-performance supported applications |
| Oblivious HTTP | Source IP를 encrypted stateless HTTP request와 분리함 | Application, relay 및 gateway의 지원이 필요함 | Session state가 없는 telemetry, queries 및 submissions |
| VPN-only workload namespace | Kernel이 clear-network route의 부재를 강제함 | VPN은 여전히 양쪽 endpoint를 모두 확인하며, host/root는 여전히 trusted 상태임 | Authorized engagement tools 및 fixed egress |
| Disposable remote browser | Destination을 local browser/endpoint에서 격리함 | Workspace provider가 activity와 login identity를 확인함 | Untrusted sites/files 및 controlled research |
| I2P internal service | 별도의 inbound/outbound overlay tunnel을 사용하며 공식 exit이 없음 | 더 작고 다른 ecosystem 및 장기간 실행되는 peer behavior | 일반 web의 대체가 아닌 I2P native services |
| Mixnet/asynchronous delivery | Delay, batching 및 cover traffic이 timing analysis에 저항함 | 높은 latency, 제한된 applications 및 낮은 maturity | Interaction이 필요하지 않은 messages/tasks |

## Knowledge를 분리하는 relays

두 operator relay pattern은 제한된 application에서 단일 VPN보다 더 나은 성능을 낼 수 있습니다:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay는 배포된 사례다. Apple이 ingress를 운영하고 다른 content provider가 egress를 운영하므로, 일반적으로 어느 쪽도 client IP와 browsing destination을 모두 볼 수 없다.<sup>[[1]](#references)</sup> 이는 제품별 Safari/DNS privacy service이지, 모든 기기에 적용되는 anonymity network가 아니며 coarse region을 의도적으로 보존한다.

Oblivious HTTP (OHTTP)는 더 제한적인 application 패턴을 표준화한다. relay는 client와 encrypted gateway traffic을 볼 수 있고, gateway는 HTTP message를 decrypt하지만 client가 아니라 relay를 본다. RFC 9458은 이를 위해 relay/gateway의 지원이 필요하며, cookies/authentication/session state가 없는 request에 가장 적합하고, traffic analysis는 보장 범위에서 제외된다고 경고한다.<sup>[[2]](#references)</sup>

### Design checklist

1. 보호할 정확한 application message를 정의한다. 인증된 임의의 web session을 조용히 proxy하지 않는다.
2. 가능한 경우 서로 독립적으로 운영되는 ingress 및 egress organization을 사용하고, administration, credentials, logging 및 legal control을 분리한다.
3. ingress가 읽을 수 없도록 application request를 gateway에 encrypt한다.
4. 적절한 layer에서 client-derived forwarding headers, TLS identifiers 및 stable per-user tokens를 제거한다.
5. transport separation에도 gateway가 request를 다시 연결할 수 있게 하는 고유한 keys, cookies 또는 payload fields를 피한다.
6. 양쪽의 logs를 aggregate, minimize 및 expire하고, collusion 및 compelled-disclosure risk를 문서화한다.
7. 검토된 protocol에 따라서만 padding 또는 batching을 사용한다. 직접 만든 traffic shaping은 correlation을 막지 못한 채 고유한 signature를 만들 수 있다.
8. controlled canary requests로 테스트하고 client, ingress, gateway 및 target이 각각 기록하는 내용을 비교한다.

일반적인 interactive browsing에는 private OHTTP proxy를 직접 만드는 대신 Tor Browser를 사용한다. OHTTP는 지원되는 application transaction을 보호할 뿐, 전체 browser identity를 보호하지 않는다.

## Enforce the route per workload

변경 가능한 host routes에만 기반한 kill switch는 DHCP renewal, sleep/wake, IPv6 changes 또는 tunnel crash 중에 실패할 수 있다. 더 강력한 Linux 패턴은 container 또는 network namespace에 loopback interface와 tunnel interface만 제공한다. WireGuard는 interface를 physical namespace에서 생성한 뒤 workload namespace로 이동하고, encrypted UDP socket은 원래 namespace에 유지할 수 있다고 문서화한다.<sup>[[3]](#references)</sup>

### Deployment pattern

1. 먼저 disposable/local-console host에서 구축한다. namespace 실수로 remote access가 끊길 수 있다.
2. physical Ethernet/Wi-Fi interface와 DHCP/supplicant를 **physical** namespace에 배치한다.
3. 그곳에서 WireGuard interface를 생성하여 encrypted transport socket이 physical-network access를 갖게 한다.
4. WireGuard interface만 **workload** namespace로 이동하고 유일한 default route로 설정한다.
5. tunnel을 통해서만 접근 가능한 namespace-specific resolver를 workload에 제공한다. IPv6를 명시적으로 고려한다.
6. browser/tool container를 해당 namespace에서 실행하되 host networking, privileged capability, shared browser directory 또는 personal credential agent를 사용하지 않는다.
7. tunnel을 중지하고 workload가 controlled IPv4 또는 IPv6 endpoint를 resolve하거나 connect할 수 없는지 확인한다.
8. workload namespace 외부에서 endpoint roaming, DHCP renewal, suspend/resume 및 captive-portal handling을 테스트한다.
9. engagement accountability를 위해 namespace/tunnel configuration hash와 승인된 egress address를 기록한다.

이는 **route enforcement**를 제공할 뿐, VPN 또는 engagement bastion으로부터의 anonymity를 제공하지 않는다. compromised host/root는 namespace를 inspect하거나 변경할 수 있다.

## Tor bridges and pluggable transports

Bridges는 공개되지 않은 Tor entry relays다. Pluggable transports는 첫 번째 hop의 traffic을 변경하여 단순한 blocking 또는 protocol classification을 어렵게 한다. 그러나 entry 이후에 anonymous relay layers를 추가하지 않으며, 더 광범위한 timing correlation이 가능한 observer를 무력화하지도 않는다.

| Transport | First-hop approach | Practical tradeoff |
|---|---|---|
| **obfs4** | Traffic을 random하게 보이도록 만들고 active probing에 저항한다 | 알려진 bridge address는 여전히 차단될 수 있다 |
| **Snowflake** | 단기간 사용되는 volunteer WebRTC proxies를 사용하여 bridge에 연결한다 | Performance가 변동하며 broker/STUN/WebRTC patterns가 존재한다 |
| **WebTunnel** | HTTPS와 유사한 WebSocket tunnel로 bridge traffic을 전달한다 | 접근 가능한 web front에 의존하며 여전히 분류될 수 있다 |

Tor Project는 Snowflake와 WebTunnel을 완벽한 indistinguishability가 아닌 censorship-circumvention transports로 설명한다.<sup>[[4]](#references)</sup>

### Safe workflow

1. Tor Browser의 direct connection으로 시작한다. local observer model에서 blocking 또는 visibility가 이를 정당화할 때만 bridge를 추가한다.
2. Tor Project channels에서 얻은 built-in transports 또는 bridge lines를 사용한다. forum에서 임의의 transport binaries나 public bridge lists를 다운로드하지 않는다.
3. 안정적으로 연결되는, 지원되는 가장 단순한 option을 사용하고 선택 이유를 기록한다.
4. 그 외에는 Tor Browser를 standard 상태로 유지한다. bridge가 custom extensions, account logins 또는 unusual browser settings를 안전하게 만들지는 않는다.
5. reconnect와 clock correctness를 테스트한다. 동일한 local observer에게 distinctive sequence를 보내는 방식으로 transports를 반복해서 전환하지 않는다.
6. censor 또는 network policy가 변경되면 재평가한다. 일부 지역에서는 사용 자체가 민감하거나 제한될 수 있다.

## Onion services as a private rendezvous

onion service는 introduction points와 rendezvous relays로 outbound Tor circuits를 구성하므로 public inbound port가 필요 없으며 onion protocol을 통해 server IP를 노출하지 않는다. Client-to-service traffic은 Tor 내부에 머물고 onion address는 service key를 authenticate한다.<sup>[[5]](#references)</sup>

lawful intake portal, private repository, administrative interface 또는 engagement evidence drop의 경우:

1. application을 dedicated host/VM에서 실행하고 loopback 또는 isolated Unix socket에 bind한다.
2. official repository에서 Tor를 설치하고 official v3 onion-service setup을 따른다. obsolete v2 instructions는 절대 사용하지 않는다.
3. onion service private key를 TLS/signing key처럼 보호한다. stable identity가 필요한 경우에만 backup한다.
4. closed group을 위해 onion-service client authorization을 추가하고, independently authenticated channel을 통해 credentials를 전달한다.<sup>[[6]](#references)</sup>
5. origin이 public IP 또는 operator account를 드러내는 third-party fonts, analytics, updates 또는 webhooks를 fetch하지 않도록 한다.
6. application에도 authentication과 authorization을 추가한다. onion address를 알고 있다는 사실은 access control이 아니다.
7. third-party telemetry를 포함하지 않은 상태로 service를 patch, rate-limit 및 monitor한다.
8. 별도의 test context에서 DNS, email, error pages, file metadata 및 response headers가 origin을 disclose하지 않는지 확인한다.
9. red-team use의 경우 ROE에 service, owner, purpose 및 shutdown time을 기재한다. 이를 사용하여 out-of-scope C2를 conceal하지 않는다.

## Remote browser and disposable workspace

remote browser는 rendering과 risky content를 local endpoint에서 멀리 이동시키고 engagement-specific cloud egress를 제공할 수 있다. 이는 일부 content와 persistence로부터 local device를 보호하지만, workspace provider에 대해 operator를 anonymous하게 만들지는 않는다. 예를 들어 AWS는 disposable browser instance가 session 종료 시 폐기되더라도 portal, identity, policy, preference 및 session-log data를 수집한다고 문서화한다.<sup>[[7]](#references)</sup>

engagement마다 organization이 제어하는 workspace를 하나씩 사용하고, downloads/uploads/clipboard를 제한하며, personal identity providers를 비활성화하고, fixed egress를 approved bastion을 통해 전송하며, evidence export 후 workspace를 expire한다. provider console, IdP 및 administrator를 observer로 취급한다.

## I2P and internal overlays

I2P는 별도의 단방향 inbound 및 outbound tunnels를 구성하며 official network-layer exits가 없다. 주로 I2P 내부의 services를 위한 것이다.<sup>[[8]](#references)</sup> 이는 public Internet을 더 빠르게 browsing하기 위한 drop-in 방식이 아니다. Outproxies는 trust point를 도입하며, official threat model은 추가 research를 명시적으로 요구하고 perfect anonymity를 주장하지 않는다.

양쪽 끝이 의도적으로 I2P를 지원하는 경우에만 I2P를 사용하고, long-lived router를 personal applications에서 격리하며, peers/local networks가 I2P participation을 관찰할 수 있음을 이해한다. 근거 없이 hop counts를 늘리거나 peer selection을 조정하지 않는다. 비정상적인 settings는 performance와 anonymity set을 저하시킬 수 있다.

## Correlation-resistant operations

- 고유한 build보다 일반적이고 지원되는 common client configuration을 선호한다.
- endpoint에서 identities를 분리한다. 어떤 routing topology도 account, payment, recovery 또는 content reuse를 복구하지 못한다.
- non-interactive tasks에는 수동으로 sleeps나 fake traffic을 추가하는 대신 검토된 asynchronous protocol/mixnet을 선호한다.
- 동일한 physical context에서 별개의 identities를 synchronized pattern으로 운영하지 않는다.
- one-way export gate를 사용한다. untrusted content는 disposable renderer로 들어가고, 검토된 sanitized result만 나간다.
- protocol security를 위해 clocks는 정확하게 유지하되, published artifacts에서 불필요하게 정밀한 timestamps는 제거한다.
- session duration과 stale infrastructure를 최소화하되, 눈에 띄고 accountability를 훼손하는 빠른 “fast-flux” rotation은 사용하지 않는다.

## Techniques that cannot use uninvolved third parties

이는 실제 adversary techniques이지, 상상 속의 것이거나 중요하지 않은 것이 아니다. 그 mechanics와 detection은 [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) 및 [APT case studies](government-and-apt-case-studies.md)에서 다룬다. authorized exercise 중에는 owned substitutes를 사용하여 observable behavior를 재현한다.

- residential/mobile exit churn은 consent가 불분명한 markets가 아니라 controlled relay pools로 model한다.
- open proxies, compromised routers 및 botnets는 owned VMs/routers로 model한다.
- stolen cloud accounts는 지정된 exercise tenant와 synthetic victim identity로 model한다.
- domain fronting은 비협조적인 CDN이 아니라 owned reverse proxy에서 model한다.
- third-party Wi-Fi는 lab이 소유한 두 개의 isolated AP로 model한다.
- custom encryption, multi-VPN chains 및 identifier rotation은 flow, account 및 endpoint artifacts가 여전히 detectable한 test hypotheses로 취급한다.

authorized red team의 경우 traffic을 덜 recognizable하게 만들려는 모든 시도는 ROE에서 명시적인 detection objective여야 하며, controller가 보유한 attribution map과 stop/deconfliction mechanism을 포함해야 한다.

## Verification matrix

| Test | Expected result | Failure means |
|---|---|---|
| Tunnel/bridge stopped | Workload에 direct IPv4/IPv6/DNS path가 없다 | Route enforcement가 불완전하다 |
| Target log inspected | 계획된 egress/application identity만 나타난다 | Header, route 또는 account leak |
| Ingress log inspected | Source는 존재하고 clear target/request는 없다 | Ingress에서 trust split이 실패했다 |
| Egress log inspected | Relay/request는 존재하고 source identity는 없다 | Egress에서 trust split이 실패했다 |
| Onion origin scanned externally | Public origin service에 접근하거나 연결할 수 없다 | Origin이 leak되었거나 dual-homed 상태다 |
| Disposable session ended | Instance state가 사라지고 approved evidence는 별도로 보존된다 | Persistence boundary가 실패했다 |
| Controller lookup exercised | Activity가 engagement/operator에 신속히 매핑된다 | Red-team accountability가 실패했다 |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
