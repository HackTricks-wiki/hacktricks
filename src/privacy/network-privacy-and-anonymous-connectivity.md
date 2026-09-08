# Network Privacy & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Network privacy는 완전한 identity가 아니라 routing decision입니다. 어떤 경로를 선택할지는 누가 **source**, **destination**, **content**, **timing**을 서로 연결하지 못해야 하는지를 기준으로 판단하세요.

모든 access-path family에 대한 정규화된 목록인 `Pros`, `Cons`, 단계별 `Procedure`, `Detection`부터 확인하려면 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)를 참고하세요. 이 페이지에서는 일반적으로 배포 가능한 옵션을 확장해 설명합니다.

## 각 observer가 일반적으로 볼 수 있는 정보

| 경로 | Local network / ISP | Intermediary | Destination | 주요 제한 사항 | 상대적 속도 |
|---|---|---|---|---|---|
| Direct HTTPS | Source, destination metadata, timing/volume | Hosting/CDN이 connection을 확인 | Source IP, browser/app data | Source-IP privacy 없음 | 가장 빠름 |
| Commercial VPN | Source가 VPN에 연결된 사실; 일반적인 destination metadata는 확인하지 못함 | VPN이 source 및 destination metadata를 확인 | VPN egress IP | 한 provider가 correlation point가 됨 | 일반적으로 빠름 |
| Self-hosted VPN/VPS | Source가 VPS에 연결된 사실 | Host/account/payment/control-plane logs | VPS egress IP | 임대한 server/account로 attribution하기 쉬움 | 일반적으로 빠름 |
| Tor Browser | Source가 Tor/bridge에 연결된 사실; timing/volume | 각 relay가 제한된 일부만 확인 | Tor exit, browser data | 더 느림; account/endpoint/correlation risks | 보통/느림 |
| Tails/Whonix | 더 강력한 routing boundaries를 사용하는 유사한 Tor path | 동일한 Tor limitations | Tor exit/application data | Operational mistakes와 host/hardware는 여전히 남음 | 보통/느림 |
| Public guest Wi-Fi + HTTPS | Venue가 local device/timing 및 destination을 확인 | Venue ISP가 metadata를 확인 | Guest public IP | Physical/captive-portal/device correlation | 빠름/가변적 |
| Cellular hotspot | Carrier가 subscriber/device/location 및 destination을 확인 | 사용 시 VPN/Tor | Carrier, VPN 또는 Tor egress IP | Mobile subscription과 location이 지속적인 identifier가 됨 | 빠름/가변적 |
| Mixnet | Access가 mixnet 사용 사실을 확인; timing/volume | 여러 mixing node | Gateway/egress | 생태계가 발전 중이며 latency와 bandwidth cost가 발생 | 가장 느림 |

HTTPS는 transit 중인 content를 보호하지만 모든 metadata를 보호하지는 않습니다. EFF에 따르면 page paths, credentials, messages가 암호화되어 있어도 domain, time, traffic size는 intermediary에 계속 노출될 수 있습니다.<sup>[[1]](#references)</sup>

## VPN: 빠른 privacy와 집중된 trust

VPN은 access ISP로부터 destination metadata를 숨기거나, 신뢰할 수 없는 network에서 first hop을 보호하거나, 안정적인 engagement egress address를 사용하거나, private network에 접근할 때 유용합니다. 하지만 VPN이 사용자를 anonymous하게 만들지는 않습니다. VPN은 source connection을 확인하고 destination metadata를 관찰할 수 있으며, accounts, cookies, GPS, fingerprints, payment information은 그대로 남습니다.<sup>[[1]](#references)</sup>

### Provider 평가 checklist

1. **Ownership and jurisdiction:** legal entity, parent company, operating countries, infrastructure subcontractors 및 적용되는 legal process를 확인합니다.
2. **Collected data:** account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries 및 destination logs를 구분합니다. “No browsing logs”가 “no data”를 의미하지는 않습니다.
3. **Retention and deletion:** 정확한 보관 기간과 backups, fraud systems, processors가 동일한 일정을 따르는지 확인합니다.
4. **Evidence:** scope, date, findings, remediation이 공개된 audits, 재현 가능하거나 open인 clients, transparency reports 및 documented incidents를 우선합니다.
5. **Protocol and client:** 유지 관리되는 WireGuard, OpenVPN 또는 검토된 다른 protocol, automatic updates, DNS 및 IPv6 handling, kill switch, platform별 leak tests를 확인합니다.
6. **Business model:** 무료 또는 subsidized service가 어떻게 자금을 조달하는지 이해합니다. App-store에 존재한다는 사실만으로 trustworthy operation이 입증되지는 않습니다.
7. **Payment fit:** alternative payment는 VPN에 대한 billing disclosure를 줄일 수 있지만, 모든 connection에서 관찰되는 source IP를 제거하지는 않습니다.

### VPN 구성 및 검증

1. 공식 source에서 provider/organization의 signed client를 설치합니다.
2. 문서화된 route가 우회해야 하는 경우가 아니라면 **full tunnel**을 선택합니다. Split tunneling은 correlation 및 leak paths를 만듭니다.
3. fail-closed/always-on behavior를 활성화하고 reconnect 중 traffic을 차단합니다.
4. DNS를 tunnel을 통해 전송하고 IPv4와 IPv6를 모두 테스트합니다. 안전하게 tunnel할 수 없고 기능 손실을 수용한 경우에만 protocol을 비활성화합니다.
5. sleep/wake, network switching, captive-portal login, tunnel crash 및 hotspot tethering을 테스트합니다. NCSC는 일부 platform에서 tethered clients가 phone의 VPN을 우회할 수 있다고 경고합니다.<sup>[[2]](#references)</sup>
6. organization-controlled test endpoint를 사용해 관찰된 IPv4, IPv6, DNS resolver 및 connection timing을 기록합니다. 민감한 engagement를 무작위 “leak test” site에 노출하지 마세요.
7. client, OS, network 또는 policy가 변경된 후 다시 테스트합니다.

## Tor Browser: 더 강력한 web unlinkability

Tor는 여러 relay를 통과하는 circuit을 구성하므로 일반적으로 단일 relay가 source와 destination을 모두 알 수 없습니다. Destination에는 사용자의 IP 대신 Tor exit가 표시되며, local network는 일반적으로 Tor connection을 확인합니다.<sup>[[3]](#references)</sup> Tor는 low-latency TCP applications를 위해 설계되었으므로 더 느리고, 양쪽 끝을 correlation할 수 있는 adversary에 대한 보호를 보장하지 않습니다.<sup>[[4]](#references)</sup>

### 안전한 Tor Browser workflow

1. Tor Browser는 Tor Project 또는 공식 mirror에서만 다운로드하고, 가능하면 signature를 검증합니다.
2. 일반 browser에서 Tor SOCKS port를 지정하지 말고 **Tor Browser**를 사용합니다. 일반 browser는 DNS/WebRTC 및 identifying state를 leak할 수 있습니다.<sup>[[5]](#references)</sup>
3. 기본 size, fonts, extensions 및 privacy settings를 유지합니다. 추가 add-ons는 browser를 더 unique하게 만들 수 있습니다.<sup>[[6]](#references)</sup>
4. 증가하는 breakage를 감수할 수 있다면 **Safer** 또는 **Safest** security level을 선택합니다.
5. direct Tor가 차단되었거나 일반 relay IP가 허용할 수 없는 local visibility를 유발할 때 bridge를 사용합니다. Bridge는 쉽게 인식되는 것을 줄이지만 traffic analysis를 제거하지는 않습니다.<sup>[[7]](#references)</sup>
6. identifying account에 로그인하거나 identifying information을 제공하지 말며, 다운로드한 active documents를 외부 networked application에서 열지 않습니다.
7. 각 identity에 별도의 session/context를 사용합니다. “New circuit”은 browser/application identity를 지우는 것과 같지 않습니다. 적절한 경우 **New Identity**를 사용하거나 isolated environment를 재시작합니다.
8. Authenticated HTTPS 또는 authenticated onion service를 우선합니다. Tor exit는 암호화되지 않은 HTTP traffic을 관찰할 수 있습니다.

### Tor와 VPN 결합

둘을 결합한다고 자동으로 더 안전해지는 것은 아닙니다. Tor 앞에 VPN을 두면 ISP로부터 직접 Tor relay connections를 숨길 수 있지만 VPN은 source를 확인합니다. Tor 앞에 VPN을 두면 VPN이 Tor 이후 활동을 안정적으로 관찰하게 되고 anonymity set이 줄어들 수 있습니다. Misconfiguration은 leaks를 유발할 수 있습니다. Tor Project는 이러한 조합을 advanced하고 명시적인 threat models에만 권장합니다.<sup>[[8]](#references)</sup>

## Public 및 guest Wi-Fi

Modern HTTPS를 사용하면 수동적으로 관찰하는 주변 사용자는 적절히 암호화된 web content를 일반적으로 읽을 수 없습니다. 그러나 guest Wi-Fi는 anonymity가 아닙니다. Venue는 association times, device identifiers, captive-portal data, destinations 및 DHCP details를 기록할 수 있으며, cameras, purchases, transport 및 physical observation이 사용자를 식별할 수 있습니다. 비슷한 이름의 fake hotspot은 portal credentials를 탈취하거나 암호화되지 않은 traffic을 조작할 수도 있습니다.<sup>[[9]](#references)</sup>

### 합법적인 guest-network workflow

1. Guest용으로 제공된 network 또는 owner가 명시적으로 permission을 부여한 network만 사용합니다. 직원에게 정확한 SSID와 portal procedure를 문의합니다.
2. 도착 전에 endpoint와 travel router를 업데이트합니다. file/printer sharing, inbound discovery, auto-join 및 remembered-network probing을 비활성화합니다.
3. OS의 private/randomized Wi-Fi address를 활성화합니다. Current Apple systems는 open/weak networks에서 rotating addresses를 사용할 수 있으며, modern Android randomization은 일반적으로 SSID별로 persistent합니다. 이는 하나의 local identifier만 줄입니다.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation과 guest network 사이에 organization-controlled travel router 또는 low-trust bridge device를 두는 방식을 우선합니다. 이렇게 하면 firewall/VPN policy를 중앙화할 수 있지만 venue로부터 router를 숨기지는 못합니다.<sup>[[12]](#references)</sup>
5. 지정된 low-trust device/browser를 통해서만 captive portal을 완료합니다. supposedly anonymous context에서 personal 또는 reused credentials를 입력하지 마세요. Connectivity가 설정되면 portal browser를 닫습니다.
6. 민감한 활동 전에 full-tunnel VPN 또는 Tor를 시작하고 fail-closed behavior를 확인합니다.
7. 사용 후 network를 forget하고 portal account/data-retention policy를 검토합니다.

{% hint style="danger" %}
이웃의 Wi-Fi를 cracking하거나, portal을 우회하거나, leaked guest credentials를 사용하거나, 다른 guest의 access를 cloning하거나, café에 Raspberry Pi를 숨기는 행위는 unauthorized activity이며 privacy technique가 아닙니다. 안전한 대안은 합법적인 guest network, client-approved site 또는 property owner's written consent를 받아 설치하고 회수하는 documented drop node입니다.
{% endhint %}

## Travel router

Travel router는 workstation을 hostile local broadcasts로부터 격리하고, firewall을 적용하며, 일관된 internal SSID를 제공하고, VPN을 자동으로 reconnect할 수 있습니다. 그러나 anonymous하지는 않습니다. Upstream은 radio identity와 traffic timing을 확인하고, VPN provider는 tunnel source를 확인합니다.

- 지원되는 OpenWrt/vendor firmware를 사용하고 사용하지 않는 services를 제거합니다.
- Ethernet 또는 unique password가 설정된 dedicated management SSID를 통해 administer합니다.
- WAN-side administration, UPnP, WPS, file sharing 및 unsolicited inbound traffic을 비활성화합니다.
- 지원되고 허용되는 경우에만 randomized/private WAN MAC을 사용합니다.
- DNS와 IPv6를 포함한 VPN policy를 router에서 강제하고 tunnel이 실패하면 egress를 차단합니다.
- Phone hotspot이 tethered devices를 phone의 VPN을 통해 tunnel한다고 가정하지 말고 테스트합니다.

## Cellular, SIM 및 eSIM

Cellular는 편리하지만 anonymous하지 않습니다. Operators는 subscriber/device identifiers와 network attachment에서 파생된 location을 보관합니다. eSIM도 여전히 mobile subscription입니다. Prepaid가 unregistered를 의미하지는 않으며, requirements는 국가별로 다르고 변경됩니다.<sup>[[13]](#references)</sup>

운영 측면에서는 다음을 따릅니다.

- Personal data의 exposure를 줄이기 위해 별도의 지원되는 device를 사용하되, fictional subscriber를 만들려는 목적으로 사용하지 않습니다.
- Threat model에 co-location이 포함되어 있다면 “separate” device를 personal phone과 함께 지속적으로 휴대하지 않습니다.
- 사용하지 않는 cellular, Wi-Fi, Bluetooth 및 location access를 비활성화합니다. 전원을 끄는 것이 UI toggle보다 강력한 radio boundary입니다.
- Sensitive traffic을 approved VPN/Tor path 안에 두되, carrier가 여전히 subscription/device location과 tunnel endpoint를 안다는 점을 인식합니다.
- National regulator 또는 local counsel을 통해 현재 registration 및 retention rules를 확인합니다. “anonymous SIM countries”의 online lists에 의존하지 않습니다.

## DNS 및 TLS metadata

- **DoH/DoT/DoQ**는 client와 resolver 사이의 DNS를 암호화하여 단순한 local reading 또는 modification을 방지하지만 resolver는 여전히 queries와 transport identifiers를 확인합니다. 이는 trust를 이동할 뿐 anonymity를 제공하지는 않습니다.<sup>[[14]](#references)</sup>
- **ODoH**는 proxy를 추가하여 proxy와 target이 collude하지 않는다는 전제하에 resolver가 client IP를 알 필요가 없도록 합니다. Traffic analysis는 명시적으로 범위에서 제외됩니다.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**는 client, DNS 및 server가 지원할 때 TLS handshake의 inner server name을 보호할 수 있습니다. Destination IP, timing, volume 및 endpoint는 여전히 노출됩니다.<sup>[[16]](#references)</sup>
- 올바르게 구성된 VPN 또는 Tor environment에서는 DNS가 해당 environment가 지원하는 route를 따라야 합니다. 별도의 resolver를 추가하면 새로운 observer 또는 fingerprint가 생길 수 있습니다.

### Encrypted-DNS/ECH verification workflow

1. DNS를 VPN/Tor environment, OS 또는 application 중 어디에서 control할지 결정합니다. 서로 관련 없는 resolver를 중첩하지 말고 **one** intended layer에서 구성합니다.
2. 공개된 privacy/retention policy를 기준으로 resolver를 선택하고 platform이 지원하면 strict encrypted mode를 활성화합니다. Opportunistic fallback은 plaintext로 조용히 돌아갈 수 있습니다.
3. 자신이 control하는 authoritative test zone 아래에 unique subdomain을 query하고 authoritative log에서 의도한 recursive resolver가 확인되는지 검증합니다.
4. Authorization을 받아 test device의 traffic만 capture합니다. Access network가 plaintext DNS를 읽을 수 없는지 확인하되, encrypted resolver/tunnel endpoint는 볼 수 있다는 점을 인식합니다.
5. 차단되었거나 도달할 수 없는 encrypted resolver를 테스트합니다. Pass condition은 선택한 fail-closed 또는 documented fallback behavior이지, 우연히 발생한 clear query가 아닙니다.
6. ECH의 경우 controlled ECH-enabled host를 사용하고 client/server diagnostics를 검사하여 **inner** ClientHello가 accepted되었는지 확인합니다. HTTPS record를 제공하는 것만으로는 ECH 성공이 입증되지 않습니다.
7. Network changes, captive portals, browser updates 및 VPN reconnects 후 반복합니다. 이후 administrators가 bypass를 만들지 않도록 어떤 component가 DNS/ECH를 소유하는지 기록합니다.

## Mixnet

Nym 또는 Katzenpost와 같은 mixnet은 fixed-size packets, delay, reordering 및 cover traffic을 추가하여 timing correlation에 대응합니다. 이러한 properties에는 latency와 bandwidth 비용이 발생하며, independent deployment-scale evidence는 제한적입니다. Current consumer mixnets는 Tor/VPN을 더 빠르거나 보장된 방식으로 대체하는 수단이 아니라 **emerging/high-latency options**로 취급하세요.<sup>[[17]](#references)</sup>

### 평가 workflow

1. 유지 관리되는 client와 정확히 지원되는 application을 확인합니다. 문서화되지 않은 proxy를 통해 임의의 browser/system traffic을 강제로 보내지 않습니다.
2. Entry, mix nodes, gateway, destination 및 collusion assumptions에 대한 current threat model을 읽습니다.
3. 공식 signed source에서 별도의 test compartment에 설치하고 benign owned endpoint만 사용합니다.
4. Delivery latency, message-size limits, reliability, retransmission 및 gateway를 사용할 수 없을 때의 동작을 측정합니다.
5. Local traffic과 owned endpoint를 검사하여 의도한 path와 source를 확인합니다. Replies에도 동일한 privacy design이 적용되는지 확인합니다.
6. Shutdown/failure를 테스트합니다. Application이 direct Internet access로 조용히 fallback해서는 안 됩니다.
7. 단순히 속도를 높이기 위해 cover traffic을 비활성화하거나 delays를 줄이거나 unusual fixed routes를 선택하지 않습니다. 이러한 변경은 명시된 anonymity model을 무효화할 수 있습니다.
8. 특정 deployment, independent analysis 및 operational reliability가 consequence level을 충족할 때까지 experimental 상태로 유지합니다.

## Network preflight checklist

- [ ] Authorization이 access network, target, dates 및 source infrastructure를 포함합니다.
- [ ] Endpoint에 관련 없는 identities 또는 active sync sessions가 없습니다.
- [ ] IPv4, IPv6, DNS 및 reconnect behavior가 plan과 일치합니다.
- [ ] Destination에는 예상한 egress만 표시됩니다.
- [ ] Captive portal 및 hotspot behavior가 sensitive traffic 없이 테스트되었습니다.
- [ ] Local sharing/discovery 및 automatic network joining이 비활성화되었습니다.
- [ ] Observer table과 residual traffic-correlation risk를 수용했습니다.
- [ ] Provider policy, retention 및 emergency contact가 최신 상태입니다.

Split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P 및 disposable remote browsers에 대해서는 [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)를 계속 참고하세요.

## References

- [1] [EFF — 자신에게 적합한 VPN 선택하기](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor가 제공하는 privacy 및 anonymity protections](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor에 대한 간단한 소개](https://spec.torproject.org/intro/)
- [5] [Tor Project — 다른 browsers에서 Tor 사용하기](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser의 plugins 및 add-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor 차단 해제](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPN과 함께 Tor Browser 사용하기](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Public Wi-Fi Networks는 안전한가?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple devices에서 Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization 구현](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstations를 위한 principles](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy 및 regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operators를 위한 recommendations](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
