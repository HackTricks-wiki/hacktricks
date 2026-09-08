# Network Privacy & Anonymous Connectivity

Network privacy는 완전한 identity가 아니라 routing decision입니다. 누가 **source**, **destination**, **content**, **timing**을 서로 연결할 수 없어야 하는지 질문하여 경로를 선택하세요.

정규화된 inventory인 모든 access-path family의 `Pros`, `Cons`, 단계별 `Procedure`, `Detection`은 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)에서 확인하세요. 이 페이지에서는 일반적으로 deploy 가능한 옵션을 확장하여 설명합니다.

## 각 observer가 일반적으로 볼 수 있는 정보

| Path | Local network / ISP | Intermediary | Destination | Main limitation | Relative speed |
|---|---|---|---|---|---|
| Direct HTTPS | Source, destination metadata, timing/volume | Hosting/CDN sees connection | Source IP, browser/app data | No source-IP privacy | Fastest |
| Commercial VPN | Source connected to VPN; not usual destination metadata | VPN sees source and destination metadata | VPN egress IP | One provider becomes a correlation point | Usually fast |
| Self-hosted VPN/VPS | Source connected to VPS | Host/account/payment/control-plane logs | VPS egress IP | Easy to attribute to the rented server/account | Usually fast |
| Tor Browser | Source connected to Tor/bridge; timing/volume | Relays each see a limited portion | Tor exit, browser data | Slower; account/endpoint/correlation risks | Moderate/slow |
| Tails/Whonix | Similar Tor path, with stronger routing boundaries | Same Tor limitations | Tor exit/application data | Operational mistakes and host/hardware remain | Moderate/slow |
| Public guest Wi-Fi + HTTPS | Venue sees local device/timing and destinations | Venue ISP sees metadata | Guest public IP | Physical/captive-portal/device correlation | Fast/variable |
| Cellular hotspot | Carrier sees subscriber/device/location and destinations | VPN/Tor if used | Carrier, VPN, or Tor egress IP | Mobile subscription and location are durable identifiers | Fast/variable |
| Mixnet | Access sees mixnet use; timing/volume | Multiple mixing nodes | Gateway/egress | Emerging ecosystem; latency and bandwidth cost | Slowest |

HTTPS는 전송 중인 content를 보호하지만 모든 metadata를 보호하지는 않습니다. EFF에 따르면 page path, credentials, messages가 암호화되어 있어도 domain, time, traffic size는 intermediary에 계속 노출될 수 있습니다.<sup>[[1]](#references)</sup>

## VPN: 빠른 privacy와 집중된 trust

VPN은 access ISP로부터 destination metadata를 숨기거나, 신뢰할 수 없는 network에서 first hop을 보호하거나, 안정적인 engagement egress address를 제공하거나, private network에 접근할 때 유용합니다. 하지만 사용자를 anonymous하게 만들지는 **않습니다**. VPN은 source connection을 볼 수 있고 destination metadata를 관찰할 수 있으며, accounts, cookies, GPS, fingerprints, payment information은 그대로 남습니다.<sup>[[1]](#references)</sup>

### Provider evaluation checklist

1. **Ownership and jurisdiction:** legal entity, parent company, operating countries, infrastructure subcontractors 및 적용 가능한 legal process를 확인합니다.
2. **Collected data:** account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries 및 destination logs를 구분합니다. “No browsing logs”가 “no data”를 의미하지는 않습니다.
3. **Retention and deletion:** 정확한 보존 기간과 backups, fraud systems, processors가 동일한 일정을 따르는지 확인합니다.
4. **Evidence:** scope, date, findings 및 remediation이 공개된 audits, reproducible/open clients, transparency reports 및 문서화된 incidents를 우선합니다.
5. **Protocol and client:** 유지 관리되는 WireGuard, OpenVPN 또는 검토된 다른 protocol, automatic updates, DNS 및 IPv6 handling, kill switch, platform별 leak tests를 확인합니다.
6. **Business model:** 무료 또는 subsidized service가 어떻게 운영 자금을 조달하는지 이해합니다. App-store presence만으로 trustworthy operation을 입증할 수는 없습니다.
7. **Payment fit:** alternative payment는 VPN에 billing disclosure를 줄일 수 있지만, 모든 connection에서 관찰되는 source IP를 삭제하지는 않습니다.

### VPN configure 및 verify

1. provider/organization의 signed client를 공식 source에서 설치합니다.
2. 문서화된 route를 우회해야 하는 경우가 아니라면 **full tunnel**을 선택합니다. Split tunneling은 correlation 및 leak path를 만듭니다.
3. fail-closed/always-on behavior를 활성화하고 reconnect 중 traffic을 차단합니다.
4. DNS를 tunnel을 통해 전송하고 IPv4 및 IPv6를 모두 테스트합니다. 안전하게 tunnel할 수 없는 경우에만 protocol을 비활성화하며, 기능 손실을 수용해야 합니다.
5. sleep/wake, network switching, captive-portal login, tunnel crash 및 hotspot tethering을 테스트합니다. NCSC는 일부 platform에서 tethered client가 phone의 VPN을 우회할 수 있다고 경고합니다.<sup>[[2]](#references)</sup>
6. organization-controlled test endpoint를 사용하여 관찰된 IPv4, IPv6, DNS resolver 및 connection timing을 기록합니다. 민감한 engagement를 무작위 “leak test” site에 노출하지 마세요.
7. client, OS, network 또는 policy가 변경된 후 다시 테스트합니다.

## Tor Browser: 더 강력한 web unlinkability

Tor는 여러 relay를 거치는 circuit을 구성하므로 일반적으로 어느 하나의 relay도 source와 destination을 모두 알 수 없습니다. Destination은 사용자의 IP 대신 Tor exit를 보며, local network에는 일반적으로 Tor connection이 보입니다.<sup>[[3]](#references)</sup> Tor는 low-latency TCP application을 위해 설계되었으므로 더 느리며, 양쪽 끝을 correlation할 수 있는 adversary에 대한 보호를 보장하지 않습니다.<sup>[[4]](#references)</sup>

### Safe Tor Browser workflow

1. Tor Browser는 Tor Project 또는 공식 mirror에서만 download하고, 가능하면 signature를 verify합니다.
2. 일반 browser에서 Tor SOCKS port를 지정하지 말고 **Tor Browser**를 사용합니다. 일반 browser는 DNS/WebRTC 및 identifying state를 leak할 수 있습니다.<sup>[[5]](#references)</sup>
3. 기본 size, fonts, extensions 및 privacy settings를 유지합니다. 추가 add-on은 browser를 더 unique하게 만들 수 있습니다.<sup>[[6]](#references)</sup>
4. 증가한 breakage를 감수할 수 있다면 **Safer** 또는 **Safest** security level을 선택합니다.
5. direct Tor가 차단되었거나 일반 relay IP가 허용할 수 없는 local visibility를 만들 경우 bridge를 사용합니다. Bridge는 쉽게 인식되는 것을 줄이지만 traffic analysis를 제거하지는 않습니다.<sup>[[7]](#references)</sup>
6. identifying account에 login하거나 identifying information을 제공하지 말고, download한 active document를 외부 networked application에서 열지 않습니다.
7. 각 identity마다 별도의 session/context를 사용합니다. “New circuit”은 browser/application identity를 지우는 것과 같지 않습니다. 적절한 경우 **New Identity**를 사용하거나 isolated environment를 restart합니다.
8. Authenticated HTTPS 또는 authenticated onion service를 우선합니다. Tor exit는 암호화되지 않은 HTTP traffic을 관찰할 수 있습니다.

### Tor plus VPN

두 가지를 결합한다고 자동으로 더 안전해지는 것은 아닙니다. Tor보다 앞에 VPN을 두면 ISP로부터 direct Tor relay connection을 숨길 수 있지만 VPN은 source를 봅니다. Tor보다 뒤에 VPN을 두면 VPN이 Tor 이후 activity를 안정적으로 관찰하게 되며 anonymity set이 줄어들 수 있습니다. 잘못된 configuration은 leaks를 만들 수 있습니다. Tor Project는 이러한 조합을 advanced하고 명확한 threat model이 있는 경우에만 권장합니다.<sup>[[8]](#references)</sup>

## Public 및 guest Wi-Fi

현대적인 HTTPS는 passive neighbor가 올바르게 암호화된 web content를 일반적으로 읽지 못하게 하지만, guest Wi-Fi는 anonymity가 아닙니다. Venue는 association times, device identifiers, captive-portal data, destinations 및 DHCP details를 기록할 수 있습니다. Cameras, purchases, transport 및 physical observation이 사용자를 식별할 수 있습니다. 비슷한 이름의 fake hotspot은 portal credentials를 capture하거나 암호화되지 않은 traffic을 조작할 수도 있습니다.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Guest에게 제공되는 network 또는 owner가 명시적으로 permission을 부여한 network만 사용합니다. 정확한 SSID와 portal procedure를 staff에게 확인합니다.
2. 도착 전에 endpoint와 travel router를 update합니다. File/printer sharing, inbound discovery, auto-join 및 remembered-network probing을 비활성화합니다.
3. OS의 private/randomized Wi-Fi address를 활성화합니다. 최신 Apple system은 open/weak network에서 rotating address를 사용할 수 있으며, 최신 Android randomization은 일반적으로 SSID별로 persistent합니다. 이는 하나의 local identifier만 줄입니다.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Privileged workstation과 guest network 사이에 organization-controlled travel router 또는 low-trust bridge device를 두는 것을 우선합니다. 이는 firewall/VPN policy를 중앙화하지만 router를 venue로부터 숨기지는 않습니다.<sup>[[12]](#references)</sup>
5. Designated low-trust device/browser를 통해서만 captive portal을 완료합니다. 익명 context에서 personal 또는 reused credentials를 입력하지 마세요. Connectivity가 확보되면 portal browser를 닫습니다.
6. 민감한 activity 전에 full-tunnel VPN 또는 Tor를 시작하고 fail-closed behavior를 확인합니다.
7. 사용 후 network를 forget하고 portal account/data-retention policy를 검토합니다.

{% hint style="danger" %}
이웃의 Wi-Fi를 cracking하거나, portal을 bypass하거나, leaked guest credentials를 사용하거나, 다른 guest의 access를 cloning하거나, café에 Raspberry Pi를 숨기는 것은 unauthorized activity이며 privacy technique가 아닙니다. 안전한 대안은 lawful guest network, client-approved site 또는 property owner's written consent를 받아 배치하고 회수하는 documented drop node입니다.
{% endhint %}

## Travel router

Travel router는 workstation을 hostile local broadcast로부터 격리하고, firewall을 적용하며, 일관된 internal SSID를 제공하고, VPN을 자동으로 reconnect할 수 있습니다. 하지만 **anonymous**하지는 않습니다. Upstream은 router의 radio identity와 traffic timing을 보고, VPN provider는 tunnel source를 봅니다.

- 지원되는 OpenWrt/vendor firmware를 사용하고 사용하지 않는 services를 제거합니다.
- Ethernet 또는 고유 password가 설정된 dedicated management SSID를 통해 administer합니다.
- WAN-side administration, UPnP, WPS, file sharing 및 unsolicited inbound traffic을 비활성화합니다.
- 지원되고 허용되는 경우 randomized/private WAN MAC을 사용합니다.
- DNS 및 IPv6를 포함한 VPN policy를 router에서 enforce하고 tunnel이 실패하면 egress를 차단합니다.
- Phone hotspot이 tethered device를 phone의 VPN을 통해 tunnel한다고 가정하지 말고 테스트합니다.

## Cellular, SIM 및 eSIM

Cellular는 편리하지만 anonymous하지 않습니다. Operator는 subscriber/device identifiers와 network attachment에서 파생된 location을 유지합니다. eSIM도 여전히 mobile subscription입니다. Prepaid가 항상 unregistered를 의미하지는 않으며, requirements는 국가별로 다르고 변경됩니다.<sup>[[13]](#references)</sup>

Operationally:

- Personal data의 exposure를 줄이기 위해 별도의 지원되는 device를 사용하되, fictional subscriber를 만들려는 목적으로 사용하지 않습니다.
- Threat model에 co-location이 포함되어 있다면 “separate” device를 personal phone과 함께 지속적으로 휴대하지 않습니다.
- 사용하지 않는 cellular, Wi-Fi, Bluetooth 및 location access를 비활성화합니다. 전원을 끄는 것이 UI toggle보다 강력한 radio boundary입니다.
- Sensitive traffic을 승인된 VPN/Tor path 내부에 두되, carrier가 subscription/device location과 tunnel endpoint를 여전히 안다는 점을 인식합니다.
- National regulator 또는 local counsel을 통해 현재 registration 및 retention rules를 확인합니다. “anonymous SIM countries”의 online list에 의존하지 마세요.

## DNS 및 TLS metadata

- **DoH/DoT/DoQ**는 client와 resolver 사이의 DNS를 암호화하여 단순한 local reading 또는 modification을 방지하지만, resolver는 여전히 queries 및 transport identifiers를 봅니다. 이는 trust를 이동시킬 뿐 anonymity를 제공하지는 않습니다.<sup>[[14]](#references)</sup>
- **ODoH**는 proxy를 추가하여 proxy와 target이 collude하지 않는 한 resolver가 client IP를 알 필요가 없도록 합니다. Traffic analysis는 명시적으로 범위에서 제외됩니다.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**는 client, DNS 및 server가 지원할 경우 TLS handshake의 inner server name을 보호할 수 있습니다. Destination IP, timing, volume 및 endpoint는 여전히 노출됩니다.<sup>[[16]](#references)</sup>
- 올바르게 configured된 VPN 또는 Tor environment에서는 DNS가 해당 environment에서 지원하는 route를 따라야 합니다. 별도의 resolver를 추가하면 새로운 observer 또는 fingerprint가 생길 수 있습니다.

### Encrypted-DNS/ECH verification workflow

1. DNS를 VPN/Tor environment, OS 또는 application 중 어디에서 control할지 결정합니다. 서로 관련 없는 resolver를 중첩하지 말고 **하나의** 의도한 layer에서 configure합니다.
2. 공개된 privacy/retention policy를 기준으로 resolver를 선택하고, platform이 지원하면 strict encrypted mode를 활성화합니다. Opportunistic fallback은 조용히 plaintext로 돌아갈 수 있습니다.
3. 자신이 control하는 authoritative test zone 아래에서 unique subdomain을 query하고 authoritative log에 의도한 recursive resolver가 표시되는지 확인합니다.
4. Authorization을 받은 상태에서 test device의 traffic만 capture합니다. Access network가 plaintext DNS를 읽을 수 없는지 확인하되, encrypted resolver/tunnel endpoint는 볼 수 있음을 인식합니다.
5. Blocked/unreachable encrypted resolver를 테스트합니다. Pass condition은 선택한 fail-closed 또는 documented fallback behavior이지, 우연히 발생한 clear query가 아닙니다.
6. ECH의 경우 controlled ECH-enabled host를 사용하고 client/server diagnostics를 검사하여 **inner** ClientHello가 accepted되었는지 확인합니다. HTTPS record를 제공하는 것만으로는 ECH 성공을 입증할 수 없습니다.
7. Network changes, captive portals, browser updates 및 VPN reconnect 후 반복합니다. 나중에 administrators가 bypass를 만들지 않도록 DNS/ECH를 어느 component가 소유하는지 기록합니다.

## Mixnet

Nym 또는 Katzenpost와 같은 Mixnet은 fixed-size packets, delay, reordering 및 cover traffic을 추가하여 timing correlation에 저항합니다. 이러한 특성에는 latency와 bandwidth 비용이 발생하며, 독립적인 deployment-scale evidence는 제한적입니다. 현재 consumer mixnet은 Tor/VPN을 더 빠르거나 보장된 방식으로 대체하는 수단이 아니라 **emerging/high-latency options**로 취급하세요.<sup>[[17]](#references)</sup>

### Evaluation workflow

1. 유지 관리되는 client와 정확히 지원되는 application을 확인합니다. 문서화되지 않은 proxy를 통해 임의의 browser/system traffic을 강제로 전송하지 않습니다.
2. Entry, mix nodes, gateway, destination 및 collusion assumptions에 대한 현재 threat model을 읽습니다.
3. 공식 signed source에서 별도의 test compartment에 install하고 benign owned endpoint만 사용합니다.
4. Delivery latency, message-size limits, reliability, retransmission 및 gateway를 사용할 수 없을 때의 동작을 측정합니다.
5. Local traffic과 owned endpoint를 검사하여 의도한 path와 source를 확인합니다. Replies가 동일한 privacy design을 사용하는지도 확인합니다.
6. Shutdown/failure를 테스트합니다. Application이 direct Internet access로 조용히 fallback해서는 안 됩니다.
7. 단순히 속도를 높이기 위해 cover traffic을 비활성화하거나, delays를 줄이거나, unusual fixed routes를 선택하지 않습니다. 이러한 변경은 명시된 anonymity model을 무효화할 수 있습니다.
8. 특정 deployment, independent analysis 및 operational reliability가 consequence level을 충족할 때까지 experimental 상태로 유지합니다.

## Network preflight checklist

- [ ] Authorization이 access network, target, dates 및 source infrastructure를 포함합니다.
- [ ] Endpoint에 unrelated identities 또는 active sync sessions가 없습니다.
- [ ] IPv4, IPv6, DNS 및 reconnect behavior가 plan과 일치합니다.
- [ ] Destination에는 예상된 egress만 표시됩니다.
- [ ] Captive portal 및 hotspot behavior가 sensitive traffic 없이 테스트되었습니다.
- [ ] Local sharing/discovery 및 automatic network joining이 비활성화되었습니다.
- [ ] Observer table 및 residual traffic-correlation risk를 수용했습니다.
- [ ] Provider policy, retention 및 emergency contact가 최신 상태입니다.

Split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P 및 disposable remote browsers는 [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)를 계속 확인하세요.

## References

- [1] [EFF — Choosing the VPN That's Right for You](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — The privacy and anonymity protections Tor offers](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — A short introduction to Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Using Tor with other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins and add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Are Public Wi-Fi Networks Safe?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy with Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implement MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principles for Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommendations for DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
