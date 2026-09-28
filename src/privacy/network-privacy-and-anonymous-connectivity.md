# 네트워크 Privacy & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Network privacy는 완전한 신원이 아니라 routing 결정입니다. 누구로부터 **source**, **destination**, **content**, **timing**을 연결할 수 없게 해야 하는지 질문하여 경로를 선택하세요.

각 access-path family에 대한 정규화된 목록인 `Pros`, `Cons`, 단계별 `Procedure`, `Detection`은 [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)에서 확인하세요. 이 페이지에서는 일반적으로 deploy 가능한 옵션을 확장해 설명합니다.

## 각 observer가 일반적으로 볼 수 있는 정보

| 경로 | 로컬 네트워크 / ISP | 중개자 | Destination | 주요 제한 | 상대적 속도 |
|---|---|---|---|---|---|
| Direct HTTPS | Source, destination 메타데이터, timing/volume | Hosting/CDN은 연결을 확인 | Source IP, browser/app data | source-IP privacy 없음 | 가장 빠름 |
| Commercial VPN | VPN에 연결된 source; 일반적인 destination 메타데이터는 확인하지 못함 | VPN은 source와 destination 메타데이터를 확인 | VPN egress IP | 한 provider가 correlation point가 됨 | 일반적으로 빠름 |
| Self-hosted VPN/VPS | VPS에 연결된 source | Host/account/payment/control-plane logs | VPS egress IP | 임대한 server/account로 쉽게 귀속 가능 | 일반적으로 빠름 |
| Tor Browser | Tor/bridge에 연결된 source; timing/volume | 각 relay는 제한된 일부만 확인 | Tor exit, browser data | 더 느림; account/endpoint/correlation risks | 보통/느림 |
| Tails/Whonix | 더 강력한 routing 경계를 사용하는 유사한 Tor 경로 | 동일한 Tor 제한 | Tor exit/application data | 운영 실수와 host/hardware가 여전히 남음 | 보통/느림 |
| Public guest Wi-Fi + HTTPS | Venue는 로컬 device/timing과 destination을 확인 | Venue ISP는 메타데이터를 확인 | Guest public IP | 물리적/captive-portal/device correlation | 빠름/가변적 |
| Cellular hotspot | Carrier는 subscriber/device/location과 destination을 확인 | 사용 시 VPN/Tor | Carrier, VPN 또는 Tor egress IP | Mobile subscription과 location은 지속적인 식별자 | 빠름/가변적 |
| Mixnet | Access는 mixnet 사용, timing/volume을 확인 | 여러 mixing node | Gateway/egress | 발전 중인 ecosystem; latency와 bandwidth 비용 | 가장 느림 |

HTTPS는 전송 중인 content를 보호하지만 모든 메타데이터를 보호하지는 않습니다. EFF에 따르면 page path, credentials, messages가 암호화되어 있어도 domain, time, traffic size는 중개자에게 계속 노출될 수 있습니다.<sup>[[1]](#references)</sup>

## VPN: 집중된 trust를 통한 빠른 privacy

VPN은 access ISP로부터 destination 메타데이터를 숨기거나, 신뢰할 수 없는 네트워크에서 첫 번째 hop을 보호하거나, 안정적인 engagement egress address를 제공하거나, private network에 접근하는 데 유용합니다. 하지만 VPN이 사용자를 anonymous하게 만들지는 않습니다. VPN은 source connection을 확인하고 destination 메타데이터를 관찰할 수 있으며, accounts, cookies, GPS, fingerprints, payment information은 그대로 남습니다.<sup>[[1]](#references)</sup>

### Provider 평가 checklist

1. **Ownership and jurisdiction:** legal entity, parent company, operating countries, infrastructure subcontractors, 적용 가능한 legal process를 식별합니다.
2. **Collected data:** account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries, destination logs를 구분합니다. “No browsing logs”가 “no data”를 의미하지는 않습니다.
3. **Retention and deletion:** 정확한 보존 기간과 backups, fraud systems, processors가 동일한 일정을 따르는지 확인합니다.
4. **Evidence:** scope, date, findings, remediation이 포함된 public audits, reproducible/open clients, transparency reports, documented incidents를 우선합니다.
5. **Protocol and client:** 유지 관리되는 WireGuard, OpenVPN 또는 검토된 다른 protocol, automatic updates, DNS 및 IPv6 handling, kill switch, platform별 leak tests를 확인합니다.
6. **Business model:** 무료 또는 subsidized service가 어떻게 자금을 조달하는지 이해합니다. App-store에 존재한다는 사실만으로 신뢰할 수 있는 운영의 증거가 되지는 않습니다.
7. **Payment fit:** alternative payment는 VPN에 대한 billing disclosure를 줄일 수 있지만, 모든 연결에서 관찰되는 source IP를 지우지는 못합니다.

### VPN 구성 및 검증

1. 공식 source에서 provider/organization의 signed client를 설치합니다.
2. 문서화된 route가 우회해야 하는 경우가 아니라면 **full tunnel**을 선택합니다. Split tunneling은 correlation 및 leak 경로를 만듭니다.
3. fail-closed/always-on 동작을 활성화하고 reconnect 중 traffic을 차단합니다.
4. DNS를 tunnel을 통해 전송하고 IPv4와 IPv6를 모두 테스트합니다. 안전하게 tunnel할 수 없고 기능 손실을 수용하는 경우에만 protocol을 비활성화합니다.
5. sleep/wake, network switching, captive-portal login, tunnel crash, hotspot tethering을 테스트합니다. NCSC는 일부 platform에서 tethered client가 phone의 VPN을 우회할 수 있다고 경고합니다.<sup>[[2]](#references)</sup>
6. organization-controlled test endpoint를 사용하여 관찰된 IPv4, IPv6, DNS resolver, connection timing을 기록합니다. 민감한 engagement를 무작위 “leak test” site에 노출하지 마세요.
7. client, OS, network 또는 policy가 변경된 후 다시 테스트합니다.

### Hostile-LAN routing bypass

VPN은 운영 체제가 VPN이 packet을 암호화하기 **전에** route를 선택하기 때문에, 선택된 packet이 VPN을 우회하는 동안에도 표면적으로 “connected” 상태를 유지할 수 있습니다. TunnelCrack은 일반적인 routing exception을 악용하는 두 가지 방법을 보여주었습니다. **LocalNet**은 Internet destination이 직접 연결된 subnet에 있는 것처럼 보이게 하며, **ServerIP**는 VPN-gateway resolution을 spoof하여 target address가 VPN transport에 필요한 clear-network exception을 상속하도록 합니다. 이는 WireGuard, OpenVPN, IPsec 또는 TLS 자체의 break가 아니라 client/routing failure입니다. HTTPS payload는 end-to-end encrypted 상태로 유지되지만, 로컬 observer는 destination/timing 메타데이터와 cleartext protocol data를 복구할 수 있습니다.<sup>[[18]](#references)</sup>

TunnelVision은 DHCP option 121을 통해 동일한 pre-encryption primitive을 적용합니다. 악성 또는 침해된 DHCP server는 VPN의 catch-all route보다 더 구체적인 classless route를 설치하여 임의의 host 또는 range에 대해 physical interface를 선택할 수 있습니다. VPN control channel은 계속 유지될 수 있으므로, tunnel disconnection만을 기준으로 작동하는 kill switch가 활성화되지 않을 수 있으며, 단일 public “IP leak” check로는 선택적인 bypass를 발견하지 못할 수 있습니다.<sup>[[19]](#references)</sup>

physical interface에서 DHCP와 authenticated VPN transport만 허용하는 packet-filter kill switch는 이를 fail-closed 동작으로 전환해야 합니다. 그러나 targeted route injection은 여전히 selective-denial side channel을 만들 수 있습니다. 영향이 큰 Linux workload에서는 더 강력한 [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload)을 우선하세요. 이 방식에서는 application namespace에 physical interface나 clear-network default route가 없습니다.<sup>[[19]](#references)</sup>

#### Owned-lab verification

소유한 AP, DHCP server, VPN endpoint, destination에서 정확한 client/OS/version을 테스트하세요. routing 및 packet-filter 구현은 platform별로 다르므로 product-wide claims는 빠르게 오래될 수 있습니다. endpoint 자체와 test server 양쪽에서 capture를 수행하세요. egress-IP website만으로는 모든 destination이 tunnel을 따르는지 입증할 수 없습니다.<sup>[[18]](#references)[[19]](#references)</sup>

1. VPN에 연결하고 VPN-server address를 기록한 뒤, 모든 IPv4/IPv6 routing table과 policy-routing rule을 저장합니다. Windows에서는 `route print`, macOS에서는 `netstat -rn`, Linux에서는 아래 명령을 사용합니다.
2. 소유한 여러 destination IP에 대해 선택된 route를 query합니다. 문서화된 VPN transport endpoint를 제외하면 next hop/interface는 tunnel이어야 합니다.
3. TunnelVision의 경우 controlled DHCP network에서 lease를 갱신하고 **소유한 test destination에만** option 121 route를 설치합니다. 통과 조건은 traffic이 여전히 tunneled되거나 blocked되는 것입니다. physical interface에서 destination traffic으로 절대 전송되어서는 안 됩니다.
4. LocalNet의 경우 client에 `203.0.113.0/24`와 같은 lab 전용 public documentation subnet을 할당하고, 소유한 test destination을 그 안에 배치합니다. LAN access를 활성화해도 Internet-class destination이 tunnel을 우회하지 않는지 확인합니다.
5. ServerIP의 경우 VPN connection 전에 controlled DNS가 소유한 VPN hostname을 소유한 test destination으로 resolve하도록 하고, lab gateway가 VPN transport를 실제 소유 VPN endpoint로 forward하도록 합니다. client는 spoofed address로 향하는 관련 없는 application traffic을 exempt해서는 안 됩니다.
6. “local network access”를 enabled 및 disabled 상태로 각각 설정하여 reconnect, sleep/wake, network switching, VPN-process crash 이후에도 반복합니다. IPv4, IPv6, DNS를 독립적으로 테스트합니다.
7. physical-interface capture를 검사합니다. 여기에는 DHCP와 VPN server로 향하는 encrypted packet이 포함되어야 하며, 소유한 test destination으로 직접 주소 지정된 packet은 포함되지 않아야 합니다. 또한 거부된 bypass가 user prompt 또는 connectivity repair 이후 조용히 fallback하지 못하는지 확인합니다.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: 더 강력한 웹 연결성 분리

Tor는 여러 relay를 통해 circuit을 구축하므로 일반적으로 단일 relay가 source와 destination을 모두 알 수 없습니다. destination에는 사용자의 IP가 아닌 Tor exit가 표시되고, local network에는 일반적으로 Tor connection이 표시됩니다.<sup>[[3]](#references)</sup> Tor는 low-latency TCP application을 위해 설계되었으므로 더 느리며, 양쪽 끝을 correlation할 수 있는 adversary에 대한 보호를 보장할 수 없습니다.<sup>[[4]](#references)</sup>

### 안전한 Tor Browser workflow

1. Tor Browser는 Tor Project 또는 공식 mirror에서만 download하고, 가능하면 signature를 verify합니다.
2. 일반 browser를 Tor SOCKS port에 연결하지 말고 **Tor Browser**를 사용합니다. 일반 browser는 DNS/WebRTC 및 식별 가능한 state를 leak할 수 있습니다.<sup>[[5]](#references)</sup>
3. 기본 size, fonts, extensions 및 privacy settings를 유지합니다. 추가 add-on은 browser를 더 unique하게 만들 수 있습니다.<sup>[[6]](#references)</sup>
4. breakage 증가를 감수할 수 있다면 **Safer** 또는 **Safest** security level을 선택합니다.
5. direct Tor가 차단되었거나 일반 relay IP가 허용할 수 없는 수준의 local visibility를 만들 경우 bridge를 사용합니다. Bridge는 쉽게 인식되는 것을 줄이지만 traffic analysis를 제거하지는 않습니다.<sup>[[7]](#references)</sup>
6. 식별 가능한 account에 log in하거나, 식별 정보를 제공하거나, download한 active document를 외부 networked application에서 열지 않습니다.
7. 각 identity마다 별도의 session/context를 사용합니다. “New circuit”은 browser/application identity를 지우는 것과 같지 않습니다. 적절한 경우 **New Identity**를 사용하거나 isolated environment를 restart합니다.
8. authenticated HTTPS 또는 authenticated onion service를 우선 사용합니다. Tor exit는 암호화되지 않은 HTTP traffic을 관찰할 수 있습니다.

### Tor와 VPN

둘을 결합한다고 자동으로 더 안전해지는 것은 아닙니다. Tor 앞에 VPN을 두면 ISP에서 direct Tor relay connection을 숨길 수 있지만 VPN은 source를 보게 됩니다. Tor 앞에 VPN을 두면 VPN은 Tor 이후 activity를 안정적으로 관찰할 수 있으며 anonymity set이 줄어들 수 있습니다. Misconfiguration은 leak을 유발할 수 있습니다. Tor Project는 이러한 조합을 advanced하고 명시적인 threat model이 있는 경우에만 권장합니다.<sup>[[8]](#references)</sup>

## Public 및 guest Wi-Fi

현대적인 HTTPS를 사용하면 passive neighbor는 일반적으로 올바르게 암호화된 web content를 읽을 수 없지만, guest Wi-Fi는 anonymity가 아닙니다. Venue는 association time, device identifier, captive-portal data, destination 및 DHCP details를 기록할 수 있습니다. Camera, purchase, transport 및 physical observation으로 사용자를 식별할 수도 있습니다. 이름이 유사한 가짜 hotspot은 portal credential을 수집하거나 암호화되지 않은 traffic을 조작할 수도 있습니다.<sup>[[9]](#references)</sup>

### 합법적인 guest-network workflow

1. Guest에게 제공되는 network 또는 소유자가 명시적으로 permission을 부여한 network만 사용합니다. 직원에게 정확한 SSID와 portal procedure를 문의합니다.
2. 도착 전에 endpoint와 travel router를 update합니다. file/printer sharing, inbound discovery, auto-join 및 remembered-network probing을 disable합니다.
3. OS의 private/randomized Wi-Fi address를 enable합니다. 현재 Apple system은 open/weak network에서 rotating address를 사용할 수 있으며, 최신 Android randomization은 일반적으로 SSID별로 persistent합니다. 이는 하나의 local identifier만 줄입니다.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. privileged workstation과 guest network 사이에 organization-controlled travel router 또는 low-trust bridge device를 우선 사용합니다. 이는 firewall/VPN policy를 centralize하지만 router를 venue로부터 숨기지는 않습니다.<sup>[[12]](#references)</sup>
5. 지정된 low-trust device/browser를 통해서만 captive portal을 완료합니다. 익명 context라고 주장하는 곳에 personal 또는 재사용 credential을 절대 입력하지 않습니다. connectivity가 확립되면 portal browser를 닫습니다.
6. sensitive activity 전에 full-tunnel VPN 또는 Tor를 시작하고 fail-closed behavior를 확인합니다.
7. 사용 후 network를 forget하고 portal account/data-retention policy를 검토합니다.

{% hint style="danger" %}
이웃의 Wi-Fi를 cracking하거나, portal을 bypass하거나, leaked guest credential을 사용하거나, 다른 guest의 access를 cloning하거나, café에 Raspberry Pi를 숨기는 행위는 unauthorized activity이며 privacy technique가 아닙니다. 안전한 대안은 합법적인 guest network, client-approved site, 또는 property owner's written consent를 받아 설치하고 회수하는 documented drop node입니다.
{% endhint %}

## Travel router

Travel router는 hostile local broadcast로부터 workstation을 isolate하고, firewall을 enforce하며, 일관된 internal SSID를 제공하고, VPN을 자동으로 reconnect할 수 있습니다. 하지만 **anonymous**하지 않습니다. Upstream은 radio identity와 traffic timing을 확인할 수 있고, VPN provider는 tunnel source를 확인할 수 있습니다.

- 지원되는 OpenWrt/vendor firmware를 사용하고 사용하지 않는 service를 제거합니다.
- Ethernet 또는 unique password가 설정된 전용 management SSID를 통해 administer합니다.
- WAN-side administration, UPnP, WPS, file sharing 및 unsolicited inbound traffic을 disable합니다.
- 지원되고 허용되는 경우에만 randomized/private WAN MAC을 사용합니다.
- DNS와 IPv6을 포함한 VPN policy를 router에서 enforce하고 tunnel이 실패하면 egress를 block합니다.
- phone hotspot이 tethered device를 phone의 VPN을 통해 tunnel한다고 가정하지 말고 test합니다.

## Cellular, SIM 및 eSIM

Cellular는 편리하지만 anonymous하지 않습니다. Operator는 subscriber/device identifier와 network attachment에서 파생된 location을 유지합니다. eSIM도 mobile subscription입니다. Prepaid라고 해서 reliably unregistered인 것은 아닙니다. 요건은 국가마다 다르고 변경됩니다.<sup>[[13]](#references)</sup>

Operationally:

- personal data의 exposure를 줄이기 위해 별도의 지원되는 device를 사용하되, fictional subscriber를 만들기 위한 용도로 사용하지 않습니다.
- co-location이 threat model에 포함되어 있다면 “separate” device를 personal phone과 계속 함께 휴대하지 않습니다.
- 사용하지 않는 cellular, Wi-Fi, Bluetooth 및 location access를 disable합니다. 전원을 끄는 것은 UI toggle보다 강력한 radio boundary입니다.
- sensitive traffic을 approved VPN/Tor path 안에 넣되, carrier가 여전히 subscription/device location과 tunnel endpoint를 알고 있음을 인식합니다.
- national regulator 또는 local counsel을 통해 현재 registration 및 retention rules를 확인합니다. “anonymous SIM countries”의 online list에 의존하지 않습니다.

## DNS 및 TLS metadata

- **DoH/DoT/DoQ**는 client와 resolver 사이의 DNS를 암호화하여 간단한 local reading 또는 modification을 방지하지만, resolver는 여전히 query와 transport identifier를 확인합니다. 이는 trust를 이동시킬 뿐 anonymity를 제공하지는 않습니다.<sup>[[14]](#references)</sup>
- **ODoH**는 proxy를 추가하여 proxy와 target이 collude하지 않는 한 resolver가 client IP를 알 필요가 없도록 합니다. Traffic analysis는 명시적으로 scope 밖입니다.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**는 client, DNS 및 server가 지원할 때 TLS handshake에서 inner server name을 보호할 수 있습니다. Destination IP, timing, volume 및 endpoint는 계속 노출됩니다.<sup>[[16]](#references)</sup>
- 올바르게 구성된 VPN 또는 Tor environment에서는 DNS가 해당 environment에서 지원하는 route를 따라야 합니다. 별도의 resolver를 추가하면 새로운 observer 또는 fingerprint가 생길 수 있습니다.

### Encrypted-DNS/ECH verification workflow

1. DNS를 VPN/Tor environment, OS 또는 application 중 어디에서 control할지 결정합니다. 관련 없는 resolver를 stacking하지 말고 **하나의** intended layer에서 구성합니다.
2. Published privacy/retention policy에 따라 resolver를 선택하고, platform이 지원하는 경우 strict encrypted mode를 enable합니다. Opportunistic fallback은 조용히 plaintext로 돌아갈 수 있습니다.
3. 자신이 control하는 authoritative test zone 아래에서 unique subdomain을 query하고, authoritative log에 intended recursive resolver가 표시되는지 확인합니다.
4. Authorization을 받은 상태에서 test device의 traffic만 capture합니다. Access network가 plaintext DNS를 읽을 수 없는지 확인하되, encrypted resolver/tunnel endpoint는 볼 수 있음을 인식합니다.
5. 차단되었거나 도달할 수 없는 encrypted resolver를 test합니다. Pass condition은 선택한 fail-closed 또는 documented fallback behavior이지, 우연히 발생한 clear query가 아닙니다.
6. ECH의 경우 controlled ECH-enabled host를 사용하고 client/server diagnostics를 inspect하여 **inner** ClientHello가 accepted되었는지 확인합니다. HTTPS record를 제공하는 것만으로 ECH 성공이 입증되지는 않습니다.
7. Network 변경, captive portal, browser update 및 VPN reconnect 후에 반복합니다. 나중에 administrator가 bypass를 만들지 않도록 어떤 component가 DNS/ECH를 소유하는지 기록합니다.

## Mixnet

Nym 또는 Katzenpost와 같은 mixnet은 fixed-size packet, delay, reordering 및 cover traffic을 추가하여 timing correlation에 저항합니다. 이러한 특성은 latency와 bandwidth 비용을 발생시키며, independent deployment-scale evidence는 제한적입니다. 현재의 consumer mixnet은 Tor/VPN을 더 빠르거나 보장된 방식으로 대체하는 수단이 아니라 **emerging/high-latency options**로 취급합니다.<sup>[[17]](#references)</sup>

### Evaluation workflow

1. 유지 관리되는 client와 정확히 지원되는 application을 확인합니다. 문서화되지 않은 proxy를 통해 임의의 browser/system traffic을 강제로 보내지 않습니다.
2. Entry, mix node, gateway, destination 및 collusion assumption에 대한 최신 threat model을 읽습니다.
3. 별도의 test compartment에 공식 signed source에서 install하고, benign owned endpoint만 사용합니다.
4. Delivery latency, message-size limit, reliability, retransmission 및 gateway를 사용할 수 없을 때의 동작을 측정합니다.
5. Local traffic과 owned endpoint를 inspect하여 intended path와 source를 확인합니다. Reply가 동일한 privacy design을 사용하는지도 확인합니다.
6. Shutdown/failure를 test합니다. Application이 direct Internet access로 조용히 fallback하지 않아야 합니다.
7. 속도만을 위해 cover traffic을 disable하거나, delay를 줄이거나, unusual fixed route를 선택하지 않습니다. 이러한 변경은 명시된 anonymity model을 무효화할 수 있습니다.
8. 특정 deployment, independent analysis 및 operational reliability가 consequence level을 충족할 때까지 experimental 상태로 유지합니다.

## Network preflight checklist

- [ ] Authorization에 access network, target, dates 및 source infrastructure가 포함됩니다.
- [ ] Endpoint에 관련 없는 identity 또는 active sync session이 없습니다.
- [ ] IPv4, IPv6, DNS 및 reconnect behavior가 plan과 일치합니다.
- [ ] Controlled DHCP/local-subnet route injection으로 인해 test traffic이 physical interface로 이동할 수 없습니다.
- [ ] Destination에는 예상된 egress만 표시됩니다.
- [ ] Captive portal 및 hotspot behavior가 sensitive traffic 없이 test되었습니다.
- [ ] Local sharing/discovery 및 automatic network joining이 disable되었습니다.
- [ ] Observer table과 잔여 traffic-correlation risk를 수용했습니다.
- [ ] Provider policy, retention 및 emergency contact가 최신 상태입니다.

Split-knowledge relay, route-enforced workload, pluggable transport, onion service, I2P 및 disposable remote browser에 대해서는 [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)를 계속 참조합니다.



## References

- [1] [EFF — 자신에게 적합한 VPN 선택하기](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor가 제공하는 privacy 및 anonymity 보호](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor에 대한 간단한 소개](https://spec.torproject.org/intro/)
- [5] [Tor Project — 다른 browser와 함께 Tor 사용하기](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser의 plugin 및 add-on](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor 차단 해제하기](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPN과 함께 Tor Browser 사용하기](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Public Wi-Fi network는 안전한가?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple device에서의 Wi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization 구현하기](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstation을 위한 원칙](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operator를 위한 권고](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Bypassing Tunnels: Routing Table 악용을 통한 VPN Client Traffic Leaking](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: 공격자가 Routing-Based VPN을 Decloak하여 Total VPN Leak을 일으키는 방법](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
