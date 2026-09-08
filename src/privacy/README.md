# Offensive Privacy, Attribution Evasion 및 OPSEC

이 섹션은 red team, intrusion operator 및 해당 operator를 재구성하려는 defender의 관점에서 privacy를 다룹니다. **Anonymity는 단순히 IP address를 숨기는 것이 아닙니다.** 성숙한 operation은 attribution graph로 연결될 수 있는 사람, endpoint, account, infrastructure, network path, payload 및 payment를 분리합니다.

이 자료에는 정부 및 APT operation에서 보고된 기법이 의도적으로 포함되어 있습니다. operational-relay-box (ORB) network, compromised edge device, residential exit, redirector tier, fast flux, domain fronting, dead-drop resolver, nearby wireless pivot, covert drop device, satellite-link abuse, false persona 및 financial layering가 이에 해당합니다. 각 기법은 다음과 같이 제시됩니다.

1. operational objective 및 ATT&CK mapping;
2. mechanism 및 trust boundary;
3. 모든 observer가 여전히 기록할 수 있는 내용;
4. 이를 무력화하는 실수와 stable artifact;
5. defensive telemetry, analytics 및 mitigation; 그리고
6. 소유하거나 명시적으로 범위가 지정된 infrastructure를 사용하는 authorized emulation.

따라서 이는 offensive tradecraft reference이자 defender의 attribution manual입니다. 목표는 advanced behavior를 이해하고 검증 가능하게 만드는 것이며, 하나의 commercial service가 operator를 보이지 않게 만든다고 가장하는 것이 아닙니다.

**Research cutoff:** 2026년 9월 8일. Provider availability, product behavior, sanctions, cash/prepaid threshold, SIM-registration rule 및 crypto regulation은 자주 변경되므로 이에 의존하기 전에 다시 확인하십시오.

{% hint style="danger" %}
Technique를 이해하는 것은 이를 수행할 authorization이 있다는 뜻이 아닙니다. 이 페이지는 compromised router, 이웃의 Wi-Fi, hidden device, stolen identity 및 laundering과 같은 criminal abuse를 mechanism-and-detection level에서 설명합니다. 재현 단계에서는 소유한 lab system, synthetic identity 및 test asset만 사용합니다. 절대로 third party에 access하거나 KYC 또는 sanctions를 회피하거나 criminal proceeds를 은닉하지 마십시오. Unauthorized access는 US CFAA, UK Computer Misuse Act 및 Directive 2013/40/EU를 이행하는 EU member-state 법률을 포함하여 많은 관할권에서 범죄로 규정됩니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Adversary objective map

| Adversary objective | Technique families | Principal defensive question |
|---|---|---|
| Operator의 origin 숨기기 | VPN/Tor, external 및 multi-hop proxy, residential/mobile exit, ORB, satellite link | Last-hop address는 actor asset, 모르는 victim 또는 단기간 relay인가? |
| 실제 C2를 발견할 수 없게 유지하기 | redirector, CDN, domain fronting, dead-drop resolver, dynamic DNS, fast flux | IP/domain rotation 이후에도 유지되는 stable behavior는 무엇인가? |
| Trust와 reputation 빌리기 | compromised server, router, cloud 및 web-service account, domain shadowing | 평판이 좋은 asset이 historical baseline과 다르게 동작하는가? |
| Physical 또는 network boundary 통과하기 | nearest-neighbor Wi-Fi pivot, on-site drop, rogue peripheral, cellular backhaul | 어떤 새로운 radio, device, switchport 또는 outbound tunnel이 나타났는가? |
| Human과 operation 분리하기 | persona, account/device compartmentation, cover communication, procurement separation | 어떤 recovery field, browser, schedule, language, payment 또는 admin event가 persona를 연결하는가? |
| Funding과 cash-out 불명확하게 만들기 | mule/nominee, prepaid value, mixer, CoinJoin, peel chain, chain hopping, OTC broker | On-chain 및 off-chain identity record가 어디에서 다시 연결되는가? |

가장 가까운 ATT&CK resource-development 및 C2 concept는 **Acquire Infrastructure (T1583)**, **Compromise Infrastructure (T1584)**, **Establish/Compromise Accounts (T1585/T1586)**, **Proxy (T1090)**, **Dynamic Resolution (T1568)** 및 **Web Service (T1102)**입니다.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

## Privacy, pseudonymity, anonymity 및 security

| Goal | Meaning | Typical failure |
|---|---|---|
| **Confidentiality** | 외부인이 content를 읽을 수 없음 | Metadata가 여전히 당사자를 식별함 |
| **Privacy** | 필요한 범위로만 information disclosure가 제한됨 | Provider가 예상보다 많은 data를 보관함 |
| **Pseudonymity** | Legal identity와 공개적으로 연결되지 않은 stable identity를 사용하여 activity 수행 | Recovery email, payment, IP, photo 또는 writing style이 이를 연결함 |
| **Anonymity** | Observer가 actor를 의미 있는 다른 집합과 구별할 수 없음 | Login, fingerprint, timing, location 또는 transaction correlation으로 집합이 축소됨 |
| **Unlinkability** | 두 action을 동일한 actor에게 신뢰성 있게 귀속할 수 없음 | 재사용된 identifier, simultaneous activity 또는 shared infrastructure가 이를 연결함 |
| **Security** | System이 compromise에 저항함 | Secure하지만 식별된 account는 여전히 anonymous하지 않음 |

이러한 property는 observer에 따라 달라집니다. Merchant는 card number를 보지 못할 수 있지만 issuer는 customer와 transaction을 여전히 알고 있습니다. Website는 home IP 대신 Tor exit를 볼 수 있지만 account login은 즉시 user를 식별할 수 있습니다.

## Observer부터 시작하기

Tool을 선택하기 전에 다음을 기록하십시오.

1. **Assets:** identity, location, browsing destination, message content, social graph, payment detail, client name, red-team source infrastructure 또는 stored evidence.
2. **Observers:** local Wi-Fi operator, ISP/mobile carrier, VPN, Tor entry/exit, DNS resolver, website, ad network, cloud host, payment issuer, merchant, exchange, counterparty, employer 또는 government.
3. **Correlation handles:** IP address, account/recovery field, phone number, device identifier, cookie, browser fingerprint, time zone, payment instrument, shipping address, writing style, transaction graph, physical presence 및 camera.
4. **Capability and time:** Passive commercial tracking은 provider를 subpoena하거나 endpoint를 압수하거나 connection의 양쪽을 감시할 수 있는 targeted observer와 다릅니다.
5. **Failure cost:** Embarrassment, account suspension, client harm, financial loss, physical danger 또는 legal exposure.

그런 다음 지속 가능한 최소한의 control을 선택하십시오. 일관되게 사용되지 않아 자주 우회되는 복잡한 계획은 일관되게 사용되는 단순한 계획보다 약합니다.

## Quick decision table

| Need | Sensible starting point | What it **does not** solve |
|---|---|---|
| ISP/local network로부터 browsing metadata 숨기기 | Reputable VPN 또는 Tor Browser | Account, cookie, device fingerprint, endpoint compromise |
| 더 강력한 web anonymity | Tor Browser; amnesic session에는 Tails | Global traffic correlation, personal disclosure, physical observation |
| 지속적인 compartmentalized work | Whonix 또는 Qubes-Whonix; separate qube/profile | Hypervisor/host compromise, behavior linking identity |
| 빠른 authorized red-team egress | Client-provided jump host 또는 engagement-specific VPS/VPN | Provider/customer attribution; scope 및 cloud policy obligation |
| Merchant의 card number 노출 줄이기 | Issuer virtual card 또는 tokenized wallet | Issuer/network knowledge, shipping, account 및 device data |
| Point-of-sale payment data 최소화 | 허용되는 곳에서 합법적으로 획득한 cash | CCTV, receipt, withdrawal trail, cash limit |
| Public-chain crypto privacy 개선 | Own wallet/node, new address, coin control, Tor, supported PayJoin | Exchange/KYC, counterparty record, permanent-chain analysis |
| On-chain amount/receiver/sender confidentiality의 기본값 | Separate wallet context 및 network privacy를 사용하는 Monero | Acquisition/off-ramp record, endpoint compromise, merchant/shipping data |

## Core rules

- **Activity가 시작되기 전에 context를 분리하십시오.** Account, device 및 payment가 이미 연결된 후 separation을 소급 적용해도 history를 되돌리는 경우는 드뭅니다.
- **자신을 customization하여 uniqueness를 만들지 마십시오.** Cookie를 지우거나 IP를 변경한 후에도 browser fingerprinting은 activity를 correlate할 수 있습니다. 일반적으로 더 큰 anonymity set을 가진 standard configuration이 선호됩니다.<sup>[[5]](#references)</sup>
- **Endpoint를 보호하십시오.** Network anonymity는 unlocked, infected 또는 seized device를 보호할 수 없습니다.
- **Content를 encrypt하고 metadata를 최소화하십시오.** End-to-end encryption은 message content를 보호하지만 누가, 언제, 어디에서, 어떤 device로 통신했는지는 반드시 보호하지 않습니다.
- **Provider를 observer로 취급하십시오.** VPN, email service, cloud host, exchange, payment issuer 및 alias forwarder는 activity의 서로 다른 부분을 봅니다.
- **검증 가능한 주장을 선호하십시오.** “military-grade” marketing보다 protocol documentation, reproducible software, public audit, retention detail 및 transparency report를 확인하십시오.
- **주기적으로 재평가하십시오.** Service, law, threat actor 및 default는 변경됩니다.

## Offensive-first section map

- [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) — 장단점, deployment/emulation step, detection, capture exposure 및 controller-side discovery monitoring을 포함한 48개 access-path family.
- [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) — 장단점, lawful workflow, detection, capture exposure 및 compromise monitoring을 포함한 48개 payment family.
- [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) — owner-approved drop을 위한 stable outbound rendezvous, dual-uplink recovery, secret minimization, capture drill 및 discovery/compromise monitoring.
- [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) — ORB, multi-hop/residential relay, redirector, fronting, fast flux, domain shadowing, web service 및 persona infrastructure.
- [Covert Physical and Wireless Access](covert-physical-wireless-access.md) — nearest-neighbor attack, public access, drop device, cellular backhaul 및 satellite abuse.
- [Government and APT Case Studies](government-and-apt-case-studies.md) — 재구성된 public case와 이를 노출한 telemetry.
- [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) — Payment layering의 작동 방식, 실패 이유 및 investigator가 이를 추적하는 방법.
- [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) — cross-layer detection model 및 실용적인 hunting logic.
- [Authorized Adversary-Emulation Labs](authorized-adversary-emulation-labs.md) — 소유한 network와 synthetic data를 사용하는 reproducible exercise.

## Operator fundamentals and supporting guides

- [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md)
- [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)
- [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)
- [Privacy Operating Systems](privacy-operating-systems.md)
- [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md)
- [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)
- [Private Digital Payments](private-digital-payments.md)
- [Cryptocurrency Privacy](cryptocurrency-privacy.md)
- [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md)
- [Reproducible Privacy Testing](reproducible-privacy-testing.md)
- [Operational Privacy Playbooks](operational-privacy-playbooks.md)

## Guide and verification index

| Technique | Deployment guide | Verification/failure test |
|---|---|---|
| 모든 Internet-access technique family | [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) | Per-technique detection 및 [reproducible labs](authorized-adversary-emulation-labs.md) |
| 모든 payment technique family | [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) | Per-technique detection 및 [synthetic payment lab](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Owner-approved physical field node | [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) | Capture drill, off-device state monitoring 및 suspected-discovery runbook |
| ORB, residential relay, fronting, fast flux 및 dead drop | [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) | [Owned emulation labs](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) |
| Nearest-neighbor Wi-Fi, drop, cellular 및 satellite path | [Covert Physical and Wireless Access](covert-physical-wireless-access.md) | [Owned wireless-pivot lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) |
| Cross-layer infrastructure 및 operator attribution | [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) | [Exercise report template](authorized-adversary-emulation-labs.md#exercise-report-template) |
| Peel chain, mixer, chain hopping, nominee 및 OTC conversion | [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) | [Synthetic transaction graph](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Identity/browser compartment | [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md) | [Browser and OS tests](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN, Tor, guest Wi-Fi, travel router, cellular | [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) | [Network-path test](reproducible-privacy-testing.md#network-path-test) |
| Split relay, OHTTP, namespace, bridge, onion, I2P | [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) | [Tor/onion 및 route test](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails, Whonix 및 Qubes | [Privacy Operating Systems](privacy-operating-systems.md) | [OS isolation test](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal, SimpleX, Briar, OnionShare 및 encrypted file | [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) | [Communications/file test](reproducible-privacy-testing.md#communications-metadata-test) |
| Authorized red-team egress/drop node | [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) | [Accountability drill](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Cash, prepaid 및 virtual card | [Private Digital Payments](private-digital-payments.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin, PayJoin/CoinJoin, Lightning 및 Monero | [Cryptocurrency Privacy](cryptocurrency-privacy.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments, Zcash, Taler 및 federated e-cash | [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [EFF Surveillance Self-Defense — Your Security Plan](https://ssd.eff.org/module/your-security-plan)
- [2] [US Code, 18 USC §1030 — Computers와 관련된 사기 및 관련 활동](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [UK Computer Misuse Act 1990, section 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — information system에 대한 공격에 관한 Directive 2013/40/EU](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Web Specification에서 Browser Fingerprinting 완화](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [MITRE ATT&CK — Acquire Infrastructure (T1583) 및 Compromise Infrastructure (T1584)](https://attack.mitre.org/techniques/T1584/)
- [7] [MITRE ATT&CK — Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
