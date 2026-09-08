# Offensive Privacy, Attribution Evasion and OPSEC

このセクションでは、red team、侵入オペレーター、そしてそのオペレーターを再構成しようとするdefenderの視点からprivacyを考察します。**Anonymityは単にIP addressを隠すことではありません。** 成熟したoperationsでは、attribution graphに結び付けられる可能性のある人員、endpoints、accounts、infrastructure、network paths、payloads、paymentsを分離します。

この資料には、政府およびAPT operationsで報告されたtechniquesが意図的に含まれています。operational-relay-box (ORB) networks、compromised edge devices、residential exits、redirector tiers、fast flux、domain fronting、dead-drop resolvers、近隣wireless pivots、covert drop devices、satellite-link abuse、false personas、financial layeringなどです。各techniqueは次の観点で説明します。

1. operational objectiveとATT&CK mapping；
2. mechanismとtrust boundaries；
3. すべてのobserverがなお記録できる情報；
4. techniqueを破綻させるmistakesとstable artifacts；
5. defensive telemetry、analytics、mitigations；および
6. ownedまたは明示的にscope指定されたinfrastructureを使用したauthorized emulation。

したがって、これはoffensive tradecraftのreferenceであると同時に、defender向けのattribution manualでもあります。目的は、1つのcommercial serviceによってoperatorが見えなくなるふりをすることではなく、高度なbehaviorを理解可能かつtest可能にすることです。

**Research cutoff:** 2026年9月8日。Provider availability、product behavior、sanctions、cash/prepaid thresholds、SIM-registration rules、crypto regulationは頻繁に変化するため、依存する前に再確認してください。

{% hint style="danger" %}
Techniqueを理解することは、それを実行するauthorizationではありません。このページでは、compromised routers、neighbor's Wi-Fi、hidden devices、stolen identities、launderingなどのcriminal abuseを、mechanism-and-detection levelで説明します。Reproduction stepsでは、owned lab systems、synthetic identities、test assetsのみを使用します。第三者にアクセスしたり、KYCやsanctionsを回避したり、criminal proceedsを隠匿したりしないでください。Unauthorized accessは、US CFAA、UK Computer Misuse Act、Directive 2013/40/EUを実装するEU member-state lawsなど、多くのjurisdictionsで犯罪とされています。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Adversary objective map

| Adversary objective | Technique families | Principal defensive question |
|---|---|---|
| Operatorのoriginを隠す | VPN/Tor、externalおよびmulti-hop proxies、residential/mobile exits、ORBs、satellite links | 最後のhop addressはactor asset、無関係なvictim、または短命なrelayのいずれか？ |
| 実際のC2を発見不能に保つ | redirectors、CDNs、domain fronting、dead-drop resolvers、dynamic DNS、fast flux | IP/domain rotation後も残るstable behaviorは何か？ |
| Trustとreputationを借用する | compromised servers、routers、cloudおよびweb-service accounts、domain shadowing | reputable assetがhistorical baselineと異なるbehaviorをしていないか？ |
| 物理またはnetwork boundaryを越える | nearest-neighbor Wi-Fi pivots、on-site drops、rogue peripherals、cellular backhaul | 新しいradio、device、switchport、またはoutbound tunnelが出現していないか？ |
| Humanとoperationを分離する | personas、account/device compartmentation、cover communications、procurement separation | どのrecovery field、browser、schedule、language、payment、またはadmin eventがpersonasを結び付けるか？ |
| Fundingとcash-outを不明瞭にする | mules/nominees、prepaid value、mixers、CoinJoin、peel chains、chain hopping、OTC brokers | on-chainとoff-chainのidentity recordsはどこで再接続するか？ |

最も関連性の高いATT&CK resource-developmentおよびC2 conceptsは、**Acquire Infrastructure (T1583)**、**Compromise Infrastructure (T1584)**、**Establish/Compromise Accounts (T1585/T1586)**、**Proxy (T1090)**、**Dynamic Resolution (T1568)**、**Web Service (T1102)**です。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

## Privacy, pseudonymity, anonymity and security

| Goal | Meaning | Typical failure |
|---|---|---|
| **Confidentiality** | 外部者がcontentを読めない | Metadataがなお当事者を特定する |
| **Privacy** | 情報開示が必要な範囲に限定される | Providerが想定以上のdataを保持している |
| **Pseudonymity** | Activityが、legal identityと公には結び付いていないstable identityを使用する | Recovery email、payment、IP、photo、またはwriting styleがlinkする |
| **Anonymity** | Observerがactorを意味のある他者の集合から区別できない | Login、fingerprint、timing、location、またはtransaction correlationによって集合が縮小する |
| **Unlinkability** | 2つのactionsを同一actorに確実にattributionできない | 再利用されたidentifiers、同時activity、またはshared infrastructureが両者を結び付ける |
| **Security** | Systemsがcompromiseに耐える | Secureだがidentifiedされたaccountはnon-anonymousのままである |

これらのpropertiesはobserver固有です。Merchantにはcard numberが見えなくても、issuerはcustomerとtransactionを把握している可能性があります。Websiteにはhome IPではなくTor exitが見えても、account loginによって即座にuserが特定される可能性があります。

## Start with the observer

Toolsを選ぶ前に、次を記録してください。

1. **Assets:** identity、location、browsing destinations、message contents、social graph、payment details、client name、red-team source infrastructure、またはstored evidence。
2. **Observers:** local Wi-Fi operator、ISP/mobile carrier、VPN、Tor entry/exit、DNS resolver、website、ad network、cloud host、payment issuer、merchant、exchange、counterparties、employer、またはgovernment。
3. **Correlation handles:** IP address、account/recovery fields、phone number、device identifiers、cookies、browser fingerprint、time zone、payment instrument、shipping address、writing style、transaction graph、physical presence、camera。
4. **Capability and time:** passive commercial trackingは、providersへのsubpoena、endpointsのseizure、またはconnectionの両端の監視が可能なtargeted observerとは異なります。
5. **Failure cost:** embarrassment、account suspension、client harm、financial loss、physical danger、またはlegal exposure。

その後、持続可能な最小限のcontrolsを選択します。日常的に迂回される複雑なplanは、一貫して使用される単純なplanより弱いものです。

## Quick decision table

| Need | Sensible starting point | What it **does not** solve |
|---|---|---|
| ISP/local networkからbrowsing metadataを隠す | Reputable VPNまたはTor Browser | Accounts、cookies、device fingerprint、endpoint compromise |
| より強いweb anonymity | Tor Browser；amnesic sessionにはTails | Global traffic correlation、personal disclosures、physical observation |
| 継続的にcompartmentalizedされたwork | WhonixまたはQubes-Whonix；separate qubes/profiles | Hypervisor/host compromise、behaviorによるidentitiesのlinking |
| 高速なauthorized red-team egress | Client-provided jump hostまたはengagement-specific VPS/VPN | Provider/customer attribution；scopeおよびcloud policy obligations |
| Merchantによるcard number exposureを減らす | Issuer virtual cardまたはtokenized wallet | Issuer/network knowledge、shipping、accountおよびdevice data |
| Point-of-sale payment dataを最小化する | 受け入れられる場合にlawfully obtained cash | CCTV、receipts、withdrawal trail、cash limits |
| Public-chain crypto privacyを改善する | Own wallet/node、new addresses、coin control、Tor、supported PayJoin | Exchange/KYC、counterparty records、permanent-chain analysis |
| On-chain amount/receiver/sender confidentialityをdefaultにする | Separate wallet contextsとnetwork privacyを備えたMonero | Acquisition/off-ramp records、endpoint compromise、merchant/shipping data |

## Core rules

- **Activity開始前にcontextsを分離する。** Accounts、devices、paymentsがすでにlinkされた後でseparationを後付けしても、historyを元に戻せることはほとんどありません。
- **自分をuniquenessにcustomizeしない。** Browser fingerprintingは、cookiesをclearしたりIPを変更したりした後でもactivityをcorrelateできます。通常は、より大きなanonymity setsを持つstandard configurationsが望ましいです。<sup>[[5]](#references)</sup>
- **Endpointを保護する。** Network anonymityでは、unlocked、infected、またはseized deviceを救えません。
- **Contentをencryptし、metadataを最小化する。** End-to-end encryptionはmessage contentを保護しますが、誰が、いつ、どこから、どのdeviceでcommunicateしたかまでは必ずしも保護しません。
- **Providersをobserversとして扱う。** VPNs、email services、cloud hosts、exchanges、payment issuers、alias forwardersは、activityの異なる部分を見ています。
- **検証可能なclaimsを優先する。** 「military-grade」というmarketingではなく、protocol documentation、reproducible software、public audits、retention details、transparency reportsを確認してください。
- **定期的に再評価する。** Services、laws、threat actors、defaultsは変化します。

## Offensive-first section map

- [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) — 48のaccess-path familiesについて、pros、cons、deployment/emulation steps、detection、capture exposure、controller-side discovery monitoringを説明します。
- [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) — 48のpayment familiesについて、pros、cons、lawful workflows、detection、capture exposure、compromise monitoringを説明します。
- [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) — owner-approved drops向けに、stable outbound rendezvous、dual-uplink recovery、secret minimization、capture drills、discovery/compromise monitoringを説明します。
- [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) — ORBs、multi-hop/residential relays、redirectors、fronting、fast flux、domain shadowing、web services、persona infrastructure。
- [Covert Physical and Wireless Access](covert-physical-wireless-access.md) — nearest-neighbor attacks、public access、drop devices、cellular backhaul、satellite abuse。
- [Government and APT Case Studies](government-and-apt-case-studies.md) — public casesの再構成と、それらを明らかにしたtelemetry。
- [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) — payment layeringの仕組み、失敗する理由、investigatorsが追跡する方法。
- [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) — cross-layer detection modelと実用的なhunting logic。
- [Authorized Adversary-Emulation Labs](authorized-adversary-emulation-labs.md) — owned networksとsynthetic dataを使用したreproducible exercises。

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
| All Internet-access technique families | [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) | Per-technique detectionおよび[reproducible labs](authorized-adversary-emulation-labs.md) |
| All payment technique families | [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) | Per-technique detectionおよび[synthetic payment lab](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Owner-approved physical field node | [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) | Capture drill、off-device state monitoring、suspected-discovery runbook |
| ORBs、residential relays、fronting、fast flux、dead drops | [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) | [Owned emulation labs](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) |
| Nearest-neighbor Wi-Fi、drops、cellular、satellite paths | [Covert Physical and Wireless Access](covert-physical-wireless-access.md) | [Owned wireless-pivot lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) |
| Cross-layer infrastructureとoperator attribution | [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) | [Exercise report template](authorized-adversary-emulation-labs.md#exercise-report-template) |
| Peel chains、mixers、chain hopping、nominees、OTC conversion | [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) | [Synthetic transaction graph](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Identity/browser compartment | [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md) | [Browser and OS tests](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN、Tor、guest Wi-Fi、travel router、cellular | [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) | [Network-path test](reproducible-privacy-testing.md#network-path-test) |
| Split relays、OHTTP、namespaces、bridges、onions、I2P | [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) | [Tor/onion and route tests](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails、Whonix、Qubes | [Privacy Operating Systems](privacy-operating-systems.md) | [OS isolation test](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal、SimpleX、Briar、OnionShare、encrypted files | [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) | [Communications/file tests](reproducible-privacy-testing.md#communications-metadata-test) |
| Authorized red-team egress/drop nodes | [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) | [Accountability drill](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Cash、prepaid、virtual cards | [Private Digital Payments](private-digital-payments.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin、PayJoin/CoinJoin、Lightning、Monero | [Cryptocurrency Privacy](cryptocurrency-privacy.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments、Zcash、Taler、federated e-cash | [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [EFF Surveillance Self-Defense — Your Security Plan](https://ssd.eff.org/module/your-security-plan)
- [2] [US Code, 18 USC §1030 — Computersに関連するfraudおよび関連activity](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [UK Computer Misuse Act 1990, section 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — 情報systemsへのattacksに関するDirective 2013/40/EU](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Web SpecificationsにおけるBrowser Fingerprintingのmitigation](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [MITRE ATT&CK — Acquire Infrastructure (T1583)およびCompromise Infrastructure (T1584)](https://attack.mitre.org/techniques/T1584/)
- [7] [MITRE ATT&CK — Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
