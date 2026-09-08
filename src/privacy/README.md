# Offensive Privacy、Attribution Evasion、OPSEC

{{#include ../banners/hacktricks-training.md}}

このセクションでは、red team、侵入オペレーター、そしてそのオペレーターの行動を再構築しようとするdefenderの観点からprivacyを検討します。**Anonymityは単にIP addressを隠すことではありません。** 成熟したオペレーションでは、attribution graphに結び付けられる可能性がある人物、endpoint、account、infrastructure、network path、payload、paymentを分離します。

この資料では、政府機関やAPTのオペレーションで報告されたtechniqueを意図的に扱います。operational-relay-box（ORB）network、compromised edge device、residential exit、redirector tier、fast flux、domain fronting、dead-drop resolver、近隣wireless pivot、covert drop device、satellite-link abuse、false persona、financial layeringなどです。各techniqueは、次の内容で説明します。

1. operational objectiveとATT&CK mapping
2. mechanismとtrust boundary
3. すべてのobserverが記録できる情報
4. それを破綻させるmistakeとstable artifact
5. defensive telemetry、analytics、mitigation
6. 所有または明示的にscopeが定められたinfrastructureを使ったauthorized emulation

したがって、これはoffensive tradecraftのreferenceであると同時に、defender向けのattribution manualでもあります。目的はadvanced behaviorを理解可能かつtestableにすることであり、1つのcommercial serviceによってオペレーターが見えなくなると装うことではありません。

**Research cutoff:** 2026年9月8日。Provider availability、product behavior、sanction、cash/prepaid threshold、SIM-registration rule、crypto regulationは頻繁に変化するため、依存する前に再確認してください。

{% hint style="danger" %}
Techniqueを理解することは、それを実行するauthorizationではありません。これらのページでは、compromised router、近隣住民のWi-Fi、hidden device、stolen identity、launderingなどのcriminal abuseを、mechanismとdetectionのレベルで説明します。Reproduction stepでは、所有するlab system、synthetic identity、test assetのみを使用します。第三者にアクセスしたり、KYCやsanctionを回避したり、criminal proceedsを隠したりしないでください。Unauthorized accessは、US CFAA、UK Computer Misuse Act、Directive 2013/40/EUを施行するEU加盟国の法律など、多くの管轄区域で犯罪とされています。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Adversary objective map

| Adversary objective | Technique families | Principal defensive question |
|---|---|---|
| オペレーターのoriginを隠す | VPN/Tor、externalおよびmulti-hop proxy、residential/mobile exit、ORB、satellite link | 最終hopのaddressはactorのassetか、無関係なvictimか、短命なrelayか？ |
| 実際のC2を発見不能に保つ | redirector、CDN、domain fronting、dead-drop resolver、dynamic DNS、fast flux | IP/domain rotation後も残るstable behaviorは何か？ |
| Trustとreputationを借用する | compromised server、router、cloudおよびweb-service account、domain shadowing | 評判の良いassetが、historical baselineと異なる動作をしていないか？ |
| 物理またはnetwork boundaryを越える | nearest-neighbor Wi-Fi pivot、on-site drop、rogue peripheral、cellular backhaul | 新しいradio、device、switchport、outbound tunnelのうち、何が出現したか？ |
| 人間とoperationを分離する | persona、account/device compartmentation、cover communication、procurement separation | どのrecovery field、browser、schedule、language、payment、admin eventがpersona同士を結び付けるか？ |
| Fundingとcash-outを不明瞭にする | mule/nominee、prepaid value、mixer、CoinJoin、peel chain、chain hopping、OTC broker | on-chainとoff-chainのidentity recordはどこで再接続するか？ |

最も関連性の高いATT&CKのresource-developmentおよびC2 conceptは、**Acquire Infrastructure (T1583)**、**Compromise Infrastructure (T1584)**、**Establish/Compromise Accounts (T1585/T1586)**、**Proxy (T1090)**、**Dynamic Resolution (T1568)**、**Web Service (T1102)**です。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

## Privacy、pseudonymity、anonymity、security

| Goal | Meaning | Typical failure |
|---|---|---|
| **Confidentiality** | 外部者がcontentを読めない | Metadataによって当事者が特定される |
| **Privacy** | 情報開示が必要な範囲に限定される | Providerが想定以上のdataを保持している |
| **Pseudonymity** | Activityが、legal identityと公に結び付いていないstable identityを使う | Recovery email、payment、IP、photo、writing styleによって関連付けられる |
| **Anonymity** | Observerがactorを、意味のある他者の集合から区別できない | Login、fingerprint、timing、location、transaction correlationによって集合が狭まる |
| **Unlinkability** | 2つのactionを同じactorに確実に帰属できない | 再利用されたidentifier、同時活動、shared infrastructureによって結び付けられる |
| **Security** | Systemがcompromiseに耐える | Secureでもidentifiedされたaccountはanonymousではない |

これらのpropertyはobserverごとに異なります。Merchantにはcard numberが見えなくても、issuerはcustomerとtransactionを把握している可能性があります。Websiteにはhome IPではなくTor exitが見えていても、account loginによってuserが直ちに特定される可能性があります。

## Observerから始める

Toolを選ぶ前に、次の事項を書き出します。

1. **Assets:** identity、location、browsing destination、message content、social graph、payment detail、client name、red-team source infrastructure、stored evidence。
2. **Observers:** local Wi-Fi operator、ISP/mobile carrier、VPN、Tor entry/exit、DNS resolver、website、ad network、cloud host、payment issuer、merchant、exchange、counterparty、employer、government。
3. **Correlation handles:** IP address、account/recovery field、phone number、device identifier、cookie、browser fingerprint、time zone、payment instrument、shipping address、writing style、transaction graph、physical presence、camera。
4. **Capability and time:** passive commercial trackingと、providerへのsubpoena、endpointのseize、connectionの両端の監視が可能なtargeted observerは異なります。
5. **Failure cost:** embarrassment、account suspension、client harm、financial loss、physical danger、legal exposure。

その後、持続可能な最小限のcontrolを選択します。日常的にbypassされる複雑な計画は、一貫して使用される単純な計画よりも弱いものです。

## Quick decision table

| Need | Sensible starting point | What it **does not** solve |
|---|---|---|
| ISP/local networkからbrowsing metadataを隠す | Reputable VPNまたはTor Browser | Account、cookie、device fingerprint、endpoint compromise |
| より強いweb anonymity | Tor Browser；amnesic sessionにはTails | Global traffic correlation、personal disclosure、physical observation |
| Persistent compartmentalized work | WhonixまたはQubes-Whonix；separate qube/profile | Hypervisor/host compromise、behaviorによるidentity linking |
| Authorized red-team egressを迅速に用意する | Client提供のjump hostまたはengagement専用VPS/VPN | Provider/customer attribution；scopeおよびcloud policy上の義務 |
| Merchantに対するcard numberの露出を減らす | Issuerのvirtual cardまたはtokenized wallet | Issuer/networkの知識、shipping、accountおよびdevice data |
| Point-of-sale payment dataを最小化する | 受け入れられる場合に、合法的に取得したcash | CCTV、receipt、withdrawal trail、cash limit |
| Public-chain crypto privacyを改善する | Own wallet/node、new address、coin control、Tor、対応するPayJoin | Exchange/KYC、counterparty record、permanent-chain analysis |
| On-chainのamount/receiver/sender confidentialityをデフォルトで確保する | Separate wallet contextとnetwork privacyを用いたMonero | Acquisition/off-ramp record、endpoint compromise、merchant/shipping data |

## Core rules

- **Activityを開始する前にcontextを分離する。** Account、device、paymentがすでに関連付けられた後で分離を後付けしても、過去のhistoryを元に戻すことはほとんどできません。
- **自分をuniqueにするcustomizationは避ける。** Cookieを消去したりIPを変更したりしても、browser fingerprintingによってactivityがcorrelateされる可能性があります。通常は、より大きなanonymity setを持つstandard configurationの方が望ましいです。<sup>[[5]](#references)</sup>
- **Endpointを保護する。** Network anonymityでは、unlockされた、感染した、またはseizeされたdeviceを救えません。
- **Contentを暗号化し、metadataを最小化する。** End-to-end encryptionはmessage contentを保護しますが、誰がいつどこからどのdeviceで通信したかまでは必ずしも保護しません。
- **Providerをobserverとして扱う。** VPN、email service、cloud host、exchange、payment issuer、alias forwarderは、activityの異なる部分を見ています。
- **検証可能なclaimを優先する。** “military-grade”というmarketingではなく、protocol documentation、reproducible software、public audit、retention detail、transparency reportを確認してください。
- **定期的に再評価する。** Service、law、threat actor、defaultは変化します。

## Offensive-first section map

- [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) — 48種類のaccess-path familyについて、長所、短所、deployment/emulation step、detection、capture exposure、controller側のdiscovery monitoringを説明します。
- [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) — 48種類のpayment familyについて、長所、短所、合法的なworkflow、detection、capture exposure、compromise monitoringを説明します。
- [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) — owner-approved drop向けに、stable outbound rendezvous、dual-uplink recovery、secret minimization、capture drill、discovery/compromise monitoringを説明します。
- [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) — ORB、multi-hop/residential relay、redirector、fronting、fast flux、domain shadowing、web service、persona infrastructureを説明します。
- [Covert Physical and Wireless Access](covert-physical-wireless-access.md) — nearest-neighbor attack、public access、drop device、cellular backhaul、satellite abuseを説明します。
- [Government and APT Case Studies](government-and-apt-case-studies.md) — 公開情報から再構築したcaseと、それを明らかにしたtelemetryを説明します。
- [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) — payment layeringの仕組み、失敗する理由、investigatorが追跡する方法を説明します。
- [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) — cross-layer detection modelと実用的なhunting logicを説明します。
- [Authorized Adversary-Emulation Labs](authorized-adversary-emulation-labs.md) — owned networkとsynthetic dataを使ったreproducible exerciseを説明します。

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
| すべてのInternet-access technique family | [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) | Techniqueごとのdetectionと[reproducible labs](authorized-adversary-emulation-labs.md) |
| すべてのpayment technique family | [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) | Techniqueごとのdetectionと[synthetic payment lab](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Owner-approved physical field node | [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) | Capture drill、off-device state monitoring、suspected-discovery runbook |
| ORB、residential relay、fronting、fast flux、dead drop | [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) | [Owned emulation labs](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) |
| Nearest-neighbor Wi-Fi、drop、cellular、satellite path | [Covert Physical and Wireless Access](covert-physical-wireless-access.md) | [Owned wireless-pivot lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) |
| Cross-layer infrastructureとoperator attribution | [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) | [Exercise report template](authorized-adversary-emulation-labs.md#exercise-report-template) |
| Peel chain、mixer、chain hopping、nominee、OTC conversion | [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) | [Synthetic transaction graph](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Identity/browser compartment | [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md) | [Browser and OS tests](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN、Tor、guest Wi-Fi、travel router、cellular | [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) | [Network-path test](reproducible-privacy-testing.md#network-path-test) |
| Split relay、OHTTP、namespace、bridge、onion、I2P | [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) | [Tor/onion and route tests](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails、Whonix、Qubes | [Privacy Operating Systems](privacy-operating-systems.md) | [OS isolation test](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal、SimpleX、Briar、OnionShare、encrypted file | [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) | [Communications/file tests](reproducible-privacy-testing.md#communications-metadata-test) |
| Authorized red-team egress/drop node | [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) | [Accountability drill](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Cash、prepaid、virtual card | [Private Digital Payments](private-digital-payments.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin、PayJoin/CoinJoin、Lightning、Monero | [Cryptocurrency Privacy](cryptocurrency-privacy.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments、Zcash、Taler、federated e-cash | [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [EFF Surveillance Self-Defense — セキュリティ計画](https://ssd.eff.org/module/your-security-plan)
- [2] [US Code, 18 USC §1030 — Computerに関連するfraudおよび関連活動](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [UK Computer Misuse Act 1990, section 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — Information systemへのattackに関するDirective 2013/40/EU](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Web SpecificationsにおけるBrowser Fingerprintingのmitigation](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [MITRE ATT&CK — Acquire Infrastructure (T1583)およびCompromise Infrastructure (T1584)](https://attack.mitre.org/techniques/T1584/)
- [7] [MITRE ATT&CK — Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
{{#include ../banners/hacktricks-training.md}}
