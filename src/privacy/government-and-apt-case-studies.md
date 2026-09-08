# Government and APT Case Studies

{{#include ../banners/hacktricks-training.md}}

これらの公開事例は、複数の privacy techniques が実際の作戦でどのように組み合わされるかを示しています。帰属のラベルは、引用された調査機関または政府が使用したものです。IP address、tool の重複、または地政学的な整合性だけでは、決定的な帰属の根拠にはなりません。

## APT28: remote nearest-neighbor Wi-Fi access

**Public finding.** Volexity は、2022 年の侵入を GruesomeLarch/APT28 に帰属させました。検証済みの credential による Internet access が MFA によって停止された後、攻撃者は標的の近くにある組織を侵害し、近隣の dual-homed host から標的の enterprise Wi-Fi に到達しました。Wi-Fi 経由では、外部 access に必要な MFA なしで credential が受け入れられました。<sup>[[1]](#references)</sup>

**Privacy effect.** 最終的な access は物理的な radio range 内から発生し、中間にあった組織は被害者でした。この作戦は移動を避け、通常の IP geolocation では近隣の場所を示すようにしました。

**What exposed it.** 標的の alert、host/network investigation、credential activity、interface topology、物理的な近接性を、1 つの chain として分析する必要がありました。異常だったのは単に新しい IP ではなく、近隣の systems が侵害されている状況で、正当な identity が通常とは異なる Wi-Fi/device context を経由して到来したことでした。

**Defensive lesson.** Wi-Fi access には certificate/device-backed access を適用し、RADIUS と NAC/MDM および物理的な context を相関させ、最後の hop が operator だと決めつけずに近隣の infrastructure を調査します。

## APT28: criminal Moobot infrastructure repurposed by the GRU

**Public finding.** 2024 年 2 月、US Department of Justice は、数百台の Ubiquiti EdgeOS routers からなる botnet について説明しました。criminal actors は、既知の default administrator credentials が残っていた routers に Moobot をインストールしていました。その後、GRU Unit 26165 が scripts と files を追加し、既存の criminal botnet を、spearphishing と credential theft に使用される espionage platform に変えました。<sup>[[2]](#references)</sup>

**Privacy effect.** GRU はすべての infrastructure を自ら構築したわけではありません。すでに侵害された fleet を借用することで、actor と標的の間に無関係な home および small-office addresses を置き、state activity と criminal activity を混在させ、actor 固有の registration artifacts を減らしました。

**What exposed it.** Router files、malware の control behavior、content 以外の routing information が調査を裏付けました。disruption により firewall rules が一時的に変更され、malicious files が削除されましたが、DOJ は、変更されていない default credentials によって再感染が可能になるおそれがあると警告しました。

**Defensive lesson.** サポート対象外の routers を交換し、Internet-exposed administration を削除し、defaults を変更して patch を適用し、edge-device configuration/flow data を収集し、fleet behavior を hunt します。「Residential US IP」は、US operator の証拠ではありません。

## Volt Typhoon: KV Botnet plus living off the land

**Public finding.** DOJ と共同 CISA advisory は、PRC state-sponsored の Volt Typhoon が、主に end-of-life の Cisco および NETGEAR SOHO routers を侵害した KV Botnet を使用し、critical infrastructure を標的とする activity の PRC origin を隠していたと説明しました。victims 内部では、actor は valid accounts と built-in administration tools を好んで使用し、一部の environments では access が少なくとも 5 年間継続していたと agencies は報告しました。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Privacy effect.** ORB-like path により発信元を隠し、living-off-the-land により、アクセス後の新規バイナリと signature の機会を減らした。Network と endpoint の隠蔽が相互に強化し合っていた。

**What exposed it.** Router/controller の構造、裁判所の許可を受けた technical collection、反復する活動、被害者間の分析は、単一の IOC よりも重要だった。説明された事例では、router を再起動すると揮発性の KV malware は除去できたが、device の根本的な end-of-life exposure は解消されなかった。

**Defensive lesson.** EOL edge device を交換し、authentication と network-device log を一元化し、administrator の行動を baseline 化し、outbound connectivity を制限し、identity、endpoint、network の各 layer にまたがる行動 sequence を hunt する。

## China-nexus ORB networks: infrastructure as a service

**Public finding.** Mandiant は、複数の China-nexus espionage actor が利用する ORB network の ecosystem を説明した。Provisioned network は leased VPS node を使用し、non-provisioned network は侵害された IoT と router を使用し、hybrid network は両者を組み合わせていた。ORB3/SPACEHOP は APT5/APT15 に関連する活動を支援していた。ORB2/FLORAHOX は、administration server、leased server、customized Tor layer、侵害された Cisco、ASUS、DrayTek device を組み合わせていた。Mandiant は、一部の network が独立して管理され、複数の APT actor に rented されていたと評価した。<sup>[[5]](#references)</sup>

**Privacy effect.** Infrastructure は service boundary になった。1人の operator が victim fleet を維持せずに geographic/residential exit を得られる一方、多数の customer がそれを共有することで、単純な actor-to-IP mapping は困難になった。Fleet の高速な turnover により、「IOC extinction」が加速した。

**What exposed it.** Network topography、cloned server image、port/service、controller relationship、router implant、lifecycle pattern は、引き続き cluster 化できた。Mandiant は、一部の node IP が ORB に存在した期間が最短で31日だったと報告した。

**Defensive lesson.** ORB を変化する entity として追跡する。node role、service fingerprint、upstream relation、scan behavior、rotation rhythm を記録する。IP indicator の期限切れは cluster を更新するべきであり、case を消去してはならない。

## PRC global espionage system: routers, trusted links and traffic mirroring

**Public finding.** 2025年の multinational advisory は、Salt Typhoon、OPERATOR PANDA、RedMike、UNC5807、GhostEmperor などの commercial reporting name と活動が重複すると説明した。各機関は、leased VPS と侵害された intermediate router が telecommunications provider および network provider への到達に使用されたと報告した。Actor は trusted provider/customer link を経由して pivot し、route を変更し、GRE/IPsec tunnel を構築し、device container を使用し、SPAN/RSPAN/ERSPAN または native packet capture を有効化して authentication と customer traffic を収集した。<sup>[[13]](#references)</sup>

**Privacy effect.** 侵害された router は、同時に relay、observation point、trusted network participant となる。Private interconnection は public Internet を前提に設計された control を迂回でき、traffic mirroring は endpoint agent を deploy せずに credential を収集する。

**What exposes it.** Configuration diff、予期しない SNMP/SSH/web administration、新しい static route/tunnel、mirror session、Guest Shell container、PCAP file、TACACS+/RADIUS destination の変更、logging の無効化。Advisory は、一部の intermediate router が以前に公表された botnet の一部ではなかったことを強調しているため、既知の ORB indicator がないことは潔白の根拠にならない。

**Defensive lesson.** Out-of-band administration、centralized configuration/authentication log、signed-image と runtime integrity check、management-interface egress の制限、route/mirror/tunnel/AAA の変更に対する alert を使用する。侵害が疑われる場合は、eviction の前に trusted peer 全体へ scope を広げる。

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Public finding.** Mandiant は、end-of-life Juniper MX router 上の custom TINYSHELL-derived backdoor を UNC3886 に帰属させた。この set には active と passive の implant、正規 daemon を模倣する name、log-disabling behavior、trusted process への process injection、SOCKS proxy capability、ORB staging node と評価された infrastructure が含まれていた。Passive variant は `libpcap` を通じて packet を検査し、magic pattern の後にのみ activate した。1つの variant は、trigger で指定された active callback に切り替えることができた。<sup>[[14]](#references)</sup>

**Privacy effect.** Passive implant には発見可能な periodic beacon がない。実際の network appliance と port/traffic を共有し、短時間だけ activate し、最終的な controller に直接接続するのではなく ORB 経由で relay できる。

**What exposes it.** Memory analysis、on-disk code と running code の差異、予期しない packet-capture filter/socket behavior、正規 daemon に近似しているだけの process/file name、terminal server 経由の administration、欠落した log、staging node と backend controller の二段階の関係。

**Defensive lesson.** Filesystem/configuration evidence とともに memory を取得し、process/module を known-good image と比較し、packet-capture/socket-filter の使用を monitor し、management terminal server を保護し、EOL network hardware を交換する。Outbound-beacon hunt がクリーンでも、問題がないとは限らない。

## APT29: Tor domain fronting

**Public finding.** MITRE は、APT29 が `meek` Tor pluggable transport を使用して C2 traffic を domain-front していたと記録している。外側の TLS name は許可された CDN-hosted domain に見える一方、内側の HTTP host が実際の route を選択していた。<sup>[[6]](#references)</sup>

**Privacy effect.** Filtering observer には、内側の destination ではなく一般的な front/CDN が見えるため、block すると collateral damage のリスクがあった。

**What exposes it.** CDN は routing mismatch を観測でき、endpoint または lawful TLS visibility を持つ defender は、process、authority、connection lifetime、byte pattern、後続の活動を correlate できる。Provider policy の変更により、この technique が無効化される可能性もある。

**Defensive lesson.** SNI allowlisting だけに依存しない。Application-aware egress を enforce し、可視であれば TLS identity と HTTP identity を比較し、network event を initiating process に結び付ける。

## APT41 and other dead-drop resolvers

**Public finding.** MITRE は、APT41 が GitHub、Pastebin、Microsoft TechNet、Cloudflare、community forum などの legitimate site を使用して C2 information を公開または取得していたと記録している。他の state-linked tooling も同様に post、document、social media を使用している。<sup>[[7]](#references)</sup>

**Privacy effect.** Binary には stable な C2 address ではなく、legitimate service/object が含まれる。Object を編集して infrastructure を rotate でき、初回 request は一般的な TLS traffic に紛れ込む。

**What exposes it.** Object または account identifier は stable であり、rare process が繰り返しそれを fetch し、content が decode され、その後に2つ目の outbound connection が続く。Provider account と API record により、publication と operator を link できる場合がある。

**Defensive lesson.** Full proxy path/object ID と endpoint process lineage を保存する。「GitHub に接続した」という domain-level event だけでは粗すぎる。

## Turla: satellite-address C2

**Public finding.** Kaspersky は、Turla が旧式の一方向 DVB-S Internet service における暗号化されていない downstream broadcast を悪用したと報告した。Satellite footprint 内の operator は legitimate subscriber address を選択して、その address 宛てに broadcast された reply を受信できたため、C2 は別地域の satellite provider の背後で hosting されているように見えた。<sup>[[8]](#references)</sup>

**Privacy effect.** 見かけ上の server address は receiver を特定せず、従来の hosting seizure/WHOIS process は有用性が低かった。

**What exposes it.** Actor には依然として outbound request path が必要であり、routing は asymmetric だった。Legitimate subscriber は C2 exchange を開始しておらず、RF/provider investigation により receiving footprint を絞り込める可能性があった。

**Defensive lesson.** Geolocation を1つの仮説として扱う。Path symmetry、RTT、routing ownership、想定された endpoint が実際に観測された service を生成できるかを検証する。

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Public finding.** 2022年の NCSC/CISA/FBI/NSA advisory は、Sandworm の modular Cyclops Blink malware が WatchGuard device 上で、firmware update として persistent に deploy され、module を追加可能だったと説明した。DOJ は別途、以前の APT28 VPNFilter botnet が router と NAS device から構成され、intelligence collection、destructive activity、misattribution が可能だったと説明した。<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Privacy effect.** Edge appliance は常時 online で、infrastructure として trusted され、EDR の coverage が不十分である。Firmware persistence は通常の restart を survive し、victim device を relay または control point にできる。

**What exposes it.** Firmware integrity、vendor-specific implant protocol、予期しない management exposure、configuration change、outbound beaconing。Edge device は透明な配管ではなく、forensic subject として扱わなければならない。

## DPRK: identity, network and financial layering

**Public finding.** DOJ の case は、DPRK worker が false または stolen identity material と VPN を使用して remote job を獲得し、cryptocurrency を受け取り、transfer を分割し、asset/chain を swap し、NFT を使用し、proceed を commingle していたと説明している。他の case では、OTC trader と front company が stolen crypto を purchase に変換していた。Treasury と FBI は、Lazarus/TraderTraitor の proceed を mixer と公に関連付け、major theft に由来する address を特定している。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Privacy effect.** これは「private coin」ではない。Persona と remote access が worker の所在地を隠し、crypto が value を移転し、layering が単純な transaction narrative を分断し、OTC trader/front company が goods と fiat への橋渡しをする、multi-domain chain である。

**What exposes it.** Employer/device anomaly、再利用された facilitator、blockchain の timing/value continuity、exchange/bridge record、sanctioned address、account identity、shipment/company record が chain を再接続する。

**Defensive lesson.** Hiring、IAM、endpoint、payroll、blockchain、sanctions の team は、shared case model を必要とする。詳細は [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) に記載されている。

## Cross-case patterns

| Pattern | APT examples | Defender adaptation |
|---|---|---|
| Exit は別の victim である | APT28/Moobot、Volt Typhoon/KV、ORB | Exit を investigate して remediate する。Exit を actor の所在地と同一視しない |
| Control は boundary ごとに異なる | APT28 nearest neighbor | Internal/wireless access に対しても、Internet access と同じ identity assurance を与える |
| Legitimate service が routing layer になる | APT29、APT41 | Destination domain だけでなく、object/path/process context を保持する |
| Edge device には telemetry がない | KV、Moobot、Cyclops Blink、ORB | Config/auth/flow log を一元化し、firmware/inventory を検証する |
| Infrastructure は shared で短命である | China-nexus ORB | Behavior/topology を cluster 化し、時間経過に伴う role change を追跡する |
| 複数の弱い separation が組み合わさる | DPRK persona + VPN + crypto + OTC | Identity、device、network、payment、physical evidence を結合する |

## References

- [1] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Moobot router botnet の disruption](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — PRC KV Botnet の disruption](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC actor による US critical infrastructure への compromise と persistent access の維持](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage actor による ORB network の使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilter disruption](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank representative charged in crypto-laundering conspiracies](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io sanctions and Lazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Chinese state-sponsored actor による worldwide network compromise への対策](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 による Juniper router の targeting](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
