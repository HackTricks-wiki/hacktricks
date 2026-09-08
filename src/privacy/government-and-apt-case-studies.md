# Government and APT Case Studies

これらの公表事例は、複数の privacy techniques が実際の operations でどのように組み合わせられるかを示している。帰属ラベルは、引用された調査機関または政府が使用したものだ。IP address、tool の重複、または地政学的な整合性だけでは、決定的な attribution とはならない。

## APT28: remote nearest-neighbor Wi-Fi access

**Public finding.** Volexity は、2022 年の侵入を GruesomeLarch/APT28 によるものと attribution した。validated credential による Internet access が MFA によって停止された後、攻撃者は標的の近隣にある組織を侵害し、近くの dual-homed host から標的の enterprise Wi-Fi に到達した。Wi-Fi 経由では、外部アクセスに必要な MFA なしで credential が受け入れられた。<sup>[[1]](#references)</sup>

**Privacy effect.** 最終的な access は物理的な radio range 内から発生し、中継となった組織は victims だった。この operation は移動を回避し、通常の IP geolocation では隣接組織を指し示すようにした。

**What exposed it.** 標的の alert、host/network investigation、credential activity、interface topology、物理的近接性を、1 つの chain として分析する必要があった。異常だったのは単なる新しい IP ではなく、近隣の systems が compromised されている状況で、正当な identity が通常とは異なる Wi-Fi/device context を通じて到来したことだった。

**Defensive lesson.** Wi-Fi access には certificate/device-backed access を適用し、RADIUS を NAC/MDM および物理的 context と相関させ、最後の hop が operator だと決めつけずに近隣の infrastructure を調査する。

## APT28: criminal Moobot infrastructure repurposed by the GRU

**Public finding.** 2024 年 2 月、US Department of Justice は、数百台の Ubiquiti EdgeOS routers から成る botnet について説明した。criminal actors は、既知の default administrator credentials が残っていた routers に Moobot を install していた。その後、GRU Unit 26165 が scripts と files を追加し、既存の criminal botnet を、spearphishing と credential theft に使用される espionage platform に転用した。<sup>[[2]](#references)</sup>

**Privacy effect.** GRU はすべての infrastructure を自ら構築したわけではない。すでに compromised されていた fleet を借用することで、actor と targets の間に無関係な家庭や small-office の addresses を置き、state activity と criminal activity を混在させ、actor 固有の registration artifacts を減らした。

**What exposed it.** Router files、malware の control behavior、content 以外の routing information が investigation を裏付けた。disruption によって firewall rules は一時的に変更され、malicious files は削除されたが、DOJ は、変更されていない default credentials によって reinfection が可能になるおそれがあると警告した。

**Defensive lesson.** サポート対象外の routers を交換し、Internet に公開された administration を削除し、defaults を変更し、patch を適用し、edge-device の configuration/flow data を収集し、fleet behavior を hunt する。「Residential US IP」は US operator の証拠ではない。

## Volt Typhoon: KV Botnet plus living off the land

**Public finding.** DOJ と共同 CISA advisory は、PRC state-sponsored の Volt Typhoon が、主に end-of-life の Cisco および NETGEAR SOHO routers を compromised した KV Botnet を使用し、critical infrastructure を標的とする activity の PRC origin を隠していたと説明した。victims 内部では、actor は valid accounts と built-in administration tools を好んで使用し、agencies は一部の environments で少なくとも 5 年間 access が継続していたと報告した。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Privacy effect.** ORB-like pathはoriginを隠し、living-off-the-landはアクセス後の新規バイナリとsignatureの機会を減らした。Networkとendpointの隠蔽が相互に強化し合った。

**What exposed it.** Router/controllerの構造、裁判所が承認したtechnical collection、反復する活動、被害者間の分析は、単一のIOCよりも重要だった。説明された事例では、routerを再起動するとvolatileなKV malwareは除去されたが、deviceの根本的なend-of-life exposureは解消されなかった。

**Defensive lesson.** EOL edge deviceを交換し、authenticationとnetwork-device logを一元化し、administratorの行動をbaseline化し、outbound connectivityを制限し、identity、endpoint、network layer全体でbehavioral sequenceをhuntする。

## China-nexus ORB networks: infrastructure as a service

**Public finding.** Mandiantは、複数のChina-nexus espionage actorが使用するORB networkのecosystemについて説明した。Provisioned networkはleased VPS nodeを使用し、non-provisioned networkはcompromised IoTとrouterを使用し、hybrid networkはそれらを組み合わせていた。ORB3/SPACEHOPはAPT5/APT15に関連する活動を支援した。ORB2/FLORAHOXは、administration server、leased server、customized Tor layer、compromised Cisco、ASUS、DrayTek deviceを組み合わせていた。Mandiantは、一部のnetworkが独立して管理され、複数のAPT actorに貸し出されていたと評価した。<sup>[[5]](#references)</sup>

**Privacy effect.** Infrastructureがservice boundaryになった。1人のoperatorは、victim fleetを維持せずにgeographic/residential exitを利用でき、一方で多くのcustomerがそれを共有することで、単純なactor-to-IP mappingは弱まった。Fleetの高速な入れ替えにより、「IOC extinction」が加速した。

**What exposed it.** Network topology、cloned server image、port/service、controller relationship、router implant、lifecycle patternは、引き続きcluster化できた。Mandiantは、一部のnode IPがORBに存在した期間がわずか31日だったと報告した。

**Defensive lesson.** ORBを変化するentityとして追跡する。node role、service fingerprint、upstream relation、scan behavior、rotation rhythmを記録する。IP indicatorの期限切れはclusterを更新するものであり、caseを消去するものではない。

## PRC global espionage system: routers, trusted links and traffic mirroring

**Public finding.** 2025年の多国間advisoryは、Salt Typhoon、OPERATOR PANDA、RedMike、UNC5807、GhostEmperorなど、commercial reportingで使用される名称と重なる活動について説明した。各機関は、telecommunications providerやnetwork providerに到達するために、leased VPSとcompromised intermediate routerが使用されたと報告した。Actorはtrusted provider/customer linkを経由してpivotし、routeを変更し、GRE/IPsec tunnelを構築し、device containerを使用し、SPAN/RSPAN/ERSPANまたはnative packet captureを有効化してauthenticationとcustomer trafficを収集した。<sup>[[13]](#references)</sup>

**Privacy effect.** Compromised routerは、同時にrelay、observation point、trusted network participantとなる。Private interconnectionは、public Internetを前提に設計されたcontrolを回避できる一方、traffic mirroringはendpoint agentをdeployせずにcredentialを収集する。

**What exposes it.** Configuration diff、予期しないSNMP/SSH/web administration、新しいstatic route/tunnel、mirror session、Guest Shell container、PCAP file、TACACS+/RADIUS destinationの変更、loggingの無効化。Advisoryは、一部のintermediate routerが、以前に公表されたbotnetの一部ではなかったことを強調している。そのため、既知のORB indicatorがないことは無実の証明にはならない。

**Defensive lesson.** Out-of-band administration、centralized configuration/authentication log、signed-imageとruntime integrity check、management-interface egressの制限、route/mirror/tunnel/AAA変更へのalertを使用する。疑わしいcompromiseをevictionする前に、trusted peer全体にscopeを広げる。

## UNC3886 RedPenguin: passive backdoors on ISP routers

**Public finding.** Mandiantは、end-of-life Juniper MX router上のcustom TINYSHELL-derived backdoorをUNC3886に帰属させた。このsetには、activeおよびpassive implant、legitimate daemonを模倣するname、log-disabling behavior、trusted processへのprocess injection、SOCKS proxy capability、ORB staging nodeと評価されたinfrastructureが含まれていた。Passive variantは`libpcap`を通じてpacketを検査し、magic patternの後にのみactivateした。1つは、triggerで提供されたactive callbackへ切り替えることができた。<sup>[[14]](#references)</sup>

**Privacy effect.** Passive implantには発見可能なperiodic beaconがない。実際のnetwork applianceとport/trafficを共有し、短時間だけactivateし、ultimate controllerへ直接接続する代わりにORBを経由してrelayできる。

**What exposes it.** Memory analysis、on-disk codeとrunning codeの差異、予期しないpacket-capture filter/socket behavior、legitimate daemonに近いだけのprocess/file name、terminal server経由のadministration、欠落したlog、staging nodeとbackend controller間のtwo-stage relationship。

**Defensive lesson.** Filesystem/configuration evidenceだけでなくmemoryも取得し、process/moduleをknown-good imageと比較し、packet-capture/socket-filterの使用をmonitorし、management terminal serverをsecureにし、EOL network hardwareを交換する。Outbound-beacon huntで何も見つからなくても、問題がないとは限らない。

## APT29: Tor domain fronting

**Public finding.** MITREは、APT29が`meek` Tor pluggable transportを使用してC2 trafficをdomain-frontしていたことを記録している。外側のTLS nameは許可されたCDN-hosted domainに見える一方、内側のHTTP hostが実際のrouteを選択していた。<sup>[[6]](#references)</sup>

**Privacy effect.** Filtering observerには、inner destinationではなくcommon front/CDNが見える可能性があり、それをblockするとcollateral damageのリスクがあった。

**What exposes it.** CDNはrouting mismatchを観測でき、endpoint visibilityまたはlawful TLS visibilityを持つdefenderは、process、authority、connection lifetime、byte pattern、後続のactivityをcorrelateできる。Provider policyの変更によってtechniqueが無効化されることもある。

**Defensive lesson.** SNI allowlistingだけに依存しない。Application-aware egressをenforceし、確認可能な場合はTLS identityとHTTP identityを比較し、network eventをinitiating processに結び付ける。

## APT41 and other dead-drop resolvers

**Public finding.** MITREは、APT41がGitHub、Pastebin、Microsoft TechNet、Cloudflare、community forumなどのlegitimate siteを使用してC2 informationを公開または取得していたことをdocumentしている。その他のstate-linked toolingも、同様にpost、document、social mediaを使用している。<sup>[[7]](#references)</sup>

**Privacy effect.** BinaryにはstableなC2 addressではなく、legitimate service/objectが含まれる。Objectはinfrastructure rotationのために編集でき、initial requestは一般的なTLS trafficに紛れ込む。

**What exposes it.** Objectまたはaccount identifierはstableであり、rare processが繰り返しそれをfetchし、contentがdecodeされ、その後に2つ目のoutbound connectionが続く。Provider accountとAPI recordがpublicationをoperatorに結び付けることがある。

**Defensive lesson.** Full proxy path/object IDとendpoint process lineageを保存する。「GitHubに接続した」のようなdomain-level eventは粗すぎる。

## Turla: satellite-address C2

**Public finding.** Kasperskyは、Turlaが古いone-way DVB-S Internet serviceからのunencrypted downstream broadcastを悪用していたと報告した。Satellite footprint内のoperatorは、正規subscriberのaddressを選択し、そのaddress宛てにbroadcastされたreplyを受信できた。これにより、C2が別regionのsatellite providerの背後でhostされているように見えた。<sup>[[8]](#references)</sup>

**Privacy effect.** 見かけ上のserver addressからreceiverを特定することはできず、通常のhosting seizure/WHOIS processの有用性も低下した。

**What exposes it.** Actorには依然としてoutbound request pathが必要であり、routingはasymmetricだった。Legitimate subscriberはC2 exchangeを開始せず、RF/provider investigationによってreceiving footprintを絞り込める可能性があった。

**Defensive lesson.** Geolocationを1つの仮説として扱う。Path symmetry、RTT、routing ownership、想定されたendpointが実際に観測されたserviceを生成できるかを検証する。

## Cyclops Blink and VPNFilter: edge devices as durable cover

**Public finding.** 2022年のNCSC/CISA/FBI/NSA advisoryは、Sandwormのmodular Cyclops Blink malwareがWatchGuard device上で、firmware updateとしてpersistentにdeployされ、moduleを追加できたことを説明した。DOJは別途、APT28によるrouterとNAS deviceのbotnetである過去のVPNFilterについて、intelligence collection、destructive activity、misattributionが可能だったと説明した。<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Privacy effect.** Edge applianceは常時onlineで、infrastructureとしてtrustedされ、EDRによるcoverageが不十分である。Firmware persistenceは通常のrestart後も生き残り、victim deviceをrelayまたはcontrol pointにする可能性がある。

**What exposes it.** Firmware integrity、vendor-specific implant protocol、予期しないmanagement exposure、configuration change、outbound beaconing。Edge deviceは透明なplumbingではなく、forensic subjectとして扱わなければならない。

## DPRK: identity, network and financial layering

**Public finding.** DOJ caseは、DPRK workerがfalseまたはstolen identity materialとVPNを使用してremote jobを得て、cryptocurrencyを受け取り、transferを分割し、asset/chainをswapし、NFTを使用し、proceedsをcommingleしていたことを説明している。その他のcaseでは、OTC traderとfront companyがstolen cryptoをpurchaseへ変換していたことが説明されている。TreasuryとFBIは、Lazarus/TraderTraitorのproceedsをmixerに公に関連付け、major theftから得られたaddressを特定している。<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Privacy effect.** これは「private coin」ではない。Personaとremote accessがworkerのlocationを隠し、cryptoがvalueを移動し、layeringが単純なtransaction narrativeを分断し、OTC trader/front companyがgoodsとfiatへのbridgeになる、multi-domain chainである。

**What exposes it.** Employer/device anomaly、再利用されたfacilitator、blockchain上のtiming/value continuity、exchange/bridge record、sanctioned address、account identity、shipment/company recordがchainを再接続する。

**Defensive lesson.** Hiring、IAM、endpoint、payroll、blockchain、sanctions teamは、shared case modelを必要とする。詳細は[Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md)に記載されている。

## Cross-case patterns

| Pattern | APT examples | Defender adaptation |
|---|---|---|
| Exitは別のvictimである | APT28/Moobot、Volt Typhoon/KV、ORB | Exitをinvestigateしてremediateする。Exitをactorのlocationと同一視しない |
| Controlはboundaryごとに異なる | APT28 nearest neighbor | Internal/wireless accessにもInternet accessと同じidentity assuranceを適用する |
| Legitimate serviceがrouting layerになる | APT29、APT41 | Destination domainだけでなく、object/path/process contextを保持する |
| Edge deviceにはtelemetryがない | KV、Moobot、Cyclops Blink、ORB | Config/auth/flow logを一元化し、firmware/inventoryを検証する |
| Infrastructureはsharedかつshort-livedである | China-nexus ORB | Behavior/topologyをcluster化し、時間経過に伴うrole changeを追跡する |
| 複数の弱い分離が組み合わさる | DPRK persona + VPN + crypto + OTC | Identity、device、network、payment、physical evidenceを結合する |

## References

- [1] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — GRU-controlled Moobot router botnetのdisruption](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — PRC KV Botnetのdisruption](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — PRC actorによるUS critical infrastructureへのcompromiseとpersistent accessの維持](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — China-nexus espionage actorによるORB networkの使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Cyclops Blink advisory AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — APT28 VPNFilterのdisruption](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — DPRK Foreign Trade Bank representativeのcrypto-laundering conspiracyでの起訴](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Blender.io sanctionsとLazarus funds](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Chinese state-sponsored actorによる世界中のnetwork compromiseへの対抗](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886によるJuniper routerのtargeting](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
