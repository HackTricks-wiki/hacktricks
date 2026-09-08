# Offensive Infrastructure と Attribution Evasion

オペレーターが単一の proxy から意味のある匿名性を得られることはほとんどありません。実際のキャンペーンでは **separation graph** を構築します。オペレーターは access node に接続し、traversal nodes がその node を exit から隠し、redirectors が実際の C2 を保護し、使い捨ての名前が公開エッジを指し示します。

あらゆる経路について、標準化された長所・短所・導入・検知の観点を確認するには、[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) を使用してください。このページでは、敵対的なインフラの構成についてさらに詳しく説明します。
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
したがって、標的から最後に確認されたアドレスは経路の証拠ではあっても、キーボードを操作していた人物の身元を証明するものではない。MITRE は主要な構成要素を Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568)、Web Service (T1102) に分類している。<sup>[[1]](#references)</sup>

## Infrastructure の分類

| 分類 | 攻撃者が利用する理由 | 持続的に残る露出 | Defender が取るべき最良の pivot |
|---|---|---|---|
| レンタル VPS/cloud | 高速で予測可能、routing 可能で、再構築が容易 | tenant、billing、console、source-login、image の履歴 | account/control-plane のイベントと繰り返される server fingerprint |
| 商用 VPN/Tor | 大規模な共有 egress セット。server administration が不要 | provider/guard の可視性と end-to-end のタイミング | destination の挙動、endpoint の証拠、flow の相関 |
| Residential/mobile proxy | Consumer ASN と地理的なもっともらしさ | broker/customer の記録、proxyware または感染ホストの挙動 | impossible travel、proxy protocol、session ごとの address churn |
| Compromised server/router/IoT | 被害者の reputation と管轄を借用 | implant、management flow、繰り返し現れる upstream controller | 1 つの exit IP ではなく、device telemetry と ORB topology |
| CDN/redirector | 公開 edge と back-end C2 を分離 | TLS/HTTP grammar、certificate、routing、cloud-account の痕跡 | edge-to-origin の相関と request-shape の clustering |
| 正規の web service | 許可された GitHub/cloud/social traffic に紛れ込む | API token、tenant/object identifier、異常な process lineage | endpoint process と service/API semantics |
| 物理/cellular/satellite 経路 | 見かけ上の物理的な発信元を変更 | RF、carrier、subscriber、device、location の記録 | radio/physical と network の証拠を組み合わせる |

## Operational relay box network

**ORB network** は、中継サービスとして使用される managed proxy fleet である。Mandiant はこれを、leased server で構成される provisioned network、compromised router/IoT で構成される non-provisioned network、そして hybrid に分類している。成熟した topology には、4 つの論理的な役割がある。<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory、credentials、health、routing policy を維持する。
2. **Access/relay node:** customer または operator を認証する。変化する mesh への安定した入口となる。
3. **Traversal nodes:** 1 台以上の leased または compromised system が opaque connection を relay する。
4. **Exit/staging node:** reconnaissance、exploitation、C2 target に対して最終的な source address を提示する。

この mesh は、country、ASN、latency、availability に基づいて exit を選択し、health が低下した node を rotate できる。複数の threat group が同じ network を rent する場合もある。Mandiant は、一部の ORB に関連付けられた IPv4 address が、短い場合には 31 日間しか維持されないことを確認した。そのため、古い IP の一覧を block するのではなく、**network を進化する actor に似た entity として扱うこと**を推奨している。<sup>[[2]](#references)</sup>

### これによって得られるものと漏洩するもの

- 標的からは、地理的に近く、一見すると residential に見える exit が確認される可能性がある。
- exit からは標的と直前の hop が確認できるが、必ずしも operator までは確認できない。
- access service からは customer と route request が確認できる。独立して管理される mesh は customer を exit から分離できるが、強力な counterparty record を生み出す。
- 繰り返される port、handshake の順序、server banner、certificate、uptime window、controller relationship によって、IP が rotate されていても fleet が露出する可能性がある。
- Compromised router には endpoint telemetry が存在しないことが多いが、その ISP には subscriber と flow のデータが残っている。押収されれば implant/configuration の痕跡も明らかになる。

{% hint style="info" %}
許可を得た exercise では、組織所有の VM または router で topology を再現し、controller の attribution map を保持すること。open proxy や第三者の device を recruit してはならない。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) は、intermediary を被害に遭わせることなく、Defender から確認できる同じ hop structure を作成する。
{% endhint %}

## Residential および mobile proxy network

Residential proxy service は consumer broadband address に session を割り当て、mobile proxy は carrier NAT pool 経由で egress する。供給元には、明示的に登録された appliance、consumer application に組み込まれた SDK/proxyware、reseller、malware などがある。これらの起源は同じではない。informed consent がない場合、その privacy service は compromised infrastructure になる。

Rotation mode は detection に影響する。

- **per-request rotation** は、高位層の identity が安定しているにもかかわらず、IP、ASN、geography が急速に discontinuity を起こす。
- **sticky session** は数分から数時間にわたって exit を維持し、通常の subscriber に似た動作をする。
- **backconnect gateway** は customer に 1 つの broker endpoint を公開し、内部で exit を選択する。
- **mobile pool** は多数の genuine subscriber を少数の carrier NAT address の背後に配置するため、IP block のコストが高くなる。

Defender は、IP を authenticated session、TLS/client fingerprint、HTTP ordering、device cookie、behavior と相関させるべきである。一見すると local な residential login の後に、他の国からの login が続き、その間も高位層の特徴がすべて同一であれば、reputation だけの場合より強い証拠となる。一方で、address sharing と mobile handoff は正当な churn を生み出すため、residential/proxy の分類を決定的な verdict として扱ってはならない。

## Multi-hop proxy chain

MITRE は external proxy と **multi-hop proxy (T1090.003)** を区別している。重要なのは hop の数ではなく、knowledge と administration の分離である。<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
一方の当事者が A と B を運用している場合、共有ログや通信のタイミングから回路を再構築できます。同じエンドポイントやアカウントから商用 VPN を順番に追加しても、遅延が増えるだけで、共通する身元情報、支払い情報、タイミングに関する証拠は残る可能性があります。Tor は、独立して選択されたリレーと共有クライアント設計によってこの問題を軽減しますが、低遅延のインタラクティブネットワークは、両端を測定する観測者に対する耐性を保証できません。

よくある失敗には、DNS または IPv6 の bypass、アプリケーションが独自のソケットを開くこと、管理トラフィックがリレーに直接到達すること、活動の同期、SSH キーの再利用、識別可能なアカウントへのログインがあります。正しい検証方法は failure test です。すべてのリレーを順番に停止し、workload が clear path にフォールバックできないことを示します。

## Redirector tiers and traffic shaping

公開 **redirector** は、operation 固有の grammar に一致するトラフィックを受け付け、保護された team server に転送します。それ以外は拒否するか、無害なコンテンツを提供できます。
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
複数の層によって露出を制限できます。public domainを切り捨てても、team serverまで露出させる必要はありません。CDNはanycastのキャパシティと信頼性のある外側のdomainを提供しますが、CDN accountとedge logsがattribution pointsになります。TLS fingerprints、certificate histories、特徴的なpaths/header order、response sizes、redirect behavior、origin allowlistsによって、一見無関係なfrontsを同一クラスタにまとめられる可能性があります。

検知のために、正規化する前のreverse-proxy fieldsを記録し、SNI/Host/authorityを比較し、まれなheader combinationsを調査し、response bodiesとTLS fingerprintsをクラスタリングし、configuration overlapについてcloud/CDN audit logsを検索します。認可済みのred teamsでは、実在ブランドのコピーや、無関係な第三者の背後へのcredential collectionの配置を避けます。

## domain fronting and domainless fronting

従来の **domain fronting (T1090.004)** では、TLS connectionがSNIで許可されたfront domainを通知する一方、暗号化されたHTTP `Host`またはHTTP/2 `:authority`が別のback-end domainを要求します。協力するCDNは内部の値に基づいてroutingします。TLS decryptionを行わないnetwork observerにはfrontだけが見えますが、CDNには両方の値とoriginが見えます。domainless variantsでは、SNIが空であり、別のrouting fieldがdestinationを選択する場合があります。<sup>[[4]](#references)</sup>

これは魔法のようななりすましではありません。intermediaryが不一致を意図的または偶発的に許可し、内部のnameをroutingする方法を知っている場合にのみ機能します。主要providerはcross-account frontingを制限しています。Encrypted ClientHello (ECH)はon-path observerに見える情報を変えますが、CDN、endpoint、applicationのrecordsを消すものではありません。

検知ポイントには次が含まれます。

- endpoint process ancestryと、そのapplicationには想定されないdestination
- TLS inspectionが合法かつ利用可能な場合の、SNIとHTTP authorityの不一致
- あるtenant/frontから別のauthority/originへroutingしていることを示すCDN logs
- 通常はinteractiveなserviceへの、異常に長時間または定期的なsessions
- 変化するfront domains全体で安定している暗号化flowのsizesとcadence

安全なlabでは、所有するreverse proxy上でrouting mismatchをシミュレートします。public CDNを悪用してはいけません。

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolutionは、logical serviceを固定されたinfrastructureから切り離します。

- **DDNS:** 認証済みclientが、addressの変更後に安定したnameを更新します。
- **DGA:** endpointとcontrollerの双方が、time/key seedからcandidate domain namesを導出し、operatorはその一部を登録します。
- **Fast flux:** nameが、侵害されたまたはproxyのaddressesを急速に変化する集合として返します。多くの場合、TTLは短くなります。
- **Double flux:** service addressesとauthoritative name-server addressesの両方をrotateさせ、control layerも隠します。

Fast fluxは、単に「多数のDNS answers」があるというだけではなく、adversarialに使用されるload-distribution patternです。より強い証拠は、低いTTL、高いunique-address count、広範なASN/geography dispersion、短いnode lifetime、繰り返されるapplication behavior、疑わしいregistration historyを組み合わせます。CDNもこれらの性質のいくつかを正当に共有します。MITREは、DNS behaviorをprocessおよびその後のconnectionsと相関させることを推奨しています。<sup>[[5]](#references)</sup>

DGAは、lexical entropy、consonant/digit patterns、NXDOMAIN bursts、同期したfirst-seen domains、process contextによって検知できます。Wordlist DGAsやgenerative modelsは単純なentropy rulesを回避するため、fleet全体でのtemporal clusteringとendpoint lineageがより重要になります。

## Compromised domains and domain shadowing

actorはregistrar/DNS accountをhijackしたり、dangling subdomainをtake overしたり、その他の点では信頼できるdomainの配下にrecordsを追加したりする可能性があります。**Domain shadowing**は、正規のapexを維持したまま、大量のattacker-controlled subdomainsを変化するdeliveryまたはC2 hostsへ向けます。domainの経過期間とreputationを利用でき、domain全体に対するblockingを回避する可能性があります。<sup>[[6]](#references)</sup>

Defendersには、registrarおよびauthoritative-DNS audit logs、MFA、registry/registrar locks、新しいdelegations/API tokens/name serversに対するalerts、certificate-transparency monitoring、DNSが参照するcloud resourcesのinventoryが必要です。subdomainのresolutionとcertificate historyは、apexのreputationとは独立して調査してください。

## Web services and dead-drop resolvers

**dead-drop resolver (T1102.001)**は、正規のpost、profile、document、repository、cloud object、またはblockchain fieldの中に、現在のC2へのencoded pointerを保存します。Malwareはpublic objectを取得し、domain/IPをdecodeして次のstageへ接続します。Bidirectional variantsは、service APIsを介してcommandsまたはfilesを交換します。<sup>[[7]](#references)</sup>

これによりresilienceが得られ、static binary analysisからback-end C2を隠せます。一方で、stable object、tenant、repository、API、access-pattern identifiersも生成されます。Defendersは次を関連付けるべきです。

1. serviceに接続したprocess
2. 正確なAPI path/objectとresponse hash
3. decodingまたはstring-processing activity
4. その直後の新しいoutbound connection
5. fleet内の別の場所にある同一のbehavior

GitHub、cloud storage、social mediaをすべてblockingすることは、ほとんどの場合実行可能ではありません。service-aware egress policyとprocess-level correlationは、domain-only blockingを上回ります。

## Personas, accounts and procurement compartments

persona、recovery email、phone、payment、browser、またはadmin IPがcompartments間をつなぐと、Infrastructure anonymityは破綻します。国家と関連するoperationsでは、使用前からsocial profiles、email identities、cloud accountsを長期間にわたって育成している場合があります。ATT&CKはこれをEstablish Accounts (T1585)として記録しており、social、email、cloud sub-techniquesが含まれます。<sup>[[8]](#references)</sup>

Defenderまたはinvestigatorは、次からgraphを構築します。

- creationとfirst-loginの時刻、locale、time zone、working schedule
- recovery fields、MFA devices、identity documents、payment instruments
- browser/TLS fingerprintsとsource-network history
- avatar reuse、image provenance、writing style、social-graph growth
- 共有されたdomain registrant、name server、certificate、analytics ID、またはrepository commit
- public relay architectureを迂回するmanagement-plane actions

認可済みのred teamでは、synthetic personasをexercise controllerに文書化し、組織所有のrecovery/payment channelsを使用し、実在する無関係な人物になりすますことを避け、計画的にretirementさせるべきです。SOCがblindのままであることはあり得ますが、operationをaccountabilityのない状態にしてはいけません。

## Emerging compound patterns to threat-model

以下は**defender-driven compositions**であり、特定のactorがそれぞれの正確なdesignをdeployしたという主張ではありません。すでに観測されているprimitivesを組み合わせたもので、purple-team hypothesesとして有用です。

### Asymmetric one-way tasking

Commandsはpublic、broadcast、またはappend-only sourceを通じて到着し、resultsはdelay後に無関係なchannelから送信されます。primitiveの例には、web-service one-way communicationとdead dropsがあります。分離によって単一のflowがbidirectionalに見えることを防ぎ、単純なrequest/response correlationを困難にします。<sup>[[9]](#references)</sup>

**Detection:** object-level readsを保持し、その後のprocess state changesと、より広いwindowにおける後続のoutbound transfersを相関させます。直後のreplyがない場合でも、同じpublic objectを読むまれなprocessをhuntします。

### Multi-stage channel promotion

静かなfirst stageがinventoryを実行し、選択されたsystemだけを無関係なsecond-stage channelへpromoteします。second endpoint、protocol、processはfirst stageとinfrastructureを共有しない場合があります。これにより、高機能なinfrastructureの露出が制限され、ATT&CK T1104として明示的にmodel化されています。<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`を関連付けます。最初のdomainをblockingしただけでincidentを終了しないでください。

### Cross-protocol relay translation

異なるhopsは、packetsをtransparentにforwardするのではなく、HTTPS、QUIC、WebSocket、DNS、SSH、またはmessage-queue APIを相互にtranslateします。Translationにより、単一のend-to-end protocol fingerprintは除去されますが、特徴的なtiming、buffering、semantic conversionを持つgatewaysが生まれます。Protocol tunneling (T1572)は、proxiesおよびservice impersonationと組み合わせることができます。<sup>[[11]](#references)</sup>

**Detection:** あるprotocolを受信して別のprotocolを開始し、byte/time behaviorが密接に連動するgateway hostsを探します。endpointの意図と、実際に運ばれているprotocolを比較します。

### Passive activation on edge devices

beaconingの代わりに、implantはrouter/VPNにすでに到達しているtrafficを監視し、magic value、source-port pattern、またはauthenticated tokenがある場合にのみactivateします。通常のtrafficは実際のserviceへ継続します。ATT&CKはこれをTraffic Signaling (T1205)と呼び、network-deviceおよびAPTのdocumented examplesがあります。<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity、認可済みのhunt中のraw packet capture、予期しないsocket filters、differential service behaviorを確認します。periodic beaconが存在しないことは、edge deviceがcleanである証拠にはなりません。

### Serverless and ephemeral origin rotation

frontは安定したlogical identityを維持しつつ、short-lived functions/containersが複数のregions/accountsで個々のstagesを処理します。これによりdisk lifetimeと固定されたorigin IPsは減少しますが、control-plane creation、image/layer、role、secret、request ID、billing telemetryが永続的なgraphになります。

**Detection:** cloud auditとinvocation logsをworkloadの外部に保持し、deployment templates、roles、environment keys、front-to-origin relationshipsをcluster化します。

### Privacy-layer diversity

operationは、意図的に単一の均質なchainを避けることがあります。例えば、あるchannelではleased relayを使用し、taskingではpublic objectを使用し、exitは所有するlab cellular linkから行い、administrationでは別のorganization networkを使用します。これにより、1つのproviderをcompromiseする価値は低下しますが、cross-layer timingとoperational-errorのriskは増大します。

**Detection:** identity、DNS、SaaS、network、cloud sensors全体でcampaign timelinesを構築します。同一のindicatorsではなく、同期したstate transitionsを検索します。

### Decentralized or transparency-log dead drops

actorは、durableなpublic append-only system、content-addressed store、またはtransparencyに類似したfeedのいずれかに、小さなencrypted pointerを配置できます。public objectはresilientですが、正確なindex/content hashとclientのpolling behaviorがstable identifiersになります。

**Detection:** 完全なAPI/object identifiersとresponse hashesを記録します。immutable objectsをpollした後にdecodingまたは新しいconnectionsを行うnonstandard processesにalertを出します。

### Delayed store-and-forward operations

Interactive C2は強いtiming correlationを生成します。store-and-forward designはencrypted jobsをbatch処理し、数分または数時間後に、別のqueueまたはphysical transferを通じてresultsを返します。これによりresponsivenessを犠牲にして、end-to-end timingを弱めます。

**Detection:** correlation windowsを延長し、periodic queue accessをmodel化し、endpoint stagingを調査します。Batchingはsignalをpacket timingからscheduled process/file behaviorへ移しますが、signal自体を消すわけではありません。

## Design review: think in observers

すべてのpathについて、deployment前およびcollection後に次のtableを埋めてください。

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

1つの通常のproviderがすべてのcolumnを埋められる場合、そのarchitectureはtargetからのconcealmentは提供しますが、堅牢なseparationは提供しません。内部controllerがactivityをengagementに結び付けられない場合、それはprofessional red teamingには不適切です。

## References

- [1] [MITRE ATT&CK — Infrastructureの取得 (T1583)、Infrastructureの侵害 (T1584)、およびProxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexusのespionage actorsがORB networksを使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Infrastructureの侵害: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
