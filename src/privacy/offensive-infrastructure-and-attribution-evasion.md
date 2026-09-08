# Offensive Infrastructure and Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

オペレーターが単一の proxy だけで意味のある匿名性を得ることはほとんどありません。実際の campaign では **separation graph** を構築します。オペレーターは access node に到達し、traversal node が exit からその node を隠し、redirector が実際の C2 を保護し、使い捨ての名前が公開 edge を指し示します。

各経路の正規化された長所・短所・deployment・detection の観点については、[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) を使用してください。このページでは、敵対的な infrastructure composition についてさらに詳しく説明します。
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
したがって、targetから最後に確認されたaddressは経路の証拠であって、keyboardを操作していた人物の証明ではない。MITREは主要コンポーネントを Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568)、Web Service (T1102) にマッピングしている。<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | なぜactorが使用するのか | 持続的に残る痕跡 | Defenderにとって最良のpivot |
|---|---|---|---|
| Rented VPS/cloud | 高速で予測可能、routing可能で、簡単に再構築できる | tenant、billing、console、source-login、imageの履歴 | account/control-planeイベントと、繰り返し現れるserver fingerprint |
| Commercial VPN/Tor | 大規模な共有egress set。server管理が不要 | provider/guardの可視性とend-to-end timing | destinationの挙動、endpointの証拠、flowの相関 |
| Residential/mobile proxy | Consumer ASNと地理的なもっともらしさ | broker/customerの記録。proxywareまたは感染hostの挙動 | impossible travel、proxy protocol、sessionごとのaddress churn |
| Compromised server/router/IoT | victimのreputationとjurisdictionを借用できる | implant、management flow、繰り返し現れるupstream controller | 1つのexit IPではなく、device telemetryとORB topology |
| CDN/redirector | public edgeとback-end C2を分離できる | TLS/HTTP grammar、certificate、routing、cloud-accountのartifact | edge-to-originの相関とrequest-shapeのclustering |
| Legitimate web service | 許可されたGitHub/cloud/social trafficに紛れ込める | API token、tenant/object identifier、異常なprocess lineage | endpoint processとservice/API semantics |
| Physical/cellular/satellite path | 見かけ上の物理的なoriginを変更できる | RF、carrier、subscriber、device、locationの記録 | radio/physical evidenceとnetwork evidenceの組み合わせ |

## Operational relay box networks

**ORB network**とは、中継サービスとして使用されるmanaged proxy fleetである。Mandiantはこれらを、leased serverによるprovisioned network、compromised router/IoTによるnon-provisioned network、およびhybridに分類している。成熟したtopologyには、4つの論理的なroleがある:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory、credential、health、routing policyを維持する。
2. **Access/relay node:** customerまたはoperatorをauthenticationする。変化するmeshへの安定したentryとなる。
3. **Traversal nodes:** 1台以上のleasedまたはcompromised systemがopaque connectionをrelayする。
4. **Exit/staging node:** reconnaissance、exploitation、またはC2 targetに対して最終的なsource addressを提示する。

meshはcountry、ASN、latency、またはavailabilityに基づいてexitを選択し、unhealthy nodeをrotateできる。複数のthreat groupが同じnetworkをrentしている場合もある。Mandiantは、一部のORBに関連付けられたIPv4 addressがわずか31日間しか維持されないケースを観測している。そのため、古いIP listをblockするのではなく、**networkを進化するactorのようなentityとして扱う**ことを推奨している。<sup>[[2]](#references)</sup>

### What this buys—and what it leaks

- targetには、地理的に近く、一見するとresidentialに見えるexitが表示される可能性がある。
- exitにはtargetと直前のhopが見えるが、必ずしもoperatorまでは見えない。
- access serviceにはcustomerとroute requestが見える。独立して管理されるmeshではcustomerをexitから分離できるが、強力なcounterparty recordが作成される。
- 繰り返し使用されるport、handshake order、server banner、certificate、uptime window、controller relationshipは、IPがrotateされている間でもfleetを露呈させる可能性がある。
- compromised routerにはendpoint telemetryが存在しないことが多いが、ISPにはsubscriberとflowのdataが残っている。押収されればimplant/configuration artifactが露呈する。

{% hint style="info" %}
authorized exerciseでは、organizationが所有するVMまたはrouterでtopologyを再現し、controllerのattribution mapを保持すること。open proxyやthird-party deviceをrecruitしてはならない。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)では、intermediaryをvictimにすることなく、Defenderから見える同じhop structureを作成できる。
{% endhint %}

## Residential and mobile proxy networks

Residential proxy serviceはsessionをconsumer broadband addressに割り当てる。mobile proxyはcarrier NAT poolを経由してegressする。供給元には、明示的にenrollされたappliance、consumer applicationに組み込まれたSDK/proxyware、reseller、またはmalwareが含まれる。これらのoriginは同じものではない。informed consentがない場合、privacy serviceはcompromised infrastructureに変わる。

rotation modeはdetectionに影響する。

- **per-request rotation**では、higher-layer identityが安定している一方、IP、ASN、geographyが急速かつ不連続に変化する。
- **sticky sessions**ではexitが数分から数時間維持され、通常のsubscriberに似た挙動になる。
- **backconnect gateways**ではcustomerにbroker endpointだけを公開し、内部でexitを選択する。
- **mobile pools**では、多数の正規subscriberが少数のcarrier NAT addressの背後に置かれるため、IP blockのコストが高くなる。

Defenderは、IPをauthenticated session、TLS/client fingerprint、HTTP ordering、device cookie、behaviorと相関させるべきである。すべてのhigher-layer featureが同一のまま、localとされるresidential loginの直後に別のcountryからのloginが続く場合、reputationだけの場合より強い証拠となる。一方、address sharingとmobile handoffは正当なchurnを生むため、residential/proxy classificationを決定的な判定として扱ってはならない。

## Multi-hop proxy chains

MITREはexternal proxyと**multi-hop proxy (T1090.003)**を区別している。重要なのはhop数ではなく、knowledgeとadministrationの分離である。<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
一方の当事者が A と B を運用している場合、共有ログや通信タイミングから回路を再構築できます。同じエンドポイントやアカウントから商用 VPN を順番に追加しても、遅延が増えるだけで、共通する身元情報、支払い情報、タイミングの証拠は残る可能性があります。Tor は、独立して選択されたリレーと共有クライアント設計によってこの問題を軽減しますが、低遅延のインタラクティブネットワークは、両端を測定する観測者への耐性を保証できません。

よくある失敗には、DNS または IPv6 のバイパス、アプリケーションが独自のソケットを開くこと、管理トラフィックがリレーへ直接到達すること、活動の同期、SSH キーの再利用、身元を特定できるアカウントへのログインがあります。正しい検証方法は失敗テストです。すべてのリレーを順番に停止し、ワークロードが clear path にフォールバックできないことを示します。

## Redirector tiers and traffic shaping

公開 **redirector** は、operation 固有の grammar に一致するトラフィックを受け取り、保護された team server に転送します。それ以外は拒否するか、無害なコンテンツを提供できます。
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
複数の層によって露出を制限できます。公開ドメインを使い捨てても、team serverまで露出させる必要はありません。CDNはanycastの容量と信頼性のある外側のドメインを追加しますが、CDNアカウントとedge logsがattribution pointsになります。TLS fingerprints、certificate histories、特徴的なパスやheader order、response sizes、redirect behavior、origin allowlistsによって、無関係に見えるfrontsをクラスタリングできます。

検知では、正規化前のreverse-proxy fieldsを記録し、SNI/Host/authorityを比較し、まれなheader combinationsを調査し、response bodiesとTLS fingerprintsをクラスタリングし、configuration overlapについてcloud/CDN audit logsを検索します。認可されたred teamでは、実在ブランドのコピーや、無関係な第三者の背後へのcredential collectionの配置を避けます。

## Domain fronting and domainless fronting

従来の **domain fronting (T1090.004)** では、TLS connectionがSNIで許可されたfront domainを広告する一方、暗号化されたHTTP `Host`またはHTTP/2 `:authority`が別のback-end domainを要求します。協力するCDNは内部値に基づいてroutingします。TLS decryptionを行わないnetwork observerにはfrontが見え、CDNには両方の値とoriginが見えます。domainless variantsでは、SNIが空で、別のrouting fieldがdestinationを選択する場合があります。<sup>[[4]](#references)</sup>

これは魔法のようななりすましではありません。intermediaryが意図的または偶然に不一致を許可し、内部名のrouting方法を把握している場合にのみ機能します。主要providerはcross-account frontingを制限しています。Encrypted ClientHello (ECH)はon-path observerに見える情報を変えますが、CDN、endpoint、applicationのrecordsを消すものではありません。

検知ポイントには次が含まれます。

- endpoint process ancestryと、そのapplicationには想定されないdestination
- TLS inspectionが合法かつ利用可能な場合の、SNIとHTTP authorityの不一致
- あるtenant/frontが別のauthority/originへroutingしていることを示すCDN logs
- 通常はinteractiveなserviceへの、通常とは異なる長時間または周期的なsessions
- 変化するfront domains間で安定したencrypted flow sizesとcadence

安全なlabでは、所有するreverse proxy上でrouting mismatchをsimulationします。public CDNを悪用してはなりません。

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolutionは、logical serviceを固定されたinfrastructureから切り離します。

- **DDNS:** authenticated clientが、address変更後にstable nameを更新します。
- **DGA:** endpointとcontrollerの双方が、time/key seedからcandidate domain namesを導出し、operatorはその一部を登録します。
- **Fast flux:** nameが、侵害またはproxyされたaddressesの急速に変化する集合を返します。多くの場合、TTLは短くなります。
- **Double flux:** service addressesとauthoritative name-server addressesの両方をrotationさせ、control layerも隠します。

Fast fluxは、単なる「多くのDNS answers」ではなく、adversarialに使用されるload-distribution patternです。より強い証拠には、低いTTL、高いunique-address count、広いASN/geography dispersion、短いnode lifetime、反復するapplication behavior、疑わしいregistration historyの組み合わせが必要です。CDNもこれらの性質のいくつかを正当に共有します。MITREは、DNS behaviorをprocessおよびその後のconnectionsと相関させることを推奨しています。<sup>[[5]](#references)</sup>

DGAは、lexical entropy、consonant/digit patterns、NXDOMAIN bursts、同期したfirst-seen domains、process contextによって検知できます。Wordlist DGAsやgenerative modelsは単純なentropy rulesを回避するため、fleet-wide temporal clusteringとendpoint lineageがより重要になります。

## Compromised domains and domain shadowing

攻撃者はregistrar/DNS accountをhijackしたり、dangling subdomainをtake overしたり、その他の点では信頼できるdomainの配下にrecordsを追加したりできます。**Domain shadowing**は、正規のapexを維持しながら、大量のattacker-controlled subdomainsを変化するdeliveryまたはC2 hostsへ向けます。domainのageとreputationを借用でき、domain-wide blockingを回避する場合があります。<sup>[[6]](#references)</sup>

Defendersには、registrarとauthoritative-DNSのaudit logs、MFA、registry/registrar locks、新しいdelegations/API tokens/name serversに対するalerts、certificate-transparency monitoring、DNSから参照されるcloud resourcesのinventoryが必要です。apexのreputationとは独立して、subdomainのresolutionとcertificate historyを調査します。

## Web services and dead-drop resolvers

**dead-drop resolver (T1102.001)** は、正規のpost、profile、document、repository、cloud object、またはblockchain fieldの内部に、current C2へのencoded pointerを保存します。Malwareはpublic objectを取得し、domain/IPをdecodeして次のstageへ接続します。Bidirectional variantsは、service APIsを介してcommandsまたはfilesを交換します。<sup>[[7]](#references)</sup>

これはresilienceを提供し、static binary analysisからback-end C2を隠します。同時に、stable object、tenant、repository、API、access-pattern identifiersを生み出します。Defendersは次を結合すべきです。

1. serviceに接続したprocess
2. 正確なAPI path/objectとresponse hash
3. decodingまたはstring-processing activity
4. その直後の新しいoutbound connection
5. fleet内の他の場所での同一のbehavior

すべてのGitHub、cloud storage、social mediaをblockingするのは、ほとんどの場合実行可能ではありません。Service-aware egress policyとprocess-level correlationは、domain-only blockingを上回ります。

## Personas, accounts and procurement compartments

Persona、recovery email、phone、payment、browser、またはadmin IPがcompartmentsを橋渡しすると、infrastructure anonymityは破綻します。State-linked operationsは、使用するかなり前からsocial profiles、email identities、cloud accountsを構築してきました。ATT&CKはこれをEstablish Accounts (T1585)として記録しており、social、email、cloud sub-techniquesが含まれます。<sup>[[8]](#references)</sup>

Defenderまたはinvestigatorは、次からgraphを構築します。

- creationとfirst-loginのtime、locale、time zone、working schedule
- recovery fields、MFA devices、identity documents、payment instruments
- browser/TLS fingerprintsとsource-network history
- avatar reuse、image provenance、writing style、social-graph growth
- 共有されたdomain registrant、name server、certificate、analytics ID、またはrepository commit
- public relay architectureを迂回するmanagement-plane actions

認可されたred teamでは、synthetic personasをexercise controllerに記録し、組織所有のrecovery/payment channelsを使用し、関係のない実在人物のなりすましを避け、計画的にretirementします。SOCがblindのままである可能性はありますが、operationをunaccountableにしてはなりません。

## Emerging compound patterns to threat-model

以下は、**defender-driven compositions**であり、特定のnamed actorが各設計を正確にdeployしたという主張ではありません。すでに観測されたprimitivesを組み合わせたもので、purple-team hypothesesとして有用です。

### Asymmetric one-way tasking

Commandsはpublic、broadcast、またはappend-only sourceを通じて到着し、resultsはdelay後に無関係なchannelから送信されます。primitiveの例には、web-service one-way communicationとdead dropsがあります。分離によって単一のflowがbidirectionalに見えることを防ぎ、単純なrequest/response correlationを妨げます。<sup>[[9]](#references)</sup>

**Detection:** object-level readsを保持し、その後のprocess state changesとlater outbound transfersを、より広いwindowで相関させます。直ちにreplyが続かない場合でも、同じpublic objectを読むrare processをhuntします。

### Multi-stage channel promotion

静かなfirst stageがinventoryを実行し、選択されたsystemsのみを無関係なsecond-stage channelへpromoteします。second endpoint、protocol、processは、first stageとinfrastructureを共有しない場合があります。これはcapable infrastructureの露出を制限し、ATT&CK T1104として明示的にmodel化されています。<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`を結合します。first domainをblockingしただけでincidentを終了してはなりません。

### Cross-protocol relay translation

異なるhopsは、packetsを透過的にforwardするのではなく、HTTPS、QUIC、WebSocket、DNS、SSH、またはmessage-queue APIをtranslationします。Translationは単一のend-to-end protocol fingerprintを除去しますが、特徴的なtiming、buffering、semantic conversionを持つgatewaysを作り出します。Protocol tunneling (T1572)はproxiesやservice impersonationと組み合わせられます。<sup>[[11]](#references)</sup>

**Detection:** あるprotocolを受信し別のprotocolを開始するgateway hostsを、緊密に結びついたbyte/time behaviorとともに探します。endpointのintentと、実際に運ばれたprotocolを比較します。

### Passive activation on edge devices

Beaconingの代わりに、implantはrouter/VPNにすでに到達しているtrafficを監視し、magic value、source-port pattern、またはauthenticated tokenがある場合にのみactivateします。通常のtrafficは実際のserviceへ継続します。ATT&CKはこれをTraffic Signaling (T1205)と呼び、network-deviceおよびAPTのdocumented examplesがあります。<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity、authorized hunt中のraw packet capture、unexpected socket filters、differential service behaviorを確認します。periodic beaconがないことは、edge deviceがcleanである証明にはなりません。

### Serverless and ephemeral origin rotation

Frontはstable logical identityを維持しながら、short-lived functions/containersが複数のregions/accountsで個々のstagesを処理します。これによりdisk lifetimeと固定origin IPsを減らせますが、control-plane creation、image/layer、role、secret、request ID、billing telemetryがdurable graphになります。

**Detection:** cloud auditとinvocation logsをworkloadの外部に保持し、deployment templates、roles、environment keys、front-to-origin relationshipsをclusterします。

### Privacy-layer diversity

Operationは、1つのhomogeneous chainを意図的に避ける場合があります。たとえば、1つのchannelはleased relayを使用し、taskingはpublic objectを使用し、exitは所有するlab cellular linkから取得し、administrationは別のorganization networkを使用します。これにより、1つのproviderをcompromiseする価値は下がりますが、cross-layer timingとoperational-errorのriskは高まります。

**Detection:** identity、DNS、SaaS、network、cloud sensorsをまたいだcampaign timelinesを構築します。同一のindicatorsではなく、同期したstate transitionsを検索します。

### Decentralized or transparency-log dead drops

攻撃者は、durableなpublic append-only system、content-addressed store、またはtransparency-like feedに、小さなencrypted pointerを配置できます。public objectはresilientですが、その正確なindex/content hashと、clientのpolling behaviorがstable identifiersになります。

**Detection:** 完全なAPI/object identifiersとresponse hashesを記録し、immutable objectsをpollした後にdecodingまたは新しいconnectionsを行うnonstandard processesにalertを出します。

### Delayed store-and-forward operations

Interactive C2は強いtiming correlationを生み出します。Store-and-forward designは、encrypted jobsをbatch処理し、minutesまたはhours後に、別のqueueまたはphysical transferを通じてresultsを返します。これはresponsivenessを犠牲にして、end-to-end timingを弱めます。

**Detection:** correlation windowsを延長し、periodic queue accessをmodel化し、endpoint stagingを調査します。Batchingはsignalをpacket timingからscheduled process/file behaviorへ移しますが、signal自体を消すわけではありません。

## Design review: think in observers

各pathについて、deployment前とcollection後に次のtableを埋めます。

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

1つの通常のproviderがすべてのcolumnを埋められる場合、そのarchitectureはtargetからのconcealmentは提供しますが、robust separationは提供しません。内部controllerのいずれもactivityをengagementに結び付けられない場合、professional red teamingには不適切です。

## References

- [1] [MITRE ATT&CK — Infrastructureの取得 (T1583)、InfrastructureのCompromise (T1584)、およびProxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actorsがORB networksを使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — InfrastructureのCompromise: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
