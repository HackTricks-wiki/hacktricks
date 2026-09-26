# Offensive Infrastructure と Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

operator が単一の proxy から意味のある anonymity を得られることはほとんどありません。実際の campaign では、**separation graph** を構築します。operator は access node に到達し、traversal node が exit からその node を隠し、redirector が実際の C2 を保護し、disposable name が public edge を指し示します。

あらゆる経路について、pros/cons、deployment、detection を正規化した一覧については、[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) を使用してください。このページでは、敵対的な infrastructure composition についてさらに詳しく説明します。
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
したがって、標的から最後に観測されたアドレスは経路の証拠であって、キーボードを操作していた人物の証明ではない。MITRE は主要な構成要素を Acquire Infrastructure (T1583)、Compromise Infrastructure (T1584)、Proxy (T1090)、Dynamic Resolution (T1568)、Web Service (T1102) に対応付けている。<sup>[[1]](#references)</sup>

## Infrastructure classes

| Class | Why an actor uses it | Durable exposure | Defender's best pivot |
|---|---|---|---|
| Rented VPS/cloud | 高速で予測可能、ルーティング可能で、容易に再構築できる | tenant、課金、コンソール、source-login、イメージ履歴 | アカウント／control-plane イベントと、繰り返し現れるサーバーフィンガープリント |
| Commercial VPN/Tor | 大規模な共有 egress セット。サーバー管理が不要 | provider／guard の可視性とエンドツーエンドのタイミング | 宛先の挙動、endpoint の証拠、フロー相関 |
| Residential/mobile proxy | コンシューマー ASN と地理的なもっともらしさ | broker／顧客記録。proxyware または感染ホストの挙動 | 不可能な移動、proxy プロトコル、セッションごとのアドレス変動 |
| Compromised server/router/IoT | 被害者の評判と管轄を借用できる | implant、管理フロー、繰り返し現れる上流 controller | 単一の exit IP ではなく、device telemetry と ORB トポロジー |
| CDN/redirector | 公開 edge とバックエンド C2 を分離できる | TLS/HTTP grammar、証明書、ルーティング、cloud-account の痕跡 | edge-to-origin 相関とリクエスト形状のクラスタリング |
| Legitimate web service | 許可された GitHub/cloud/social トラフィックに紛れ込める | API token、tenant/object 識別子、異常なプロセス系譜 | endpoint プロセスと service/API semantics |
| Physical/cellular/satellite path | 見かけ上の物理的な発信元を変更できる | RF、carrier、subscriber、device、位置情報の記録 | radio／物理的証拠とネットワーク証拠の組み合わせ |

## Operational relay box networks

**ORB network** は、中継サービスとして使用される管理型 proxy fleet である。Mandiant はこれらを、リースされたサーバーによる provisioned network、侵害された router/IoT による non-provisioned network、そして hybrid に分類している。成熟したトポロジーには、4 つの論理的な役割がある。<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** inventory、credentials、health、routing policy を維持する。
2. **Access/relay node:** customer または operator を認証する。変化する mesh への安定した入口となる。
3. **Traversal nodes:** 1 台以上のリース済みまたは侵害済みシステムが opaque connection を中継する。
4. **Exit/staging node:** reconnaissance、exploitation、または C2 target に対して最終的な source address を提示する。

mesh は country、ASN、latency、availability に基づいて exit を選択し、health の低い node をローテーションできる。複数の threat group が同じ network をレンタルする可能性がある。Mandiant は、一部の ORB に関連付けられた IPv4 address が、短い場合には 31 日間しか維持されないことを観測した。そのため、古くなった IP リストを block するのではなく、**network を進化する actor のような entity として扱う**ことを推奨している。<sup>[[2]](#references)</sup>

### What this buys—and what it leaks

- 標的からは、地理的に近く、見かけ上は residential に見える exit が観測される可能性がある。
- exit からは標的と直前の hop が見えるが、必ずしも operator が見えるわけではない。
- access service からは customer と route request が見える。独立して管理される mesh は customer と exit を分離できるが、強力な counterparty record を作り出す。
- 繰り返し使用される port、handshake order、server banner、certificate、uptime window、controller relationship によって、IP がローテーションされていても fleet が露見する可能性がある。
- 侵害された router には endpoint telemetry がないことが多いが、その ISP には subscriber と flow のデータが残っている。押収されれば implant/configuration の痕跡が露見する。

{% hint style="info" %}
認可された演習では、組織所有の VM または router でこのトポロジーを再現し、controller の attribution map を保持すること。open proxy や第三者の device を勧誘してはならない。[lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) は、中継者を被害に遭わせることなく、defender から見える同じ hop 構造を作成する。
{% endhint %}

## Residential and mobile proxy networks

Residential proxy service はセッションを consumer broadband address に割り当てる。mobile proxy は carrier NAT pool 経由で egress する。供給元には、明示的に登録された appliance、consumer application に組み込まれた SDK/proxyware、reseller、malware などがある。これらの起源は同一ではない。十分な informed consent がなければ、privacy service は compromised infrastructure へと変わる。

Rotation mode は detection に影響する。

- **per-request rotation** は、上位レイヤーの identity が安定している一方で、IP、ASN、geography に急速な不連続を生じさせる。
- **sticky sessions** は数分から数時間にわたって exit を維持し、通常の subscriber に似た挙動になる。
- **backconnect gateways** は customer に 1 つの broker endpoint を公開し、内部で exit を選択する。
- **mobile pools** は、多数の genuine subscriber を少数の carrier NAT address の背後に配置するため、IP block のコストが高くなる。

Defender は、IP を authenticated session、TLS/client fingerprint、HTTP ordering、device cookie、behavior と相関させるべきである。上位レイヤーのすべての特徴が同一であるにもかかわらず、local に見える residential login の直後に別の country が現れる場合、reputation だけの場合より強い判断材料となる。反対に、address sharing と mobile handoff は正当な churn を生じさせるため、residential/proxy の分類を決定的な verdict として扱ってはならない。

### Proxyware control planes and reseller overlap

Residential pool を exit の平坦なリストとしてモデル化してはならない。IPIDEA ecosystem の分析により、再利用可能な **two-tier control plane** が明らかになった。embedded SDK はまず device/enrollment metadata を Tier One domain に報告し、scheduling と Tier Two の `connect`/`proxy` IP:port pair を受け取る。node は定期的に Tier Two の connect port を polling して encoded task を取得し、対応する proxy port への 2 つ目の connection を開き、提供された bytes を要求された destination に relay する。表面上は異なる SDK と proxy brand が、それぞれ別の discovery domain を持っていたが、common ownership と reseller relationship を通じて、共有された Tier Two infrastructure と重複する exit pool に収束していた。<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
これは residential IP block よりも、より持続性の高いハンティングの pivot を生み出します:<sup>[[13]](#references)</sup>

- 予期しない utility、VPN、ゲーム、または組み込みデバイスのプロセスが、安定した device ID/customer key を送信し、変化するサーバーリストを受け取る；
- endpoint が通常とは異なるポート上の直接 IP を polling し、その直後、新しい宛先 socket を開く前に、同じアドレス上の別のポートへ接続する；
- 複数の見かけ上異なるブランドが、Tier Two アドレス、プロトコル文法、SDK code、または exit-node の重複を共有する；
- 異なる Tier One ドメインに接続する別々のアプリケーションが、同じ Tier Two pool からアドレスを受け取る。

この重複は attribution も制限します。ある vendor の広告された pool に IP が存在することを確認しても、該当する時点でどの reseller、customer、または threat actor が使用したかは確定できません。flow の timestamps、process lineage、Tier One の response bodies、Tier Two の task identifiers を保存してください。<sup>[[13]](#references)</sup> 認可された exercise では、組織が所有する endpoint のみを使用してこの階層を模倣してください。consumer devices や third-party proxyware を enroll してはいけません。

## Multi-hop proxy chains

MITRE は external proxies と **multi-hop proxies (T1090.003)** を区別しています。重要なのは hop の数ではなく、知識と管理の分離です。<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
一方の当事者が A と B を運用している場合、共有ログやフローのタイミングから回路を再構築できます。同じエンドポイントやアカウントから順番に商用 VPN を追加しても、レイテンシが増えるだけで、共通する身元情報、支払い情報、タイミングの証拠は残る可能性があります。Tor は、独立して選択されるリレーと共有クライアント設計によってこの問題を軽減しますが、低レイテンシのインタラクティブネットワークは、両端を測定する観測者に対する耐性を保証できません。

よくある失敗には、DNS または IPv6 のバイパス、アプリケーションによる独自ソケットの開設、リレーへ直接到達する管理トラフィック、活動の同期、再利用された SSH キー、身元を特定できるアカウントへのログインがあります。正しい検証方法は failure test です。すべてのリレーを順番に停止し、workload が clear path にフォールバックできないことを示します。

### Tunnel の崩壊と upstream への漏洩

リレーアーキテクチャは、失敗したときに最も attribution されやすくなることがあります。Unit 42 は、被害者側 VPS、リレー VPS、住宅用プロキシ、Tor、その他の proxy services を使用した多層の espionage path を記録しました。Tunnel が省略または崩壊すると、隠された upstream インフラがリレーおよび被害者側システムに直接接続していました。同じ調査では、upstream インフラ上に一時的に露出した X.509 certificate も、tier 間の pivot として利用されました。<sup>[[14]](#references)</sup>

**data plane**（`victim <-> exit`）と **control plane**（`operator/upstream -> relay administration`）を分離して維持します。所有するすべての tier で ingress と authentication のログ、certificate の履歴、短時間の失敗した接続を保持します。成功した C2 セッションだけを記録してはいけません。リレーの停止中にのみ現れる、または複数の被害者側ノードを直接管理する source は、通常の exit より有力な upstream 候補ですが、その ASN や geolocation は依然として仮説であり、operator の身元の証明ではありません。

認可された lab では、workload が fail closed するようにします。Linux network namespace 内で隔離された workload では、最初の route は tunnel を使用する必要があります。tunnel を削除した後は、physical uplink を選択するのではなく、request と route lookup の両方が失敗しなければなりません。
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
DNS と IPv6、および各 relay boundary でテストを繰り返す。いずれかの probe が成功した場合は、policy routing または firewall を修復する前に、実際の interface/source address を記録する。その観測結果が、調査担当者に見える attribution leak となる。

## Redirector tiers and traffic shaping

公開 **redirector** は、operation 固有の grammar に一致する traffic を受け付け、保護された team server に転送する。それ以外は拒否するか、無害な content を返すことができる。
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
複数の層によって露出を制限できます。公開ドメインを使い捨てにしても、チームサーバーまで露出する必要はありません。CDNはanycastの容量と信頼性のある外側のドメインを提供しますが、CDNアカウントとedgeログがattribution pointになります。TLS fingerprint、証明書履歴、特徴的なパス/ヘッダー順序、レスポンスサイズ、リダイレクト動作、origin allowlistによって、一見無関係なfrontを同一グループとして分類できます。

検知では、正規化前のreverse-proxyフィールドを記録し、SNI/Host/authorityを比較し、珍しいヘッダーの組み合わせを調査し、レスポンス本文とTLS fingerprintをクラスタリングし、cloud/CDN audit logで設定の重複を検索します。許可を得たred teamでは、実在ブランドのコピーや、無関係な第三者の背後でのcredential collectionを避けてください。

## Domain fronting and domainless fronting

従来の**domain fronting (T1090.004)**では、TLS接続がSNIで許可されたfront domainを示す一方、暗号化されたHTTP `Host`またはHTTP/2 `:authority`が別のback-end domainを要求します。協力するCDNは内部値に基づいてルーティングします。TLS復号を行わないnetwork observerにはfrontが見え、CDNには両方の値とoriginが見えます。domainless variantでは、SNIが空で、別のrouting fieldが宛先を選択する場合があります。<sup>[[4]](#references)</sup>

これは魔法のようななりすましではありません。intermediaryが意図的または偶発的に不一致を許可し、内部名をルーティングする方法を把握している場合にのみ機能します。主要providerはaccountをまたぐfrontingを制限しています。Encrypted ClientHello (ECH)はon-path observerに見える情報を変えますが、CDN、endpoint、applicationの記録を消すものではありません。

検知ポイントには次が含まれます。

- そのapplicationでは予期されないendpoint process ancestryとdestination
- TLS inspectionが合法かつ利用可能な場合の、SNIとHTTP authorityの不一致
- あるtenant/frontが別のauthority/originへルーティングしていることを示すCDN log
- 通常は対話的なserviceへの、異常に長時間または周期的なsession
- front domainが変化しても安定している暗号化flowのサイズと頻度

安全なlabでは、所有するreverse proxy上でrouting mismatchをシミュレートします。public CDNを悪用してはいけません。

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolutionは、論理serviceを固定されたinfrastructureから切り離します。

- **DDNS:** 認証済みclientが、addressの変更後に安定したnameを更新します。
- **DGA:** endpointとcontrollerの両方が、時刻/鍵seedから候補domain nameを導出し、operatorはその一部だけを登録します。
- **Fast flux:** nameが、侵害された、またはproxyとして機能するaddressの急速に変化する集合を返します。多くの場合、TTLは短くなります。
- **Double flux:** service addressとauthoritative name-server addressの両方をローテーションし、control layerも隠します。

Fast fluxは、単に「多くのDNS回答」があるというだけではなく、攻撃者が利用するload-distribution patternです。より強い証拠には、短いTTL、高いunique-address count、広範なASN/geographyへの分散、短いnode lifetime、反復するapplication behavior、疑わしいregistration historyの組み合わせが含まれます。CDNも正当にこれらの特徴のいくつかを持ちます。MITREは、DNS behaviorをprocessおよびその後のconnectionと相関させることを推奨しています。<sup>[[5]](#references)</sup>

DGAは、lexical entropy、子音/数字のパターン、NXDOMAIN burst、同期したfirst-seen domain、process contextによって検知できます。wordlist DGAやgenerative modelは単純なentropy ruleを回避するため、fleet全体での時間的クラスタリングとendpoint lineageがより重要になります。

## Compromised domains and domain shadowing

攻撃者はregistrar/DNS accountを乗っ取ったり、放置されたsubdomainを掌握したり、その他は信頼できるdomainの配下にrecordを追加したりする可能性があります。**Domain shadowing**は正規のapexを維持したまま、大量の攻撃者管理subdomainを変化するdeliveryまたはC2 hostへ向けます。これはdomainの経過年数とreputationを借用し、domain全体のblockingを回避する可能性があります。<sup>[[6]](#references)</sup>

Defenderには、registrarおよびauthoritative-DNS audit log、MFA、registry/registrar lock、新しいdelegation/API token/name serverに対するalert、certificate-transparency monitoring、DNSが参照するcloud resourceのinventoryが必要です。subdomainのresolutionとcertificate historyは、apexのreputationとは独立して調査してください。

## Web services and dead-drop resolvers

**dead-drop resolver (T1102.001)**は、正規のpost、profile、document、repository、cloud object、またはblockchain field内に、現在のC2へのencoded pointerを保存します。malwareはpublic objectを取得し、domain/IPをdecodeして次のstageへ接続します。双方向variantでは、service APIを通じてcommandまたはfileを交換します。<sup>[[7]](#references)</sup>

これは耐障害性を提供し、static binary analysisからback-end C2を隠します。一方で、安定したobject、tenant、repository、API、access-pattern identifierも作り出します。Defenderは次の情報を結合すべきです。

1. serviceへ接続したprocess
2. 正確なAPI path/objectとresponse hash
3. decodingまたはstring-processing activity
4. その直後の新たなoutbound connection
5. fleet内の別の場所での同一behavior

GitHub、cloud storage、social mediaをすべてblockするのは、ほとんどの場合現実的ではありません。service-aware egress policyとprocess-level correlationは、domainのみのblockingを上回ります。

## Personas, accounts and procurement compartments

persona、recovery email、phone、payment、browser、またはadmin IPがcompartment間をつなぐと、infrastructure anonymityは破綻します。国家と関連するoperationでは、利用するかなり前からsocial profile、email identity、cloud accountが作成されてきました。ATT&CKではこれをEstablish Accounts (T1585)として記録し、social、email、cloud sub-techniqueを含めています。<sup>[[8]](#references)</sup>

Defenderまたはinvestigatorは、次の情報からgraphを構築します。

- creationおよびfirst-loginの時刻、locale、time zone、working schedule
- recovery field、MFA device、identity document、payment instrument
- browser/TLS fingerprintとsource-network history
- avatarの再利用、image provenance、writing style、social-graphの成長
- 共通するdomain registrant、name server、certificate、analytics ID、repository commit
- public relay architectureを迂回するmanagement-plane action

許可を得たred teamでは、synthetic personaをexercise controllerに文書化し、組織所有のrecovery/payment channelを使用し、関係のない実在人物へのなりすましを避け、計画的なretirementを行うべきです。SOCがblindのままである可能性はありますが、operationを説明責任のない状態にしてはいけません。

## Emerging compound patterns to threat-model

以下は**defender-driven composition**であり、特定のactorがそれぞれの正確なdesignをdeployしたという主張ではありません。すでに観測されたprimitiveを組み合わせたもので、purple-team hypothesisとして役立ちます。

### Asymmetric one-way tasking

commandはpublic、broadcast、またはappend-only sourceを通じて到着し、resultは遅延後に無関係なchannelから送信されます。このprimitiveの例には、web-service one-way communicationとdead dropがあります。分離により、単一のflowがbidirectionalに見えることを防ぎ、単純なrequest/response correlationを妨げます。<sup>[[9]](#references)</sup>

**Detection:** object-level readを保持し、その後のprocess state changeと、より広い時間枠における後続のoutbound transferを相関させます。即座にreplyが続かない場合でも、同じpublic objectを読むまれなprocessをhuntします。

### Multi-stage channel promotion

静かなfirst stageがinventoryを実行し、選択されたsystemだけを無関係なsecond-stage channelへpromoteします。second endpoint、protocol、processはfirstとinfrastructureを共有しない可能性があります。これにより、高機能なinfrastructureの露出を制限し、ATT&CK T1104として明示的にmodel化されています。<sup>[[10]](#references)</sup>

**Detection:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`を結合し、first domainをblockした時点でincidentを終了しないでください。

### Cross-protocol relay translation

異なるhopが、packetを透過的にforwardするのではなく、HTTPS、QUIC、WebSocket、DNS、SSH、またはmessage-queue APIを相互に変換します。translationによって単一のend-to-end protocol fingerprintは除去されますが、特徴的なtiming、buffering、semantic conversionを持つgatewayが生まれます。Protocol tunneling (T1572)は、proxyおよびservice impersonationと組み合わせることができます。<sup>[[11]](#references)</sup>

**Detection:** あるprotocolを受信し、別のprotocolを開始するgateway hostを、緊密に結び付いたbyte/time behaviorとともに探します。endpointの意図と、実際に運ばれているprotocolを比較します。

### Passive activation on edge devices

beaconを送信する代わりに、implantはすでにrouter/VPNへ到達しているtrafficを監視し、magic value、source-port pattern、またはauthenticated tokenに対してのみactivateします。通常のtrafficはreal serviceへ継続して送られます。ATT&CKではこれをTraffic Signaling (T1205)と呼び、network-deviceおよびAPTの事例が文書化されています。<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity、許可を得たhunt中のraw packet capture、予期しないsocket filter、差分によるservice behaviorを確認します。周期的なbeaconがないことは、edge deviceがcleanである証明にはなりません。

### Serverless and ephemeral origin rotation

frontは安定した論理identityを維持しながら、短命なfunction/containerが複数のregion/accountで個別のstageを処理します。これによりdisk lifetimeと固定origin IPは減少しますが、control-plane creation、image/layer、role、secret、request ID、billing telemetryが永続的なgraphになります。

**Detection:** cloud auditとinvocation logをworkloadの外部に保持し、deployment template、role、environment key、front-to-origin relationshipをcluster化します。

### Privacy-layer diversity

operationは、1つの均一なchainを意図的に避ける場合があります。例えば、1つのchannelではleased relayを使用し、taskingではpublic objectを使用し、exitは所有するlab cellular linkから行い、administrationには別のorganization networkを使用します。これにより、1つのproviderを侵害する価値は下がりますが、layer間のtimingとoperational errorのriskは増加します。

**Detection:** identity、DNS、SaaS、network、cloud sensorをまたいだcampaign timelineを構築します。同一のindicatorではなく、同期したstate transitionを検索します。

### Decentralized or transparency-log dead drops

actorは、永続的なpublic append-only system、content-addressed store、またはtransparencyに似たfeedのいずれかに、小さなencrypted pointerを置くことができます。public objectはresilientですが、その正確なindex/content hashとclientのpolling behaviorが安定したidentifierになります。

**Detection:**完全なAPI/object identifierとresponse hashを記録し、immutable objectをpollingした後にdecodingまたは新しいconnectionを行うnonstandard processにalertを出します。

### Delayed store-and-forward operations

Interactive C2は強いtiming correlationを生みます。store-and-forward designでは、encrypted jobをbatch処理し、数分または数時間後に別のqueueまたは物理的なtransferを通じてresultを返します。これは応答性を犠牲にする代わりに、end-to-end timingを弱めます。

**Detection:** correlation windowを延長し、periodic queue accessをmodel化し、endpoint stagingを調査します。batchingによってsignalはpacket timingからscheduled process/file behaviorへ移りますが、消えるわけではありません。

## Design review: think in observers

すべてのpathについて、deployment前とcollection後に次のtableを埋めてください。

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

1つの一般的なproviderがすべてのcolumnを埋められる場合、そのarchitectureはtargetからのconcealmentは提供しますが、堅牢な分離は提供しません。内部controllerのいずれもactivityをengagementに結び付けられない場合、それはprofessional red teamingには不適切です。

## References

- [1] [MITRE ATT&CK — Infrastructureの取得 (T1583)、Infrastructureの侵害 (T1584)、およびProxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actorがORＢ networkを使用](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
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
- [13] [Google Threat Intelligence Group — 世界最大のResidential Proxy Networkの妨害](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Global Espionageの解明](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
