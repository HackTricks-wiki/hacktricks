# Anonymous Internet Access Technique Catalog

これは標準的なアクセス経路のインベントリです。すべてのベンダー名ではなく、プロトコルおよび運用上の**ファミリー**を扱います。インターネット経路だけで匿名性が保証されることはありません。アカウント、ブラウザー、エンドポイント、タイミング、支払い、cloud-control-plane、物理的証拠により、完全に見える経路でも特定される可能性があります。

すべての項目は同じフィールドを使用します。「Procedure」は、合法的な導入または所有ラボでのエミュレーションを意味します。実際の技術がルーターの侵害、アクセスの窃取、または同意のない中継者の悪用に依存する場合、再現では演習用に所有するシステムを使用します。

## Coverage matrix

| ファミリー | 宛先から見えるもの | 最も強い特性 | 速度 | 扱い |
|---|---|---|---|---|
| Shared NAT/CGNAT | 共有パブリックアドレス | 加入者間の曖昧性 | 高 | 導入可能 |
| VPN、VPS、SOCKS/HTTP/SSH proxy | relayアドレス | 高速な送信元アドレス分離 | 高 | 導入可能 |
| Multi-hop/split relay、MASQUE | 最終proxy | 知識分割または完全IPトンネル | 高/中 | 信頼できるrelayで導入可能 |
| Tor、bridge、onion service | exitまたはonion identity | 複数主体の経路と共通ブラウザー | 中 | 導入可能 |
| I2P、GNUnet、mixnet | overlay peer/gateway | overlayまたはタイミング耐性 | 低/可変 | アプリケーション依存 |
| OHTTP/ODoH、Private Relay | gateway/egress | 送信元とリクエストの分割 | 高 | 対応アプリケーションのみ |
| Public Wi-Fi、travel router | 会場/tunnelアドレス | 場所/アクセス経路の変更 | 高 | 許可が必要 |
| Cellular/eSIM、satellite | carrier/providerアドレス | 独立した物理uplink | 高/可変 | 加入・providerが監視 |
| Remote browser/jump host | リモートworkspace | endpointとegressの分離 | 高 | 導入可能 |
| Residential/mobile proxy | consumer/carrierアドレス | consumer networkらしさ | 高 | 同意/出所が重要 |
| ORB/compromised relay | 他の被害者のアドレス | 発信元の秘匿と借用したreputation | 高 | 所有ラボでのみ再現 |
| CDN/fronting/redirector | CDN/frontアドレス | バックエンドインフラの保護 | 高 | provider/所有者の承認が必要 |
| Fast flux/DGA/dead drop | 変動するnode/service | インフラ発見への耐性 | 可変 | 所有ラボでのみ再現 |
| Drop/nearest-neighbor | 対象近傍のローカルアドレス | 地理/ネットワーク境界の通過 | 高 | 所有サイトのラボのみ |
| Store-and-forward/offline | gatewayまたは物理receiver | 対話タイミングの関連付け低減 | 低 | アプリケーション依存 |
| Pluggable/refraction transport | Tor entryまたは協力するdiversion proxy | 検閲耐性のある到達性 | 可変 | 対応clientまたは研究ラボ |
| IPFS gateway/PIR/remote fetcher | gatewayまたはアプリケーションservice | publisher/query/requestの分割 | 可変 | 限定的なアプリケーションのみ |
| Anycast/QUIC/MPTCP | 安定したbrokerまたは複数subflow | rendezvousとsession継続 | 高 | 可用性用であり匿名性用ではない |
| CI/CD automation runner | hosted runnerアドレス | 使い捨て可能で説明責任のあるegress | 高 | 所有workflowのみ |
| Non-IP local first hop | organization gateway | sensorからインターネットstackを排除 | 低 | 所有者承認の導入 |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** 複数ユーザーが1つのパブリックアドレスを共有し、access providerが加入者側のアドレスとportをパブリックtupleへマッピングします。

**Pros:** 高速、特別なclient不要、宛先側IPだけでは家庭、会場、carrier poolしか特定できない場合があります。

**Cons:** providerは加入者/port/timeの対応表を保持できます。アカウントとfingerprintは残り、他ユーザーがアドレスreputationを損なう可能性があります。

**Procedure:** (1) authorized accessがNAT/CGNATを使用しているか確認する。(2) 所有endpointで正確なpublic IPとsource portを記録する。(3) アプリケーションidentityを分離する。(4) shared addressingをprivacy controlとみなさない。(5) ISPに宛先を知られたくない場合は、より強い経路を使用する。

**Detection:** 宛先はIPだけでなくsource portと正確な時刻を保持すべきです。providerはNAT allocation logを相関し、調査者はアカウント、device、browserの証拠を結合します。

## Commercial VPN

**Mechanics:** 暗号化されたfull-tunnel接続がVPNで終端し、宛先にはそのegressが見えます。VPNは通常、source、timing、destinationを関連付けられます。

**Pros:** 高速、簡単、ローカルの受動的監視から保護、安定または共有されたexit、管理されたred-team egressに適しています。

**Cons:** 信頼の集中、billing/login telemetry、kill-switch/DNS/IPv6の失敗、共有exitのreputation block。

**Procedure:** (1) provider、所有者、管轄、retention、assessment policyを確認する。(2) 署名済みの公式clientをインストールする。(3) full tunnel、always-on、fail-closedを有効にする。(4) DNSとIPv6を意図的にrouteする。(5) 所有endpointで観測されるIPv4/IPv6/DNSを検証する。(6) tunnelを停止/再接続し、clear fallbackがないことを確認する。<sup>[[1]](#references)</sup>

**Detection:** ローカルネットワークにはVPN infrastructureへの長時間の暗号化flowが見えます。providerにはauthentication/connection recordがあり、宛先はASN/reputation、アカウント、TLS/browser、行動の相関を使用します。

## Self-hosted VPN or rented VPS egress

**Mechanics:** operatorがWireGuard/OpenVPN gatewayを管理するか、rented serverを通してtrafficをforwardします。

**Pros:** 予測可能な高速性、allowlist可能な固定アドレス、custom logging/firewall、良好なincident control。

**Cons:** 匿名性集合が小さい。cloud tenant、支払い、source login、API、image履歴がoperatorを結び付け、特徴的な新serverは容易にcluster化されます。

**Procedure:** (1) engagement専用のorganization projectを作成する。(2) 対応imageと固定アドレスをprovisionする。(3) 管理をMFA/key-based administrationに制限する。(4) full-tunnel egressとDNSを設定する。(5) 可能な範囲で対象を限定する。(6) leak/failure behaviorをテストする。(7) controller audit recordを保持する。(8) teardown時にcredentialとresourceを破棄する。

**Detection:** hosting ASN、初回観測アドレス、certificate/service fingerprint、scanning behaviorを相関します。cloud ownerはcontrol-plane、console、billing、flow logを使用します。

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** applicationがproxyにTCP streamの開設を要求します。SOCKSはversionによってname resolutionとUDPも伝送でき、SSHは1つの暗号化session内でstreamをforwardします。

**Pros:** 軽量、アプリケーション単位、高速、chainingと分離networkへの到達に有用。

**Cons:** applicationが迂回可能、DNS leak、proxyに隣接endpointが見える、browser stateが残る、open proxyはtrapまたは侵害済みsystemの可能性があります。

**Procedure:** (1) 所有hostにproxyを導入する。(2) authenticationを必須にし、source/destinationを制限する。(3) 使い捨てapplication profileを1つ設定する。(4) 必要時はremote DNS resolutionを確実にする。(5) 所有DNS/HTTP endpointで検証する。(6) workloadのdirect egressをblockする。(7) proxy credentialを確認しrotateする。

**Detection:** tunnel-capable process、CONNECT/SOCKS negotiation、長時間SSH session、applicationと整合しない宛先を特定します。proxy logからstreamを再構成できます。

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** websiteが宛先をfetchしてlink/formを自身のorigin経由に書き換えるか、extensionがbrowser requestをproxyへ送ります。宛先にはserviceが見えますが、serviceはTLS終端後のplaintextを読み、contentを注入・保持できます。

**Pros:** system-wide client不要、単純な閲覧では高速、VPNをインストールできない場所で動作。

**Cons:** proxyがcredential/contentを読み、downloadを書き換え、userをfingerprintできます。script/WebSocket/downloadが迂回する場合があり、browser extensionは広い権限を持ち、匿名性集合は小さくblockも多い。

**Procedure:** (1) authorized testing用にorganization-operated proxyのみ使用する。(2) personal accountのない使い捨てbrowserで分離する。(3) password入力とsensitive downloadを禁止する。(4) 所有pageで全subresourceがproxy経由になることを確認する。(5) WebSocket、download、form behaviorをテストする。(6) 使用後にextension/profileを削除する。

**Detection:** 宛先にはproxyが記録されます。enterprise proxy/DNSとextension inventoryからserviceを特定でき、content-security/reportingまたは所有canary subresourceでdirect bypassを発見できます。

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** entryはsourceを見ますが、1つ以上のtraversal relayがentryとdestinationを分離し、exitがdestinationを見ます。

**Pros:** 通常、単一relayが両端を知る必要がない。1 nodeの障害/押収で露出が減り、地理を柔軟に選べます。

**Cons:** 共有administration/logが分離を無効化し、latency、timing correlation、failure、DNS経路が増えます。同一account/paymentが全hopを結び付けます。

**Procedure:** (1) 各hopが除去するobserverを定義する。(2) 分離が重要なら、独立管理の所有/承認relayを使用する。(3) workloadからentry-only accessを強制する。(4) 各relayが次のhopにのみ到達できるようにする。(5) 全layerのlogを検証する。(6) 各hopを停止しfail-closedを確認する。[Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)で再現する。

**Detection:** 隣接NetFlowのtiming/volume、反復するproxy handshake、共通controller infrastructureを相関します。exitからoperatorの地理を推定してはいけません。

## Split-knowledge application relay and OHTTP

**Mechanics:** clientはstateless HTTP messageをgateway向けに暗号化し、relay経由で送信します。relayにはclient IPが見えますがrequestは見えず、gatewayにはrequestが見えますが通常relay IPしか見えません。

**Pros:** 対応requestで強力かつ監査可能なprivacy partition、general anonymity networkより低overhead。

**Cons:** arbitrary browsingではない。cookie/authenticationで再関連付け可能、relay/gatewayのcollusionとtraffic analysisが残り、application側の実装が必要です。

**Procedure:** (1) RFC 9458を明示的にサポートするapplicationを選ぶ。(2) official configuration pathでgateway keyを検証する。(3) stable per-user fieldを避ける。(4) 対応するstateless requestのみ送信する。(5) relay、gateway、target logを比較する。(6) direct fallbackなしでkey rotation/failureをテストする。<sup>[[2]](#references)</sup>

**Detection:** enterprise endpointには起動processとOHTTP relayが見えます。gatewayはmalformed/replayed trafficを検知し、timingとstable payload/account fieldがrequestを相関させます。

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUICがUDPまたはIP packetをproxy経由で運びます。modern VPNに似たtunnelを実装し、HTTP/3に混在できますが、proxyは依然としてobserverです。<sup>[[3]](#references)</sup>

**Pros:** 効率的なmultiplexing/roaming、UDPまたはfull IPをサポート、modern HTTP infrastructure経由で導入可能。

**Cons:** anonymity networkではない。proxy/accountにはsourceとdestinationが見え、QUIC/HTTP fingerprintと既知のpathがendpoint/providerに見えます。

**Procedure:** (1) RFC 9298/9484対応を文書化したclient/serviceを使う。(2) proxy certificate/configurationを認証する。(3) 許可するtarget routeを定義する。(4) path内でencrypted DNSを有効にする。(5) 所有endpointでUDP、TCP、IPv6、failoverを検証する。(6) proxy request/flow logを確認する。

**Detection:** endpointにはclient processとvirtual interfaceが見えます。networkはproxyへの継続的QUIC/TLSを分類でき、proxy logにはCONNECT target/pathが残ります。

## Tor Browser

**Mechanics:** Torはguard、middle、exit relayを選び、layered encryptionで各relayの視野を制限します。Tor Browserはfingerprinting耐性を意図した標準browserを追加します。

**Pros:** 大きなpublic anonymity set、通常1つのrelayが両端を知ることがない、server運用なしでdestination unlinkability。

**Cons:** 遅い、TCP中心、exit reputation/block、loginや開示でuserが特定される、low-latency timing correlationが残る。

**Procedure:** (1) projectからTor Browserをdownloadし検証する。(2) defaultを維持しextensionを避ける。(3) 適切なsecurity levelを選ぶ。(4) 別identity/sessionを作る。(5) 識別可能なaccountと外部active documentを避ける。(6) HTTPSまたはauthenticated onion serviceを使用する。(7) 所有endpointでのみexitを検証する。<sup>[[4]](#references)</sup>

**Detection:** local networkはbridge/transportなしでは既知のguard trafficを特定できます。宛先にはexitとTor Browser behaviorが見え、end-to-end observerはtiming/volumeを相関します。

## Tor bridges and pluggable transports

**Mechanics:** 非公開bridgeがpublic guardを置き換え、obfs4、Snowflake、WebTunnelがfirst-hop transportを変更して単純なblock/probeに耐えます。

**Pros:** censorshipを回避し、明白なpublic-relay destinationを隠し、entry後はTor circuitを維持します。

**Cons:** transport pattern/bridge discoveryは可能、performanceは可変、accountやglobal timingからの保護は追加されません。

**Procedure:** (1) 最初にdirect Torを試す。(2) Tor Browser Connection設定でbuilt-in対応transportを選ぶか、公式bridgeを要求する。(3) random binary/listを使わない。(4) 接続して無害なtestを実行する。(5) reconnectとclockをテストする。(6) 他のbrowser設定は標準のままにする。<sup>[[5]](#references)</sup>

**Detection:** censorはdestination discovery、protocol/flow classification、active probingを使用します。defenderはcircumvention利用とcompromiseを区別し、endpoint process/contextに依存すべきです。

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Torはaccess ISPからdirect Tor利用を隠しますが、sourceはVPNに見えます。Tor-before-VPNではVPNにpost-Tor trafficが見え、安定したcustomer/tunnel identityになることがあります。

**Pros:** 正しく設計すれば特定observerを除去し、1つのlayerをblockするnetworkに到達できます。

**Cons:** 複雑性、特徴的fingerprint、leak、縮小した匿名性集合、false confidence。Tor Projectは組み合わせをadvancedとして扱います。<sup>[[6]](#references)</sup>

**Procedure:** (1) 除去するobserverと新たに導入するobserverを書く。(2) 使い捨て環境を使う。(3) 意図したouter pathのみ確立する。(4) firewall routeを強制する。(5) DNS/IPv4/IPv6と各failure orderを検証する。(6) 両providerのvisibilityを比較する。(7) 測定可能な利点がなければstackを破棄する。

**Detection:** local/VPN/Tor observerには異なる隣接layerが見えます。timingはend-to-endで残り、nested tunnel fingerprintとprovider accountがsessionを結び付けます。

## Onion service

**Mechanics:** clientとserviceがともにTor circuitをrendezvousへ構築し、service IPを隠してexitを回避します。

**Pros:** sourceとservice locationの保護、end-to-end onion authentication、public inbound port不要、任意のclient authorization。

**Cons:** update/analytics/errorからoriginが漏れる。onion keyが重要で、application identity/timingとhost compromiseは残ります。

**Procedure:** (1) applicationを分離しloopback/socketのみにbindする。(2) 対応Torをinstallする。(3) 公式手順でv3 onion serviceを設定する。(4) stable identityが必要な場合のみkeyを保護/backupする。(5) closed useではclient authorizationを追加する。(6) third-party fetchを削除する。(7) 外部からoriginに到達できないことを検証する。<sup>[[7]](#references)</sup>

**Detection:** host/network defenderはTor process/configurationとoutbound circuitを発見できます。application error、DNS、certificate、third-party resourceからoriginが露出する可能性があります。

## I2P internal services

**Mechanics:** I2Pはoverlay内のdestination向けに、別々の一方向inbound/outbound tunnelを使用します。public-Internet outproxyはtrust pointを追加します。

**Pros:** decentralized internal publishing、公式exit依存なし、inbound/outbound pathの分離。

**Cons:** 一般webの代替ではない、ecosystemが小さい、長時間のpeer behavior、outproxyがpublic browsingを観測可能。

**Procedure:** (1) 公式sourceからinstallする。(2) 専用contextを使う。(3) integration/bandwidth stabilizationを許可する。(4) 所有するI2P-native serviceへアクセスする。(5) 明示的に必要でない限りoutproxyを避ける。(6) shutdownでdirect fallbackがないことを検証する。(7) local peer/service logを確認する。<sup>[[8]](#references)</sup>

**Detection:** local networkには長時間のpeer trafficとbootstrap behaviorが見えます。endpointにはrouter/application processが露出し、outproxyにはexitが記録されます。

## Mixnets

**Mechanics:** fixed-size packet、batching、delay、reordering、cover trafficでtiming correlationを低減し、gatewayがapplicationをbridgeします。

**Pros:** low-latency proxyよりtiming analysisへの耐性が高く、非同期message/transactionに有用。

**Cons:** latency、bandwidth overhead、小規模な導入、application制限、gateway/account metadataの残存。

**Procedure:** (1) 維持されているclientと対応applicationを選ぶ。(2) 実際のthreat modelを読む。(3) 別compartmentにinstallする。(4) 所有endpointへ無害なdataを送る。(5) latency/reliabilityとreply pathを測定する。(6) gateway failureをテストする。(7) speedのためだけにdelay/cover trafficを無効化しない。<sup>[[9]](#references)</sup>

**Detection:** endpointはclientを特定できます。access networkはgateway/packet cadenceを分類でき、gateway/exitは隣接roleを観測します。広範な相関には長い統計windowが必要です。

## GNUnet anonymous file sharing

**Mechanics:** GNUnetはpeer経由でpublish/search/download requestをrouteし、anonymity levelに応じてcover trafficを追加できます。公式文書は、default level 1ではcover trafficが必須でなく、強力なtraffic analysisでoriginが特定され得ると警告しています。<sup>[[10]](#references)</sup>

**Pros:** decentralizedでapplication-nativeなanonymous sharing、cover-traffic要件を調整可能。

**Cons:** 通常のanonymous web accessではない、performance/storage cost、peerとtraffic-analysisの制限。GNUnet VPN文書は、IP overlayが良好な匿名性を提供しないと説明しています。

**Procedure:** (1) 維持された公式buildをinstallする。(2) test peerを分離する。(3) bandwidth/storageを制限する。(4) 選択したanonymity levelで無害なunique test fileをpublishする。(5) 別の所有peerからretrieveする。(6) cover trafficとlatencyを記録する。(7) IP VPN componentが同等の匿名性を提供すると主張しない。

**Detection:** peer bootstrap、overlay traffic、local datastore/process、file identifierを確認します。広域observerはcover trafficとtraffic volumeを分析できます。

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQはresolverまで暗号化し、ODoHはproxyとresolver間でclient addressとqueryを分離し、ECHはinner TLS ClientHello/server nameを暗号化します。

**Pros:** 一部のlocal observerからplaintext DNS/SNIを除去し、ODoHはsource/query knowledgeを分割します。

**Cons:** IP-anonymity pathではない。resolver/proxy/serverのroleは残り、destination IP/timing/volumeとendpointも残ります。fallbackで漏れる可能性があります。

**Procedure:** (1) OS、application、tunnelのどれがDNSを管理するか選ぶ。(2) strict encrypted modeまたは対応ODoHを有効にする。(3) uniqueな所有domainをテストする。(4) local captureでclear queryがないことを確認する。(5) resolverを停止し意図したbehaviorを検証する。(6) ECHではserver diagnosticsでinner ClientHelloの受理を確認する。<sup>[[11]](#references)</sup>

**Detection:** endpoint/resolver logにはqueryが露出します。networkはencrypted-resolver endpointとdestination flowを識別し、ECH stateはpath上で隠れてもendpoint/CDNには見えます。

## Split-provider privacy relay

**Mechanics:** iCloud Private Relayなどの製品は、clientを知るingressとdestinationを知る独立運用のegressを使用し、地域情報を粗く処理します。

**Pros:** frictionの少ないknowledge split、高速、対応trafficに統合されたDNS/web protection。

**Cons:** product/application scopeが限定的、account/platform providerはcustomerを識別、任意のsystem anonymityではない、collusion/legal/timing risk。

**Procedure:** (1) 対応するapplicationとtraffic typeを確認する。(2) 適切なら専用platform contextでfeatureを有効にする。(3) region behaviorを選択する。(4) Safari/DNSとunsupported applicationを別々にテストする。(5) destination addressを確認する。(6) network switching/failureをテストする。<sup>[[12]](#references)</sup>

**Detection:** accessにはingress、destinationにはegressが見えます。platform/relay logとaccount recordは各layerを記録し、unsupported applicationは通常経路を露出します。

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** browsing/tool executionをremote systemで実行し、destinationにはそのegressが見えます。workspace providerにはoperator connectionとcontrol planeが見えます。

**Pros:** 高速、危険なcontentを分離、安定した管理egress、使い捨てstate、強いorganization audit。

**Cons:** provider/adminはsession/accountを観測可能、screen/clipboard/file channelから漏れる、remote browser fingerprintがuniqueな可能性、workspace ownerに対して匿名ではない。

**Procedure:** (1) engagementごとにorganization-owned workspaceを作成する。(2) MFAを必須にし管理を制限する。(3) clipboard/upload/downloadを無効化または制限する。(4) approved fixed egressを経由する。(5) personal IdP/syncを使わない。(6) 確認済みevidenceのみexportする。(7) scheduleに従いworkspaceとcredentialを破棄する。

**Detection:** providerとIdP logがuserとsessionを結び付けます。destinationはworkspace egress/browserをcluster化し、enterprise defenderはremote-control protocolと異常なcloud sessionを識別します。

## Public or guest Wi-Fi

**Mechanics:** trafficは会場NATまたはそこで開始されたtunnelからegressします。

**Pros:** 高速、共有された非自宅address、専用infrastructure不要。

**Cons:** venue association/DHCP/portal、camera、purchase、location evidence、悪意あるpeer/AP、terms、物理的リスク。

**Procedure:** (1) guest向けaccessを取得しstaffでSSIDを確認する。(2) patch済みのlow-trust deviceを使う。(3) sharing/auto-joinを無効化しprivate MACを有効にする。(4) reused identityなしでportalを完了する。(5) fail-closed VPN/Tor pathを開始する。(6) tethered trafficを検証する。(7) networkをforgetする。

**Detection:** venueはAP、MAC、DHCP、portal、時刻を相関します。destinationにはvenue/tunnelが見えます。調査者は物理証拠とdevice evidenceを結合します。access controlを決して迂回しないでください。

## Travel router

**Mechanics:** operator-owned routerがvenue Wi-Fi/Ethernetに接続し、enforced tunnel policy付きの分離internal networkを提供します。

**Pros:** workstationを分離、central kill switch/DNS、一貫したclient network、privileged endpointをlocal broadcastから保護。

**Cons:** routerが安定したradio/DHCP fingerprintになる、attack surfaceが増える、captive portal/tetheringがtunnelを迂回する可能性。

**Procedure:** (1) 対応firmwareを更新する。(2) unique management credentialを設定しWAN admin/WPS/UPnPを無効化する。(3) 許可される場合private upstream MACを設定する。(4) 別のinternal SSIDを作る。(5) full-tunnel DNS/IPv6 firewall policyを強制する。(6) portal、reconnect、tunnel failureをテストする。

**Detection:** venueにはrouter associationとtraffic shapeが見えます。local RF/DHCP fingerprintingで識別でき、VPN providerにはvenue sourceが見えます。

## Cellular, prepaid SIM and eSIM

**Mechanics:** modemがcarrier radio accessと通常carrier NATを使用し、VPN/Tor layerでdestination-visible exitを変更できます。

**Pros:** local wired/Wi-Fi networkから独立、mobile、高速、authorized dropのbackhaulに有用。

**Cons:** carrierはsubscriber/eSIM、IMSI、IMEI、cell、time、assigned portを把握します。registration lawは地域で異なり、personal phoneとの同一場所利用でdeviceが結び付く可能性があります。

**Procedure:** (1) 必要事項を正確に申告して合法的にserviceを取得する。(2) organization-ownedの別modem/deviceを使用する。(3) exercise controllerに記録する。(4) 無関係なradio/accountを無効化する。(5) approved tunnelを確立する。(6) tethered clientが実際にそれを経由するかテストする。(7) travel前にproviderとretentionの前提を確認する。<sup>[[13]](#references)</sup>

**Detection:** carrier recordとRF location、enterprise USB/PCI/MDM inventory、rogue-hotspot survey、destination/tunnel timingを確認します。

## Satellite Internet and satellite downlink abuse

**Mechanics:** 通常serviceは登録済みterminal/providerを使用します。以前の一方向DVB-S abuseでは、beam内のreceiverが正規subscriber宛ての暗号化されていないdownlink trafficを観測し、別経路でoutbound requestを送れました。

**Pros:** 広いfootprint、独立したlast mile、過去の一方向abuseではC2をsubscriber geographyに誤帰属させられた可能性。

**Cons:** equipment/RF/provider record、latencyとcoverage、現代の双方向systemとの差、outbound pathとasymmetric routingが証拠として残る。

**Procedure:** 合法的なaccessでは所有terminalを登録し、必要に応じてtrafficをtunnelする。歴史的Turla behaviorのemulateには、RF-free lab内でsynthetic one-way packet captureを再生し、requestを送っていないhostへのreplyを分析者が検知できるかテストする。live satellite trafficをinterceptしてはいけません。<sup>[[14]](#references)</sup>

**Detection:** provider/terminal telemetry、RF direction finding、impossible/asymmetric flow、RTT/routing inconsistency、malware configurationを確認します。

## Residential/mobile proxy or consented proxyware

**Mechanics:** backconnect gatewayがconsumer broadband/mobile exitをstickyまたはrotatingで割り当てます。供給元は同意済み、欺瞞的bundle、または悪意あるものの可能性があります。

**Pros:** 高速、地理選択、consumer ASNによるhosting block回避、large pool。

**Cons:** provenance/consentと法的リスク、brokerがcustomerを把握、infected exitが被害者に影響、rotationによる異常、高価で不安定。

**Procedure:** emulationには文書化されたinformed consentのorganization-owned agentのみ使用する。(1) test endpointをenrollする。(2) owner/IPをinventoryする。(3) gatewayを設定する。(4) sticky/per-request modeをrotateする。(5) 所有targetだけに送信する。(6) gateway/exit/target logを比較する。(7) 全agentを削除する。

**Detection:** impossible travel、急速なIP/ASN変更中も同一browser/account、backconnect protocol、proxyware process/network artifact、broker/controller relationを確認します。

## ORB, botnet and compromised edge-device relays

**Mechanics:** leasedまたはcompromised router/IoT/serverがaccess、traversal、exit roleを形成し、fleetとして管理されます。複数のAPT customerが共有することもあります。

**Pros:** 借用したreputation/geography、短命なexit、resilient multi-hop mesh、actorとIPの直接リンクが弱い。

**Cons:** 犯罪的な被害、implant/controllerとfleet pattern、intermediary seizure、性能の不安定さ、operator/customer service record。

**Procedure:** 実deviceを侵害してはいけません。[Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)を使用する。(1) isolated entry/transit/target networkを作る。(2) 所有するdual-homed relay containerを接続する。(3) 1つのtest portのみforwardする。(4) 無害なrequestを送る。(5) targetにexitだけが見えることを確認する。(6) exitをrotateする。(7) 名前付きassetをすべてtear downする。<sup>[[15]](#references)</sup>

**Detection:** topology、port/service、controller relation、implant fingerprint、node lifecycleを追跡します。edge configuration/flow/integrity telemetryを集中し、exit IPをactorと同一視しません。

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** public edgeが特定のgrammarに一致するtrafficのみforwardします。frontingでは、intermediaryが許可する場合、benign outer SNIと異なるinner HTTP authority、またはblank SNIを使用します。

**Pros:** backendを隠し保護、global edgeによる高速性、shared serviceにdestinationを混在、迅速なcutover。

**Cons:** CDNには全routingとtenantが見え、多くのproviderはcross-tenant frontingを禁止。SNI/Host/process/flowとaccount artifactが残り、configuration再利用でcampaignがcluster化されます。

**Procedure:** 所有reverse proxy上でのみ再現する。[Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging)でlocal certificate/edgeを作成し、mismatched Hostを所有targetへrouteし、SNIとHostをlogし、normal/mismatched requestを送信してからcontainerを削除する。<sup>[[16]](#references)</sup>

**Detection:** endpointまたはterminating edgeでSNI/ECH/Host/`:authority`を比較し、initiating process、tenant/origin、request grammar、flow cadenceを結合します。

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNSはstable nameを更新し、DGAは変化するcandidate nameを生成し、fast fluxは低TTLでservice addressをrotateし、double fluxはname serverもrotateします。

**Pros:** resilient discovery、迅速なinfrastructure replacement、多数nodeによるcontroller隠蔽。

**Cons:** DNSがcentralized telemetryを作り、entropy/NXDOMAIN/churn、low TTL、広範なASN patternが現れ、registrationとauthoritative infrastructureが残ります。

**Procedure:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry)を使用する。所有zoneがRFC 5737 addressを5秒TTLで返すようにし、繰り返しqueryし、synthetic epochを変更してanalyticsを検証する。test recordをthird partyへ向けてはいけません。<sup>[[17]](#references)</sup>

**Detection:** sliding-window unique answer/ASN、median TTL、geography、authoritative churn、DGA NXDOMAIN/lexical/temporal cluster、process follow-onを確認します。contextを考慮して正規CDNを除外します。

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** public post、repository、document、object、feedにencoded current endpointまたはtaskを含めます。clientは別channelで結果を返す場合があります。

**Pros:** 高reputationの許可済みservice、TLS、binaryを変更せずendpoint rotation、asymmetric taskingによる単純なflow correlationの妨害。

**Cons:** stable object/account/API identifier、provider record、endpoint decode/follow-on sequence、contentの押収・変更。

**Procedure:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence)を使用する。1つの所有containerにencoded pointerを置き、短命clientからfetch/decodeし、2つ目の所有serviceへcontactし、両方のlogを保持してからtear downする。

**Detection:** unusual process → stable object read → decode → new destinationを相関します。contentをhash/preserveし、domainだけでなく完全なobject pathを保持します。

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** function/short-lived jobがprovider NATまたはfrontの背後で実行され、logical serviceは安定したままinstanceとaddressがrotateします。

**Pros:** 迅速なdeployment/destruction、provider規模のshared egress、local diskが少ない、elastic regional routing。

**Cons:** tenant、role、API、image、secret、invocation、billing、front-to-origin logが永続。cold-startとplatform fingerprint、provider policyも残ります。

**Procedure:** (1) organization-owned exercise tenantを使う。(2) 所有endpointのみをrequestするbenign functionをdeployする。(3) project/role/image/configを記録する。(4) 複数instanceでinvokeする。(5) target IPとaudit/request IDを比較する。(6) log retentionをテストする。(7) function、role、secretを削除する。

**Detection:** cloud audit/invocation log、異常なrole作成、shared egressとstable request grammar、image/layerとsecretの再利用、front-origin correlationを確認します。

## Authorized on-site drop

**Mechanics:** inventoried small computerがlocal wired/Wi-Fiとoutbound VPN/cellular rendezvousを使用し、local sourceとして振る舞います。

**Pros:** realistic internal-origin testing、高速、NAC、physical inventory、egress controlをテスト可能。

**Cons:** physical discovery/theft、serial/MAC/USB/DHCP/PoE/RF/camera evidence、紛失時のcredential露出。

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)に従う。(1) 正確な書面placement authorityを得る。(2) serial、MAC、photo、location、retrieval timeを記録する。(3) signed minimal imageとshort-lived mutual credentialを使う。(4) outbound-only destination/capabilityを制限する。(5) server-side quarantineとbandwidth limitを追加する。(6) SOC visibilityとloss responseをテストする。(7) 回収し、必要なevidenceを保持してから、合意したlifecycle policyに従ってsanitizeする。同意のない会場に隠してはいけません。

**Detection:** NAC/802.1X、switchport/PoE/DHCP、USB inventory、RF survey、recurring tunnel、receiving/camera、physical inspectionを確認します。

## Nearest-neighbor wireless pivot

**Mechanics:** actorがtargetのradio range内のhostを管理し、target Wi-Fi credentialを使ってremoteにboundaryを越えます。APT28がこの方法でnearby compromised organizationを使用しました。<sup>[[18]](#references)</sup>

**Pros:** operatorの移動不要、targetにはlocal radio sourceが見え、Internet entryだけに適用されたcontrolを回避。

**Cons:** nearby compromised/owned dual-radio hostとvalid accessが必要。RADIUS/NAC/AP、neighbor endpoint evidence、signal/device anomalyが残ります。

**Procedure:** [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot)でのみ再現する。owned pivotをneighbor/target lab SSIDへ接続し、1 serviceのみforwardし、両AP/pivot logを収集する。その後EAP-TLS/device postureを有効にし、2回目が失敗することを確認する。

**Detection:** RADIUS identity、managed certificate/posture、first-seen device、AP edge/signal、同時login、physical presenceを相関します。近傍endpointで同時radio、forwarding、tunnelを探します。

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** trafficは1つのinteractive Internet sessionではなく、local peer、非同期gateway、removable media、scheduled queueを通過します。

**Pros:** disruption/censorship時に動作、遅延/batch deliveryで単純なtimingを弱め、local communicationにcentral last mile不要。

**Cons:** 高latency、小さな匿名性集合、custody/physical metadata、悪意あるpeer、最終的にはgatewayがdataを観測。

**Procedure:** (1) isolated owned three-node meshまたはfile queueを構築する。(2) contentをend-to-endでencrypt/authenticateする。(3) originからdirect Internet routeを削除する。(4) controlled delay後にbenign fileをrelayする。(5) gatewayのみがowned destinationにcontactすることを確認する。(6) custody/timestampを比較する。(7) 必要なevidenceを保持してから、承認されたcloseoutでtemporary media/queueをsanitizeする。

**Detection:** endpoint file/process activity、peer-radio link、removable-media audit、queue/gateway periodicity、content identifierを確認します。interactive-flow analysisの代わりに長いcorrelation windowを使用します。

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN)はpublic relay addressを割り当て、clientとpeer間でUDP、TCP、TLS trafficを運びます。ICE policyでdirect candidateを公開せずrelay利用を強制できます。TURNは到達性を解決するもので、general anonymityを提供しません。serverはclientを認証し、allocation、peer、time、volumeを観測します。<sup>[[19]](#references)</sup>

**Pros:** 広く実装、restrictive NATに対応、mobile WebRTCをサポート、relay-only policyが正しく適用されればpeerにclientのdirect transport addressを渡さない。

**Cons:** TURN operatorは両隣接側を見、application identity、media fingerprint、signalingが残る。relay-onlyはbandwidth/latency costがあり、誤設定でhost/server-reflexive candidateを収集される可能性があります。

**Procedure:** (1) TLSとshort-lived credentialを備えたorganization-owned TURN serviceをdeployする。(2) realm、peer、port、quota、expirationを制限する。(3) test applicationをrelay-only ICEにする。(4) owned peerにcallする。(5) `getStats()`とpacket captureでmediaがrelay candidateのみを通過したことを確認する。(6) relayを停止しdirect fallbackがないことを確認する。(7) engagement用allocation logを保持する。

**Detection:** signaling、browser process、TURN allocationからsessionとrelayを結合できます。networkにはTURN portまたはTLS endpointへの継続flowが見え、peerにはallocated relayが見えます。**Captured node:** application stateとephemeral TURN credentialからrealmとrendezvous serviceが判明する可能性があります。per-deviceのshort-lived credentialを使用し、operator authenticationはcontrollerだけに保持します。

## Outbound-only rendezvous or reverse overlay

**Mechanics:** NAT背後のnodeがorganization-controlled brokerへauthenticated connectionを開始します。operatorはbrokerへ別途認証し、brokerが狭いmanagement channelを認可します。inbound port forwardingもdirect operator-to-node routeも不要です。

**Pros:** NATとcaptive last mileの背後で安定、central revocation/audit、field-node address変更時にoperator discovery不要、operator identityとnode credentialを分離。

**Cons:** brokerが高価値のcorrelation point、periodic keepaliveが識別可能、広いtunnelはunsafe pivotになり得る、broker喪失で管理不能。

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous)に従う。scoped device identityを1つ発行し、owned brokerとapproved management serviceのみ許可し、authenticated keepalive、fail-closed routing、address change、reboot recoveryをテストし、loss drillでidentityをrevokeする。WireGuardは、実際に必要な場合に25秒のpersistent keepaliveを広く有用なNAT intervalとして文書化しています。<sup>[[20]](#references)</sup>

**Detection:** brokerとidentity-provider logが両側を結び付け、access networkには反復するencrypted destination/cadenceが見え、endpoint inventoryにはoverlay agentが現れます。**Captured node:** device key、broker name、tunnel address、cached task dataが露出すると仮定します。operator private key、personal account、再利用可能なcontroller tokenを含めてはいけません。

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** field workloadがauthenticated mailboxをpollし、署名済みの事前承認jobを取得してbounded resultを投稿します。operatorは別のcontrol planeからqueueへ書き込み、両者間にinteractive socketはありません。

**Pros:** intermittent linkに耐性、timing/addressingを分離、quota/schemaでcapabilityを制約、central audit/revocationが容易。

**Cons:** polling cadenceとstable object/queue nameがfingerprintになる。provider logがproducer/consumerを結び付け、controlは遅延し、queued dataの取得でexerciseが露出する可能性。

**Procedure:** (1) engagement queueとdevice identityを各1つ作る。(2) benignで明示的にscopeされたsigned schemaを定義する。(3) message TTL、maximum result size、rateを設定する。(4) nodeが自分のqueueだけをpullし、result prefixだけへwriteするよう制限する。(5) offline accumulation、duplicate delivery、revocationをテストする。(6) immutable access logを集中管理する。(7) retention requirement後にqueueを削除する。

**Detection:** unusual processによるperiodic API call、stable bucket/object/queue path、同一user-agent/TLS behavior、fetch-then-new-connection sequenceを探します。**Captured node:** local cacheにpending jobとobject nameが残る可能性があるため、cacheをencrypted、bounded、disposableにし、authoritative controller logを保持します。

## Dual-uplink failover and connection migration

**Mechanics:** approved field nodeがvenue Ethernet/Wi-Fiとorganization cellularなど2つの独立uplinkを持ち、route変更時もoverlayまたはmessage brokerでcontrol sessionを維持します。これはavailability engineeringであり匿名性ではありません。

**Pros:** provider、AP、captive portalの1つが失敗しても継続、計画保守、疑わしいpathの迅速な隔離。

**Cons:** 2 providerが2つのlocation/account recordを作る。同時使用でcorrelationが容易、failover中のroute/DNS leak、cellular co-location evidence。

**Procedure:** (1) organization-owned interface/providerを両方登録する。(2) deterministic route priorityとowned endpoint health checkを設定する。(3) DNS/managementをoverlayにbindする。(4) secondary pathがinbound trafficを受けないようにする。(5) 各pathを抜いてsession recovery、source policy、direct destination accessがないことを確認する。(6) unplanned path changeをalertする。(7) data useとroaming limitを文書化する。

**Detection:** 同じdevice certificate、request grammar、timingをASN間で相関します。local inventoryには両radioが見え、carrier/venueは各自のrecordを保持します。**Captured node:** SIM/device identifierと既知SSIDが見える可能性があるため、organization assetを使用しpersonal deviceと同一場所・pairingをしません。

## Organization private APN or managed cellular tunnel

**Mechanics:** carrier private APNがenrolled SIMをprivate routed domainへ置くか、trafficをenterprise gatewayへtunnelします。deviceをpublic mobile Internetから分離しますが、carrierまたはcontracting organizationからは隠しません。

**Pros:** stable private address、carrier-level enrollment/traffic policy、public inbound exposure回避、authorized remote applianceに有用。

**Cons:** subscriber、IMSI/IMEI、cell、billing attributionが強い。procurement lead time/cost、carrier/gateway outage、operatorに対して匿名ではない。

**Procedure:** (1) assessment organization名義でAPNを契約する。(2) registered SIMとgateway prefixのみallowlistする。(3) application-layer mutual authenticationを追加する。(4) APN routeをrendezvous/update serviceに制限する。(5) SIM removal、roaming、public-Internet breakout、revocationをテストする。(6) carrier/gateway recordを監視する。(7) closeoutで全SIMをcancelまたはquarantineする。

**Detection:** carrier inventory/cell telemetry、APN gateway flow、SIM/IMEI mismatch、enterprise asset record。**Captured node:** storageがencryptedでもSIMとmodemがcontractを特定するため、capture resilienceはdeniabilityではなく迅速なsuspensionと狭いauthorizationを意味します。

## Long-range point-to-point wireless bridge

**Mechanics:** directional Wi-Fiまたはlicensed/unlicensed point-to-point radioがowner-approved siteを接続し、remote siteでInternet egressします。commercial proxyなしで見かけのIP locationを移動できます。

**Pros:** 高throughput、中間wired carrierから独立、RF/routingを制御、segmentationとremote-site monitoringのtestに有用。

**Cons:** line-of-sight、spectrum、landlord、regulatory制約、特徴的RF emission/hardware、両endpointのphysical evidence、weather/power/alignmentによる不安定さ。

**Procedure:** (1) 両siteの書面許可とspectrum/power ruleを確認する。(2) approved parameter外で送信せずsurveyする。(3) authenticated encryptionとmanagement VLANを使う。(4) bridgeをowned rendezvous/test subnetに制限する。(5) failover、alignment、power recovery、RF containmentをテストする。(6) 両radioをlabel/inventoryする。(7) exercise後にremoveしconfiguration resetを確認する。

**Detection:** RF survey、spectrum analysis、rooftop/site inspection、bridge MAC/OUI、management traffic、remote-site egress log。**Captured node:** configurationからpeerとmanagement domainが判明するため、unique exercise credential、personal management accountなし、迅速なpeer-key revocationを使用します。

## Consented cooperative or community exit

**Mechanics:** volunteerまたはpartner organizationが公開policyに基づきrelayを意図的に運用します。trafficはshared community poolからexitし、coordination layerがabuseとrevocationをaccountします。

**Pros:** diverse non-cloud network、proxywareより安全な明示的同意、shared governanceによるtrust分散、research/censorship-resilience studyに有用。

**Cons:** 小さなpoolとmembership recordで匿名性が低下、exit operatorにcomplaintとtraffic metadataが見える、malicious participant、uptime変動、jurisdiction差。

**Procedure:** (1) acceptable-use/logging policyを公開する。(2) 各operatorからinformed opt-inを得る。(3) unique relay identityを発行しdestination/rateを制限する。(4) abuse handlingとone-action revocationを提供する。(5) testではowned endpointへのauthorized trafficのみ送る。(6) churnとcorrelation exposureを測定する。(7) consent終了時にrelayをcleanly removeする。

**Detection:** membership/control-plane record、relay certificate、common software fingerprint、exit behaviorからpoolを識別します。**Captured node:** relay configurationはcooperativeを特定し得ますがclient identityを含めず、client-to-session accountabilityはaccess control下のauthorized controllerに保持します。

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensionはtemporary interface identifierを作り、すべてのoutbound connectionでstable addressを再利用しないようにします。provider prefix変更でrotationを追加できますが、delegated prefix、subscriber record、upper-layer fingerprintは残ります。<sup>[[21]](#references)</sup>

**Pros:** stable interface identifierによる長期passive trackingを低減、一般OSに内蔵、relay overheadなし。

**Cons:** source anonymityではない。ISP/local networkにはprefix/deviceが見え、DNS、account、browser stateがsessionを結び付け、address churnがallowlist/loggingを複雑化。

**Procedure:** (1) 所有clientでstable/temporary addressを確認する。(2) third-party spoofingではなくOS-supported privacy address defaultを有効にする。(3) address lifetimeをまたいでowned IPv6 endpointへ繰り返しrequestする。(4) inbound serviceが意図したstable addressのみにbindすることを確認する。(5) DHCPv6/RA/neighborと正確なendpoint logを保持する。(6) すべてのIPv6 addressでVPN/firewall behaviorをテストする。

**Detection:** 1 addressを1 deviceとみなさず、delegated prefix、layer-2 identity、neighbor discovery、account、endpoint telemetryを相関します。**Captured node:** network profileとinterface identifierは残り、temporary addressingは1つのpassive identifierを防ぐだけでforensic attributionは防ぎません。

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** pluggable transportはfirst Tor connectionの見え方またはbridgeへの到達方法を変更します。Snowflakeは短命なvolunteer WebRTC proxyを使用し、WebTunnelは通常のHTTPSに似せ、obfs4は単純なprotocol identification/active probingに耐え、meekは対応web infrastructureを経由します。これはTorへのcensorship-circumvention transportであり、追加のend-to-end anonymity layerではありません。<sup>[[22]](#references)</sup>

**Pros:** direct Torまたはknown relayがblockされた場合に有用、Snowflakeはstable public bridge addressを避け、maintained Tor clientに統合、destinationには通常のTor propertyが残る。

**Cons:** performance低下/変動、broker/front/bridgeとlocal networkが異なるmetadataを観測、transport fingerprintとblockは可能、volunteer proxyはTorの代替ではなくapplication plaintextを信頼すべきでない。

**Procedure:** (1) official Tor Browserまたは対応Tor clientをinstall/verifyする。(2) Connection/Bridgesでbuilt-in transportを選ぶ。(3) owned diagnostic pageだけへ接続する。(4) pageにSnowflake/WebTunnel peerではなくTor exitが見えることを確認する。(5) bootstrap/performanceを比較する。(6) transportを失敗させdirect connectionへsilent fallbackしないことを確認する。(7) test後は標準設定へ戻す。

**Detection:** censorはdestination allowlist、TLS/WebRTC behavior、broker discovery、flow analysisを結合できます。endpointにはTorとtransport configurationが露出します。**Capture-resilient OPSEC:** standard clientを使用し、personal browser stateをcopyせず、bridge/broker historyが復元可能と仮定します。**Monitoring:** Tor bootstrap log、unexpected direct DNS/connection、controller側のowned-page observationを監視します。transport failureはdiscoveryの証拠ではありません。

## Refraction networking or decoy routing

**Mechanics:** 協力network operatorが、許可されたdecoy宛てに見えるtraffic内のcovert signalを検知し、flowをcircumvention proxyへredirectします。network path内のinfrastructureが必要で、clientが無害なwebsiteを選ぶだけでは作れません。<sup>[[23]](#references)</sup>

**Pros:** apparent destinationをblockするとcollateral damageが生じる可能性、public bridge addressの配布不要、on-path-assisted circumventionの研究modelに有用。

**Cons:** specialized ISP/transit participation、routing依存のdeployability/performance、client-to-decoy flowとproxy-side activityが残り、global/cooperating observerはtimingを相関可能。

**Procedure:** 関与しないnetworkを通じてsignalしてはいけません。isolated labで再現する。(1) owned client/router/decoy/proxy namespaceを作る。(2) benign tagged test requestを使う。(3) owned routerがそのtagだけをproxyへredirectする。(4) pre/post-routing tupleとrequest IDをlogする。(5) ordinary/signaled flowを比較する。(6) false positiveとremoveをテストする。(7) lab routeをdestroyする。

**Detection:** authorized network operatorはrouting divergence、異常なclient hello/tag behavior、decoyとbackendのflow差を検査できます。**Capture-resilient OPSEC:** research clientにはtest keyとdocumentation addressのみを保持させます。**Monitoring:** signed lab-router decisionとproxy arrivalを比較し、production transit providerをprobeして検知状況を判断しないでください。

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gatewayがIPFS content identifier (CID)をcacheまたはpeerから取得し、検証可能なcontentをclientへ返します。original publisherにはgatewayまたは他peerが見え、final readerは見えない場合があります。gatewayにはreader IPとrequested CIDが見えます。native peer-to-peer retrievalではclientがpeerとDHT/routing participantに露出します。<sup>[[24]](#references)</sup>

**Pros:** cacheによるpublisher/reader分離、immutable contentのhash検証、replicated data、native peer stack不要のHTTP client。

**Cons:** public CIDとgateway logからinterestが判明、first retrieval timingでpublisher/readerを相関可能、malicious web contentとpath-style same-origin hazard、public gatewayはbest-effortでabuseを禁止。

**Procedure:** (1) owned private IPFS swarmまたはowned gatewayへharmless test fileをpublishする。(2) CIDを記録する。(3) subdomain isolation付きの別owned HTTP gatewayからretrieveする。(4) bytesをCIDと照合する。(5) caching後に再実行する。(6) publisher/peer/gateway logを比較する。(7) retention終了時にunpinしtest contentを削除する。

**Detection:** gatewayにはsource/CID、DHT/peer connectionにはretrieval、endpoint history/file hashにはcontentが記録されます。**Capture-resilient OPSEC:** read-only field clientにprivate publishing keyを置かず、sensitive contentはcontent addressing前にencryptします。**Monitoring:** unexpected pinning、peer-set change、allowlist外CID request、gateway account noticeをalertします。

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR)は、指定indexをserverからcryptographically隠しながらdatabaseから1 recordを取得します。single/multi-server threat modelに依存します。bounded datasetのquery selectionを保護しますが、general web accessやIP anonymityではありません。<sup>[[25]](#references)</sup>

**Pros:** application-specific query privacy、測定可能なleakage model、key directory/blocklist/small public databaseに有用、exact lookup termの開示を低減。

**Cons:** computation/bandwidth overhead、relayなしではserverにconnection time/IPが見える、dataset version/response size/application stateでuserがpartitionされ、implementation maturityは様々。

**Procedure:** (1) synthetic owned databaseにaudited PIR implementationをdeployする。(2) dataset version/parameterを公開する。(3) 同一request sizeで複数indexをretrieveする。(4) localでcorrectnessを検証する。(5) server logを比較しindexがないことを確認する。(6) malicious/truncated responseとversion mismatchをテストする。(7) anonymous browsingと呼ばず正確なprivacy assumptionを文書化する。

**Detection:** networkにはservice useとvolume、endpoint telemetryにはclientとfinal record useが見え、compromised serverはdataset/timingを操作できます。**Capture-resilient OPSEC:** clientにはpublic database parameterとbounded cacheだけを保持します。**Monitoring:** signed dataset root、fixed request shape、error-rate change、server-key rotationを検証します。

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** remote serviceがURLをfetch/renderし、screenshot、metadata、sanitized contentを返します。destinationにはfetcher address、serviceにはrequester、URL、resultが見えます。link-preview bot、security scanner、third-party URL fetcherのabuseはauthorized proxy useではありません。

**Pros:** active contentをworkstationから分離、destinationにはcontrolled fetcher fingerprint、file type/size/destination/rendering limitを強制、disposable execution environment。

**Cons:** serviceがrequestを完全に把握、account/API/billing record、SSRF/data-exfiltration risk、script/authentication/interactive siteの非対応、unique URLによるcorrelation。

**Procedure:** (1) owned test domainだけをallowlistしたorganization-owned fetcherをdeployする。(2) private/link-local/metadata/redirect-to-unapproved addressをblockする。(3) method、redirect、byte、render timeを制限する。(4) credential/cookieをstripする。(5) owned URLをsubmitする。(6) requester/fetcher/target logを比較する。(7) render instanceをdestroyしpolicyに従ってcentral auditを保持する。

**Detection:** targetにはservice ASN/fingerprint、provider/controller logにはrequesterとURL、endpoint process/API callにはsubmissionが見えます。**Capture-resilient OPSEC:** arbitrary destination authorityのない短命allowlisted service tokenを1つだけ使用します。**Monitoring:** allowlist denial、redirect violation、controller job IDなしfetch、provider abuse noticeをalertします。

## Anycast rendezvous pool

**Mechanics:** organization-controlled nodeが同一stable service addressをadvertise/frontし、routingが近いinstanceを選びます。Anycastはavailabilityを高めclientからindividual backendを隠しますが、operatorは全instanceを管理しservice addressはstableです。<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress、instance failure時のfield reconfiguration不要、DDoS/load distribution、central policyでknown node間のsession移動。

**Cons:** BGP/CDN/provider recordからorganizationが識別、path changeでstateful sessionが壊れる、client locationによるmonitoring差、stable addressがblock/reputation clusterされやすい。

**Procedure:** provider-supported organization projectまたはisolated routing labを使用する。(1) 同一authenticated health endpointを2つdeployする。(2) documented service addressを1つ公開する。(3) session stateをedgeでなくbrokerに置く。(4) nodeをwithdrawしてreconnectionを確認する。(5) certificate/policy/log consistencyをテストする。(6) unauthorized origin/regionをalertする。(7) closeoutでadvertisementとcredentialを削除する。

**Detection:** BGP/RPKI/history、provider tenancy、certificate、identical service behaviorからpoolを識別します。**Capture-resilient OPSEC:** edgeにはregional service identityのみを置き、operator/fleet-enrollment keyを置きません。**Monitoring:** authorized monitorから全regionをprobeし、route originとconfiguration digestを比較します。unexpected originはincidentとして扱います。

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDはNAT rebinding/address change後もsessionを維持でき、Multipath TCPは複数subflowで1つのreliable byte streamを運べます。Wi-Fi/cellular transitionのcontinuityを改善しますが、common peerには旧新pathが見え、cross-path correlationが容易になります。<sup>[[27]](#references)</sup>

**Pros:** uplink change時のrecovery高速化、application session再起動不要、MPTCPによるresilience/throughput、approved field nodeに有用。

**Cons:** anonymityではない。peerにはmigration/subflowが見え、connection IDと同時trafficがpathを結び付け、middlebox/carrier supportは可変、provider recordが増える。

**Procedure:** (1) owned field clientとrendezvous間でのみ対応transportを有効にする。(2) applicationをIPから独立してauthenticateする。(3) approved Wi-Fiでbounded transferを開始する。(4) organization cellularへ切り替える。(5) path validation、data integrity、clear/direct fallbackなしを確認する。(6) idle timeoutとreturnをテストする。(7) 全path transitionのbroker recordを保持する。

**Detection:** peerはaddress migration/MPTCP subflowを直接観測し、providerには各自の部分が見えます。connection ID、TLS identity、timingが両者を結び付けます。**Capture-resilient OPSEC:** device-scoped session materialのみ保持しresumable stateを短時間でexpireします。**Monitoring:** impossible path change、同時に未承認network、migration storm、quarantine後のresumptionをalertします。

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** organization-owned workflowがhosted runner上でbounded network checkを実行します。destinationにはcloud runner address、platformにはrepository、actor、workflow、token、log、billing attributionが見えます。これはaccountable egressを伴うremote executionであり、providerからの匿名性ではありません。<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment、再現可能なjob定義、inbound connection不要、地域分散availability check、強力なcontroller audit。

**Cons:** platform/organizationがinitiatorを識別、広いworkflow tokenとuntrusted pull requestは危険、shared IP reputation、log/artifactにsecretやtarget dataが残る。

**Procedure:** (1) assessment用private organization repository/environmentを作る。(2) owned endpoint向けのmanually approved fixed benign jobのみ許可する。(3) minimal read-only workflow permissionを使いproduction secretを使わない。(4) checkを実行する。(5) workflow/provider/target recordを比較する。(6) artifactにcredentialがないことを確認する。(7) environment tokenを削除し必要なauditを保持する。

**Detection:** provider audit/workflow logが直接attributionを提供し、targetはrunner ASN/rangeとstable request grammarを識別します。**Capture-resilient OPSEC:** field-device、signing、wallet、cloud-administrator secretをrunner variableに置いてはいけません。**Monitoring:** branch/environment approvalを必須にし、workflow edit、fork execution、secret read、unexpected destinationをalertします。

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh、Wi-Fi Aware/Direct、low-power radio、serial/optical linkがnearby sensorからowner-approved Internet gatewayへbounded messageを運びます。field device自体にはInternet routeがなく、gatewayだけがegressです。radio range/protocol limitがあるため、telemetry/store-and-forward設計でありinteractive anonymous Internetではありません。

**Pros:** 最小field deviceからInternet stackとcredentialを排除、low power、gatewayによるpolicy集中、temporary dead zoneをbridge可能。

**Cons:** RF/physical discovery、pairing、device identifier、低bandwidth/range、gatewayによる全messageの関連付け、spectrum/encryption restriction、captureによるqueued data露出。

**Procedure:** (1) site/spectrum approvalを得る。(2) unique keyでowned sensorとowned gatewayを1対1でpairする。(3) signed fixed-size message type、TTL、rateを定義する。(4) sensorにdefault IP routeを与えない。(5) gatewayがowned collectorへだけforwardするようにする。(6) replay、range loss、gateway outageをテストする。(7) 両deviceをinventoryし回収する。

**Detection:** RF survey、pairing database、physical inspection、gateway process/flow logからpathを特定します。**Capture-resilient OPSEC:** sensorにはpairwise keyとbounded encrypted queueのみを保持し、operator、Wi-Fi、cellular、controller credentialは置きません。**Monitoring:** new peer、sequence rollback、key failure、異常RF rate、unregistered gateway経由のmessageをalertします。

## Capture/compromise exposure matrix

この表は、上記すべてのfamilyにcapture-resilience checkを適用します。「Minimize」はauthorized asset上のsecretとblast radiusを減らすことを意味し、evidenceを消去したり調査から隠れることを意味しません。

| Technique family | captured endpoint/relayが露出し得るもの | 最低限のauthorized control |
|---|---|---|
| NAT/CGNAT、public Wi-Fi、travel router | known network、DHCP/portal history、MAC、tunnel peer | organization deviceを分離、対応時はprivate MAC、personal accountなし、controller inventory |
| VPN、VPS、HTTP/SOCKS/SSH、multi-hop | provider/hostname、key、route、log、隣接hop | engagementごとにidentity、short TTL、狭いroute、broker-side revocation、master keyなし |
| OHTTP/ODoH、MASQUE、split-provider relay | relay/gateway configuration、application identifier、cached request | payload identifierを最小化、approved configをpin、bounded cache、strict no-direct fallback |
| Tor、bridge、onion service、I2P、mixnet、GNUnet | installed software、bridge/onion material、local state、peer history | standard client、service key分離、encrypted minimal state、侵害時にservice identityをrotate |
| Remote browser/VDI/jump host | workspace token、clipboard/file、remote tenant | gatewayでphishing-resistant MFA、transfer channel無効化、迅速なsession revocation |
| Cellular、satellite、private APN | SIM/eSIM、IMEI/terminal identity、provider、概略location | organization contract、personal co-locationなし、狭いAPN/overlay policy、provider suspension runbook |
| Residential/cooperative proxy、ORB lab | agent identity、controller/next hop、cached traffic | consented/owned nodeのみ、signed agent、nodeごとのcredential、controller保持のparticipant mapping |
| CDN/fronting、fast flux、serverless | tenant/origin/config、API token、deployment、billing reference | dedicated project、least-privilege role、short-lived deploy token、provider auditをcentralに保持 |
| Dead drop、pull mailbox、store-and-forward | object name、queue、cached job/result、custody data | signed bounded job、TTL、encrypted cache、producer identity分離、immutable server log |
| Drop、nearest-neighbor、long-range bridge | serial/radio/SSID/peer、device key、physical placement artifact | written placement、unique device identity、operator secretなし、tamper/state telemetry、revoke/recover |
| TURN、reverse overlay、dual-uplink | realm/broker、device credential、peer/route、uplink profile | outbound-only narrow service、short-lived device credential、operator login分離、fail-closed path |
| IPv6 temporary addressing | profile、prefix history、endpoint/application state | anti-trackingとしてのみ扱い、network log保持、endpoint compartmentationと併用 |
| Pluggable transport/refraction lab | bridge/broker/decoy setting、Tor state、research key | standard clientまたはisolated lab、personal browser stateなし、production signalingなし |
| IPFS/PIR/fetcher | requested CID/query、cached content、gateway/service token | encrypted bounded cache、public-only parameter、short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service node、connection ID、resumable state、known path | regional identityのみ、short resumption lifetime、central route/session revocation |
| Managed CI/CD runner | repository、workflow、provider token、log、artifact | least-privilege workflow、production/field/wallet secretなし、environment approval |
| Non-IP local hop | radio peer、pairwise key、queued message、gateway identity | unique pairwise key、fixed message schema、Wi-Fi/cellular/operator credentialなし |

## Monitoring possible discovery for every access family

client-side testだけでinvestigatorまたはdefenderの監視を証明することはできません。engagementが所有するsystem上の変化をmonitorし、controller/clientでcorroborateし、observerをprobeするのではなく停止します。以下は上記すべてのtechniqueを対象とします。[field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise)と組み合わせてください。

| 対象technique | 安全なcontroller-side signal | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT、public/guest Wi-Fi、travel router、cellular/eSIM、satellite、private APN | lease/portal/carrier session、public tuple、BSSID/cell/path change、provider notice | 未承認network/SIM/device、説明できない移動、provider/SOC escalation |
| VPN/VPS、HTTP/SOCKS/SSH、multi-hop、residential/cooperative proxy | peer authentication、tunnel state、route/DNS leak、new admin/API event、complaint | duplicate/stolen credential、unknown administrator、direct fallback、scope外egress |
| OHTTP/ODoH/ECH、MASQUE、split-provider relay、TURN | relay/gateway allocation、key/config version、unsupported direct connection、error/replay rate | key mismatch、direct fallback、unknown realm/peer、provider abuse notice |
| Tor Browser、bridge、Snowflake/WebTunnel/obfs4/meek、VPN±Tor、onion service | bootstrap state、circuit failure、onion descriptor/service health、owned canary page | personal-account crossover、unexpected non-Tor connection、compromised service key |
| I2P、mixnet、GNUnet、mesh/store-forward、non-IP local hop | peer set、queue age/sequence、gateway arrival、radio association、content hash | unknown peer/gateway、sequence rollback、unauthorized content、missing custody record |
| Remote browser/VDI/jump host、CI/CD runner、serverless | IdP session、workflow/image/config change、new token use、artifact/export、cloud audit | unknown login/workflow edit、secret read、unexpected destination、project-role escalation |
| ORB lab、fast flux/DGA、CDN/fronting、dead drop/pull mailbox | owned node inventory、DNS/edge/object access、controller graph、job signature、TTL | unknown node/origin/object writer、unsigned/replayed job、lab外topology |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat、boot/config hash、enclosure state、AP/switch context、duplicate identity | moved/opened node、unexpected boot/hash/path、sentinel use、site report |
| IPv6 temporary address、QUIC migration、MPTCP | delegated prefix、connection ID/subflow、path-validation、broker session | impossible migration、同時未承認path、revoke後のsession resumption |
| IPFS/cache、PIR、constrained fetcher | CID/query shape/root version、peer/gateway change、redirect/allowlist denial | unexpected pin/query/destination、unsigned dataset root、provider abuse notice |
| Refraction/decoy-routing lab、anycast rendezvous | owned diversion decision、proxy arrival、BGP/RPKI origin、regional config digest | production-path signal、unknown route origin、region/config inconsistency |

## Choosing and testing a path

1. 除去するobserverと隠すdataを明確にする。
2. それを除去できる最も単純なfamilyを選ぶ。
3. source、entry、traversal、exit、DNS、account、payment observerを図示する。
4. 別のendpoint/application identityを使用する。
5. IPv4、IPv6、DNS、WebRTC/application bypass、destination viewを検証する。
6. すべてのhopを停止し、failureがclosedになることを確認する。
7. 管理する各componentのlogを比較する。
8. 残存するtiming、provider、endpoint、physical linkを記録する。

## References

- [1] [EFF — VPNの選び方](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — HTTPでのUDP proxying](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Torの保護機能](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Torのblock解除](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — VPNとTor Browserの併用](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion serviceの概要](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
