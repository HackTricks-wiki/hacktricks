# 高度な Network Privacy アーキテクチャ

{{#include ../banners/hacktricks-training.md}}

複雑さは、特定の observer または failure mode を取り除く場合にのみ有用です。独自の tunnel stack、カスタム packet shape、珍しい user agent、または頻繁に rotating されるインフラは、数千人が使用する標準構成よりも強力な fingerprint になる可能性があります。

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) では、共通の `Pros`/`Cons`/`Procedure`/`Detection` schema を提供しています。このページでは、より複雑なアーキテクチャと trust boundary について詳しく説明します。

したがって、高度な目標は **knowledge の分離** です。通常、どのコンポーネントも user identity、destination、plaintext、long-term activity history のすべてを同時に保持すべきではありません。これは invisibility ではなく、collusion、legal process、endpoint compromise、または end-to-end traffic correlation によって path が再構築される可能性は依然としてあります。

## アーキテクチャの選択

| Pattern | 得られる特性 | 新たな trust/failure | 適した用途 |
|---|---|---|---|
| Standard Tor Browser | 共有された browser fingerprint と multi-relay path | 低 latency により traffic correlation が可能 | 一般的な anonymous web browsing |
| Tor bridge + pluggable transport | 直接的な Tor blocking/classification を困難にする | Bridge/transport は依然として検出可能。bridge は source を把握する | Censored networks |
| Onion service | service IP を隠し、exit を回避し、onion identity を認証する | Onion key と server endpoint が critical asset になる | Private publishing、intake、または administration |
| Independent ingress + egress relays | 通常、単一の relay が source と destination の両方を見ることがない | Operators が collude する可能性があり、timing は両方を通過する | High-performance supported applications |
| Oblivious HTTP | source IP と encrypted stateless HTTP request を分離する | Application、relay、gateway の support が必要 | Session state を使用しない telemetry、queries、submissions |
| VPN-only workload namespace | Kernel により clear-network route が存在しないことを強制する | VPN は依然として両端を把握する。host/root は引き続き trusted | Authorized engagement tools と fixed egress |
| Disposable remote browser | Destination を local browser/endpoint から隔離する | Workspace provider は activity と login identity を把握する | Untrusted sites/files と controlled research |
| I2P internal service | Separate inbound/outbound overlay tunnels。official exits はない | より小規模で異なる ecosystem。long-running peer behavior | I2P native の services。ordinary web replacement ではない |
| Mixnet/asynchronous delivery | Delay、batching、cover traffic により timing analysis に対抗する | 高 latency、限定的な applications、成熟度の問題 | Interaction を必要としない messages/tasks |

## Split-knowledge relays

2-operator relay pattern は、限定された application において single VPN を上回る可能性があります:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relayは実際に展開されている例です。Appleがingressを運用し、別のcontent providerがegressを運用するため、通常はどちらもclient IPとbrowsing destinationの両方を見ることはありません。<sup>[[1]](#references)</sup> これは製品固有のSafari/DNS privacy serviceであり、すべてのデバイスを対象とするanonymity networkではありません。また、意図的に大まかな地域情報を保持します。

Oblivious HTTP (OHTTP)は、より限定されたapplication patternを標準化します。relayはclientと暗号化されたgateway trafficを認識し、gatewayはHTTP messageを復号しますが、clientではなくrelayを認識します。RFC 9458は、relay/gateway双方の対応が必要であり、cookies/authentication/session stateを含まないrequestに最適で、traffic analysisは保証の対象外であると警告しています。<sup>[[2]](#references)</sup>

### 設計チェックリスト

1. 保護対象となる正確なapplication messageを定義し、認証済みの任意のweb sessionを暗黙にproxyしない。
2. 可能な限り、別々の管理、credentials、logging、法的管理を持つ、独立運用のingress組織とegress組織を使用する。
3. ingressが読み取れないよう、application requestをgateway向けに暗号化する。
4. 適切なlayerで、client由来のforwarding header、TLS identifier、安定したper-user tokenを削除する。
5. transport separationにもかかわらずgatewayがrequestを再関連付けできるような、固有のkey、cookie、payload fieldを避ける。
6. 両側のlogを集約、最小化し、期限切れにする。collusionおよび強制開示のリスクを文書化する。
7. レビュー済みのprotocolに従う場合にのみpaddingまたはbatchingを行う。自作のtraffic shapingは、correlationを阻止できないまま固有のsignatureを作る可能性がある。
8. 制御されたcanary requestでテストし、client、ingress、gateway、targetがそれぞれ何を記録するかを比較する。

通常の対話型browsingには、独自のprivate OHTTP proxyを作るのではなく、Tor Browserを使用してください。OHTTPは対応するapplication transactionを保護するものであり、browser identity全体を保護するものではありません。

## workloadごとにrouteを強制する

変更可能なhost routeだけに基づくkill switchは、DHCP renewal、sleep/wake、IPv6 change、またはtunnel crashの際に失敗する可能性があります。より強固なLinux patternでは、containerまたはnetwork namespaceにloopback interfaceとtunnel interfaceだけを与えます。WireGuardの文書では、interfaceをphysical namespaceで作成し、workload namespaceへ移動させ、暗号化されたUDP socketを元のnamespaceに保持できると説明されています。<sup>[[3]](#references)</sup>

### Deployment pattern

1. まず使い捨ての/local-console host上で構築する。namespaceのミスによってremote accessが失われる可能性がある。
2. physical Ethernet/Wi-Fi interfaceとDHCP/supplicantを**physical** namespaceに配置する。
3. そこでWireGuard interfaceを作成し、暗号化されたtransport socketがphysical networkへアクセスできるようにする。
4. WireGuard interfaceだけを**workload** namespaceへ移動し、それを唯一のdefault routeにする。
5. tunnel経由でのみ到達可能な、namespace固有のresolverをworkloadに与える。IPv6を明示的に考慮する。
6. host networking、privileged capability、共有browser directory、personal credential agentを使用せず、そのnamespaceでbrowser/tool containerを実行する。
7. tunnelを停止し、workloadが管理下のIPv4またはIPv6 endpointをresolveまたはconnectできないことを確認する。
8. workload namespaceの外側で、endpoint roaming、DHCP renewal、suspend/resume、captive-portal処理をテストする。
9. engagementの説明責任のため、namespace/tunnel configuration hashと承認済みegress addressを記録する。

これは**route enforcement**を提供するものであり、VPNまたはengagement bastionからのanonymityを提供するものではありません。侵害されたhost/rootはnamespaceを検査または変更できます。

## Tor bridgesとpluggable transports

Bridgesは非公開のTor entry relayです。Pluggable transportsはfirst-hop trafficを変更し、単純なblockingやprotocol classificationを困難にします。ただし、entry後にanonymous relay layerを追加するものではなく、より広範なtiming correlationが可能なobserverを阻止するものでもありません。

| Transport | First-hop approach | Practical tradeoff |
|---|---|---|
| **obfs4** | Trafficをランダムに見せ、active probingに抵抗する | 既知のbridge addressは依然としてblocking可能 |
| **Snowflake** | 短期間だけ存在するvolunteer WebRTC proxyを使用してbridgeに到達する | Performanceは変動する。broker/STUN/WebRTC patternが存在する |
| **WebTunnel** | HTTPSに似たWebSocket tunnelでbridge trafficを運ぶ | 到達可能なweb frontに依存し、依然としてclassificationされる可能性がある |

Tor Projectは、SnowflakeとWebTunnelを、完全なindistinguishabilityではなく、censorship-circumvention transportとして説明しています。<sup>[[4]](#references)</sup>

### Safe workflow

1. Tor Browserのdirect connectionから開始する。local observer modelにおけるblockingまたはvisibilityによって必要性が正当化される場合にのみbridgeを追加する。
2. Tor Projectのchannelから取得したbuilt-in transportまたはbridge lineを使用する。forumからランダムなtransport binaryやpublic bridge listをdownloadしない。
3. 安定して接続できる、対応済みの最も単純なoptionを試し、選択理由を記録する。
4. それ以外のTor Browserは標準状態に保つ。bridgeを使用しても、custom extension、account login、通常とは異なるbrowser settingが安全になるわけではない。
5. reconnectとclock correctnessをテストする。同じlocal observerにdistinctiveなsequenceを送るような形で、transportを繰り返し切り替えない。
6. censorまたはnetwork policyが変化した場合は再評価する。場所によっては、その使用自体がsensitiveまたはrestrictedである可能性がある。

## private rendezvousとしてのOnion services

Onion serviceはintroduction pointとrendezvous relayへのoutbound Tor circuitを作成するため、public inbound portを必要とせず、onion protocolを通じてserver IPを公開しません。client-to-service trafficはTor内部にとどまり、onion addressがservice keyを認証します。<sup>[[5]](#references)</sup>

合法的なintake portal、private repository、administrative interface、またはengagement evidence dropの場合:

1. 専用のhost/VM上でapplicationを実行し、loopbackまたはisolated Unix socketにbindする。
2. 公式repositoryからTorをinstallし、公式のv3 onion-service setupに従う。obsoleteなv2 instructionは決して使用しない。
3. onion service private keyをTLS/signing keyと同様に保護する。安定したidentityが必要な場合にのみbackupする。
4. closed group向けにonion-service client authorizationを追加し、independently authenticated channelを通じてcredentialsを配布する。<sup>[[6]](#references)</sup>
5. originがthird-party font、analytics、update、webhookをfetchしてpublic IPまたはoperator accountを明らかにしないようにする。
6. application内にもauthenticationとauthorizationを実装する。onion addressを知っていることはaccess controlではない。
7. third-party telemetryを埋め込まずにserviceへpatch、rate-limit、monitoringを行う。
8. 別のtest contextから、DNS、email、error page、file metadata、response headerがoriginを開示していないことを確認する。
9. red-teamで使用する場合は、service、owner、purpose、shutdown timeをROEに記載する。scope外のC2を隠すために使用しない。

## Remote browserとdisposable workspace

Remote browserはrenderingとriskのあるcontentをlocal endpointから移動させ、engagement固有のcloud egressを提示できます。local deviceを一部のcontentとpersistenceから保護しますが、workspace providerに対してoperatorをanonymousにするものではありません。例えばAWSは、disposable browser instanceがsession終了時に破棄される場合でも、portal、identity、policy、preference、session-log dataの収集を文書化しています。<sup>[[7]](#references)</sup>

engagementごとにorganization-controlled workspaceを1つ使用し、download/upload/clipboardを制限し、personal identity providerを無効にし、その固定egressをapproved bastion経由で送信し、evidence export後にworkspaceを期限切れにします。provider console、IdP、administratorをobserverとして扱います。

## I2Pとinternal overlay

I2Pは、別々の一方向のinbound tunnelとoutbound tunnelを構築し、official network-layer exitを持ちません。主にI2P内部のservice向けです。<sup>[[8]](#references)</sup> public Internetをbrowsingするための、単純に置き換え可能な高速手段ではありません。Outproxyはtrust pointを導入し、official threat modelはさらなるresearchを明示的に求め、完全なanonymityを主張していません。

両端が意図的に対応している場合にのみI2Pを使用し、長期間稼働するrouterをpersonal applicationから分離し、peer/local networkがI2P participationを観察できることを理解してください。根拠なしにhop countを増やしたりpeer selectionを調整したりしないでください。通常とは異なる設定はperformanceとanonymity setを低下させる可能性があります。

## Correlation-resistant operations

- 固有のbuildではなく、一般的で対応済みのclient configurationを優先する。
- endpointでidentityを分離する。routing topologyによってaccount、payment、recovery、content reuseが修復されることはない。
- non-interactive taskには、手動でsleepやfake trafficを追加するのではなく、レビュー済みのasynchronous protocol/mixnetを優先する。
- 同じphysical contextから、分離されているとされるidentityを同期したpatternで運用することを避ける。
- one-way export gateを使用する。untrusted contentはdisposable rendererに入り、レビュー済みでsanitizedされたresultだけが外に出る。
- protocol securityのためclockを正確に保つが、公開artifactから不要な高精度timestampを削除する。
- session durationと古いinfrastructureを最小化する。ただし、目立ちやすくaccountabilityを損なう急速な「fast-flux」rotationは行わない。

## 関与していない第三者を利用できない技術

これらは実在するadversary techniqueであり、想像上のものでも重要でないものでもありません。その仕組みとdetectionは、[Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md)、[Covert Physical and Wireless Access](covert-physical-wireless-access.md)、[APT case studies](government-and-apt-case-studies.md)で説明されています。authorized exerciseでは、所有する代替手段を使って観測可能な挙動を再現してください。

- residential/mobile exit churnを、同意が不明確なmarketではなく、管理下のrelay poolでmodel化する。
- open proxy、compromised router、botnetを、所有するVM/routerでmodel化する。
- stolen cloud accountを、指定されたexercise tenantとsynthetic victim identityでmodel化する。
- domain frontingを、 unwilling CDNではなく、所有するreverse proxyでmodel化する。
- third-party Wi-Fiを、labが所有する2つのisolated APでmodel化する。
- custom encryption、multi-VPN chain、identifier rotationは、flow、account、endpoint artifactが検出可能なままのtest hypothesisとして扱う。

authorized red teamでは、trafficをより認識しにくくする試みは、ROEにおける明示的なdetection objectiveとし、controllerが保持するattribution mapを用意し、stop/deconfliction mechanismを含める必要があります。

## 検証マトリクス

| Test | Expected result | Failure means |
|---|---|---|
| Tunnel/bridge stopped | Workloadにdirect IPv4/IPv6/DNS pathがない | Route enforcementが不完全 |
| Target log inspected | 計画されたegress/application identityだけが表示される | Header、route、またはaccount leak |
| Ingress log inspected | Sourceは存在するが、clear target/requestは存在しない | Ingressでtrust splitに失敗 |
| Egress log inspected | Relay/requestは存在するが、source identityは存在しない | Egressでtrust splitに失敗 |
| Onion origin scanned externally | Public origin serviceに到達またはlinkできない | Originがleakした、またはdual-homed |
| Disposable session ended | Instance stateは消失し、approved evidenceは別途保持される | Persistence boundaryに失敗 |
| Controller lookup exercised | Activityが迅速にengagement/operatorへ対応付けられる | Red-team accountabilityに失敗 |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
