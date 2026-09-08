# 高度な Network Privacy アーキテクチャ

複雑さは、特定の observer や failure mode を排除する場合にのみ有用です。独自の tunnel stack、カスタム packet shape、珍しい user agent、または頻繁にローテーションする infrastructure は、数千人が使用する標準構成よりも強力な fingerprint になる可能性があります。

[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) では、共通の `Pros`/`Cons`/`Procedure`/`Detection` schema を提供しています。このページでは、より複雑なアーキテクチャと trust boundary について詳しく説明します。

したがって、高度な目標は **knowledge の分離** です。通常の component が、user identity、destination、plaintext、長期的な activity history を同時に保持しないようにします。これは不可視性を意味するものではなく、collusion、legal process、endpoint compromise、または end-to-end traffic correlation によって、経路が再構築される可能性はあります。

## Architecture selection

| Pattern | Property gained | New trust/failure | Suitable use |
|---|---|---|---|
| Standard Tor Browser | 共有された browser fingerprint と multi-relay path | 低 latency により traffic correlation が可能 | 一般的な anonymous web browsing |
| Tor bridge + pluggable transport | 直接的な Tor blocking/classification をより困難にする | Bridge/transport は依然として検出可能で、bridge は source を把握する | Censored networks |
| Onion service | Service IP を隠し、exit を回避し、onion identity を認証する | Onion key と server endpoint が critical asset になる | Private publishing、intake、または administration |
| Independent ingress + egress relays | 通常、単一の relay が source と destination の両方を見ることがない | Operator が collude する可能性があり、timing は両方を通過する | High-performance supported applications |
| Oblivious HTTP | Source IP を encrypted stateless HTTP request から分離する | Application、relay、gateway の support が必要 | Telemetry、query、session state を必要としない submission |
| VPN-only workload namespace | Kernel により clear-network route が存在しないことを強制する | VPN は依然として両端を把握し、host/root は trusted のまま | Authorized engagement tools と固定 egress |
| Disposable remote browser | Destination を local browser/endpoint から分離する | Workspace provider は activity と login identity を把握する | Untrusted sites/files と controlled research |
| I2P internal service | Separate inbound/outbound overlay tunnels。official exit は存在しない | より小規模で異なる ecosystem と、長時間稼働する peer behavior | I2P native services。通常の web の代替ではない |
| Mixnet/asynchronous delivery | Delay、batching、cover traffic により timing analysis に対抗する | High latency、限定的な applications、未成熟さ | Interaction を必要としない messages/tasks |

## Split-knowledge relays

2 つの operator による relay pattern は、限定された application において、単一の VPN を上回る可能性があります。
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
Apple Private Relayは実際に導入されている例です。Appleがingressを運用し、別のcontent providerがegressを運用するため、通常、どちらもclient IPとbrowsing destinationの両方を見ることはありません。<sup>[[1]](#references)</sup> これは製品固有のSafari/DNS privacy serviceであり、すべてのデバイスを対象とするanonymity networkではありません。また、粗い地域情報を意図的に保持します。

Oblivious HTTP (OHTTP)は、より限定されたアプリケーションパターンを標準化します。relayはclientと暗号化されたgateway trafficを確認し、gatewayはHTTP messageを復号しますが、clientではなくrelayを認識します。RFC 9458は、これにはrelay/gatewayの協力が必要であり、cookie/authentication/session stateを含まないrequestに最適で、traffic analysisは保証の対象外であると警告しています。<sup>[[2]](#references)</sup>

### Design checklist

1. 保護対象の正確なapplication messageを定義し、認証済みの任意のweb sessionを黙ってproxyしない。
2. 可能な限り、独立して運用されるingressとegressの組織を使用し、administration、credential、logging、legal controlを分離する。
3. ingressが読み取れないよう、application requestをgateway宛てに暗号化する。
4. 適切なlayerで、client由来のforwarding header、TLS identifier、安定したper-user tokenを削除する。
5. transport separationがあってもgatewayがrequestを再関連付けできるようなunique key、cookie、payload fieldを避ける。
6. 両側のlogを集約、最小化し、期限を設けて削除する。collusionとcompelled-disclosureのリスクを文書化する。
7. paddingやbatchingは、レビュー済みのprotocolに従う場合にのみ行う。自作のtraffic shapingは、correlationを防げないままunique signatureを作る可能性がある。
8. 管理されたcanary requestでテストし、client、ingress、gateway、targetがそれぞれ何を記録するか比較する。

通常のinteractive browsingには、private OHTTP proxyを発明するのではなくTor Browserを使用します。OHTTPが保護するのは対応するapplication transactionであり、完全なbrowser identityではありません。

## workloadごとにrouteを強制する

変更可能なhost routeだけに基づくkill switchは、DHCP renewal、sleep/wake、IPv6の変更、またはtunnel crashの際に失敗する可能性があります。より強固なLinux patternでは、containerまたはnetwork namespaceにloopback interfaceとtunnel interfaceだけを与えます。WireGuardの文書では、physical namespaceでinterfaceを作成し、それをworkload namespaceに移動させ、暗号化されたUDP socketを元のnamespaceに保持できることが説明されています。<sup>[[3]](#references)</sup>

### Deployment pattern

1. まずdisposable/local-console host上で構築する。namespaceの誤りによりremote accessを失う可能性がある。
2. physical Ethernet/Wi-Fi interfaceとDHCP/supplicantを**physical** namespaceに配置する。
3. そこでWireGuard interfaceを作成し、暗号化されたtransport socketがphysical networkにアクセスできるようにする。
4. WireGuard interfaceだけを**workload** namespaceに移動し、それを唯一のdefault routeにする。
5. tunnel経由でのみ到達可能な、namespace固有のresolverをworkloadに与える。IPv6を明示的に考慮する。
6. host networking、privileged capability、shared browser directory、personal credential agentを使用せず、そのnamespaceでbrowser/tool containerを実行する。
7. tunnelを停止し、workloadが管理下のIPv4またはIPv6 endpointをresolveまたはconnectできないことを確認する。
8. workload namespaceの外側で、endpoint roaming、DHCP renewal、suspend/resume、captive-portal handlingをテストする。
9. engagementの説明責任のため、namespace/tunnel configuration hashと承認済みegress addressを記録する。

これは**route enforcement**を提供するものであり、VPNまたはengagement bastionからのanonymityを提供するものではありません。侵害されたhost/rootはnamespaceを検査または変更できます。

## Tor bridges and pluggable transports

Bridgeは非公開のTor entry relayです。Pluggable transportはfirst-hop trafficを変更し、単純なblockingやprotocol classificationを困難にします。ただし、entry後にanonymous relay layerを追加するものではなく、より広範なtiming correlationが可能なobserverを阻止するものでもありません。

| Transport | First-hop approach | Practical tradeoff |
|---|---|---|
| **obfs4** | trafficをrandomに見せ、active probingに抵抗する | 既知のbridge addressは引き続きblockされる可能性がある |
| **Snowflake** | 短期間だけ存在するvolunteer WebRTC proxyを使用してbridgeに到達する | performanceは変動し、broker/STUN/WebRTC patternが存在する |
| **WebTunnel** | HTTPSに似たWebSocket tunnelでbridge trafficを運ぶ | 到達可能なweb frontに依存し、classificationされる可能性もある |

Tor Projectは、SnowflakeとWebTunnelをcensorship-circumvention transportとして説明しており、完全なindistinguishabilityを実現するものとはしていません。<sup>[[4]](#references)</sup>

### Safe workflow

1. Tor Browserのdirect connectionから開始する。local observer modelにおけるblockingまたはvisibilityがbridgeを正当化する場合にのみ追加する。
2. Tor Projectのchannelから入手したbuilt-in transportまたはbridge lineを使用する。forumからrandomなtransport binaryやpublic bridge listをdownloadしない。
3. 接続が安定する、対応済みの最も複雑でないoptionを試し、選択理由を記録する。
4. それ以外ではTor Browserを標準状態に保つ。bridgeを使用しても、custom extension、account login、または通常と異なるbrowser settingが安全になるわけではない。
5. reconnectとclock correctnessをテストする。同じlocal observerにdistinctive sequenceを送るような方法で、transportを繰り返し切り替えない。
6. censorまたはnetwork policyが変わった場合は再評価する。一部の地域では、使用自体がsensitiveまたはrestrictedである可能性がある。

## private rendezvousとしてのOnion service

Onion serviceはintroduction pointとrendezvous relayへのoutbound Tor circuitを構築するため、public inbound portを必要とせず、onion protocolを通じてserver IPを公開しません。client-to-service trafficはTor内にとどまり、onion addressがservice keyを認証します。<sup>[[5]](#references)</sup>

lawful intake portal、private repository、administrative interface、またはengagement evidence dropには、次の手順を使用します。

1. applicationをdedicated host/VM上で実行し、loopbackまたはisolated Unix socketにbindする。
2. official repositoryからTorをinstallし、official v3 onion-service setupに従う。obsolete v2 instructionは決して使用しない。
3. onion service private keyをTLS/signing keyと同様に保護する。stable identityが必要な場合にのみbackupする。
4. closed group向けにonion-service client authorizationを追加し、credentialをindependently authenticated channel経由で配布する。<sup>[[6]](#references)</sup>
5. originがthird-party font、analytics、update、webhookをfetchしてpublic IPまたはoperator accountを明らかにしないようにする。
6. applicationにもauthenticationとauthorizationを実装する。onion addressを知っているだけではaccess controlにならない。
7. third-party telemetryを組み込まずに、serviceへpatch、rate-limit、monitoringを適用する。
8. 別のtest contextから、DNS、email、error page、file metadata、response headerがoriginを開示していないことを確認する。
9. red-teamで使用する場合は、service、owner、purpose、shutdown timeをROEに記載する。out-of-scope C2を隠すために使用しない。

## Remote browser and disposable workspace

Remote browserはrenderingとriskのあるcontentをlocal endpointから遠ざけ、engagement固有のcloud egressを提示できます。これは一部のcontentとpersistenceからlocal deviceを保護しますが、workspace providerに対してoperatorをanonymousにするものではありません。例えばAWSは、disposable browser instanceがsession終了時に破棄される場合でも、portal、identity、policy、preference、session-log dataを収集することを説明しています。<sup>[[7]](#references)</sup>

engagementごとにorganizationが管理するworkspaceを1つ使用し、download/upload/clipboardを制限し、personal identity providerを無効化し、その固定egressを承認済みbastion経由で送信し、evidence export後にworkspaceを期限切れにします。provider console、IdP、administratorをobserverとして扱います。

## I2P and internal overlays

I2Pは個別の一方向inboundおよびoutbound tunnelを構築し、official network-layer exitを持ちません。主な用途はI2P内部のserviceです。<sup>[[8]](#references)</sup> public Internetをbrowseするための、簡単に導入できる高速な代替手段ではありません。Outproxyはtrust pointを導入し、official threat modelもさらなるresearchを明示的に求め、完全なanonymityを主張していません。

両端が意図的にI2Pをサポートする場合にのみI2Pを使用し、そのlong-lived routerをpersonal applicationから分離します。また、peerやlocal networkがI2P participationを観測できることを理解します。根拠なしにhop countを増やしたりpeer selectionを調整したりしないでください。通常と異なる設定はperformanceとanonymity setを低下させる可能性があります。

## Correlation-resistant operations

- unique buildよりも、一般的でsupportedなclient configurationを優先する。
- endpointでidentityを分離する。routing topologyによってaccount、payment、recovery、content reuseが修復されることはない。
- non-interactive taskでは、sleepやfake trafficを手動で追加するより、reviewed asynchronous protocol/mixnetを優先する。
- 同じphysical contextから、分離されているはずのidentityをsynchronized patternで運用することを避ける。
- one-way export gateを使用する。untrusted contentはdisposable rendererに入り、review済みでsanitizedされたresultだけが外に出る。
- protocol securityのためclockを正確に保つが、公開artifactから不要な正確なtimestampを削除する。
- session durationとstale infrastructureを最小化する。ただし、目立ちやすくaccountabilityを損なう急速な「fast-flux」rotationは行わない。

## 関与していない第三者を利用できないTechnique

これらは実在するadversary techniqueであり、架空でも重要性のないものでもありません。そのmechanicsとdetectionについては、[Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md)、[Covert Physical and Wireless Access](covert-physical-wireless-access.md)、[APT case studies](government-and-apt-case-studies.md)で説明しています。authorized exercise中は、所有する代替手段を使って観測可能な挙動を再現します。

- residential/mobile exit churnを、consentが不明確なmarketではなく、管理下のrelay poolでモデル化する。
- open proxy、compromised router、botnetを、所有するVM/routerでモデル化する。
- stolen cloud accountを、指定されたexercise tenantとsynthetic victim identityでモデル化する。
- domain frontingを、協力を望まないCDNではなく、所有するreverse proxyでモデル化する。
- third-party Wi-Fiを、labが所有する2台のisolated APでモデル化する。
- custom encryption、multi-VPN chain、identifier rotationは、flow、account、endpoint artifactが引き続き検出可能なtest hypothesisとして扱う。

authorized red teamでは、trafficを認識しにくくする試みは、ROEにおける明示的なdetection objectiveとし、controllerが保持するattribution mapを用意し、stop/deconfliction mechanismを含める必要があります。

## Verification matrix

| Test | Expected result | Failure means |
|---|---|---|
| Tunnel/bridge stopped | workloadに直接のIPv4/IPv6/DNS pathがない | Route enforcementが不完全 |
| Target log inspected | planned egress/application identityのみが現れる | Header、route、またはaccount leak |
| Ingress log inspected | sourceは存在し、clear target/requestは存在しない | ingressでtrust splitに失敗 |
| Egress log inspected | relay/requestは存在し、source identityは存在しない | egressでtrust splitに失敗 |
| Onion origin scanned externally | public origin serviceに到達またはlinkできない | Originがleakしているかdual-homed |
| Disposable session ended | instance stateは消え、承認済みevidenceは別途保持される | Persistence boundaryに失敗 |
| Controller lookup exercised | activityが速やかにengagement/operatorへmapされる | Red-team accountabilityに失敗 |

## References

- [1] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing and Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake and pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — How Onion Services work](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Onion Service advanced settings and client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption in Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
