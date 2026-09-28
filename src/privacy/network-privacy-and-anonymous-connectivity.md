# Network Privacy & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Network privacy は routing の選択であり、完全な identity ではありません。誰から **source**、**destination**、**content**、**timing** への接続を不可能にしたいのかを考えて、経路を選択してください。

正規化された inventory（すべての access-path family に対する `Pros`、`Cons`、手順ごとの `Procedure`、`Detection`）については、まず [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) を確認してください。このページでは、一般的に deploy 可能な選択肢を詳しく説明します。

## 各 observer が通常確認できる情報

| 経路 | Local network / ISP | Intermediary | Destination | 主な制約 | 相対速度 |
|---|---|---|---|---|---|
| Direct HTTPS | Source、destination metadata、timing/volume | Hosting/CDN は connection を認識 | Source IP、browser/app data | source-IP privacy がない | 最速 |
| Commercial VPN | Source が VPN に接続していること、通常の destination metadata | VPN は source と destination metadata を認識 | VPN egress IP | 1 つの provider が correlation point になる | 通常は高速 |
| Self-hosted VPN/VPS | Source が VPS に接続していること | Host/account/payment/control-plane logs | VPS egress IP | rented server/account に容易に attribution できる | 通常は高速 |
| Tor Browser | Source が Tor/bridge に接続していること、timing/volume | 各 relay は情報の一部だけを認識 | Tor exit、browser data | 低速、account/endpoint/correlation risks | 中速/低速 |
| Tails/Whonix | より強い routing boundaries を持つ同様の Tor path | 同じ Tor の制約 | Tor exit/application data | Operational mistakes と host/hardware は残る | 中速/低速 |
| Public guest Wi-Fi + HTTPS | Venue は local device/timing と destinations を認識 | Venue の ISP は metadata を認識 | Guest public IP | Physical/captive-portal/device correlation | 高速/変動 |
| Cellular hotspot | Carrier は subscriber/device/location と destinations を認識 | 使用していれば VPN/Tor | Carrier、VPN、または Tor egress IP | Mobile subscription と location は持続的な identifier | 高速/変動 |
| Mixnet | Access は mixnet の使用、timing/volume を認識 | 複数の mixing node | Gateway/egress | Emerging ecosystem、latency と bandwidth cost | 最低速 |

HTTPS は transit 中の content を保護しますが、すべての metadata を保護するわけではありません。EFF は、page paths、credentials、messages が暗号化されていても、domain、time、traffic size は intermediary から見える可能性があると説明しています。<sup>[[1]](#references)</sup>

## VPNs: 集中した trust による高速な privacy

VPN は、access ISP から destination metadata を隠したり、untrusted network 上の first hop を保護したり、安定した engagement egress address を提示したり、private network に到達したりする場合に便利です。ただし、VPN は user を anonymous にするものではありません。VPN は source connection を認識し、destination metadata を観察できます。また、accounts、cookies、GPS、fingerprints、payment information は残ります。<sup>[[1]](#references)</sup>

### Provider の評価 checklist

1. **Ownership and jurisdiction:** legal entity、parent company、operating countries、infrastructure subcontractors、適用される legal process を特定する。
2. **Collected data:** account/billing、source IP、connection timestamps、bandwidth、crash telemetry、DNS queries、destination logs を区別する。“No browsing logs” は “no data” を意味しない。
3. **Retention and deletion:** 正確な retention duration と、backups、fraud systems、processors が同じ schedule に従うかを確認する。
4. **Evidence:** scope、date、findings、remediation が公開された audits、reproducible/open clients、transparency reports、documented incidents を優先する。
5. **Protocol and client:** 維持管理された WireGuard、OpenVPN、または review 済みの別の protocol、automatic updates、DNS と IPv6 handling、kill switch、platform ごとの leak tests を確認する。
6. **Business model:** free または subsidized service がどのように資金提供されているかを理解する。App-store の存在だけでは trustworthy operation の証拠にならない。
7. **Payment fit:** alternative payment により VPN に対する billing disclosure を減らせる可能性はあるが、各 connection で観測される source IP が消えるわけではない。

### VPN の configure と verify

1. Provider/organization の signed client を official source から install する。
2. documented route が bypass する必要がない限り、**full tunnel** を選択する。Split tunneling は correlation と leak paths を作る。
3. fail-closed/always-on behavior を有効にし、reconnect 中の traffic を block する。
4. DNS を tunnel 経由で送信し、IPv4 と IPv6 の両方を test する。安全に tunnel できない場合に限り protocol を disable し、functionality loss を受け入れる。
5. sleep/wake、network switching、captive-portal login、tunnel crash、hotspot tethering を test する。NCSC は、一部の platform では tethered clients が phone の VPN を bypass する可能性があると警告しています。<sup>[[2]](#references)</sup>
6. organization-controlled test endpoint を使用して、observed IPv4、IPv6、DNS resolver、connection timing を記録する。sensitive engagement を無作為な “leak test” sites に expose しない。
7. client、OS、network、policy を変更した後に再度 test する。

### Hostile-LAN routing bypasses

VPN は “connected” と表示されたままでも、OS が VPN で packet を encrypt する**前**に route を選択するため、選択された packet が bypass する可能性があります。TunnelCrack は、一般的な routing exceptions を悪用する 2 つの方法を示しました。**LocalNet** は Internet destination が directly connected subnet 上にあるように見せ、一方 **ServerIP** は VPN-gateway resolution を spoof し、target address が VPN transport に必要な clear-network exception を継承するようにします。これらは WireGuard、OpenVPN、IPsec、TLS 自体の break ではなく、client/routing failures です。HTTPS payloads は end-to-end encrypted のままですが、local observer は destination/timing metadata と cleartext protocol data を復元できます。<sup>[[18]](#references)</sup>

TunnelVision は、DHCP option 121 を通じて同じ pre-encryption primitive を適用します。malicious または compromised DHCP server は、VPN の catch-all route よりも specific な classless route を install し、任意の host または range に対して physical interface を選択できます。VPN control channel は稼働し続ける可能性があるため、tunnel disconnection だけで trigger される kill switch は activate せず、単一の public “IP leak” check では selective bypass を見逃す可能性があります。<sup>[[19]](#references)</sup>

physical interface 上で DHCP と authenticated VPN transport のみを許可する packet-filter kill switch は、これを fail-closed behavior にできるはずです。ただし、targeted route injection は依然として selective-denial side channel を作成できます。High-consequence Linux workloads では、より強力な [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) を優先してください。この pattern では、application namespace に physical interface も clear-network default route もありません。<sup>[[19]](#references)</sup>

#### Owned-lab verification

正確な client/OS/version を、owned AP、DHCP server、VPN endpoint、destination 上で test してください。routing と packet-filter implementations は platform-specific であるため、product-wide claims はすぐに古くなります。test server だけでなく endpoint 自体でも capture してください。egress-IP website だけでは、すべての destination が tunnel に従っていることを証明できません。<sup>[[18]](#references)[[19]](#references)</sup>

1. VPN に接続し、VPN-server address を記録して、すべての IPv4/IPv6 routing table と policy-routing rule を保存する。Windows では `route print`、macOS では `netstat -rn`、Linux では以下の commands を使用する。
2. 複数の owned destination IP について selected route を query する。documented VPN transport endpoint を除き、next hop/interface は tunnel でなければならない。
3. TunnelVision では、controlled DHCP network 上で lease を renew し、**owned test destination のみに** option 121 route を install する。pass の条件は、traffic が引き続き tunneled または blocked されることであり、physical interface 上で destination traffic として送信されることではない。
4. LocalNet では、client に `203.0.113.0/24` のような lab-only public documentation subnet を割り当て、owned test destination をその内部に配置する。LAN access を有効にしても Internet-class destinations が tunnel を bypass しないことを verify する。
5. ServerIP では、VPN connection 前に controlled DNS が owned VPN hostname を owned test destination に resolve するようにし、lab gateway が VPN transport を実際の owned VPN endpoint に forward するようにする。client は spoofed address 宛ての無関係な application traffic を exempt してはならない。
6. “local network access” を enabled と disabled の両方にして、reconnect、sleep/wake、network switching、VPN-process crash の後にも繰り返す。IPv4、IPv6、DNS を個別に test する。
7. physical-interface capture を inspect する。そこには DHCP と VPN server 宛ての encrypted packets が含まれ、owned test destination に直接 address された packets は含まれていないはずである。また、rejected bypass が user prompts または connectivity repair の後に silently fall back できないことも確認する。
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: より強固なWeb unlinkability

Torは複数のrelayを通る回路を構築するため、通常、単一のrelayが送信元と宛先の両方を知ることはありません。宛先からはユーザーのIPではなくTor exitが見え、ローカルネットワークからは通常Tor接続が見えます。<sup>[[3]](#references)</sup> Torは低遅延のTCPアプリケーション向けに設計されているため低速であり、両端を相関分析できる攻撃者に対する保護を保証することはできません。<sup>[[4]](#references)</sup>

### Safe Tor Browser workflow

1. Tor BrowserはTor Projectまたは公式mirrorからのみダウンロードし、可能な場合はsignatureを検証します。
2. 通常のbrowserをTor SOCKS portに向けるのではなく、**Tor Browser**を使用します。通常のbrowserはDNS/WebRTCや識別可能なstateをleakする可能性があります。<sup>[[5]](#references)</sup>
3. デフォルトのサイズ、font、extension、privacy設定を維持します。追加のadd-onによりbrowserがよりuniqueになる可能性があります。<sup>[[6]](#references)</sup>
4. 破損が増えても許容できる場合は、セキュリティレベルとして**Safer**または**Safest**を選択します。
5. 直接Torがblockされている場合、または通常のrelay IPによって許容できないほどローカルで可視化される場合はbridgeを使用します。bridgeは簡単な識別を困難にしますが、traffic analysisを排除するものではありません。<sup>[[7]](#references)</sup>
6. 識別可能なaccountにloginしたり、識別情報を提供したり、ダウンロードしたactive documentを外部ネットワーク接続アプリケーションで開いたりしないでください。
7. identityごとに別のsession/contextを使用します。「New circuit」はbrowser/application identityを消去することと同じではありません。必要に応じて**New Identity**を使用するか、隔離された環境をrestartします。
8. 認証済みHTTPSまたは認証済みonion serviceを優先します。Tor exitは暗号化されていないHTTP trafficを監視できます。

### Tor plus VPN

両者を組み合わせても、自動的に安全になるわけではありません。Torの前にVPNを置くと、ISPから直接のTor relay接続を隠せる一方、VPNには送信元が見えます。Torの前にVPNを置かず、Torの後にVPNを置くと、VPNにはTor後の活動が安定して見えるため、anonymity setが小さくなる可能性があります。設定ミスによってleakが発生することもあります。Tor Projectは、このような組み合わせを高度で明確なthreat modelの場合にのみ推奨しています。<sup>[[8]](#references)</sup>

## Public and guest Wi-Fi

現代のHTTPSでは、適切に暗号化されたWeb contentを受動的な近隣ユーザーが通常読み取ることはできませんが、guest Wi-Fiは匿名性を提供しません。施設は接続時刻、device identifier、captive portal data、宛先、DHCPの詳細を記録できます。camera、購入履歴、transport、物理的な監視によってユーザーを特定できる場合もあります。また、似た名前の偽hotspotによってportal credentialsを取得されたり、暗号化されていないtrafficを改ざんされたりする可能性があります。<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. guest向けに提供されたnetwork、または所有者から明示的な許可を得たnetworkのみを使用します。staffに正確なSSIDとportalの手順を確認します。
2. 到着前にendpointとtravel routerをupdateします。file/printer sharing、inbound discovery、auto-join、記憶済みnetworkのprobeを無効にします。
3. OSのprivate/randomized Wi-Fi addressを有効にします。現在のApple systemはopen/weak network上でrotating addressを使用でき、modern Androidのrandomizationは通常SSIDごとにpersistentです。これは1つのローカルidentifierを減らすだけです。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. privileged workstationとguest networkの間には、組織が管理するtravel routerまたはlow-trust bridge deviceを優先します。これによりfirewall/VPN policyを一元化できますが、施設からrouterが見えなくなるわけではありません。<sup>[[12]](#references)</sup>
5. captive portalへの入力は、指定されたlow-trust device/browserからのみ行います。匿名contextであるはずの環境に、個人用または再利用されたcredentialsを入力しないでください。接続が確立したらportal browserを閉じます。
6. sensitive activityの前にfull-tunnel VPNまたはTorを開始し、fail-closed動作を確認します。
7. 使用後はnetworkをforgetし、portalのaccount/data-retention policyを確認します。

{% hint style="danger" %}
近隣のWi-FiをCrackingしたり、portalをbypassしたり、leaked guest credentialsを使用したり、他のguestのaccessをcloneしたり、caféにRaspberry Piを隠したりする行為は、unauthorized activityであり、privacy techniqueではありません。安全な代替手段は、lawful guest network、client-approved site、またはproperty ownerの書面による同意を得て設置・回収する、文書化されたdrop nodeです。
{% endhint %}

## Travel routers

travel routerは、敵対的なローカルbroadcastからworkstationを隔離し、firewallを適用し、一貫した内部SSIDを提供し、VPNへ自動的に再接続できます。**匿名ではありません**。upstreamからはradio identityとtraffic timingが見え、VPN providerからはtunnel sourceが見えます。

- 対応しているOpenWrt/vendor firmwareを使用し、不要なserviceを削除します。
- Ethernetまたはunique passwordを設定した専用management SSID経由で管理します。
- WAN-side administration、UPnP、WPS、file sharing、未承諾のinbound trafficを無効にします。
- 対応しており、かつ許可されている場合のみ、randomized/private WAN MACを使用します。
- DNSとIPv6を含むVPN policyをrouter上で適用し、tunnelが失敗した場合はegressをblockします。
- phone hotspotがtethered deviceをphoneのVPN経由でtunnelすると想定しないでください。実際にtestします。

## Cellular, SIMs and eSIMs

Cellularは便利ですが匿名ではありません。operatorはsubscriber/device identifierと、networkへの接続から導出されるlocationを保持します。eSIMもmobile subscriptionです。Prepaidだからといって確実にunregisteredとは限りません。要件は国によって異なり、変更されます。<sup>[[13]](#references)</sup>

運用上は、次の点に注意します。

- 個人データの露出を減らすため、別の対応deviceを使用します。架空のsubscriberを作成するためではありません。
- co-locationがthreat modelに含まれる場合、personal phoneと「別の」deviceを常に一緒に持ち歩かないでください。
- 使用していないcellular、Wi-Fi、Bluetooth、location accessを無効にします。電源を切ることは、UI toggleより強力なradio boundaryです。
- sensitive trafficを承認済みのVPN/Tor path内に置きます。ただし、carrierにはsubscription/deviceのlocationとtunnel endpointが依然として分かることを認識してください。
- 現在のregistrationおよびretention ruleをnational regulatorまたはlocal counselに確認します。「anonymous SIM countries」のonline listに依存しないでください。

## DNS and TLS metadata

- **DoH/DoT/DoQ**はclientとresolver間のDNSを暗号化し、単純なローカルでの読み取りや改ざんを防ぎます。ただしresolverにはqueryとtransport identifierが見えます。trustの移転であり、匿名性を提供するものではありません。<sup>[[14]](#references)</sup>
- **ODoH**はproxyを追加するため、proxyとtargetがcolludeしない限り、resolverはclient IPを知る必要がありません。Traffic analysisは明示的に対象外です。<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**は、client、DNS、serverが対応している場合、TLS handshake内のinner server nameを保護できます。destination IP、timing、volume、endpointは引き続き可視です。<sup>[[16]](#references)</sup>
- 正しく設定されたVPNまたはTor environmentでは、DNSはそのenvironmentがサポートするrouteに従う必要があります。別のresolverを追加すると、新たなobserverやfingerprintが発生する可能性があります。

### Encrypted-DNS/ECH verification workflow

1. DNSをVPN/Tor environment、OS、applicationのいずれがcontrolするかを決めます。関係のないresolverをstackするのではなく、意図した**1つ**のlayerで設定します。
2. 公開されたprivacy/retention policyに基づいてresolverを選択し、platformが対応している場合はstrict encrypted modeを有効にします。opportunistic fallbackでは、気付かないうちにplaintextへ戻る可能性があります。
3. 自分が管理するauthoritative test zone下のunique subdomainにqueryし、authoritative logに意図したrecursive resolverが記録されることを確認します。
4. 許可を得たうえで、test deviceのtrafficのみをcaptureします。access networkがplaintext DNSを読み取れないことを確認します。ただし、access networkからencrypted resolver/tunnel endpointが見えることは認識してください。
5. blockまたは到達不能なencrypted resolverをtestします。pass条件は、選択したfail-closedまたは文書化されたfallback動作であり、偶然のclear queryではありません。
6. ECHについては、管理下のECH-enabled hostを使用し、client/server diagnosticsを調べて**inner** ClientHelloが受理されたことを確認します。HTTPS recordを提供しているだけでは、ECHの成功は証明できません。
7. network変更、captive portal、browser update、VPN reconnectの後に再実行します。後のadministratorがbypassを作らないよう、どのcomponentがDNS/ECHを所有するかを記録します。

## Mixnets

NymやKatzenpostなどのMixnetは、fixed-size packet、delay、reordering、cover trafficを追加し、timing correlationに対抗します。これらの特性にはlatencyとbandwidthのコストがあり、独立したdeployment-scaleの証拠は限られています。現在のconsumer向けMixnetは、Tor/VPNのより高速または保証された代替ではなく、**emerging/high-latency options**として扱ってください。<sup>[[17]](#references)</sup>

### Evaluation workflow

1. 維持管理されているclientと、正確に対応しているapplicationを特定します。文書化されていないproxyを通して、任意のbrowser/system trafficを無理に流さないでください。
2. entry、mix node、gateway、destination、collusionの前提について、現在のthreat modelを読みます。
3. 公式のsigned sourceから別のtest compartmentにinstallし、無害な自分のendpointのみを使用します。
4. delivery latency、message-size limit、reliability、retransmission、gatewayが利用できない場合の動作を測定します。
5. local trafficと自分が管理するendpointを調べ、意図したpathとsourceを確認します。replyが同じprivacy designを使用するか確認します。
6. shutdown/failureをtestします。applicationがdirect Internet accessへ黙ってfallbackしてはなりません。
7. 速度のためにcover trafficを無効化したり、delayを短縮したり、通常と異なるfixed routeを選択したりしないでください。これらの変更により、明示されたanonymity modelが無効になる可能性があります。
8. 特定のdeployment、独立したanalysis、運用上のreliabilityが影響の大きさに見合うまで、experimentalなものとして扱います。

## Network preflight checklist

- [ ] Authorizationがaccess network、target、dates、source infrastructureを対象としている。
- [ ] endpointに無関係なidentityやactive sync sessionが存在しない。
- [ ] IPv4、IPv6、DNS、reconnect behaviorが計画と一致している。
- [ ] 制御されたDHCP/local-subnet route injectionによって、test trafficがphysical interfaceへ移動しない。
- [ ] destinationから見えるのは想定したegressだけである。
- [ ] captive portalとhotspotの動作を、sensitive trafficなしでtest済みである。
- [ ] local sharing/discoveryとautomatic network joiningが無効になっている。
- [ ] observer tableと残存するtraffic-correlation riskを受け入れている。
- [ ] provider policy、retention、emergency contactが最新である。

split-knowledge relay、route-enforced workload、pluggable transport、onion service、I2P、disposable remote browserについては、[Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)に進んでください。



## References

- [1] [EFF — VPNの選び方](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Torが提供するprivacyとanonymityの保護](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Torの簡単な紹介](https://spec.torproject.org/intro/)
- [5] [Tor Project — Torを他のbrowserで使用する](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browserのpluginとadd-on](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Torのblockを解除する](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Tor BrowserをVPNとともに使用する](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Public Wi-Fi networkは安全か？](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple deviceにおけるWi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomizationの実装](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstationの原則](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operatorへの推奨事項](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Bypassing Tunnels: Routing Tableの悪用によるVPN Client Trafficのleak](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: 攻撃者がRouting-Based VPNのcloakを解除し、VPN Leakを引き起こす方法](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
