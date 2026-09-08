# Network Privacy & Anonymous Connectivity

Network privacy is a routing decision, not a complete identity. Select a path by asking who should be unable to connect **source**, **destination**, **content**, and **timing**.

正規化されたインベントリ—すべてのアクセス経路ファミリーについての`Pros`、`Cons`、手順ごとの`Procedure`、および`Detection`—については、[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md)から始めてください。このページでは、一般的に展開可能な選択肢を詳しく説明します。

## 各オブザーバーが通常確認できるもの

| 経路 | ローカルネットワーク / ISP | 仲介者 | 宛先 | 主な制限 | 相対速度 |
|---|---|---|---|---|---|
| Direct HTTPS | Source、宛先メタデータ、タイミング/通信量 | Hosting/CDNは接続を確認 | Source IP、browser/app data | Source-IP privacyなし | 最速 |
| Commercial VPN | SourceがVPNに接続していること。通常の宛先メタデータは見えない | VPNはSourceと宛先のメタデータを確認 | VPN egress IP | 1つのproviderがcorrelation pointになる | 通常は高速 |
| Self-hosted VPN/VPS | SourceがVPSに接続していること | Host/account/payment/control-plane logs | VPS egress IP | 借りたserver/accountに簡単に帰属できる | 通常は高速 |
| Tor Browser | SourceがTor/bridgeに接続していること。タイミング/通信量 | 各relayは限定的な一部のみ確認 | Tor exit、browser data | 低速。account/endpoint/correlation risks | 中速/低速 |
| Tails/Whonix | より強いrouting boundariesを備えた同様のTor経路 | 同じTorの制限 | Tor exit/application data | Operational mistakesとhost/hardwareは残る | 中速/低速 |
| Public guest Wi-Fi + HTTPS | Venueはlocal device/timingと宛先を確認 | VenueのISPはメタデータを確認 | Guest public IP | 物理的な/captive-portal/device correlation | 高速/変動 |
| Cellular hotspot | Carrierはsubscriber/device/locationと宛先を確認 | 使用時はVPN/Tor | Carrier、VPN、またはTor egress IP | Mobile subscriptionとlocationは永続的な識別子 | 高速/変動 |
| Mixnet | Accessはmixnetの使用、タイミング/通信量を確認 | 複数のmixing node | Gateway/egress | 発展途上のecosystem。latencyとbandwidth cost | 最低速 |

HTTPSは転送中のcontentを保護しますが、すべてのmetadataを保護するわけではありません。EFFによると、page paths、credentials、messagesが暗号化されていても、domain、time、traffic sizeは仲介者から見える場合があります。<sup>[[1]](#references)</sup>

## VPN: 高速なprivacyと集中したtrust

VPNは、access ISPから宛先メタデータを隠す、信頼できないnetwork上のfirst hopを保護する、安定したengagement egress addressを提示する、またはprivate networkに到達するために役立ちます。VPNは**userをanonymousにはしません**。VPNはSource connectionを確認し、宛先メタデータを監視できます。また、accounts、cookies、GPS、fingerprints、payment informationは残ります。<sup>[[1]](#references)</sup>

### Providerの評価チェックリスト

1. **Ownership and jurisdiction:** legal entity、parent company、operating countries、infrastructure subcontractors、および適用されるlegal processを特定する。
2. **Collected data:** account/billing、source IP、connection timestamps、bandwidth、crash telemetry、DNS queries、destination logsを区別する。「No browsing logs」は「no data」を意味しない。
3. **Retention and deletion:** 正確な保存期間と、backups、fraud systems、processorsが同じscheduleに従うかを確認する。
4. **Evidence:** scope、date、findings、remediationが公開されたaudits、reproducible/open clients、transparency reports、記録されたincidentsを優先する。
5. **Protocol and client:** 維持管理されたWireGuard、OpenVPN、またはレビュー済みの別のprotocol、automatic updates、DNSとIPv6 handling、kill switch、platformごとのleak testsを確認する。
6. **Business model:** 無料または補助金で運営されるserviceの資金源を理解する。App-storeへの掲載だけでは、信頼できる運用の証拠にならない。
7. **Payment fit:** alternative paymentはVPNへのbilling disclosureを減らせるが、すべてのconnectionで観測されるsource IPを消すことはできない。

### VPNの設定と検証

1. Provider/organizationの署名付きclientを公式sourceからインストールする。
2. 文書化されたrouteを迂回させる必要がない限り、**full tunnel**を選択する。Split tunnelingはcorrelationとleak pathsを作る。
3. fail-closed/always-on behaviorを有効にし、reconnect中のtrafficをblockする。
4. DNSをtunnel経由で送信し、IPv4とIPv6の両方をtestする。安全にtunnelできない場合に限りprotocolを無効化し、機能低下を受け入れる。
5. sleep/wake、network switching、captive-portal login、tunnel crash、hotspot tetheringをtestする。NCSCは、一部のplatformではtethered clientsがphoneのVPNを迂回する可能性があると警告している。<sup>[[2]](#references)</sup>
6. organizationが管理するtest endpointを使い、観測されたIPv4、IPv6、DNS resolver、connection timingを記録する。機密性のあるengagementを、無作為な「leak test」siteに公開しない。
7. client、OS、network、またはpolicyを変更した後に再testする。

## Tor Browser: より強力なweb unlinkability

Torは複数のrelayを通るcircuitを構築するため、通常、単一のrelayがSourceと宛先の両方を知ることはありません。宛先からはuserのIPではなくTor exitが見え、local networkからは通常Tor connectionが見えます。<sup>[[3]](#references)</sup> Torはlow-latency TCP applications向けに設計されているため低速であり、両端をcorrelateできるadversaryに対する保護を保証できません。<sup>[[4]](#references)</sup>

### 安全なTor Browser workflow

1. Tor BrowserはTor Projectまたは公式mirrorからのみdownloadし、可能な場合はsignatureを検証する。
2. 通常のbrowserをTor SOCKS portに向けるのではなく、**Tor Browser**を使用する。通常のbrowserはDNS/WebRTCや識別可能なstateをleakする可能性がある。<sup>[[5]](#references)</sup>
3. defaultのsize、fonts、extensions、privacy settingsを維持する。追加のadd-onsはbrowserをよりuniqueにする可能性がある。<sup>[[6]](#references)</sup>
4. breakageの増加を許容できる場合は、**Safer**または**Safest** security levelを選択する。
5. direct Torがblockされている場合、または通常のrelay IPによって許容できないlocal visibilityが生じる場合はbridgeを使用する。Bridgeは容易なrecognitionを減らすが、traffic analysisを排除するものではない。<sup>[[7]](#references)</sup>
6. identifying accountにloginしたり、identifying informationを提供したり、downloadしたactive documentsを外部のnetworked applicationで開いたりしない。
7. identityごとに別のsession/contextを使用する。「New circuit」はbrowser/application identityを消去することと同じではない。適切に**New Identity**を使用するか、isolated environmentをrestartする。
8. authenticated HTTPSまたはauthenticated onion serviceを優先する。Tor exitは暗号化されていないHTTP trafficを監視できる。

### TorとVPNの併用

組み合わせれば自動的に安全になるわけではありません。Torの前にVPNを置くと、ISPからdirect Tor relay connectionsを隠せますが、VPNはSourceを確認します。VPNをTorの前に置くと、VPNはpost-Tor activityを安定して把握でき、anonymity setを縮小する可能性があります。Misconfigurationによってleaksが発生することもあります。Tor Projectは、このような組み合わせをadvancedで明確なthreat modelsの場合にのみ推奨しています。<sup>[[8]](#references)</sup>

## Publicおよびguest Wi-Fi

現代のHTTPSにより、適切に暗号化されたweb contentを受動的な近隣利用者が通常読み取ることはできません。しかし、guest Wi-Fiはanonymityではありません。Venueはassociation times、device identifiers、captive-portal data、destinations、DHCP detailsを記録できます。また、cameras、purchases、transport、physical observationによってuserを特定できます。偽の類似名hotspotは、portal credentialsを取得したり、暗号化されていないtrafficを操作したりする可能性もあります。<sup>[[9]](#references)</sup>

### 合法的なguest-network workflow

1. Guest向けに提供されたnetwork、またはownerから明示的なpermissionを得たnetworkのみを使用する。スタッフに正確なSSIDとportal procedureを確認する。
2. 到着前にendpointとtravel routerをupdateする。file/printer sharing、inbound discovery、auto-join、remembered-network probingを無効化する。
3. OSのprivate/randomized Wi-Fi addressを有効にする。Current Apple systemsはopen/weak networksでrotating addressesを使用でき、modern Android randomizationはSSIDごとにpersistentであることが多い。これによりlocal identifierを1つだけ減らせる。<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. privileged workstationとguest networkの間に、organization-controlled travel routerまたはlow-trust bridge deviceを置くことを優先する。これによりfirewall/VPN policyを集中管理できるが、router自体をvenueから隠すことはできない。<sup>[[12]](#references)</sup>
5. captive portalはdesignated low-trust device/browser経由でのみ完了する。匿名context用にpersonalまたは再利用credentialsを入力しない。接続確立後はportal browserを閉じる。
6. sensitive activityの前にfull-tunnel VPNまたはTorを開始し、fail-closed behaviorを確認する。
7. 使用後はnetworkをforgetし、portal account/data-retention policyを確認する。

{% hint style="danger" %}
近隣のWi-FiをCrackingすること、portalをbypassすること、leaked guest credentialsを使用すること、別のguestのaccessをcloningすること、またはcaféにRaspberry Piを隠すことは、privacy techniqueではなくunauthorized activityです。安全な代替手段は、合法的なguest network、client-approved site、またはproperty owner's written consentを得て設置・回収するdocumented drop nodeです。
{% endhint %}

## Travel router

Travel routerは、workstationをhostile local broadcastsから隔離し、firewallを適用し、一貫したinternal SSIDを提供し、VPNを自動的にreconnectできます。ただし、**anonymousではありません**。Upstreamはそのradio identityとtraffic timingを確認し、VPN providerはtunnel sourceを確認します。

- Supported OpenWrt/vendor firmwareを使用し、不要なservicesを削除する。
- Ethernetまたはunique passwordを設定したdedicated management SSID経由で管理する。
- WAN-side administration、UPnP、WPS、file sharing、unsolicited inbound trafficを無効化する。
- 対応し、かつ許可されている場合に限り、randomized/private WAN MACを使用する。
- DNSとIPv6を含むVPN policyをrouter上で適用し、tunnel failure時にはegressをblockする。
- Phone hotspotがtethered devicesをphoneのVPN経由でtunnelすると想定せず、testする。

## Cellular、SIM、eSIM

Cellularは便利ですがanonymousではありません。Operatorsはsubscriber/device identifiersと、network attachmentから導出されるlocationを保持します。eSIMもmobile subscriptionです。Prepaidが確実にunregisteredを意味するわけではなく、requirementsはcountryごとに異なり、変更されます。<sup>[[13]](#references)</sup>

運用上の注意:

- personal dataのexposureを減らすために、separateでsupported deviceを使用する。fictional subscriberを作成するためではない。
- Threat modelにco-locationが含まれる場合、personal phoneと「separate」deviceを常に一緒に持ち歩かない。
- 未使用のcellular、Wi-Fi、Bluetooth、location accessを無効化する。powering offはUI togglesより強いradio boundaryとなる。
- sensitive trafficをapproved VPN/Tor path内に入れる。ただしcarrierはsubscription/device locationとtunnel endpointを引き続き把握していることを認識する。
- national regulatorまたはlocal counselにcurrent registration and retention rulesを確認する。「anonymous SIM countries」のonline listsに依存しない。

## DNSとTLS metadata

- **DoH/DoT/DoQ**はclientとresolver間のDNSを暗号化し、単純なlocal readingまたはmodificationを防ぐが、resolverはqueriesとtransport identifiersを引き続き確認する。Trustを移動するだけで、anonymityは提供しない。<sup>[[14]](#references)</sup>
- **ODoH**はproxyを追加するため、proxyとtargetがcolludeしない限りresolverはclient IPを知る必要がない。Traffic analysisは明示的にscope外である。<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**は、client、DNS、serverが対応している場合、TLS handshake内のinner server nameを保護できる。Destination IP、timing、volume、endpointは引き続き見える。<sup>[[16]](#references)</sup>
- 正しく設定されたVPNまたはTor environmentでは、DNSはそのenvironmentが対応するrouteに従うべきである。別のresolverを追加すると、新たなobserverまたはfingerprintが生じる可能性がある。

### Encrypted-DNS/ECH verification workflow

1. DNSをVPN/Tor environment、OS、applicationのどれが管理するかを決める。関係のないresolverをstackするのではなく、**1つ**の意図したlayerで設定する。
2. 公開されたprivacy/retention policyを確認してresolverを選択し、platformが対応している場合はstrict encrypted modeを有効にする。Opportunistic fallbackは、気付かないうちにplaintextへ戻る可能性がある。
3. 自分が管理するauthoritative test zone配下のunique subdomainをqueryし、authoritative logが意図したrecursive resolverを確認していることを確認する。
4. 許可を得た上で、test deviceのtrafficのみをcaptureする。Access networkがplaintext DNSを読み取れないことを確認する。ただし、encrypted resolver/tunnel endpointは見える可能性がある。
5. Blocked/unreachableなencrypted resolverをtestする。合格条件は、選択したfail-closedまたはdocumented fallback behaviorであり、偶発的なclear queryではない。
6. ECHについては、controlled ECH-enabled hostを使用し、client/server diagnosticsを検査して**inner** ClientHelloがacceptedされたことを確認する。HTTPS recordを提供しているだけでは、ECHが成功した証拠にならない。
7. Network changes、captive portals、browser updates、VPN reconnectsの後に再実施する。どのcomponentがDNS/ECHを所有するかを記録し、後続のadministratorがbypassを作らないようにする。

## Mixnet

NymやKatzenpostなどのMixnetは、fixed-size packets、delay、reordering、cover trafficを追加してtiming correlationに対抗します。これらの特性にはlatencyとbandwidthのコストがあり、独立したdeployment-scale evidenceは限られています。現在のconsumer mixnetsは、Tor/VPNより高速または保証された代替手段ではなく、**emerging/high-latency options**として扱ってください。<sup>[[17]](#references)</sup>

### 評価workflow

1. 維持管理されたclientと、正確に対応するapplicationを特定する。文書化されていないproxyを通して任意のbrowser/system trafficを無理に送らない。
2. Entry、mix nodes、gateway、destination、collusion assumptionsに関するcurrent threat modelを読む。
3. 公式の署名付きsourceからseparate test compartmentにinstallし、benignな自分のendpointのみを使用する。
4. Delivery latency、message-size limits、reliability、retransmission、gateway unavailable時の動作を測定する。
5. Local trafficと自分が管理するendpointを検査して、意図したpathとsourceを確認する。Repliesが同じprivacy designを使用するか確認する。
6. Shutdown/failureをtestする。Applicationがdirect Internet accessへ黙ってfallbackしてはならない。
7. Speedのためにcover trafficを無効化したり、delaysを減らしたり、通常とは異なるfixed routesを選択したりしない。これらの変更により、明示されたanonymity modelが無効になる可能性がある。
8. 特定のdeployment、independent analysis、operational reliabilityがconsequence levelを満たすまで、experimentalとして扱う。

## Network preflight checklist

- [ ] Authorizationがaccess network、target、dates、source infrastructureを対象としている。
- [ ] Endpointに無関係なidentitiesやactive sync sessionsが存在しない。
- [ ] IPv4、IPv6、DNS、reconnect behaviorがplanと一致している。
- [ ] Destinationが期待されるegressのみを確認している。
- [ ] Captive portalとhotspot behaviorがsensitive trafficなしでtest済みである。
- [ ] Local sharing/discoveryとautomatic network joiningが無効になっている。
- [ ] Observer tableと残存するtraffic-correlation riskを受け入れている。
- [ ] Provider policy、retention、emergency contactが最新である。

Split-knowledge relays、route-enforced workloads、pluggable transports、onion services、I2P、disposable remote browsersについては、[Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)を参照してください。

## References

- [1] [EFF — 自分に適したVPNの選び方](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Torが提供するprivacyとanonymityの保護](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Torの短い紹介](https://spec.torproject.org/intro/)
- [5] [Tor Project — 他のbrowserでTorを使用する](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browserのpluginsとadd-ons](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Torのblockを解除する](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — VPNとTorでTor Browserを使用する](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Public Wi-Fi Networksは安全か](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple devicesでのWi-Fi privacy](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomizationを実装する](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Secure Privileged Access Workstationsの原則](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Privacy Service Operatorsへの推奨事項](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
