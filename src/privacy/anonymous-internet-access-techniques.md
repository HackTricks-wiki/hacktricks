# Anonymous Internet Access Technique Catalog

{{#include ../banners/hacktricks-training.md}}

これは標準的な access-path inventory です。すべての vendor 名ではなく、protocol と運用上の **families** を対象にします。Internet path だけで anonymity が保証されることはありません。account、browser、endpoint、timing、payment、cloud-control-plane、物理的証拠によって、完全に見える route でも特定される可能性があります。

各項目は同じ fields を使用します。「Procedure」は、合法的な deployment または所有する lab での emulation を意味します。実際の technique が router の compromise、access の窃取、または同意していない intermediary の悪用に依存する場合、再現では exercise 用に所有する systems を使用します。

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | 共有 public address | subscriber 間の曖昧性 | high | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | source-address の高速な分離 | high | deployable |
| Multi-hop/split relay, MASQUE | final proxy | 知識の分割または full-IP tunnel | high/moderate | trusted relays で deployable |
| Tor, bridge, onion service | exit または onion identity | 複数当事者による path と共通 browser | moderate | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay または timing 耐性 | low/variable | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request の分割 | high | supported applications only |
| Public Wi-Fi, travel router | venue/tunnel address | location/access-path の変更 | high | permission required |
| Cellular/eSIM, satellite | carrier/provider address | 独立した物理 uplink | high/variable | subscription/provider observes |
| Remote browser/jump host | remote workspace | endpoint と egress の分離 | high | deployable |
| Residential/mobile proxy | consumer/carrier address | consumer-network の外観 | high | consent/provenance critical |
| ORB/compromised relay | 別 victim の address | origin concealment と借用した reputation | high | owned-lab reproduction only |
| CDN/fronting/redirector | CDN/front address | back-end infrastructure の保護 | high | provider/owner approval required |
| Fast flux/DGA/dead drop | rotating node/service | infrastructure discovery resistance | variable | owned-lab reproduction only |
| Drop/nearest-neighbor | local target-adjacent address | geographic/network boundary の通過 | high | owned-site lab only |
| Store-and-forward/offline | gateway または physical receiver | interactive timing linkage の低減 | low | application-specific |
| Pluggable/refraction transport | Tor entry または cooperating diversion proxy | censorship-resistant reachability | variable | supported client or research lab |
| IPFS gateway/PIR/remote fetcher | gateway または application service | publisher/query/request の分割 | variable | bounded application only |
| Anycast/QUIC/MPTCP | stable broker または multiple subflows | rendezvous と session continuity | high | availability, not anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | high | owned workflow only |
| Non-IP local first hop | organization gateway | sensor から Internet stack を除去 | low | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** 複数の users が一つの public address を共有し、access provider が subscriber 側の address と port を public tuple に mapping します。

**Pros:** 高速、特別な client 不要。destination 側の IP だけでは household、venue、carrier pool までしか識別できない場合があります。

**Cons:** provider は subscriber/port/time mapping を保持できます。account と fingerprint は残り、他の users によって address reputation が損なわれる可能性があります。

**Procedure:** (1) authorized access が NAT/CGNAT を使用しているか確認する。(2) owned endpoint で正確な public IP と source port を記録する。(3) application identity を分離する。(4) shared addressing を privacy control とみなさない。(5) ISP に destination を知られたくない場合は、より強い path を使用する。

**Detection:** destination は IP だけでなく source port と正確な時刻を保持すべきです。Provider は NAT allocation log を相関し、investigator は account/device/browser evidence を結合します。

## Commercial VPN

**Mechanics:** encrypted full-tunnel connection が VPN で終端し、destination には VPN の egress が表示されます。VPN は通常、source、timing、destination を関連付けられます。

**Pros:** 高速、簡単、local passive observation から保護、安定または共有された exits、controlled red-team egress に適しています。

**Cons:** trust が集中します。billing/login telemetry、kill-switch/DNS/IPv6 failure があり、shared exits は reputation により block されがちです。

**Procedure:** (1) provider、owner、jurisdiction、retention、assessment policy を確認する。(2) signed official client を install する。(3) full tunnel、always-on、fail-closed を有効にする。(4) DNS と IPv6 の経路を意図的に設定する。(5) owned endpoint で観測される IPv4/IPv6/DNS を確認する。(6) tunnel を停止・再接続し、clear fallback がないことを確認する。<sup>[[1]](#references)</sup>

**Detection:** local network には VPN infrastructure への長時間の encrypted flow が見えます。Provider は authentication/connection records を持ち、destination は ASN/reputation、account、TLS/browser、behavior correlation を使用します。

## Self-hosted VPN or rented VPS egress

**Mechanics:** operator が WireGuard/OpenVPN gateway を管理するか、rented server を介して traffic を forward します。

**Pros:** 予測可能な高速性、allowlist 可能な固定 address、custom logging/firewall、優れた incident control。

**Cons:** anonymity set が小さい。cloud tenant、payment、source login、API、image history が operator と結び付き、特徴的な新規 server は容易に cluster 化されます。

**Procedure:** (1) engagement 専用の organization project を作成する。(2) supported image と固定 address を provision する。(3) management を MFA/key-based administration に制限する。(4) full-tunnel egress と DNS を設定する。(5) 可能な場合は scoped destinations のみを許可する。(6) leak/failure behavior を test する。(7) controller audit records を保持する。(8) teardown 時に credentials と resources を破棄する。

**Detection:** hosting ASN、first-seen address、certificate/service fingerprint、scanning behavior を相関する。Cloud owner は control-plane、console、billing、flow logs を使用します。

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** application が proxy に TCP stream の開設を要求します。SOCKS は version により name resolution と UDP も伝送でき、SSH は一つの encrypted session 内で streams を forward します。

**Pros:** 軽量、application 単位、高速、chaining と segmented network への到達に有用。

**Cons:** application が bypass する可能性、DNS leak、proxy に隣接 endpoint が見えること、browser state の残存。Open proxy は trap または compromised system の場合があります。

**Procedure:** (1) owned host に proxy を deploy する。(2) authentication を要求し、source/destination を制限する。(3) disposable application profile を一つ設定する。(4) 必要時には remote DNS resolution を保証する。(5) owned DNS/HTTP endpoint で検証する。(6) workload の direct egress を block する。(7) proxy credentials を確認し rotate する。

**Detection:** tunnel-capable processes、CONNECT/SOCKS negotiation、長時間 SSH session、application と不整合な destinations を特定します。Proxy log から streams を再構成できます。

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** website が destination を fetch し、自身の origin を通るよう links/forms を rewrite するか、extension が browser request を proxy に送ります。Destination には service が見えますが、TLS termination 後の plaintext を service が閲覧でき、content を inject/retain できます。

**Pros:** system-wide client 不要、単純な browsing では高速、VPN install 不可の環境でも動作。

**Cons:** proxy が credentials/content を読め、downloads を rewrite し、users を fingerprint できます。Scripts/WebSockets/downloads が bypass する可能性、browser extension の広範な権限、小さな anonymity set、頻繁な blocking。

**Procedure:** (1) authorized testing では organization-operated proxy のみ使用する。(2) personal account のない disposable browser に隔離する。(3) password entry と sensitive download を禁止する。(4) owned page 上の各 subresource が proxy 経由で解決されることを確認する。(5) WebSocket、download、form behavior を test する。(6) 使用後に extension/profile を削除する。

**Detection:** destination は proxy を log します。Enterprise proxy/DNS と extension inventory が service を識別し、content-security/reporting または owned canary subresource が direct bypass を明らかにします。Proxy log は user session と targets を対応付けます。

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** entry は source を見ますが、一つ以上の traversal relay がそれを exit から分離し、exit が destination を見ます。

**Pros:** 通常の relay 一つが両端を知る必要がない。1 node の failure/seizure で露出する情報が減り、地理的に柔軟です。

**Cons:** 共有 administration/logs が split を無効化し、latency、timing correlation、failure、DNS route が増加します。同一 account/payment が全 hop を結び付けることもあります。

**Procedure:** (1) 各 hop が除去する observer を定義する。(2) separation が重要な場合、独立管理の owned/approved relays を使う。(3) workload から entry-only access を強制する。(4) 各 relay が next hop のみへ接続できるようにする。(5) 各 layer の logs を確認する。(6) 各 hop を停止し fail-closed を確認する。[Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) で再現します。

**Detection:** 隣接する NetFlow の timing/volume、繰り返される proxy handshake、共通 controller infrastructure を相関します。Exit から operator の geography を推測してはいけません。

## Split-knowledge application relay and OHTTP

**Mechanics:** client は stateless HTTP message を gateway 用に暗号化し、relay 経由で送信します。Relay は client IP を見ますが request は見えず、gateway は request を見ますが通常 relay IP しか見えません。

**Pros:** supported request に対する強力で監査可能な privacy partition、general anonymity network より低 overhead。

**Cons:** arbitrary browsing ではありません。Cookies/authentication が再結合を可能にし、relay/gateway collusion と traffic analysis は残ります。Application 側の実装が必要です。

**Procedure:** (1) RFC 9458 を明示的に support する application を選ぶ。(2) official configuration path で gateway keys を確認する。(3) stable per-user fields を避ける。(4) supported stateless request のみ送る。(5) relay、gateway、target log を比較する。(6) direct fallback なしで key rotation/failure を test する。<sup>[[2]](#references)</sup>

**Detection:** Enterprise endpoint は initiating process と OHTTP relay を露出します。Gateway は malformed/replayed traffic を検出し、timing と stable payload/account fields が request を相関させます。

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** HTTP Extended CONNECT over TLS/QUIC が UDP または IP packet を proxy 経由で運びます。現代的な VPN-like tunnel を実装し、transport を HTTP/3 に紛れ込ませられますが、proxy は observer のままです。<sup>[[3]](#references)</sup>

**Pros:** 効率的な multiplexing/roaming、UDP または full IP の support、modern HTTP infrastructure 経由の deployment。

**Cons:** anonymity network ではありません。Proxy/account は source と destinations を見ます。QUIC/HTTP fingerprint と well-known path は endpoints/providers に見えます。

**Procedure:** (1) RFC 9298/9484 support を document する client/service を使う。(2) proxy certificate/configuration を authenticate する。(3) allowed target routes を定義する。(4) path 内の encrypted DNS を有効にする。(5) owned endpoint に対し UDP、TCP、IPv6、failover を検証する。(6) proxy request と flow logs を確認する。

**Detection:** endpoint には client process と virtual interface が見えます。Network は proxy への継続的 QUIC/TLS を分類でき、proxy log は CONNECT target/path と assigned routes を露出します。

## Tor Browser

**Mechanics:** Tor は guard、middle、exit relay を選択し、layered encryption により各 relay の視野を制限します。Tor Browser は fingerprinting resistance を意図した標準化 browser を追加します。

**Pros:** 大きな public anonymity set、通常の relay 一つが両端を知らない、server を運用せず destination unlinkability を得られる。

**Cons:** 遅い、TCP 中心、exit reputation/block、login と disclosure による identification、low-latency timing correlation。

**Procedure:** (1) project から Tor Browser を download し verify する。(2) defaults を維持し extensions を避ける。(3) 適切な security level を選ぶ。(4) separate identity/session を作る。(5) identifying accounts と external active documents を避ける。(6) HTTPS または authenticated onion service を使う。(7) owned endpoint でのみ exit を確認する。<sup>[[4]](#references)</sup>

**Detection:** bridge/transport がない場合、local network は known guard traffic を識別できます。Destination には exits と Tor Browser behavior が見え、end-to-end observer は timing/volume を相関します。

## Tor bridges and pluggable transports

**Mechanics:** non-public bridge が public guard を置き換えます。obfs4、Snowflake、WebTunnel は first-hop transport を変更し、単純な blocking/probing に耐えます。

**Pros:** censorship を回避し、明白な public-relay destination を隠します。Entry 後は Tor circuit を維持します。

**Cons:** transport pattern/bridge discovery は可能です。性能が変動し、account や global timing への保護は追加されません。

**Procedure:** (1) 最初に direct Tor を試す。(2) Tor Browser Connection settings で built-in supported transport を選ぶか official bridge を request する。(3) random binaries/lists を使わない。(4) 接続して benign test を実行する。(5) reconnect と clock を test する。(6) 他の browser settings は標準のままにする。<sup>[[5]](#references)</sup>

**Detection:** Censor は destination discovery、protocol/flow classification、active probing を使用します。Defender は circumvention use と compromise を区別し、endpoint process/context に依存すべきです。

## VPN before Tor and Tor before VPN

**Mechanics:** VPN-before-Tor は access ISP から direct Tor use を隠しますが、VPN には source が見えます。Tor-before-VPN では VPN に post-Tor traffic と stable customer/tunnel identity が見えることが多くなります。

**Pros:** 正しく設計すれば特定の observer を除去でき、片方の layer を block する network に到達できます。

**Cons:** complexity、uncommon fingerprint、leaks、reduced anonymity set、false confidence。Tor Project は combinations を advanced としています。<sup>[[6]](#references)</sup>

**Procedure:** (1) 除去する observer と新たに導入する observer を記述する。(2) disposable environment を使う。(3) intended outer path のみを確立する。(4) firewall route を強制する。(5) DNS/IPv4/IPv6 と failure order を確認する。(6) 両 provider の visibility を比較する。(7) measurable advantage がなければ stack を廃棄する。

**Detection:** local/VPN/Tor observers は異なる隣接 layer を見ます。Timing は end-to-end に残り、nested tunnel fingerprint と provider account が session を関連付けます。

## Onion service

**Mechanics:** client と service がそれぞれ rendezvous への Tor circuit を構築し、service IP を隠して exit を回避します。

**Pros:** source と service location の保護、end-to-end onion authentication、public inbound port 不要、optional client authorization。

**Cons:** updates/analytics/errors から origin が leak する可能性、onion key の重要性、application identity/timing、host compromise。

**Procedure:** (1) application を隔離し loopback/socket のみに bind する。(2) supported Tor を install する。(3) official instructions で v3 onion service を設定する。(4) stable identity が必要な場合のみ key を protect/backup する。(5) closed use には client authorization を追加する。(6) third-party fetches を削除する。(7) origin に外部から到達できないことを確認する。<sup>[[7]](#references)</sup>

**Detection:** Host/network defender は Tor process/configuration と outbound circuits を発見します。Application error、DNS、certificate、third-party resource が origin を露出させる可能性があります。

## I2P internal services

**Mechanics:** I2P は overlay 内の destinations に対して、独立した一方向 inbound/outbound tunnel を使用します。Public-Internet outproxy は trust point を追加します。

**Pros:** decentralized internal publishing、official exit dependency 不要、inbound/outbound path の分離。

**Cons:** general web replacement ではない、小さな ecosystem、長期的な peer behavior、outproxy による public browsing の監視。

**Procedure:** (1) official source から install する。(2) dedicated context を使う。(3) integration/bandwidth stabilization を許可する。(4) I2P-native owned service に access する。(5) 明示的に必要でない限り outproxy を避ける。(6) shutdown 後に direct fallback がないことを確認する。(7) local peer と service log を確認する。<sup>[[8]](#references)</sup>

**Detection:** Local network には長時間の peer traffic と bootstrap behavior が見えます。Endpoint は router/application process を露出し、outproxy は exits を log します。

## Mixnets

**Mechanics:** fixed-size packet、batching、delay、reordering、cover traffic により timing correlation を低減し、gateway が applications を bridge します。

**Pros:** low-latency proxy より timing analysis に強く、非同期 message/transaction に有用。

**Cons:** latency、bandwidth overhead、小規模な deployment、application limits。Gateway/account metadata は残存します。

**Procedure:** (1) maintained client と supported application を選ぶ。(2) 実際の threat model を読む。(3) separate compartment に install する。(4) owned endpoint に benign data を送る。(5) latency/reliability/reply path を測定する。(6) gateway failure を test する。(7) speed のために delay/cover traffic を無効化しない。<sup>[[9]](#references)</sup>

**Detection:** Endpoint は client を識別します。Access network は gateway/packet cadence を分類でき、gateway と exits は隣接 role を見ます。広範な correlation にはより長い統計期間が必要です。

## GNUnet anonymous file sharing

**Mechanics:** GNUnet は peer 経由で publish/search/download request を route し、anonymity level に応じて cover traffic を追加できます。公式 documentation は、default level 1 では cover traffic が必須でなく、強力な traffic analysis により origin が特定され得ると警告しています。<sup>[[10]](#references)</sup>

**Pros:** decentralized、application-native anonymous sharing、cover-traffic requirement の調整可能性。

**Cons:** 通常の anonymous web access ではない。Performance/storage cost、peer/traffic-analysis limitation。GNUnet VPN documentation は IP overlay が十分な anonymity を提供しないと述べています。

**Procedure:** (1) maintained official build を install する。(2) test peer を隔離する。(3) bandwidth/storage を制限する。(4) 選択した anonymity level で harmless unique test file を publish する。(5) 別の owned peer から retrieve する。(6) cover traffic と latency を記録する。(7) IP VPN component が同等の anonymity を提供すると主張しない。

**Detection:** Peer bootstrap、overlay traffic、local datastore/process、file identifier。広範な observer は cover traffic と traffic volume を分析できます。

## Encrypted DNS, ODoH and ECH

**Mechanics:** DoH/DoT/DoQ は resolver への通信を暗号化します。ODoH は proxy と resolver の間で client address と query を分割し、ECH は inner TLS ClientHello/server name を暗号化します。

**Pros:** 一部の local observer から plaintext DNS/SNI を除去し、ODoH は source/query knowledge を分割します。

**Cons:** IP-anonymity path ではありません。Resolver/proxy/server の role は残り、destination IP/timing/volume と endpoint も残ります。Fallback が leak する可能性があります。

**Procedure:** (1) OS、application、tunnel のどれが DNS を管理するか選ぶ。(2) strict encrypted mode または supported ODoH を有効にする。(3) unique owned domain を test する。(4) local capture で clear query がないことを確認する。(5) resolver を fail させ intended behavior を確認する。(6) ECH では server diagnostics が inner ClientHello acceptance を示すことを確認する。<sup>[[11]](#references)</sup>

**Detection:** Endpoint/resolver log は query を露出します。Network は encrypted-resolver endpoint と destination flow を識別でき、ECH state は path 上で隠れていても endpoint/CDN には見えます。

## Split-provider privacy relay

**Mechanics:** iCloud Private Relay のような products は、client を知る ingress と destination を知る independently operated egress を使用し、coarse region を扱います。

**Pros:** 低摩擦の split knowledge、高速、supported traffic に統合された DNS/web protection。

**Cons:** product/application scope が限定され、account/platform provider は customer を識別します。任意の system anonymity ではなく、collusion/legal/timing risk が残ります。

**Procedure:** (1) supported な applications と traffic type を確認する。(2) 必要に応じ dedicated platform context で feature を有効にする。(3) region behavior を選ぶ。(4) Safari/DNS と unsupported applications を分けて test する。(5) destination address を確認する。(6) network switching/failure を test する。<sup>[[12]](#references)</sup>

**Detection:** Access には ingress、destination には egress が見えます。Platform/relay log と account record は respective layer をまたぎ、unsupported application は通常の path を露出します。

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** Browsing/tool execution は remote system 上で行われます。Destination には remote egress が見え、workspace provider には operator connection と control plane が見えます。

**Pros:** 高速、危険な content を隔離、安定した controlled egress、disposable state、強力な organizational audit。

**Cons:** Provider/admin は session/account を監視可能。Screen/clipboard/file channel が leak し、remote browser fingerprint が unique になる可能性があります。Workspace owner に対して anonymous ではありません。

**Procedure:** (1) engagement ごとに organization-owned workspace を一つ作成する。(2) MFA を要求し administration を制限する。(3) clipboard/upload/download を disable または制限する。(4) approved fixed egress を通す。(5) personal IdP/sync を使わない。(6) reviewed evidence のみ export する。(7) schedule に従い workspace と credentials を破棄する。

**Detection:** Provider と IdP log が user と session を対応付けます。Destination は workspace egress/browser を cluster 化し、enterprise defender は remote-control protocol と anomalous cloud session を特定します。

## Public or guest Wi-Fi

**Mechanics:** Traffic は venue NAT またはそこで開始された tunnel から egress します。

**Pros:** 高速で、共有された non-home address を使用できます。専用 infrastructure 不要。

**Cons:** Venue association/DHCP/portal、camera、purchase、location evidence。Hostile peer/AP、terms、physical risk。

**Procedure:** (1) guest に提供された access を取得し、staff と SSID を確認する。(2) patched low-trust device を使う。(3) sharing/auto-join を disable し private MAC を有効にする。(4) reused identity なしで portal を完了する。(5) fail-closed VPN/Tor path を開始する。(6) tethered traffic を確認する。(7) network を forget する。

**Detection:** Venue は AP、MAC、DHCP、portal、time を相関します。Destination には venue/tunnel が見え、investigator は physical/device evidence を結合します。Access control を bypass してはいけません。

## Travel router

**Mechanics:** Operator-owned router が venue Wi-Fi/Ethernet に接続し、enforced tunnel policy を持つ isolated internal network を提供します。

**Pros:** Workstation を隔離、central kill switch/DNS、統一された client network、privileged endpoint を local broadcast から保護。

**Cons:** Router が stable radio/DHCP fingerprint になり、attack surface を追加します。Captive portal と tethering が tunnel を bypass する可能性があります。

**Procedure:** (1) supported firmware を update する。(2) unique management credentials を設定し WAN admin/WPS/UPnP を disable する。(3) 許可される場合は private upstream MAC を設定する。(4) separate internal SSID を作る。(5) full-tunnel DNS/IPv6 firewall policy を強制する。(6) portal、reconnect、tunnel failure を test する。

**Detection:** Venue は router association と traffic shape を見ます。Local RF/DHCP fingerprinting が識別し、VPN provider には venue source が見えます。

## Cellular, prepaid SIM and eSIM

**Mechanics:** Modem が carrier radio access と通常 carrier NAT を使用します。VPN/Tor layer は destination-visible exit を変更できます。

**Pros:** wired/Wi-Fi network から独立、mobile、高速、authorized drop の backhaul に有用。

**Cons:** Carrier は subscriber/eSIM、IMSI、IMEI、cell、time、assigned port を知ります。Registration law は地域により異なり、personal phone との co-location が devices を結び付けます。

**Procedure:** (1) 必要な正確な情報を提供し lawful に service を取得する。(2) organization-owned の別 modem/device を使用する。(3) exercise controller に記録する。(4) 無関係な radios/accounts を disable する。(5) approved tunnel を確立する。(6) tethered client が実際に従うか test する。(7) travel 前に provider と retention assumption を確認する。<sup>[[13]](#references)</sup>

**Detection:** Carrier records と RF location、enterprise USB/PCI/MDM inventory、rogue-hotspot survey、destination/tunnel timing。

## Satellite Internet and satellite downlink abuse

**Mechanics:** 通常の service は registered terminal/provider を使用します。過去の one-way DVB-S abuse では、receiver が beam 内で legitimate subscriber 宛の unencrypted downlink traffic を観測し、outbound request には別の path を使用しました。

**Pros:** 広い footprint、独立した last mile。Historical one-way abuse は C2 を subscriber geography に誤帰属させる可能性がありました。

**Cons:** Equipment/RF/provider record、latency、coverage。Modern bidirectional system は異なり、outbound path と asymmetric routing は証拠として残ります。

**Procedure:** 合法的な access では owned terminal を登録し、必要に応じ traffic を tunnel します。Historical Turla behavior を emulate する場合は、RF-free lab 内で synthetic one-way packet capture を replay し、request を行っていない host への reply を analyst が検出できるか test します。Live satellite traffic を intercept してはいけません。<sup>[[14]](#references)</sup>

**Detection:** Provider/terminal telemetry、RF direction finding、impossible/asymmetric flow、RTT/routing inconsistency、malware configuration。

## Residential/mobile proxy or consented proxyware

**Mechanics:** Backconnect gateway が consumer broadband/mobile exit を sticky または rotating で割り当てます。Supply は consensual、deceptively bundled、malicious のいずれかです。

**Pros:** 高速、地理的選択、consumer ASN により hosting block を一部回避、大規模 pool。

**Cons:** Provenance/consent と legal risk、broker に customer が見える、infected exit による victim harm、rotation anomaly、高価で不安定。

**Procedure:** Emulation では documented, informed-consent の organization-owned agent のみ使用する。(1) test endpoint を enroll。(2) owner/IP を inventory。(3) gateway を設定。(4) sticky/per-request mode を rotate。(5) owned target のみに送る。(6) gateway/exit/target log を比較。(7) すべての agent を削除する。

**Detection:** Impossible travel、rapid IP/ASN change 中の stable browser/account、backconnect protocol、proxyware process/network artifact、broker/controller relation。

## ORB, botnet and compromised edge-device relays

**Mechanics:** Leased または compromised router/IoT/server が access、traversal、exit role を形成し fleet として管理されます。複数の APT customer が共有する場合があります。

**Pros:** 借用した reputation/geography、短命な exits、resilient multi-hop mesh、actor-to-IP の直接 link が弱い。

**Cons:** Criminal victimization、implant/controller と fleet pattern、intermediary seizure、不安定な performance、operator/customer service records。

**Procedure:** Real device を compromise してはいけません。[Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) を使用します。(1) isolated entry/transit/target network を作る。(2) owned dual-homed relay container を接続する。(3) test port 一つだけを forward する。(4) benign request を送る。(5) target が exit のみを見ることを確認する。(6) exit を rotate する。(7) named asset をすべて teardown する。<sup>[[15]](#references)</sup>

**Detection:** Topology、port/service、controller relation、implant fingerprint、node lifecycle を追跡します。Edge configuration/flow/integrity telemetry を centralize し、exit IP を actor と同一視しません。

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** Public edge は grammar に一致する traffic のみ forward します。Fronting は intermediary が許可する場合、benign outer SNI と異なる inner HTTP authority、または blank SNI を使用します。

**Pros:** Back-end を隠蔽・保護、global edge による高速性、shared service に destination を紛れ込ませ、迅速な cutover。

**Cons:** CDN は全 routing と tenant を把握します。多くの provider は cross-tenant fronting を禁止し、SNI/Host/process/flow/account artifact が残ります。Configuration reuse が campaigns を cluster 化します。

**Procedure:** Owned reverse proxy 上でのみ再現します。[Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) を使用し、local certificate/edge を作り、mismatched Host 一つを owned target に route し、SNI と Host を log します。通常 request と mismatched request を送り、その後 container を削除します。<sup>[[16]](#references)</sup>

**Detection:** Endpoint または terminating edge で SNI/ECH/Host/`:authority` を比較し、initiating process、tenant/origin、request grammar、flow cadence を結合します。

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** DDNS は stable name を更新し、DGA は変化する candidate name を生成します。Fast flux は低 TTL で service address を rotate し、double flux は name server も rotate します。

**Pros:** Resilient discovery、迅速な infrastructure replacement、多数の node による controller の隠蔽。

**Cons:** DNS は centralized telemetry を生成します。Entropy/NXDOMAIN/churn、低 TTL、広範な ASN pattern、registration と authoritative infrastructure が残ります。

**Procedure:** [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry) を使用します。Owned zone が RFC 5737 address を five-second TTL で返すよう設定し、繰り返し query し、synthetic epoch を変更して analytics を検証します。Test record を third party に向けてはいけません。<sup>[[17]](#references)</sup>

**Detection:** Sliding-window unique answer/ASN、median TTL、geography、authoritative churn、DGA NXDOMAIN/lexical/temporal cluster、process follow-on。Legitimate CDN は context とともに除外します。

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** Public post、repository、document、object、feed に encoded current endpoint または task を含めます。Client は別 channel で result を返す場合があります。

**Pros:** High-reputation service、TLS、binary を変更せず endpoint rotation、asymmetric tasking により単純な flow correlation を妨害。

**Cons:** Stable object/account/API identifier、provider record、endpoint decode/follow-on sequence。Content は seize または変更される可能性があります。

**Procedure:** [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence) を使用します。Owned container 一つに encoded pointer を host し、short-lived client から fetch/decode し、第二の owned service に contact します。両方の log を保存して teardown します。

**Detection:** Unusual process → stable object read → decode → new destination の sequence を相関します。Content を hash/preserve し、domain だけでなく full object path を保持します。

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** Function/short-lived job が provider NAT または front の背後で実行され、logical service は安定したまま instances と addresses が rotate します。

**Pros:** Rapid deployment/destruction、provider-scale shared egress、local disk が少ない、elastic regional routing。

**Cons:** Tenant、role、API、image、secret、invocation、billing、front-to-origin log は durable です。Cold-start と platform fingerprint、provider policy も残ります。

**Procedure:** (1) organization-owned exercise tenant を使う。(2) owned endpoint のみに request する benign function を deploy する。(3) project/role/image/config を記録する。(4) 複数 instance から invoke する。(5) target IP と audit/request ID を比較する。(6) log retention を test する。(7) function、role、secret を削除する。

**Detection:** Cloud audit/invocation log、unusual role creation、shared egress と stable request grammar、image/layer と secret reuse、front-origin correlation。

## Authorized on-site drop

**Mechanics:** Inventoried small computer が local wired/Wi-Fi と outbound VPN/cellular rendezvous を使い、local source として表示されます。

**Pros:** Realistic internal-origin testing、高速、NAC、physical inventory、egress control を test 可能。

**Cons:** Physical discovery/theft、serial/MAC/USB/DHCP/PoE/RF と camera evidence、loss による credential exposure。

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) に従います。(1) exact written placement authority を得る。(2) serial、MAC、photo、location、retrieval time を記録する。(3) signed minimal image と short-lived mutual credential を使う。(4) outbound-only destination/capability を制限する。(5) server-side quarantine と bandwidth limit を追加する。(6) SOC visibility と loss response を test する。(7) 回収し、必要な evidence を preserve した後、合意済み lifecycle policy に従い sanitize する。同意していない venue に隠してはいけません。

**Detection:** NAC/802.1X、switchport/PoE/DHCP、USB inventory、RF survey、recurring tunnel、receiving/camera、physical inspection。

## Nearest-neighbor wireless pivot

**Mechanics:** Actor が target の radio range 内の host を管理し、target Wi-Fi credential を使って boundary を remote に越えます。APT28 がこの方法で nearby compromised organization を使用しました。<sup>[[18]](#references)</sup>

**Pros:** Operator の travel 不要、target には local radio source が見える、Internet entry のみを対象とする controls を bypass。

**Cons:** Nearby compromised/owned dual-radio host と valid access が必要。RADIUS/NAC/AP、neighbor endpoint evidence、signal/device anomaly が残ります。

**Procedure:** [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) でのみ再現します。Owned pivot を neighbor と target の lab SSID に join し、一つの service のみ forward し、両 AP/pivot log を収集します。その後 EAP-TLS/device posture を有効にし、二回目が失敗することを確認します。

**Detection:** RADIUS identity、managed certificate/posture、first-seen device、AP edge/signal、concurrent login、physical presence を相関します。Nearby endpoint の simultaneous radio、forwarding、tunnel を hunt します。

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** Traffic は一つの interactive Internet session ではなく、local peer、asynchronous gateway、removable media、scheduled queue を通過します。

**Pros:** Disruption/censorship 中でも動作、遅延・batch delivery により単純な timing が弱まる、local communication に central last mile が不要。

**Cons:** High latency、小さな anonymity set、custody/physical metadata、malicious peer、最終的には gateway が traffic を観測。

**Procedure:** (1) isolated owned three-node mesh または file queue を構築する。(2) content を end to end で encrypt/authenticate する。(3) origin から direct Internet route を削除する。(4) controlled delay 後に benign file を relay する。(5) gateway のみが owned destination に contact することを確認する。(6) custody/timestamp を比較する。(7) 必要な evidence を preserve し、approved closeout で temporary media/queue を sanitize する。

**Detection:** Endpoint file/process activity、peer-radio link、removable-media audit、queue/gateway periodicity、content identifier。Interactive-flow analysis の代わりに長い correlation window を使います。

## TURN relay and forced-relay WebRTC

**Mechanics:** Traversal Using Relays around NAT (TURN) は public relay address を allocate し、client と peer の間で UDP、TCP、TLS traffic を運びます。ICE policy により direct candidate ではなく relay use を強制できます。TURN は reachability を解決しますが general anonymity ではありません。Server は client を authenticate し、allocation、peer、time、volume を観測します。<sup>[[19]](#references)</sup>

**Pros:** 広く実装、restrictive NAT に対応、mobile WebRTC を support。Relay-only policy が正しく enforced されれば、peer は client の direct transport address を受け取りません。

**Cons:** TURN operator は両隣の sides を見ます。Application identity、media fingerprint、signaling は残り、relay-only は bandwidth と latency を消費します。Misconfiguration により host/server-reflexive candidate が収集される可能性があります。

**Procedure:** (1) TLS と short-lived credential を持つ organization-owned TURN service を deploy する。(2) realm、peer、port、quota、expiration を制限する。(3) test application の ICE を relay-only に設定する。(4) owned peer に call する。(5) `getStats()` と packet capture で relay candidate のみが media を運んだことを確認する。(6) relay を fail させ direct fallback がないことを確認する。(7) engagement 用 allocation log を保持する。

**Detection:** Signaling、browser process、TURN allocation が session と relay を結合します。Network は TURN port または TLS endpoint への継続 flow を観測し、peer には allocated relay が見えます。**Captured node:** Application state と ephemeral TURN credential が realm と rendezvous service を明らかにします。Per-device の short-lived credential を使い、operator authentication は controller のみに保持して exposure を減らします。

## Outbound-only rendezvous or reverse overlay

**Mechanics:** NAT 背後の node が organization-controlled broker へ authenticated connection を開始します。Operator は別途 broker に authenticate し、broker が狭い management channel を authorize します。Inbound port forwarding と direct operator-to-node route は不要です。

**Pros:** NAT と captive last mile の背後で安定、central revocation/audit、field-node address の変更で operator discovery 不要、operator identity と node credential を明確に分離。

**Cons:** Broker が高価値の correlation point、periodic keepalive が認識可能、広い tunnel は unsafe pivot になり得る、broker loss で management 終了。

**Procedure:** [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous) に従います。Scoped device identity 一つを発行し、owned broker と approved management service のみを許可し、authenticated keepalive を使い、fail-closed routing を強制します。Address change と reboot recovery を test し、loss drill 中に identity を revoke します。WireGuard は必要な場合に broadly useful NAT interval として 25 秒の persistent keepalive を document しています。<sup>[[20]](#references)</sup>

**Detection:** Broker と identity-provider log が両 sides を対応付けます。Access network には repeated encrypted destination/cadence が見え、endpoint inventory には overlay agent が現れます。**Captured node:** Device key、broker name、tunnel address、cached task data が露出すると想定します。Operator private key、personal account、reusable controller token を置いてはいけません。

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** Field workload が authenticated mailbox を poll し、signed pre-approved job を取得して bounded result を post します。Operator は別の control plane から queue に書き込み、両者の間に interactive socket はありません。

**Pros:** Intermittent link に耐える、timing/addressing を分離、quota/schema で capability を制限、central audit/revocation が容易。

**Cons:** Polling cadence と stable object/queue name が fingerprint になり、provider log が producer/consumer を結合します。Control は遅延し、captured queued data が exercise を露出させます。

**Procedure:** (1) engagement queue 一つと device identity 一つを作成する。(2) benign で明示的に scoped な signed schema を定義する。(3) message TTL、maximum result size、rate を設定する。(4) node は自身の queue のみ pull し、result prefix のみ write できるようにする。(5) offline accumulation、duplicate delivery、revocation を test する。(6) immutable access log を centralize する。(7) retention requirement 後に queue を削除する。

**Detection:** Unusual process による periodic API call、stable bucket/object/queue path、同一 user-agent/TLS behavior、fetch-then-new-connection sequence を hunt します。**Captured node:** Local cache は pending job と object name を露出します。Cache を encrypted、bounded、disposable にし、authoritative controller log は保持します。

## Dual-uplink failover and connection migration

**Mechanics:** Approved field node が venue Ethernet/Wi-Fi と organization cellular など、独立した二つの uplink を持ち、overlay または message broker により route 変更中も control session を維持します。これは availability engineering であり anonymity ではありません。

**Pros:** Provider、AP、captive-portal の一つが fail しても継続、planned maintenance、suspect path の迅速な isolation。

**Cons:** 二 provider が二つの location/account record を作成。同時使用は correlation を容易にし、failover 中に route/DNS leak が起き得ます。Cellular co-location evidence も残ります。

**Procedure:** (1) 両 organization-owned interface/provider を register する。(2) owned endpoint への deterministic route priority と health check を設定する。(3) DNS と management を overlay に bind する。(4) secondary path が inbound traffic を受けないようにする。(5) 各 path を unplug し session recovery、source policy、direct destination access がないことを確認する。(6) unplanned path change を alert する。(7) data use と roaming limit を記録する。

**Detection:** 同じ device certificate、request grammar、timing を ASN 間で相関します。Local inventory は両 radios を見、carrier/venue はそれぞれの記録を保持します。**Captured node:** 両 SIM/device identifier と known SSID が見える可能性があります。Organization asset を使い、personal device と co-locate/pair しません。

## Organization private APN or managed cellular tunnel

**Mechanics:** Carrier private APN が enrolled SIM を private routed domain に置くか、traffic を enterprise gateway に tunnel します。Device を public mobile Internet から分離しますが、carrier または contracting organization からは隠しません。

**Pros:** Stable private addressing、carrier-level enrollment/traffic policy、public inbound exposure の回避、authorized remote appliance に有用。

**Cons:** Subscriber、IMSI/IMEI、cell、billing attribution は強力。Procurement lead time/cost、carrier/gateway outage、operator に対する非匿名性。

**Procedure:** (1) assessment organization 名義で APN を契約する。(2) registered SIM と gateway prefix のみ whitelist する。(3) application-layer mutual authentication を追加する。(4) APN route を rendezvous と update service に限定する。(5) SIM removal、roaming、public-Internet breakout、revocation を test する。(6) carrier/gateway record を monitor する。(7) closeout 時に全 SIM を cancel/quarantine する。

**Detection:** Carrier inventory/cell telemetry、APN gateway flow、SIM/IMEI mismatch、enterprise asset record。**Captured node:** Storage が encrypted でも SIM と modem は contract を識別します。Capture resilience とは deniability ではなく、迅速な suspension と狭い authorization です。

## Long-range point-to-point wireless bridge

**Mechanics:** Directional Wi-Fi または licensed/unlicensed point-to-point radio が owner-approved site 間を接続し、remote site で Internet egress します。Commercial proxy を使わず apparent IP location を移動できます。

**Pros:** 高 throughput、中間 wired carrier から独立、RF/routing を control、segmentation と remote-site monitoring の test に有用。

**Cons:** Line-of-sight、spectrum、landlord、regulatory constraint。特徴的な RF emission/hardware、両 endpoint の physical evidence、weather/power/alignment による不安定性。

**Procedure:** (1) 両 site の written permission と spectrum/power rule を確認する。(2) approved parameter 外で transmit せず path survey する。(3) authenticated encryption と management VLAN を使う。(4) bridge を owned rendezvous/test subnet に限定する。(5) failover、alignment、power recovery、RF containment を test する。(6) 両 radios を label/inventory する。(7) exercise 後に除去し configuration reset を確認する。

**Detection:** RF survey、spectrum analysis、rooftop/site inspection、bridge MAC/OUI、management traffic、remote-site egress log。**Captured node:** Configuration が peer と management domain を露出します。Unique exercise credential を使い、personal management account を置かず、peer key を迅速に revoke します。

## Consented cooperative or community exit

**Mechanics:** Volunteers または partner organization が published policy に従い knowingly relay を運用します。Traffic は shared community pool から exit し、coordination layer が abuse/revocation を管理します。

**Pros:** Diverse non-cloud network、proxyware より明確な consent、shared governance による trust 分散、research/censorship-resilience study に有用。

**Cons:** 小規模 pool と membership record が anonymity を低下させ、exit operator は complaint と traffic metadata を受け取ります。Malicious participant、variable uptime、jurisdiction difference。

**Procedure:** (1) acceptable-use/logging policy を公開する。(2) 各 operator から informed opt-in を得る。(3) unique relay identity を発行し destinations/rates を制限する。(4) abuse handling と one-action revocation を提供する。(5) test 中は authorized traffic のみ owned endpoint に送る。(6) churn と correlation exposure を測定する。(7) consent 終了時に relay を cleanly remove する。

**Detection:** Membership/control-plane record、relay certificate、common software fingerprint、exit behavior が pool を識別します。**Captured node:** Relay configuration は cooperative を識別し得ますが client identity を含めてはいけません。Client-to-session accountability は access control 下の authorized controller に保存します。

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extension は temporary interface identifier を作り、すべての outbound connection で stable address を再利用しないようにします。Provider prefix change が rotation を追加することもありますが、delegated prefix、subscriber record、upper-layer fingerprint は残ります。<sup>[[21]](#references)</sup>

**Pros:** Stable interface identifier による passive long-term tracking を低減、一般的な OS に組み込み、relay overhead 不要。

**Cons:** Source anonymity ではありません。ISP/local network は prefix/device を知り、DNS、account、browser state が session を結び付けます。Address churn は allowlist/logging を複雑にします。

**Procedure:** (1) owned client の stable/temporary address を確認する。(2) third-party spoofing ではなく OS-supported privacy-address default を有効にする。(3) address lifetime 中に owned IPv6 endpoint へ繰り返し request する。(4) inbound service が intended stable address のみに bind されることを確認する。(5) DHCPv6/RA/neighbor と precise endpoint log を保持する。(6) すべての IPv6 address で VPN/firewall behavior を test する。

**Detection:** 一つの address を一つの device と扱わず、delegated prefix、layer-2 identity、neighbor discovery、account、endpoint telemetry を相関します。**Captured node:** Network profile と interface identifier は残ります。Temporary addressing は一つの passive identifier を防ぐだけで forensic attribution は防ぎません。

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** Pluggable transport は first Tor connection の見え方、または bridge への到達方法を変更します。Snowflake は short-lived volunteer WebRTC proxy、WebTunnel は通常の HTTPS に似た外観、obfs4 は単純な protocol identification と active probing に抵抗し、meek は supported web infrastructure を relay します。これは Tor への censorship-circumvention transport であり、追加の end-to-end anonymity layer ではありません。<sup>[[22]](#references)</sup>

**Pros:** Direct Tor または known relay が block された場合に有用。Snowflake は stable public bridge address を避け、maintained Tor client に統合され、destination は通常の Tor property を受け取ります。

**Cons:** Performance が低下または変動。Broker/front/bridge と local network は異なる metadata を見ます。Transport fingerprint と blocking は可能で、volunteer proxy は Tor の代替ではなく application plaintext を信頼すべきではありません。

**Procedure:** (1) official Tor Browser または supported Tor client を install/verify する。(2) Connection/Bridges で built-in transport を選ぶ。(3) owned diagnostic page のみに接続する。(4) page が Snowflake/WebTunnel peer ではなく Tor exit を見ることを確認する。(5) bootstrap と performance を比較する。(6) transport を fail させ、client が silently direct connect しないことを確認する。(7) test 後は standard supported configuration に戻す。

**Detection:** Censor は destination allowlist、TLS/WebRTC behavior、broker discovery、flow analysis を結合できます。Endpoint は Tor と transport configuration を露出します。**Capture-resilient OPSEC:** Standard client を使い、personal browser state を copy せず、bridge/broker history が recoverable だと仮定します。**Monitoring:** Tor bootstrap log、unexpected direct DNS/connection attempt、controller-side owned-page observation を監視します。Transport failure は discovery の証拠ではありません。

## Refraction networking or decoy routing

**Mechanics:** Cooperating network operator が、許可された decoy 宛に見える traffic 内の covert signal を検出し、flow を circumvention proxy に divert します。Deployment には network path 内の infrastructure が必要で、innocent website を選ぶだけで client が作成できるものではありません。<sup>[[23]](#references)</sup>

**Pros:** Apparent destination を block するには collateral damage が必要になる場合、public bridge address の配布不要、on-path-assisted circumvention の research model に有用。

**Cons:** Specialized ISP/transit participation、routing に依存する deployability/performance、client-to-decoy flow と proxy-side activity、global/cooperating observer による timing correlation。

**Procedure:** Uninvolved network を通じて signal してはいけません。Isolated lab で再現します。(1) owned client/router/decoy/proxy namespace を作る。(2) benign tagged test request を使う。(3) owned router がその tag のみを proxy に redirect する。(4) pre/post-routing tuple と request ID を log する。(5) ordinary と signaled flow を比較する。(6) false positive と removal を test する。(7) lab route を destroy する。

**Detection:** Authorized network operator は routing divergence、unusual client hello/tag behavior、decoy-versus-back-end flow discrepancy を調べられます。**Capture-resilient OPSEC:** Research client には test key と documentation address のみを置きます。**Monitoring:** signed lab-router decision と proxy arrival を比較し、production transit provider を probe して signal 検出の有無を調べてはいけません。

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway が IPFS content identifier (CID) を cache または peer から retrieve し、verifiable content を client に返します。Original publisher には final reader ではなく gateway/other peer が見える場合があります。Gateway には reader IP と requested CID が見えます。Native peer-to-peer retrieval では client が peer と DHT/routing participant に露出します。<sup>[[24]](#references)</sup>

**Pros:** Cache により publisher と reader を分離、immutable content を hash-verifiable、replicated data が一つの host の障害に耐え、HTTP client は native peer stack 不要。

**Cons:** Public CID と gateway log が interests を露出。First retrieval timing が publisher/reader を相関し、malicious web content、path-style same-origin hazard、public gateway の best-effort/abuse restriction が存在。

**Procedure:** (1) owned private IPFS swarm または owned gateway に harmless test file を publish する。(2) CID を記録する。(3) subdomain isolation を使い別の owned HTTP gateway 経由で retrieve する。(4) bytes を CID と照合する。(5) cache 後に repeat する。(6) publisher/peer/gateway log を比較する。(7) retention 終了時に unpin し test content を削除する。

**Detection:** Gateway は source/CID を log します。DHT/peer connection が retrieval を露出し、endpoint history と file hash が content を識別します。**Capture-resilient OPSEC:** Read-only field client に private publishing key を保存せず、sensitive content は content addressing 前に encrypt します。**Monitoring:** Unexpected pinning、peer-set change、allowlist 外 CID request、gateway account notice を alert します。

## Private information retrieval service

**Mechanics:** Private Information Retrieval (PIR) は、定義された single- または multi-server threat model 下で selected index を cryptographically hide しながら database から一つの record を取得します。Bounded dataset の query selection を保護しますが、general web access または IP anonymity ではありません。<sup>[[25]](#references)</sup>

**Pros:** Strong application-specific query privacy、measurable leakage model、key directory/blocklist/small public database に有用、exact lookup term の開示を低減。

**Cons:** Computation/bandwidth overhead。Server は relay と組み合わせなければ connection time/IP を知ります。Dataset version、response size、application state が users を分割し、implementation maturity はさまざまです。

**Procedure:** (1) synthetic owned database に audited PIR implementation を deploy する。(2) dataset version と parameters を publish する。(3) identical request size で複数 index を retrieve する。(4) local で correctness を確認する。(5) server log を比較し index がないことを確認する。(6) malicious/truncated response と version mismatch を test する。(7) anonymous browsing と呼ばず、正確な privacy assumption を document する。

**Detection:** Network には service use と volume が見えます。Endpoint telemetry は client と final record use を露出し、compromised server は dataset/timing を操作できます。**Capture-resilient OPSEC:** Client には public database parameter と bounded cache のみ保持します。**Monitoring:** Signed dataset root、fixed request shape、error-rate change、server-key rotation を検証します。

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** Remote service が URL を fetch/render し、screenshot、metadata、sanitized content を返します。Destination には fetcher address が見え、service には requester、URL、result が見えます。Link-preview bot、security scanner、third-party URL fetcher の abuse は authorized proxy use ではありません。

**Pros:** Workstation から active content を隔離、destination に controlled fetcher fingerprint、file type/size/destination/rendering limit の enforcement、disposable execution environment。

**Cons:** Service は request knowledge を完全に持ち、account/API/billing record が残ります。SSRF/data-exfiltration risk、script/authentication/interactive site の制約、unique URL による requester/fetch correlation。

**Procedure:** (1) owned test domain の strict allowlist を持つ organization-owned fetcher を deploy する。(2) private、link-local、metadata、redirect-to-unapproved address を block する。(3) method、redirect、byte、render time を制限する。(4) credentials/cookies を strip する。(5) owned URL を submit する。(6) requester/fetcher/target log を比較する。(7) render instance を destroy し policy に従い central audit を保持する。

**Detection:** Target には service ASN/fingerprint が見え、provider/controller log が requester と URL を対応付けます。Endpoint process/API call が submission を示します。**Capture-resilient OPSEC:** arbitrary destination authority のない short-lived project token 一つを使います。**Monitoring:** Allowlist denial、redirect violation、controller job ID のない fetch、provider abuse notice を alert します。

## Anycast rendezvous pool

**Mechanics:** 複数の organization-controlled node が一つの stable service address を advertise/front し、routing が近い instance を選びます。Anycast は availability を高め client から individual back-end を隠しますが、operator は全 instance を control し service address は stable です。<sup>[[26]](#references)</sup>

**Pros:** Resilient regional ingress、instance failure 時に field reconfiguration 不要、DDoS/load distribution、central policy による session 移動。

**Cons:** BGP/CDN/provider record が organization を識別。Path change が stateful session を壊し、client location で monitoring が変わり、一つの stable address は block/reputation cluster 化されやすい。

**Procedure:** Provider-supported organization project または isolated routing lab を使います。(1) identical authenticated health endpoint を二つ deploy。(2) documented service address 一つを expose。(3) session state は edge ではなく broker に保持。(4) 一つの node を withdraw して reconnection を確認。(5) certificate/policy/log consistency を test。(6) unauthorized origin/region を alert。(7) closeout で advertisement と credential を削除。

**Detection:** BGP/RPKI/history、provider tenancy、certificate、identical service behavior が pool を識別します。**Capture-resilient OPSEC:** Edge には regional service identity のみを置き operator/fleet-enrollment key は置きません。**Monitoring:** Authorized monitor から全 region を probe し route origin と configuration digest を比較します。Unexpected origin は incident と扱います。

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection ID は NAT rebinding/address change 後も client session を維持できます。Multipath TCP は一つの reliable byte stream を複数 subflow で運びます。Wi-Fi/cellular transition の continuity を改善しますが、common peer には old/new path が見え、cross-path correlation が容易になります。<sup>[[27]](#references)</sup>

**Pros:** Uplink change 中の高速 recovery、application session の再起動不要、MPTCP による resilience/throughput、approved field node に有用。

**Cons:** Anonymity ではありません。Peer は migration/subflow を見、connection ID と simultaneous traffic が path を link します。Middlebox/carrier support は一定せず、provider record が増えます。

**Procedure:** (1) owned field client と rendezvous 間で supported transport のみ有効化する。(2) IP とは独立して application を authenticate する。(3) approved Wi-Fi で bounded transfer を開始する。(4) organization cellular に switch する。(5) path validation、data integrity、clear/direct fallback がないことを確認する。(6) idle timeout と return を test する。(7) 全 path transition の broker record を保持する。

**Detection:** Peer は address migration/MPTCP subflow を直接観測し、access provider は respective part を見ます。Connection ID、TLS identity、timing が両者を結合します。**Capture-resilient OPSEC:** Device-scoped session material のみ保存し resumable state の lifetime を短くします。**Monitoring:** Impossible path change、simultaneous unapproved network、migration storm、quarantine 後の resumption を alert します。

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** Organization-owned workflow が hosted runner 上で bounded network check を実行します。Destination には cloud runner address が見え、platform は repository、actor、workflow、token、log、billing attribution を保持します。これは accountable egress を伴う remote execution であり、provider からの anonymity ではありません。<sup>[[28]](#references)</sup>

**Pros:** Disposable clean environment、reproducible job definition、inbound connection 不要、geographically distributed availability check、strong controller audit。

**Cons:** Platform と organization は initiator を識別します。Broad workflow token と untrusted pull request は危険。Shared IP reputation、log/artifact に secret/target data が残る可能性。

**Procedure:** (1) assessment 用 private organization repository/environment を作る。(2) owned endpoint に対する manually approved fixed benign job のみ許可する。(3) minimal read-only workflow permission と production secret 不使用。(4) check を実行する。(5) workflow/provider/target record を比較する。(6) artifact に credential がないことを確認する。(7) environment token を削除し、必要な audit を保持する。

**Detection:** Provider audit と workflow log が直接 attribution を提供します。Target は runner ASN/range と stable request grammar を識別します。**Capture-resilient OPSEC:** Field-device、signing、wallet、cloud-administrator secret を runner variable に置いてはいけません。**Monitoring:** Branch/environment approval を要求し workflow edit、fork execution、secret read、unexpected destination を alert します。

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh、Wi-Fi Aware/Direct、low-power radio、serial/optical link が nearby sensor から owner-approved Internet gateway へ bounded message を運びます。Field device 自体には Internet route がなく、gateway のみが egress します。Radio range/protocol limit により telemetry/store-and-forward design であり interactive anonymous Internet ではありません。

**Pros:** 最小の field device から Internet stack と credential を除去、low power、gateway に policy を集中、temporary dead zone の bridge。

**Cons:** RF/physical discovery、pairing、device identifier、低 bandwidth/range、gateway による全 message の link、spectrum/encryption restriction、capture による queued data exposure。

**Procedure:** (1) site と spectrum approval を得る。(2) unique key で owned sensor 一つと gateway 一つを pair。(3) signed fixed-size message type、TTL、rate を定義。(4) sensor に default IP route を与えない。(5) gateway は owned collector のみに forward。(6) replay、range loss、gateway outage を test。(7) 両 device を inventory/retrieve。

**Detection:** RF survey、pairing database、physical inspection、gateway process/flow log が path を露出します。**Capture-resilient OPSEC:** Sensor には pairwise key と bounded encrypted queue のみを持たせ、operator/Wi-Fi/cellular/controller credential は置きません。**Monitoring:** New peer、sequence rollback、key failure、unusual RF rate、unregistered gateway 経由の message を alert します。

## Capture/compromise exposure matrix

この table は上記すべての family に capture-resilience check を適用します。「Minimize」は authorized asset 上の secret と blast radius を減らす意味であり、evidence を消去したり investigation から隠れたりする意味ではありません。

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known network、DHCP/portal history、MAC、tunnel peer | separate organization device、supported 時 private MAC、personal account 不使用、controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostname、key、route、log、adjacent hop | engagement ごとに identity 一つ、short TTL、narrow route、broker-side revocation、master key 不使用 |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration、application identifier、cached request | payload identifier を最小化、approved config を pin、bounded cache、strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software、bridge/onion material、local state、peer history | standard client、separate service key、encrypted minimal state、compromised service identity の rotation |
| Remote browser/VDI/jump host | workspace token、clipboard/file、remote tenant | gateway に phishing-resistant MFA、transfer channel disable、rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM、IMEI/terminal identity、provider、approximate location | organization contract、personal co-location 不可、narrow APN/overlay policy、provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity、controller/next hop、cached traffic | consented/owned node のみ、signed agent、per-node credential、controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config、API token、deployment、billing reference | dedicated project、least-privilege role、short-lived deploy token、provider audit を central に保持 |
| Dead drop, pull mailbox, store-and-forward | object name、queue、cached job/result、custody data | signed bounded job、TTL、encrypted cache、separate producer identity、immutable server log |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer、device key、physical placement artifact | written placement、unique device identity、operator secret 不使用、tamper/state telemetry、revoke/recover |
| TURN, reverse overlay, dual-uplink | realm/broker、device credential、peer/route、uplink profile | outbound-only narrow service、short-lived device credential、independent operator login、fail-closed path |
| IPv6 temporary addressing | profile、prefix history、endpoint/application state | anti-tracking としてのみ扱い、network log を保持、endpoint compartmentation と併用 |
| Pluggable transport/refraction lab | bridge/broker/decoy setting、Tor state、research key | standard client または isolated lab、personal browser state 不使用、production signaling 不使用 |
| IPFS/PIR/fetcher | requested CID/query、client、cached content、gateway/service token | encrypted bounded cache、public-only parameter、short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service node、connection ID、resumable state、known path | regional identity のみ、short resumption lifetime、central route/session revocation |
| Managed CI/CD runner | repository、workflow、provider token、log、artifact | least-privilege workflow、production/field/wallet secret 不使用、environment approval |
| Non-IP local hop | radio peer、pairwise key、queued message、gateway identity | unique pairwise key、fixed message schema、Wi-Fi/cellular/operator credential 不使用 |

## Monitoring possible discovery for every access family

Client-side test だけでは investigator や defender が監視していることを証明できません。Engagement が所有する system の change を monitor し、controller/client と corroborate して、probe せず停止します。以下の rows は上記すべての technique を対象とします。[field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise) と組み合わせてください。

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session、public tuple、BSSID/cell/path change、provider notice | unapproved network/SIM/device、unexplained relocation、provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication、tunnel state、route/DNS leak、new admin/API event、complaint | duplicate/stolen credential、unknown administrator、direct fallback、out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation、key/config version、unsupported direct connection、error/replay rate | key mismatch、direct fallback、unknown realm/peer、provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state、circuit failure、onion descriptor/service health、owned canary page | personal-account crossover、unexpected non-Tor connection、compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set、queue age/sequence、gateway arrival、radio association、content hash | unknown peer/gateway、sequence rollback、unauthorized content、missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session、workflow/image/config change、new token use、artifact/export、cloud audit | unknown login/workflow edit、secret read、unexpected destination、project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory、DNS/edge/object access、controller graph、job signature、TTL | unknown node/origin/object writer、unsigned/replayed job、topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat、boot/config hash、enclosure state、AP/switch context、duplicate identity | moved/opened node、unexpected boot/hash/path、sentinel use、site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix、connection ID/subflows、path-validation、broker session | impossible migration、simultaneous unapproved path、session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query shape/root version、peer/gateway change、redirect/allowlist denial | unexpected pin/query/destination、unsigned dataset root、provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision、proxy arrival、BGP/RPKI origin、regional config digest | production-path signal、unknown route origin、region/config inconsistency |

## Choosing and testing a path

1. 除去したい observer と隠したい data を明確にする。
2. それを除去できる最も単純な family を選ぶ。
3. Source、entry、traversal、exit、DNS、account、payment observer を図示する。
4. Separate endpoint/application identity を使用する。
5. IPv4、IPv6、DNS、WebRTC/application bypass、destination view を検証する。
6. 各 hop を破壊し、failure が closed であることを確認する。
7. Control する各 component の log を比較する。
8. 残存する timing、provider、endpoint、physical link を記録する。

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
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
{{#include ../banners/hacktricks-training.md}}
