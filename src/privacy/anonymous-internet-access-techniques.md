# Anonymous Internet Access Technique Catalog

这是标准的访问路径清单，涵盖协议和运营**类别**，而非每个 vendor 名称。没有任何 Internet 路径能保证 anonymity：account、browser、endpoint、timing、payment、cloud-control-plane 和物理证据都可能击破看似完美的路径。

每个条目使用相同字段。“Procedure”表示合法部署或自有实验室仿真。如果真实技术依赖于 compromise router、窃取 access 或滥用不知情的 intermediary，复现时会改用 exercise 所有的系统。

## Coverage matrix

| Family | Destination sees | Strongest property | Speed | Treatment |
|---|---|---|---|---|
| Shared NAT/CGNAT | 共享 public address | subscriber 间的歧义性 | high | 可部署 |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | 快速的源地址分离 | high | 可部署 |
| Multi-hop/split relay, MASQUE | final proxy | knowledge split 或完整 IP tunnel | high/moderate | 可用受信任 relay 部署 |
| Tor, bridge, onion service | exit 或 onion identity | 多方路径和统一 browser | moderate | 可部署 |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay 或 timing resistance | low/variable | 依应用而定 |
| OHTTP/ODoH, Private Relay | gateway/egress | source/request partitioning | high | 仅受支持的 applications |
| Public Wi-Fi, travel router | venue/tunnel address | 位置/访问路径变化 | high | 需要 permission |
| Cellular/eSIM, satellite | carrier/provider address | 独立物理 uplink | high/variable | subscription/provider 可观察 |
| Remote browser/jump host | remote workspace | endpoint 与 egress 分离 | high | 可部署 |
| Residential/mobile proxy | consumer/carrier address | consumer-network 外观 | high | consent/provenance 至关重要 |
| ORB/compromised relay | 另一 victim 的 address | origin concealment 和借用 reputation | high | 仅限自有实验室复现 |
| CDN/fronting/redirector | CDN/front address | 保护后端 infrastructure | high | 需要 provider/owner approval |
| Fast flux/DGA/dead drop | 轮换的 node/service | 抗 infrastructure discovery | variable | 仅限自有实验室复现 |
| Drop/nearest-neighbor | 靠近 local target 的 address | 跨越 geographic/network boundary | high | 仅限自有场地实验室 |
| Store-and-forward/offline | gateway 或物理 receiver | 减少 interactive timing linkage | low | 依应用而定 |
| Pluggable/refraction transport | Tor entry 或 cooperating diversion proxy | 抗 censorship 的 reachability | variable | 需要受支持 client 或 research lab |
| IPFS gateway/PIR/remote fetcher | gateway 或 application service | publisher/query/request partitioning | variable | 仅限受限应用 |
| Anycast/QUIC/MPTCP | stable broker 或 multiple subflows | rendezvous 和 session continuity | high | 提高 availability，不提供 anonymity |
| CI/CD automation runner | hosted runner address | 可废弃且可审计的 egress | high | 仅限自有 workflow |
| Non-IP local first hop | organization gateway | 从 sensor 移除 Internet stack | low | 需要 owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics：**多个用户共享一个 public address；access provider 将 subscriber-side addresses 和 ports 映射到 public tuple。

**Pros：**速度快；无需特殊 client；仅凭 destination-side IP 可能只能识别 household、venue 或 carrier pool。

**Cons：**provider 可保留 subscriber/port/time mappings；accounts 和 fingerprints 仍然存在；其他用户可能损害该 address 的 reputation。

**Procedure：**(1) 确认 authorized access 是否使用 NAT/CGNAT；(2) 在自有 endpoint 记录 exact public IP 和 source port；(3) 分离 application identities；(4) 不要把 shared addressing 当作 privacy control；(5) 如果 ISP 不应了解 destinations，使用更强的 path。

**Detection：**destinations 应保存 source port 和精确时间，而不只是 IP。Providers 关联 NAT allocation logs；investigators 将其与 account/device/browser evidence 关联。

## Commercial VPN

**Mechanics：**加密的 full-tunnel connection 在 VPN 处终止；destinations 看到其 egress。VPN 通常可以关联 source、timing 和 destinations。

**Pros：**速度快；简单；防止 local passive observation；提供稳定或共享的 exits；适合受控 red-team egress。

**Cons：**trust 集中；billing/login telemetry；kill-switch/DNS/IPv6 failures；shared exits 经常因 reputation 被阻断。

**Procedure：**(1) 确认 provider、owner、jurisdiction、retention 和 assessment policy；(2) 安装并验证签名的 official client；(3) 启用 full tunnel、always-on 和 fail-closed；(4) 有意配置 DNS 和 IPv6；(5) 在自有 endpoint 验证可见的 IPv4/IPv6/DNS；(6) 停止并重新连接 tunnel，确认没有 clear fallback。<sup>[[1]](#references)</sup>

**Detection：**local networks 可看到到 VPN infrastructure 的长时间加密流；providers 拥有 authentication/connection records；destinations 使用 ASN/reputation，加上 account、TLS/browser 和 behavior correlation。

## Self-hosted VPN or rented VPS egress

**Mechanics：**operator 控制 WireGuard/OpenVPN gateway，或通过 rented server 转发 traffic。

**Pros：**可预测的 high speed；固定且可加入 allowlist 的 address；自定义 logging/firewall；便于 incident control。

**Cons：**anonymity set 小；cloud tenant、payment、source login、API 和 image history 会关联 operator；具有独特特征的新 server 很容易被聚类。

**Procedure：**(1) 创建 engagement-specific organization project；(2) provision supported image 和 fixed address；(3) 仅允许 MFA/key-based administration；(4) 配置 full-tunnel egress 和 DNS；(5) 在可行时仅允许 scoped destinations；(6) 测试 leak/failure behavior；(7) 保留 controller audit records；(8) teardown 时销毁 credentials 和 resources。

**Detection：**关联 hosting ASN、first-seen address、certificate/service fingerprint 和 scanning behavior；cloud owners 使用 control-plane、console、billing 和 flow logs。

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics：**application 请求 proxy 打开 TCP stream；SOCKS 还可根据版本传递 name resolution 和 UDP；SSH 在一个加密 session 内转发 streams。

**Pros：**轻量；按 application 使用；速度快；适合 chaining 和访问 segmented networks。

**Cons：**applications 可能绕过它；DNS 可能 leak；proxy 能看到相邻 endpoints；browser state 仍然存在；open proxies 可能是 traps 或 compromised systems。

**Procedure：**(1) 在自有 host 部署 proxy；(2) 要求 authentication 并限制 source/destination；(3) 配置一个 disposable application profile；(4) 必要时确保 remote DNS resolution；(5) 使用自有 DNS/HTTP endpoint 验证；(6) 阻止 workload 的 direct egress；(7) 检查并轮换 proxy credentials。

**Detection：**识别具 tunnel 能力的 processes、CONNECT/SOCKS negotiation、长时间 SSH sessions，以及与 application 不一致的 destinations；proxy logs 可重建 streams。

## URL-rewriting web proxy and browser proxy extension

**Mechanics：**website 获取 destination 并通过自身 origin 重写 links/forms，或 extension 将 browser requests 指向 proxy。Destination 看到 service；service 在 TLS termination 后可看到 plaintext，并能注入或保留内容。

**Pros：**无需 system-wide client；适合简单 browsing，速度快；VPN 无法安装时仍可使用。

**Cons：**proxy 能读取 credentials/content、重写 downloads 并 fingerprint users；scripts/WebSockets/downloads 可能绕过；browser extension 权限广；anonymity set 小且经常被阻断。

**Procedure：**(1) 仅使用 organization-operated proxy 进行 authorized testing；(2) 在 disposable browser 中隔离，不使用 personal accounts；(3) 禁止输入 passwords 和下载敏感内容；(4) 在自有 page 验证每个 subresource 都经 proxy 解析；(5) 测试 WebSocket、download 和 form behavior；(6) 使用后移除 extension/profile。

**Detection：**destination 记录 proxy；enterprise proxy/DNS 和 extension inventory 可识别 service；content-security/reporting 或自有 canary subresources 可发现 direct bypass；proxy logs 将 user session 映射到 targets。

## Multi-hop proxy or provider multi-hop VPN

**Mechanics：**entry 看到 source；一个或多个 traversal relays 将其与看到 destination 的 exit 分开。

**Pros：**普通 relay 无需同时知道两端；一个 node 发生 failure/seizure 时暴露更少；geography 灵活。

**Cons：**shared administration/logs 会破坏 split；存在 latency、timing correlation、更多 failure 和 DNS routes；同一 account/payment 可连接所有 hops。

**Procedure：**(1) 明确每个 hop 要移除的 observer；(2) separation 重要时使用独立管理的自有/获批 relays；(3) 强制 workload 只能访问 entry；(4) 确保每个 relay 只能访问下一个 hop；(5) 验证每一层 logs；(6) 停止各 hop，确认 fail-closed。使用 [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) 复现。

**Detection：**关联相邻 NetFlow 的 timing/volume、重复 proxy handshakes 和共同 controller infrastructure；不要根据 exit 推断 operator geography。

## Split-knowledge application relay and OHTTP

**Mechanics：**client 将 stateless HTTP message 加密到 gateway，并经 relay 发送。Relay 看到 client IP 但看不到 request；gateway 看到 request，但通常只看到 relay IP。

**Pros：**对受支持 requests 提供强且可审计的 privacy partition；开销低于通用 anonymity networks。

**Cons：**不能进行 arbitrary browsing；cookies/authentication 可能重新关联；relay/gateway collusion 和 traffic analysis 仍存在；application 必须实现该功能。

**Procedure：**(1) 选择明确支持 RFC 9458 的 application；(2) 通过 official configuration path 验证 gateway keys；(3) 避免稳定的 per-user fields；(4) 仅发送受支持的 stateless request；(5) 比较 relay、gateway 和 target logs；(6) 测试 key rotation/failure，确保不会 direct fallback。<sup>[[2]](#references)</sup>

**Detection：**enterprise endpoints 暴露 initiating process 和 OHTTP relay；gateways 检测 malformed/replayed traffic；timing 和 stable payload/account fields 可关联 requests。

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics：**HTTP Extended CONNECT over TLS/QUIC 通过 proxy 携带 UDP 或 IP packets。它可实现现代 VPN-like tunnel，并将 transport 混入 HTTP/3，但 proxy 仍是 observer。<sup>[[3]](#references)</sup>

**Pros：**高效 multiplexing/roaming；支持 UDP 或 full IP；可通过现代 HTTP infrastructure 部署。

**Cons：**不是 anonymity network；proxy/account 可看到 source 和 destinations；QUIC/HTTP fingerprints 及 well-known paths 对 endpoints/providers 可见。

**Procedure：**(1) 使用记录支持 RFC 9298/9484 的 client/service；(2) authentication proxy certificate/configuration；(3) 定义 allowed target routes；(4) 在 path 内启用 encrypted DNS；(5) 使用自有 endpoints 验证 UDP、TCP、IPv6 和 failover；(6) 检查 proxy request 和 flow logs。

**Detection：**endpoints 看到 client process 和 virtual interface；networks 可将持续 QUIC/TLS 归类为 proxy traffic；proxy logs 暴露 CONNECT target/path 和 assigned routes。

## Tor Browser

**Mechanics：**Tor 选择 guard、middle 和 exit relays；layered encryption 限制每个 relay 的可见范围。Tor Browser 提供旨在抵抗 fingerprinting 的标准化 browser。

**Pros：**大型 public anonymity set；普通 relay 无法知道两端；无需运行 servers 即可实现 destination unlinkability。

**Cons：**较慢；以 TCP 为主；exit reputation/blocks；logins 和 disclosures 会识别 user；low-latency timing correlation 仍存在。

**Procedure：**(1) 从 project 下载并验证 Tor Browser；(2) 保持 defaults，避免 extensions；(3) 选择合适 security level；(4) 创建独立 identity/session；(5) 避免 identifying accounts 和 external active documents；(6) 使用 HTTPS 或 authenticated onion services；(7) 仅通过自有 endpoint 验证 exit。<sup>[[4]](#references)</sup>

**Detection：**local networks 可识别 known guard traffic，除非使用 bridge/transport；destinations 看到 exits 和 Tor Browser behavior；end-to-end observers 可关联 timing/volume。

## Tor bridges and pluggable transports

**Mechanics：**non-public bridge 替代 public guard；obfs4、Snowflake 或 WebTunnel 改变 first-hop transport，以抵抗简单 blocking/probing。

**Pros：**绕过 censorship，隐藏明显的 public-relay destinations；进入后仍保留 Tor circuit。

**Cons：**transport patterns/bridge discovery 仍可能发生；performance 不稳定；不能防止 accounts 或 global timing。

**Procedure：**(1) 先尝试 direct Tor；(2) 在 Tor Browser Connection settings 选择内置的 supported transport，或请求 official bridge；(3) 不使用随机 binaries/lists；(4) 连接并运行 benign test；(5) 测试 reconnect 和 clock；(6) 保持其他 browser settings 标准。<sup>[[5]](#references)</sup>

**Detection：**censors 使用 destination discovery、protocol/flow classification 和 active probing；defenders 应区分 circumvention use 与 compromise，并依赖 endpoint process/context。

## VPN before Tor and Tor before VPN

**Mechanics：**VPN-before-Tor 向 access ISP 隐藏 direct Tor use，但 VPN 看到 source。Tor-before-VPN 使 VPN 看到 post-Tor traffic，且通常得到稳定的 customer/tunnel identity。

**Pros：**设计正确时可移除特定 observer；可访问阻断某一层的 networks。

**Cons：**复杂、fingerprint 不常见、leaks、anonymity set 减小以及 false confidence；Tor Project 将组合使用视为 advanced。<sup>[[6]](#references)</sup>

**Procedure：**(1) 写明被移除的 observer 和新增的 observer；(2) 使用 disposable environment；(3) 只建立预期的 outer path；(4) 强制 firewall routes；(5) 验证 DNS/IPv4/IPv6 和每种 failure order；(6) 比较两个 providers 的 visibility；(7) 若无可测优势则放弃该 stack。

**Detection：**local/VPN/Tor observers 看到不同的相邻 layers；timing 仍是 end-to-end；不常见的 nested tunnel fingerprints 和 provider accounts 可关联 sessions。

## Onion service

**Mechanics：**client 和 service 都建立 Tor circuits 到 rendezvous，隐藏 service IP 并避免 exit。

**Pros：**保护 source 和 service location；end-to-end onion authentication；无 public inbound port；可选 client authorization。

**Cons：**updates/analytics/errors 可能 leak origin；onion key 至关重要；application identity/timing 和 host compromise 仍存在。

**Procedure：**(1) 隔离 application，只绑定 loopback/socket；(2) 安装 supported Tor；(3) 按官方 instructions 配置 v3 onion service；(4) 仅在需要稳定 identity 时保护/备份 key；(5) 对 closed use 添加 client authorization；(6) 移除 third-party fetches；(7) 从外部验证 origin 不可达。<sup>[[7]](#references)</sup>

**Detection：**host/network defenders 可发现 Tor process/configuration 和 outbound circuits；application errors、DNS、certificates 或 third-party resources 可能暴露 origin。

## I2P internal services

**Mechanics：**I2P 为 overlay 内的 destinations 使用独立的单向 inbound/outbound tunnels；public-Internet outproxies 增加 trust point。

**Pros：**去中心化 internal publishing；不依赖官方 exit；分离 inbound/outbound paths。

**Cons：**不是通用 web replacement；ecosystem 较小；长期 peer behavior；outproxy 可观察 public browsing。

**Procedure：**(1) 从官方 source 安装；(2) 使用 dedicated context；(3) 允许 integration/bandwidth stabilization；(4) 访问自有 I2P-native service；(5) 除非明确需要，否则避免 outproxies；(6) 验证 shutdown 不会产生 direct fallback；(7) 检查 local peer 和 service logs。<sup>[[8]](#references)</sup>

**Detection：**local networks 看到长期 peer traffic 和 bootstrap behavior；endpoints 暴露 router/application processes；outproxies 记录 exits。

## Mixnets

**Mechanics：**fixed-size packets、batching、delay、reordering 和 cover traffic 降低 timing correlation；gateways 为 applications 提供 bridge。

**Pros：**比 low-latency proxies 更能抵抗 timing analysis；适合 asynchronous messages/transactions。

**Cons：**latency、bandwidth overhead、deployment 较少和 application limits；gateway/account metadata 可能持久存在。

**Procedure：**(1) 选择维护中的 client 和 supported application；(2) 阅读实际 threat model；(3) 在独立 compartment 安装；(4) 向自有 endpoint 发送 benign data；(5) 测量 latency/reliability 和 reply path；(6) 测试 gateway failure；(7) 不要只为提速而禁用 delays/cover traffic。<sup>[[9]](#references)</sup>

**Detection：**endpoints 可识别 client；access networks 可分类 gateways/packet cadence；gateways 和 exits 观察相邻 roles，更广泛的 correlation 需要更长的统计窗口。

## GNUnet anonymous file sharing

**Mechanics：**GNUnet 可通过 peers 路由 publish/search/download requests，并按 anonymity level 添加 cover traffic。其文档警告，默认 level 1 不要求 cover traffic，强大的 traffic analysis 可能识别 origin。<sup>[[10]](#references)</sup>

**Pros：**去中心化、application-native anonymous sharing；cover-traffic requirement 可调。

**Cons：**不是普通 anonymous web access；performance/storage cost；peer 和 traffic-analysis limitations；GNUnet VPN documentation 表示其 IP overlay 不提供良好 anonymity。

**Procedure：**(1) 安装维护中的 official build；(2) 隔离 test peer；(3) 限制 bandwidth/storage；(4) 以指定 anonymity level 发布 harmless unique test file；(5) 从另一个自有 peer 获取；(6) 记录 cover-traffic 和 latency；(7) 不要声称 IP VPN component 提供等效 anonymity。

**Detection：**peer bootstrap、overlay traffic、local datastore/process 和 file identifiers；广泛 observer 可将 traffic volume 与 cover traffic 比较。

## Encrypted DNS, ODoH and ECH

**Mechanics：**DoH/DoT/DoQ 加密到 resolver；ODoH 在 proxy 和 resolver 之间分割 client address 与 query；ECH 加密 inner TLS ClientHello/server name。

**Pros：**从部分 local observers 移除 plaintext DNS/SNI；ODoH 分割 source/query knowledge。

**Cons：**不是 IP-anonymity path；resolver/proxy/server 仍保留各自 roles；destination IP/timing/volume 和 endpoint 仍暴露；fallback 可能 leak。

**Procedure：**(1) 确定由 OS、application 还是 tunnel 负责 DNS；(2) 启用 strict encrypted mode 或 supported ODoH；(3) 测试 unique owned domain；(4) 在本地 capture，确认没有 clear query；(5) 使 resolver failure，验证预期 behavior；(6) 对 ECH，确认 server diagnostics 显示 inner ClientHello acceptance。<sup>[[11]](#references)</sup>

**Detection：**endpoint/resolver logs 暴露 queries；networks 可识别 encrypted-resolver endpoints 和 destination flows；即使 path 上隐藏，ECH state 仍对 endpoints/CDN 可见。

## Split-provider privacy relay

**Mechanics：**iCloud Private Relay 等 products 使用知道 client 的 ingress 和知道 destination 的 independently operated egress，并进行粗略 region handling。

**Pros：**低摩擦的 split knowledge；速度快；为受支持 traffic 集成 DNS/web protection。

**Cons：**product/application scope 有限；account/platform provider 仍可识别 customer；不是任意的 system anonymity；存在 collusion/legal 和 timing risks。

**Procedure：**(1) 确认支持的确切 applications 和 traffic types；(2) 在适当情况下于 dedicated platform context 启用 feature；(3) 选择 region behavior；(4) 分别测试 Safari/DNS 和 unsupported applications；(5) 检查 destination address；(6) 测试 network switching/failure。<sup>[[12]](#references)</sup>

**Detection：**access 看到 ingress；destination 看到 egress；platform/relay logs 与 account records 覆盖各自 layer；unsupported applications 暴露 normal paths。

## Remote browser, VDI, RDP or organization jump host

**Mechanics：**browsing/tool execution 在 remote system 上进行；destination 看到其 egress，workspace provider 看到 operator connection 和 control plane。

**Pros：**速度快；隔离危险内容；稳定、受控的 egress；disposable state 和强 organization audit。

**Cons：**provider/admin 可观察 session/account；screen/clipboard/file channels 会 leak；remote browser fingerprint 可能独特；对 workspace owner 并不 anonymous。

**Procedure：**(1) 每个 engagement 创建一个 organization-owned workspace；(2) 要求 MFA 并限制 administration；(3) 禁用或限制 clipboard/upload/download；(4) 经 approved fixed egress 路由；(5) 不使用 personal IdP/sync；(6) 仅导出已审查 evidence；(7) 按计划销毁 workspace 和 credentials。

**Detection：**provider 和 IdP logs 将 user 映射到 session；destinations 聚类 workspace egress/browser；enterprise defenders 识别 remote-control protocols 和异常 cloud sessions。

## Public or guest Wi-Fi

**Mechanics：**traffic 通过 venue NAT 或在那里启动的 tunnel 退出。

**Pros：**速度快且使用 shared non-home address；无需专用 infrastructure。

**Cons：**venue association/DHCP/portal、camera、purchase 和 location evidence；hostile peers/APs；terms；physical risk。

**Procedure：**(1) 获取向 guests 提供的 access，并与 staff 核实 SSID；(2) 使用 patched low-trust device；(3) 禁用 sharing/auto-join 并启用 private MAC；(4) 不使用 reused identity 完成 portal；(5) 启动 fail-closed VPN/Tor path；(6) 验证 tethered traffic；(7) 忘记该 network。

**Detection：**venue 关联 AP、MAC、DHCP、portal 和时间；destination 看到 venue/tunnel；investigators 结合 physical 与 device evidence。绝不要绕过 access control。

## Travel router

**Mechanics：**operator-owned router 加入 venue Wi-Fi/Ethernet，并提供带 enforced tunnel policy 的 isolated internal network。

**Pros：**隔离 workstations；central kill switch/DNS；一致的 client network；保护 privileged endpoints 不受 local broadcasts 影响。

**Cons：**router 成为稳定的 radio/DHCP fingerprint；增加 attack surface；captive portals 和 tethering 可能绕过 tunnel。

**Procedure：**(1) 更新 supported firmware；(2) 设置 unique management credentials，禁用 WAN admin/WPS/UPnP；(3) 在允许时配置 private upstream MAC；(4) 创建独立 internal SSID；(5) 强制 full-tunnel DNS/IPv6 firewall policy；(6) 测试 portal、reconnect 和 tunnel failure。

**Detection：**venue 看到 router association 和 traffic shape；local RF/DHCP fingerprinting 可识别它；VPN provider 看到 venue source。

## Cellular, prepaid SIM and eSIM

**Mechanics：**modem 使用 carrier radio access，通常经过 carrier NAT；VPN/Tor layer 可改变 destination-visible exit。

**Pros：**独立于 local wired/Wi-Fi network；移动性强；速度快；适合作为 authorized drops 的 backhaul。

**Cons：**carrier 知道 subscriber/eSIM、IMSI、IMEI、cells、time 和 assigned ports；registration laws 各异；与 personal phone 同地会关联 devices。

**Procedure：**(1) 按法律并使用所需真实资料取得 service；(2) 使用 organization-owned 的独立 modem/device；(3) 向 exercise controller 登记；(4) 禁用无关 radios/accounts；(5) 建立 approved tunnel；(6) 测试 tethered clients 是否确实经过 tunnel；(7) 出行前验证 provider 和 retention assumptions。<sup>[[13]](#references)</sup>

**Detection：**carrier records 和 RF location；enterprise USB/PCI/MDM inventory 与 rogue-hotspot surveys；destination/tunnel timing。

## Satellite Internet and satellite downlink abuse

**Mechanics：**正常 service 使用 registered terminal/provider。旧式单向 DVB-S abuse 允许 beam 内 receiver 观察发送给 legitimate subscriber 的 unencrypted downlink traffic，同时通过另一条 path 发送 outbound requests。

**Pros：**覆盖范围广；独立 last mile；历史上的 one-way abuse 可能将 C2 错误归因于 subscriber geography。

**Cons：**equipment/RF/provider records；latency 和 coverage；modern bidirectional systems 不同；outbound path 和 asymmetric routing 仍是 evidence。

**Procedure：**合法 access 应注册自有 terminal，并按需 tunnel traffic。要仿真历史 Turla behavior，在无 RF 的实验室内 replay synthetic one-way packet captures，测试 analysts 是否发现未发出 request 的 host 却收到 reply；不要 intercept live satellite traffic。<sup>[[14]](#references)</sup>

**Detection：**provider/terminal telemetry、RF direction finding、impossible/asymmetric flow、RTT/routing inconsistency 和 malware configuration。

## Residential/mobile proxy or consented proxyware

**Mechanics：**backconnect gateway 分配 consumer broadband/mobile exits，可 sticky 或 rotating。Supply 可能来自 consent、deceptive bundling 或 malicious sources。

**Pros：**速度快；geographic choice；consumer ASN 可避开部分 hosting blocks；pool 大。

**Cons：**provenance/consent 和 legal risk；broker 可看到 customer；infected exits 会伤害 victims；rotation 产生 anomalies；成本高且不可靠。

**Procedure：**仅使用 documented、知情同意且 organization-owned agents 进行 emulation：(1) enroll test endpoints；(2) inventory owners/IPs；(3) 配置 gateway；(4) 轮换 sticky/per-request modes；(5) 仅发送到自有 target；(6) 比较 gateway/exit/target logs；(7) 移除所有 agents。

**Detection：**impossible travel、rapid IP/ASN changes 下仍稳定的 browser/account、backconnect protocols、proxyware process/network artifacts 和 broker/controller relations。

## ORB, botnet and compromised edge-device relays

**Mechanics：**leased 或 compromised routers/IoT/servers 组成 access、traversal 和 exit roles，由 fleet 统一管理。多个 APT customers 可能共享它。

**Pros：**借用 reputation/geography；短时 exits；有韧性的 multi-hop mesh；actor 与 IP 的直接 link 较弱。

**Cons：**criminal victimization；implant/controller 和 fleet patterns；intermediary seizure；performance 不一致；operator/customer service records。

**Procedure：**绝不要 compromise real devices。使用 [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)：(1) 创建隔离的 entry/transit/target networks；(2) 连接自有 dual-homed relay containers；(3) 仅转发一个 test port；(4) 发送 benign request；(5) 验证 target 仅看到 exit；(6) 轮换 exit；(7) teardown 所有 named assets。<sup>[[15]](#references)</sup>

**Detection：**追踪 topology、ports/services、controller relations、implant fingerprints 和 node lifecycle；集中 edge configuration/flow/integrity telemetry；不要将 exit IP 等同于 actor。

## CDN redirector, domain fronting and domainless fronting

**Mechanics：**public edge 仅转发符合 grammar 的 traffic；fronting 在 intermediary 允许时使用 benign outer SNI 和不同的 inner HTTP authority，或 blank SNI。

**Pros：**隐藏/保护 back-end；global edge 速度快；与 shared service 混合 destination；可快速 cutover。

**Cons：**CDN 看到所有 routing 和 tenant；许多 providers 禁止 cross-tenant fronting；SNI/Host/process/flow 和 account artifacts；configuration reuse 会聚类 campaigns。

**Procedure：**仅在自有 reverse proxy 上复现，使用 [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging)：创建 local certificate/edge，将一个 mismatched Host 路由到自有 target，记录 SNI 和 Host，发送 normal/mismatched requests，然后移除 containers。<sup>[[16]](#references)</sup>

**Detection：**在 endpoint 或 terminating edge 比较 SNI/ECH/Host/`:authority`；关联 initiating process、tenant/origin、request grammar 和 flow cadence。

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics：**DDNS 更新稳定 name；DGA 生成变化的 candidate names；fast flux 以低 TTL 轮换 service addresses；double flux 同时轮换 name servers。

**Pros：**抗 discovery；可快速替换 infrastructure；通过许多 nodes 隐藏 controller。

**Cons：**DNS 产生集中 telemetry；entropy/NXDOMAIN/churn；low TTL 和 broad ASN patterns；registration 与 authoritative infrastructure 仍存在。

**Procedure：**使用 [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry)：提供返回 RFC 5737 addresses 且 TTL 为五秒的自有 zone，重复查询，改变 synthetic epoch，并验证 analytics。绝不要让 test records 指向 third parties。<sup>[[17]](#references)</sup>

**Detection：**sliding-window unique answers/ASNs、median TTL、geography、authoritative churn、DGA NXDOMAIN/lexical/temporal clusters 和 process follow-on；结合 context 排除 legitimate CDNs。

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics：**public post、repository、document、object 或 feed 包含 encoded current endpoint 或 task。Client 可能通过另一 channel 返回 results。

**Pros：**使用 high-reputation service；TLS；无需更改 binary 即可轮换 endpoint；asymmetric tasking 使简单 flow correlation 更困难。

**Cons：**稳定的 object/account/API identifiers；provider records；endpoint decode/follow-on sequence；content 可能被 seized 或 changed。

**Procedure：**使用 [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence)：在一个自有 container 上托管 encoded pointer，由 short-lived client fetch/decode，联系第二个自有 service，保存两边 logs，然后 teardown。

**Detection：**关联 unusual process → stable object read → decode → new destination；hash/preserve content，并保存完整 object paths，而不只是 domain。

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics：**functions/short-lived jobs 在 provider NAT 或 front 后运行；logical service 保持稳定，而 instances 和 addresses 轮换。

**Pros：**部署/销毁快；provider-scale shared egress；本地 disk 少；regional routing 弹性强。

**Cons：**tenant、role、API、image、secret、invocation、billing 和 front-to-origin logs 持久存在；cold-start 和 platform fingerprints；provider policy。

**Procedure：**(1) 使用 organization-owned exercise tenant；(2) 部署只请求自有 endpoint 的 benign function；(3) 记录 project/role/image/config；(4) 在多个 instances 上 invoke；(5) 将 target IPs 与 audit/request IDs 比较；(6) 测试 log retention；(7) 移除 function、roles 和 secrets。

**Detection：**cloud audit/invocation logs、异常 role creation、shared egress 加 stable request grammar、image/layer 和 secret reuse，以及 front-origin correlation。

## Authorized on-site drop

**Mechanics：**inventoried small computer 使用 local wired/Wi-Fi 和 outbound VPN/cellular rendezvous，呈现 local source。

**Pros：**真实的 internal-origin testing；速度快；可测试 NAC、physical inventory 和 egress controls。

**Cons：**physical discovery/theft；serial/MAC/USB/DHCP/PoE/RF 和 camera evidence；丢失可能暴露 credentials。

**Procedure：**遵循 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)：(1) 取得精确的书面 placement authority；(2) 记录 serial、MAC、photo、location 和 retrieval time；(3) 使用 signed minimal image 和 short-lived mutual credentials；(4) 限制 outbound-only destinations/capabilities；(5) 添加 server-side quarantine 和 bandwidth limits；(6) 测试 SOC visibility 和 loss response；(7) 按约定 lifecycle policy retrieve、保留必要 evidence，然后 sanitize。绝不要将其隐藏在不知情的 venue。

**Detection：**NAC/802.1X、switchport/PoE/DHCP、USB inventory、RF survey、recurring tunnel、receiving/camera 和 physical inspection。

## Nearest-neighbor wireless pivot

**Mechanics：**actor 控制 target radio range 内的 host，然后使用 target Wi-Fi credentials 远程跨越 boundary。APT28 曾以此方式利用附近 compromised organizations。<sup>[[18]](#references)</sup>

**Pros：**无需 operator travel；target 看到 local radio source；绕过仅应用于 Internet entry 的 controls。

**Cons：**需要 nearby compromised/owned dual-radio host 和有效 access；RADIUS/NAC/AP 及 neighbor endpoint evidence；signal/device anomalies。

**Procedure：**仅使用 [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) 复现：将自有 pivot 加入 neighbor 和 target lab SSIDs，仅转发一个 service，收集两个 AP/pivot logs，然后启用 EAP-TLS/device posture 并确认第二次 attempt 失败。

**Detection：**关联 RADIUS identity、managed certificate/posture、first-seen device、AP edge/signal、concurrent login 和 physical presence；在附近 endpoints 中查找 simultaneous radios、forwarding 和 tunnels。

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics：**traffic 通过 local peers、asynchronous gateways、removable media 或 scheduled queues 传输，而非一个 interactive Internet session。

**Pros：**中断/censorship 期间仍可工作；delayed/batched delivery 减弱简单 timing；local communication 无需 central last mile。

**Cons：**latency 高；anonymity set 小；custody/physical metadata；malicious peers；data 最终到达可观察它的 gateway。

**Procedure：**(1) 构建隔离的自有 three-node mesh 或 file queue；(2) 对 content 进行 end-to-end encryption/authentication；(3) 移除 origin 的 direct Internet routes；(4) 在受控 delay 后 relay benign file；(5) 验证只有 gateway 联系自有 destination；(6) 比较 custody/timestamps；(7) 保留必要 evidence，然后在获批 closeout 清理 temporary media/queues。

**Detection：**endpoint file/process activity、peer-radio links、removable-media audit、queue/gateway periodicity 和 content identifiers。更长的 correlation windows 取代 interactive-flow analysis。

## TURN relay and forced-relay WebRTC

**Mechanics：**Traversal Using Relays around NAT (TURN) 分配 public relay address，在 client 与 peers 之间承载 UDP、TCP 或 TLS traffic。ICE policy 可强制使用 relay，而不暴露 direct candidate。TURN 解决 reachability，不解决 general anonymity：server authentication client，并观察 allocations、peers、time 和 volume。<sup>[[19]](#references)</sup>

**Pros：**广泛实现；处理 restrictive NAT；支持 mobile WebRTC；正确强制 relay-only policy 时，peer 不会收到 client 的 direct transport address。

**Cons：**TURN operator 看到两侧相邻信息；application identity、media fingerprint 和 signaling 仍存在；relay-only 消耗 bandwidth 和 latency；错误配置仍可能收集 host 或 server-reflexive candidates。

**Procedure：**(1) 部署带 TLS 和 short-lived credentials 的 organization-owned TURN service；(2) 限制 realms、peers、ports、quotas 和 expiration；(3) 将 test application 的 ICE 设置为 relay-only；(4) 呼叫自有 peer；(5) 检查 `getStats()` 和 packet capture，确认只有 relay candidates 承载 media；(6) 使 relay failure，确认没有 direct fallback；(7) 保留 engagement 的 allocation logs。

**Detection：**signaling、browser process 和 TURN allocations 将 session 与 relay 关联；networks 可看到到 TURN ports 或 TLS endpoints 的持续 flows；peer 看到 allocated relay。**Captured node：**application state 和 ephemeral TURN credentials 可能暴露 realm 与 rendezvous service。使用 per-device、short-lived credentials 减少暴露，并只在 controller 保存 operator authentication。

## Outbound-only rendezvous or reverse overlay

**Mechanics：**NAT 后 node 主动向 organization-controlled broker 建立 authenticated connection。Operator 另行向 broker authentication，由 broker 授权 narrow management channel；无需 inbound port forwarding 或 direct operator-to-node route。

**Pros：**在 NAT 和 captive last miles 后保持稳定；central revocation/audit；field-node address changes 无需 operator discovery；清晰分离 operator identity 与 node credential。

**Cons：**broker 成为 high-value correlation point；periodic keepalives 可识别；宽泛 tunnel 可能成为不安全 pivot；broker 丢失会终止 management。

**Procedure：**遵循 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous)：签发一个 scoped device identity，仅允许自有 broker 和 approved management service，使用 authenticated keepalive，强制 fail-closed routing，测试 address changes 和 reboot recovery，并在 loss drill 中 revoke identity。WireGuard 文档将 25 秒 persistent keepalive 作为实际需要时广泛适用的 NAT interval。<sup>[[20]](#references)</sup>

**Detection：**broker 和 identity-provider logs 映射两端；access network 看到重复的 encrypted destination/cadence；endpoint inventory 显示 overlay agent。**Captured node：**假定其 device key、broker name、tunnel addresses 和 cached task data 已暴露。不得包含 operator private key、personal account 或 reusable controller token。

## Pull mailbox, message queue or object-store rendezvous

**Mechanics：**field workload 轮询 authenticated mailbox，获取 signed、pre-approved jobs，并提交 bounded results。Operator 通过独立 control plane 写入 queue；双方之间没有 interactive socket。

**Pros：**容忍 intermittent links；解耦 timing 和 addressing；quotas/schemas 可限制 capability；集中 audit 和 revocation 简单。

**Cons：**polling cadence 和稳定 object/queue names 会 fingerprint system；provider logs 关联 producer 与 consumer；control 延迟；captured queued data 可能暴露 exercise。

**Procedure：**(1) 创建一个 engagement queue 和 device identity；(2) 定义 signed schema，仅包含 benign、明确 scoped jobs；(3) 设置 message TTL、maximum result size 和 rate；(4) node 只能 pull 自己的 queue，并只能写自己的 result prefix；(5) 测试 offline accumulation、duplicate delivery 和 revocation；(6) 集中 immutable access logs；(7) 满足 retention requirements 后删除 queue。

**Detection：**查找 unusual process 的 periodic API calls、stable bucket/object/queue paths、相同 user-agent 或 TLS behavior，以及 fetch-then-new-connection sequence。**Captured node：**local cache 可能暴露 pending jobs 和 object names；保持 cache encrypted、bounded、disposable，同时保留 authoritative controller logs。

## Dual-uplink failover and connection migration

**Mechanics：**approved field node 有两个 independent uplinks，例如 venue Ethernet/Wi-Fi 和 organization cellular，并通过 overlay 或 message broker 在 routes 改变时维持 control session。这是 availability engineering，不是 anonymity。

**Pros：**承受 provider、AP 或 captive-portal failure；支持 planned maintenance；可快速隔离可疑 path。

**Cons：**两个 providers 产生两套 location/account records；同时使用使 correlation 更容易；failover 时存在 route 和 DNS leaks；cellular co-location evidence 仍存在。

**Procedure：**(1) 注册两个 organization-owned interfaces 和 providers；(2) 为 owned endpoints 设置 deterministic route priorities 和 health checks；(3) 将 DNS 和 management 绑定到 overlay；(4) 防止 secondary path 接收入站 traffic；(5) 拔掉每条 path，验证 session recovery、source policy 和无 direct destination access；(6) 对非计划 path change 报警；(7) 记录 data use 和 roaming limits。

**Detection：**跨 ASNs 关联同一 device certificate、request grammar 和 timing；local inventory 看到两个 radios；carriers/venues 保留各自 records。**Captured node：**两个 SIM/device identifiers 和已知 SSIDs 可能可见；使用 organization assets，绝不要与 personal devices 同地或配对。

## Organization private APN or managed cellular tunnel

**Mechanics：**carrier private APN 将 enrolled SIMs 放入 private routed domain，或将 traffic tunnel 到 enterprise gateway。它把 device 与 public mobile Internet 分离，但不会对 carrier 或 contracting organization 隐藏。

**Pros：**stable private addressing；carrier-level enrollment 和 traffic policy；避免 public inbound exposure；适合 authorized remote appliances。

**Cons：**subscriber、IMSI/IMEI、cell 和 billing attribution 很强；采购周期和成本；carrier/gateway outage；对 operator 不 anonymous。

**Procedure：**(1) 以 assessment organization 名义签约 APN；(2) 仅 whitelist registered SIMs 和 gateway prefixes；(3) 添加 application-layer mutual authentication；(4) 将 APN route 限制到 rendezvous 和 update services；(5) 测试 SIM removal、roaming、public-Internet breakout 和 revocation；(6) 监控 carrier 和 gateway records；(7) closeout 时 cancel 或 quarantine 每张 SIM。

**Detection：**carrier inventory 和 cell telemetry、APN gateway flows、SIM/IMEI mismatch 和 enterprise asset records。**Captured node：**即使 storage encrypted，SIM 和 modem 仍识别 contract；capture resilience 意味着快速 suspension 和 narrow authorization，而非 deniability。

## Long-range point-to-point wireless bridge

**Mechanics：**directional Wi-Fi 或其他 licensed/unlicensed point-to-point radio 连接两个 owner-approved sites，并从 remote site 进行 Internet egress。它无需 commercial proxy 即可移动 apparent IP location。

**Pros：**throughput 高；独立于 intermediate wired carriers；RF 和 routing 可控；适合测试 segmentation 和 remote-site monitoring。

**Cons：**line-of-sight、spectrum、landlord 和 regulatory constraints；独特 RF emissions 和 hardware；两端都是 physical evidence；weather/power/alignment 影响稳定性。

**Procedure：**(1) 取得两地书面 permission 并确认 spectrum/power rules；(2) 不在 approved parameters 外 transmit 即完成 path survey；(3) 使用 authenticated encryption 和 management VLAN；(4) 将 bridge 限制到自有 rendezvous 或 test subnet；(5) 测试 failover、alignment、power recovery 和 RF containment；(6) 标记/inventory 两个 radios；(7) exercise 后移除并验证 configuration reset。

**Detection：**RF surveys、spectrum analysis、rooftop/site inspection、bridge MAC/OUI、management traffic 和 remote-site egress logs。**Captured node：**configuration 暴露 peer 和 management domain；使用 unique exercise credentials、无 personal management accounts，并快速 revoke peer-key。

## Consented cooperative or community exit

**Mechanics：**volunteers 或 partner organizations 按 published policy 知情运行 relays。Traffic 从 shared community pool 退出，coordination layer 负责 abuse 和 revocation。

**Pros：**多样化的 non-cloud networks；explicit consent 比 proxyware 更安全；shared governance 可分散 trust；适合 research 和 censorship-resilience studies。

**Cons：**pool 小且 membership records 会降低 anonymity；exit operators 收到 complaints 并观察 traffic metadata；存在 malicious participants、uptime 不稳定和 jurisdiction 差异。

**Procedure：**(1) 发布 acceptable-use 和 logging policy；(2) 从每个 operator 获取 informed opt-in；(3) 签发 unique relay identity，限制 destinations/rates；(4) 提供 abuse handling 和 one-action revocation；(5) 测试时仅向自有 endpoints 发送 authorized traffic；(6) 测量 churn 和 correlation exposure；(7) consent 结束时 cleanly 移除 relay。

**Detection：**membership/control-plane records、relay certificates、common software fingerprint 和 exit behavior 可识别 pool。**Captured node：**relay configuration 可能识别 cooperative，但不应包含 client identities；client-to-session accountability 应由 authorized controller 在 access control 下保存。

## IPv6 temporary addresses and prefix rotation

**Mechanics：**IPv6 privacy extensions 创建 temporary interface identifiers，避免每个 outbound connection 重用 stable address。Provider prefix changes 可增加 rotation，但 delegated prefix、subscriber record 和 upper-layer fingerprint 仍存在。<sup>[[21]](#references)</sup>

**Pros：**减少基于 stable interface identifier 的长期被动 tracking；常见 operating systems 内置；无 relay overhead。

**Cons：**不是 source anonymity；ISP 和 local network 仍知道 prefix/device；DNS、accounts 和 browser state 可关联 sessions；address churn 使 allowlists 和 logging 更复杂。

**Procedure：**(1) 在自有 client 检查当前 stable 和 temporary addresses；(2) 启用 OS-supported privacy-address default，不使用 third-party spoofing；(3) 在 address lifetimes 间反复请求自有 IPv6 endpoint；(4) 确认 inbound services 仅绑定预期 stable addresses；(5) 保留 DHCPv6/RA/neighbor 和精确 endpoint logs；(6) 测试 VPN/firewall 对每个 IPv6 address 的 behavior。

**Detection：**关联 delegated prefix、layer-2 identity、neighbor discovery、account 和 endpoint telemetry，不要把一个 address 当作一个 device。**Captured node：**network profiles 和 interface identifiers 仍存在；temporary addressing 防止一个 passive identifier，但不能防止 forensic attribution。

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics：**pluggable transport 改变 first Tor connection 的外观或到达 bridge 的方式。Snowflake 使用短期 volunteer WebRTC proxies；WebTunnel 类似普通 HTTPS；obfs4 抵抗简单 protocol identification 和 active probing；meek 通过 supported web infrastructure relay。它们是进入 Tor 的 censorship-circumvention transports，不是额外的 end-to-end anonymity layers。<sup>[[22]](#references)</sup>

**Pros：**direct Tor 或 known relays 被阻断时仍有用；Snowflake 避免稳定 public bridge address；集成在维护中的 Tor clients；destination 仍获得普通 Tor properties。

**Cons：**performance 较低或不稳定；broker/front/bridge 和 local network 看到不同 metadata；transport fingerprints 和 blocking 仍可能发生；volunteer proxy 不替代 Tor，也不应被信任以处理 application plaintext。

**Procedure：**(1) 安装并验证 official Tor Browser 或 supported Tor client；(2) 在 Connection/Bridges 选择内置 transport；(3) 仅连接自有 diagnostic page；(4) 确认 page 看到 Tor exit，而非 Snowflake/WebTunnel peer；(5) 比较 bootstrap 和 performance；(6) 使 transport failure，确认 client 不会静默 direct connect；(7) 测试后恢复标准 supported configuration。

**Detection：**censor 可结合 destination allowlists、TLS/WebRTC behavior、broker discovery 和 flow analysis；endpoints 暴露 Tor 和 transport configuration。**Capture-resilient OPSEC：**使用 standard client，绝不要复制 personal browser state，并假设 bridge/broker history 可恢复。**Monitoring：**监视 Tor bootstrap logs、意外 direct DNS/connection attempts 和 controller-side owned-page observations；transport failure 不等于 discovery。

## Refraction networking or decoy routing

**Mechanics：**cooperating network operator 在看似发往 allowed decoy 的 traffic 中检测 covert signal，并将 flow 转发到 circumvention proxy。部署需要 network path 中存在 infrastructure；client 不能仅通过选择 innocent website 创建它。<sup>[[23]](#references)</sup>

**Pros：**censor 可能难以阻断 apparent destination 而不造成 collateral damage；无需分发 public bridge address；适合作为 on-path-assisted circumvention research model。

**Cons：**需要 specialized ISP/transit participation；deployability 和 performance 依赖 routing；client-to-decoy flow 和 proxy-side activity 仍存在；global 或 cooperating observer 可关联 timing。

**Procedure：**不要通过 uninvolved networks 发 signal。在 isolated lab 复现：(1) 创建 owned client、router、decoy 和 proxy namespaces；(2) 使用 benign tagged test request；(3) 让 owned router 只将该 tag redirect 到 proxy；(4) 记录 pre/post-routing tuples 和 request IDs；(5) 比较 ordinary 与 signaled flows；(6) 测试 false positives 和 removal；(7) 销毁 lab routes。

**Detection：**authorized network operators 可检查 routing divergence、异常 client hello/tag behavior 和 decoy-versus-back-end flow discrepancies。**Capture-resilient OPSEC：**research client 只应持有 test keys 和 documentation addresses。**Monitoring：**比较 signed lab-router decisions 与 proxy arrivals；不要探测 production transit providers 来判断是否发现 signaling。

## Content-addressed gateway or cached peer retrieval

**Mechanics：**HTTP gateway 获取 IPFS content identifier (CID)，可能来自 cache 或 peers，并向 client 返回可验证 content。Original publisher 可能看到 gateway 或其他 peers，而不是 final reader；gateway 看到 reader IP 和 requested CID。Native peer-to-peer retrieval 会将 client 暴露给 peers 和 DHT/routing participants。<sup>[[24]](#references)</sup>

**Pros：**caches 可分离 publisher 和 reader；immutable content 可通过 hash 验证；replicated data 可在一个 host 失效后继续；HTTP clients 无需 native peer stack。

**Cons：**public CIDs 和 gateway logs 暴露 interests；first retrieval timing 可能关联 publisher 和 reader；malicious web content 和 path-style same-origin hazards；public gateways 仅 best-effort 且禁止 abuse。

**Procedure：**(1) 将 harmless test file 发布到自有 private IPFS swarm 或 gateway；(2) 记录 CID；(3) 通过独立的自有 HTTP gateway 并使用 subdomain isolation 获取；(4) 依据 CID 验证 bytes；(5) caching 后重复获取；(6) 比较 publisher、peer 和 gateway logs；(7) retention 结束时 unpin 并移除 test content。

**Detection：**gateways 记录 source/CID；DHT 和 peer connections 暴露 retrieval；endpoint history 和 file hashes 识别 content。**Capture-resilient OPSEC：**read-only field client 不保存 private publishing key；对敏感 content 在 content addressing 前 encryption。**Monitoring：**对 unexpected pinning、peer-set change、allowlist 外 CID requests 或 gateway account notices 报警。

## Private information retrieval service

**Mechanics：**Private Information Retrieval (PIR) 允许 client 从 database 获取一条 record，同时在指定的 single- 或 multi-server threat model 下，以 cryptographic 方式隐藏选择的 index。它保护 bounded dataset 中的 query selection，不是 general web access 或 IP anonymity。<sup>[[25]](#references)</sup>

**Pros：**application-specific query privacy 强；leakage model 可测量；适合 key directories、blocklists 或 small public databases；可减少暴露 exact lookup terms 的需要。

**Cons：**computation/bandwidth overhead；除非结合 relay，否则 server 知道 connection time/IP；dataset version、response size 和 application state 可划分 users；implementation maturity 不同。

**Procedure：**(1) 针对 synthetic owned database 部署 audited PIR implementation；(2) 发布 dataset version 和 parameters；(3) 以相同 request sizes 获取多个 indices；(4) 本地验证 correctness；(5) 比较 server logs，确认 index 未出现；(6) 测试 malicious/truncated responses 和 version mismatch；(7) 记录 exact privacy assumption，不要称其为 anonymous browsing。

**Detection：**networks 看到 service use 和 volume；endpoint telemetry 暴露 client 和 final record use；compromised server 可操纵 datasets 或 timing。**Capture-resilient OPSEC：**client 仅保存 public database parameters 和 bounded cache。**Monitoring：**验证 signed dataset roots、fixed request shapes、error-rate changes 和 server-key rotations。

## Constrained server-side fetcher, preview or rendering service

**Mechanics：**remote service 获取或渲染 URL，并返回 screenshot、metadata 或 sanitized content。Destination 看到 fetcher address；service 看到 requester、URL 和 result。滥用 link-preview bots、security scanners 或 third-party URL fetchers 不属于 authorized proxy use。

**Pros：**隔离 workstation 的 active content；destination 收到受控 fetcher fingerprint；可限制 file type、size、destination 和 rendering；execution environment 可 disposable。

**Cons：**service 完全知道 request；account/API/billing records；SSRF 和 data-exfiltration risk；scripts、authentication 和 interactive sites 可能无法工作；unique URLs 可关联 requester 与 fetch。

**Procedure：**(1) 部署 organization-owned fetcher，仅 allowlist 自有 test domains；(2) 阻止 private、link-local、metadata 以及 redirect-to-unapproved addresses；(3) 限制 methods、redirects、bytes 和 render time；(4) 删除 credentials/cookies；(5) 提交自有 URL；(6) 比较 requester、fetcher 和 target logs；(7) 销毁 render instance，并按 policy 保留 central audit。

**Detection：**target 看到 service ASN/fingerprint；provider/controller logs 将 requester 映射到 URL；endpoint process/API calls 显示 submission。**Capture-resilient OPSEC：**使用一个 short-lived project token，不授予 arbitrary destination authority。**Monitoring：**对 allowlist denials、redirect violations、无 controller job ID 的 fetches 和 provider abuse notices 报警。

## Anycast rendezvous pool

**Mechanics：**多个 organization-controlled nodes 宣告或 front 一个 stable service address，routing 选择 nearby instance。Anycast 提高 availability 并隐藏 individual back-end，但 operator 仍控制所有 instances，service address 仍稳定。<sup>[[26]](#references)</sup>

**Pros：**resilient regional ingress；一个 instance failure 时无需 field reconfiguration；DDoS/load distribution；central policy 可在已知 nodes 间移动 sessions。

**Cons：**BGP/CDN 和 provider records 识别 organization；path changes 可能破坏 stateful sessions；monitoring 因 client location 而不同；单一 stable address 易被阻断或按 reputation 聚类。

**Procedure：**使用 provider-supported organization project 或 isolated routing lab：(1) 部署两个相同的 authenticated health endpoints；(2) 暴露一个 documented service address；(3) 在 broker 保持 session state，而不是 edge；(4) withdraw 一个 node，验证 reconnection；(5) 测试 certificate、policy 和 log consistency；(6) 对 unauthorized origin/region 报警；(7) closeout 时移除 advertisements 和 credentials。

**Detection：**BGP/RPKI/history、provider tenancy、certificates 和 identical service behavior 可识别 pool。**Capture-resilient OPSEC：**edge 仅保存 regional service identity，不保存 operator 或 fleet-enrollment key。**Monitoring：**从 authorized monitors 探测每个 region，比较 route origin 和 configuration digest，并将 unexpected origin 视为 incident。

## QUIC migration and Multipath TCP continuity

**Mechanics：**QUIC connection IDs 可在 NAT rebinding 或 address changes 后保持 client session；Multipath TCP 可通过多个 subflows 承载一个 reliable byte stream。两者提高 Wi-Fi/cellular transition 的 continuity，但 common peer 看到 old/new paths，且 cross-path correlation 可能更容易。<sup>[[27]](#references)</sup>

**Pros：**uplink changes 时 recovery 更快；application session 不必重启；MPTCP 可结合 resilience 和 throughput；适合 approved field nodes。

**Cons：**不是 anonymity；peer 看到 migration/subflows；connection identifiers 和 simultaneous traffic 关联 paths；middlebox/carrier support 不同；更多 provider records 增加 exposure。

**Procedure：**(1) 仅在自有 field client 与 rendezvous 之间启用 supported transport；(2) 独立于 IP 对 application authentication；(3) 在 approved Wi-Fi 上开始 bounded transfer；(4) 切换到 organization cellular；(5) 确认 path validation、data integrity 和无 clear/direct fallback；(6) 测试 idle timeout 和 return；(7) 保留 broker 的每次 path transition records。

**Detection：**peer 直接观察 address migration 或 MPTCP subflows；access providers 看到各自部分；connection IDs、TLS identity 和 timing 将两者关联。**Capture-resilient OPSEC：**只保存 device-scoped session material，并快速使 resumable state 过期。**Monitoring：**对 impossible path changes、simultaneous unapproved networks、migration storms 和 quarantine 后 resumption 报警。

## Managed CI/CD or ephemeral automation runner egress

**Mechanics：**organization-owned workflow 在 hosted runner 上执行 bounded network check。Destination 看到 cloud runner address，而 platform 保留 repository、actor、workflow、token、log 和 billing attribution。这是带 accountable egress 的 remote execution，不是对 provider 的 anonymity。<sup>[[28]](#references)</sup>

**Pros：**disposable clean environment；reproducible job definition；无 inbound connection；适合 geographically distributed availability checks；controller audit 强。

**Cons：**platform 和 organization 可识别 initiator；broad workflow tokens 和 untrusted pull requests 危险；shared IP reputation；logs/artifacts 可能保留 secrets 或 target data。

**Procedure：**(1) 创建 private organization repository 和 assessment environment；(2) 仅允许针对自有 endpoints 的 manually approved、fixed benign jobs；(3) 使用 minimal read-only workflow permissions，不使用 production secrets；(4) 运行 check；(5) 比较 workflow、provider 和 target records；(6) 验证 artifacts 不含 credentials；(7) 删除 environment token，并保留必要 audit。

**Detection：**provider audit 和 workflow logs 可直接归因；targets 识别 runner ASNs/ranges 和 stable request grammar。**Capture-resilient OPSEC：**绝不要将 field-device、signing、wallet 或 cloud-administrator secrets 放入 runner variables。**Monitoring：**要求 branch/environment approval，并对 workflow edits、fork execution、secret reads 和 unexpected destinations 报警。

## Non-IP local first hop to an owned gateway

**Mechanics：**Bluetooth mesh、Wi-Fi Aware/Direct、low-power radio 或 serial/optical link 将 bounded messages 从 nearby sensor 传到 owner-approved Internet gateway。Field device 自身没有 Internet route；gateway 是唯一 egress。Radio range 和 protocol limits 使其成为 telemetry/store-and-forward design，而不是 interactive anonymous Internet。

**Pros：**从最小 field device 移除 Internet stack 和 credentials；低功耗；gateway 集中 policy；可跨越临时 dead zones。

**Cons：**RF/physical discovery、pairing 和 device identifiers；bandwidth/range 小；gateway 仍关联所有 messages；spectrum 和 encryption restrictions 不同；capture 可能暴露 queued data。

**Procedure：**(1) 取得 site 和 spectrum approval；(2) 使用 unique keys 将一个自有 sensor 与一个自有 gateway 配对；(3) 定义 signed fixed-size message types、TTL 和 rate；(4) sensor 不提供 default IP route；(5) gateway 仅向自有 collector 转发；(6) 测试 replay、range loss 和 gateway outage；(7) inventory 并 retrieve 两个 devices。

**Detection：**RF survey、pairing database、physical inspection 和 gateway process/flow logs 暴露 path。**Capture-resilient OPSEC：**sensor 只保存 pairwise key 和 bounded encrypted queue，绝不保存 operator、Wi-Fi、cellular 或 controller credentials。**Monitoring：**对 new peers、sequence rollback、key failure、异常 RF rate 和通过 unregistered gateway 到达的 messages 报警。

## Capture/compromise exposure matrix

此表对上述每个 family 应用 capture-resilience 检查。“Minimize”表示降低 authorized assets 上的 secrets 和 blast radius；绝不表示清除 evidence 或躲避 investigation。

| Technique family | A captured endpoint/relay can reveal | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | known networks、DHCP/portal history、MACs、tunnel peer | 独立 organization device；支持时使用 private MAC；无 personal accounts；controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames、keys、routes、logs 和 adjacent hop | 每个 engagement 一个 identity；short TTL；narrow routes；broker-side revocation；无 master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration、application identifiers 和 cached requests | 最小化 payload identifiers；pin approved config；bounded cache；strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software、bridge/onion material、local state 和 peer history | standard client；分离 service keys；encrypted minimal state；rotate compromised service identity |
| Remote browser/VDI/jump host | workspace token、clipboard/files 和 remote tenant | gateway 使用 phishing-resistant MFA；禁用 transfer channels；快速 session revocation |
| Cellular, satellite, private APN | SIM/eSIM、IMEI/terminal identity、provider 和 approximate location | organization contract；无 personal co-location；narrow APN/overlay policy；provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity、controller/next hop、cached traffic | 仅使用 consented/owned nodes；signed agent；per-node credential；controller 保存 participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config、API tokens、deployment 和 billing references | dedicated project；least-privilege role；short-lived deploy token；集中保留 provider audit |
| Dead drop, pull mailbox, store-and-forward | object names、queue、cached jobs/results 和 custody data | signed bounded jobs；TTL；encrypted cache；separate producer identity；immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer、device key、physical placement artifacts | written placement；unique device identity；无 operator secret；tamper/state telemetry；revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker、device credential、peer/route 和 uplink profiles | outbound-only narrow service；short-lived device credential；independent operator login；fail-closed paths |
| IPv6 temporary addressing | profiles、prefix history 和 endpoint/application state | 仅视为 anti-tracking；保留 network logs；结合 endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings、Tor state 和 research keys | standard client 或 isolated lab；无 personal browser state；无 production signaling |
| IPFS/PIR/fetcher | requested CID/query client、cached content、gateway 或 service token | encrypted bounded cache；public-only parameters；short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes、connection IDs、resumable state 和所有 known paths | regional identity only；short resumption lifetime；central route/session revocation |
| Managed CI/CD runner | repository、workflow、provider token、logs 和 artifacts | least-privilege workflow；无 production/field/wallet secrets；environment approval |
| Non-IP local hop | radio peer、pairwise key、queued messages 和 gateway identity | unique pairwise key；fixed message schema；无 Wi-Fi/cellular/operator credential |

## Monitoring possible discovery for every access family

没有 client-side test 能证明 investigator 或 defender 正在观察。监控 engagement 所有的 systems 中的变化，用 controller/client 进行 corroborate，并停止而不是 probe observers。以下 rows 覆盖上述所有 techniques；结合 [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise)。

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session、public tuple、BSSID/cell/path change、provider notice | unapproved network/SIM/device、无法解释的 relocation 或 provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication、tunnel state、route/DNS leaks、new admin/API event、complaint | duplicate/stolen credential、unknown administrator、direct fallback 或 out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation、key/config version、unsupported direct connection、error/replay rate | key mismatch、direct fallback、unknown realm/peer 或 provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state、circuit failure、onion descriptor/service health 和 owned canary page | personal-account crossover、unexpected non-Tor connection 或 compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set、queue age/sequence、gateway arrival、radio association 和 content hash | unknown peer/gateway、sequence rollback、unauthorized content 或 missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session、workflow/image/config change、new token use、artifact/export 和 cloud audit | unknown login/workflow edit、secret read、unexpected destination 或 project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory、DNS/edge/object access、controller graph、job signature 和 TTL | unknown node/origin/object writer、unsigned/replayed job、topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat、boot/config hash、enclosure state、AP/switch context、duplicate identity | moved/opened node、unexpected boot/hash/path、sentinel use 或 site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix、connection ID/subflows、path-validation 和 broker session | impossible migration、simultaneous unapproved paths 或 session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version、peer/gateway change、redirect/allowlist denial | unexpected pin/query/destination、unsigned dataset root 或 provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision、proxy arrival、BGP/RPKI origin、regional config digest | production-path signal、unknown route origin、region/config inconsistency |

## Choosing and testing a path

1. 明确要移除的 observer 和要隐藏的数据。
2. 选择能移除该 observer 的最简单 family。
3. 绘制 source、entry、traversal、exit、DNS、account 和 payment observers。
4. 使用独立的 endpoint/application identity。
5. 验证 IPv4、IPv6、DNS、WebRTC/application bypass 和 destination view。
6. 破坏每个 hop，确认 failure 是 closed。
7. 比较你控制的每个 component 的 logs。
8. 记录残余 timing、provider、endpoint 和 physical links。

## References

- [1] [EFF — 选择适合你的 VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — 使用 Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services 概述](https://community.torproject.org/onion-services/overview/)
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
