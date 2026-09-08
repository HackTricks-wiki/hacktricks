# Anonymous Internet Access Technique Catalog

{{#include ../banners/hacktricks-training.md}}

这是标准的访问路径清单，涵盖协议和运营**类别**，而不是每个供应商名称。没有任何 Internet 路径能保证 anonymity：账户、浏览器、端点、时间、付款、cloud-control-plane 和物理证据，都可能破坏看似完美的路径。

每个条目都使用相同字段。“Procedure”表示合法部署或自有实验室仿真。如果真实技术依赖于入侵路由器、窃取访问权限或滥用不知情的中间方，则复现时会改用练习者自有的系统。

## Coverage matrix

| 类别 | 目标看到 | 最强特性 | 速度 | 处理方式 |
|---|---|---|---|---|
| Shared NAT/CGNAT | 共享 public address | 订户之间的歧义性 | 高 | 可部署 |
| VPN、VPS、SOCKS/HTTP/SSH proxy | relay address | 快速的 source-address separation | 高 | 可部署 |
| Multi-hop/split relay、MASQUE | final proxy | knowledge split 或完整 IP tunnel | 高/中 | 使用受信任 relay 可部署 |
| Tor、bridge、onion service | exit 或 onion identity | 多方路径和统一浏览器 | 中 | 可部署 |
| I2P、GNUnet、mixnet | overlay peer/gateway | overlay 或 timing resistance | 低/可变 | 特定应用 |
| OHTTP/ODoH、Private Relay | gateway/egress | source/request partitioning | 高 | 仅受支持的应用 |
| Public Wi-Fi、travel router | venue/tunnel address | 位置/访问路径变化 | 高 | 需要许可 |
| Cellular/eSIM、satellite | carrier/provider address | 独立的物理上行链路 | 高/可变 | 订阅方/供应商可观察 |
| Remote browser/jump host | remote workspace | 端点和 egress 分离 | 高 | 可部署 |
| Residential/mobile proxy | consumer/carrier address | consumer-network 外观 | 高 | 同意和来源至关重要 |
| ORB/compromised relay | 另一受害者的 address | 来源隐藏和借用的 reputation | 高 | 仅限自有实验室复现 |
| CDN/fronting/redirector | CDN/front address | 保护后端基础设施 | 高 | 需要供应商/所有者批准 |
| Fast flux/DGA/dead drop | 轮换的 node/service | 基础设施发现阻力 | 可变 | 仅限自有实验室复现 |
| Drop/nearest-neighbor | 靠近目标的本地 address | 跨越地理/网络边界 | 高 | 仅限自有站点实验室 |
| Store-and-forward/offline | gateway 或物理接收方 | 降低交互式时间关联 | 低 | 特定应用 |
| Pluggable/refraction transport | Tor entry 或合作 diversion proxy | 抗审查可达性 | 可变 | 支持的 client 或研究实验室 |
| IPFS gateway/PIR/remote fetcher | gateway 或 application service | publisher/query/request partitioning | 可变 | 受限应用 |
| Anycast/QUIC/MPTCP | stable broker 或多个 subflow | rendezvous 和 session continuity | 高 | 可用性，不是 anonymity |
| CI/CD automation runner | hosted runner address | 一次性、可审计的 egress | 高 | 仅限自有 workflow |
| Non-IP local first hop | organization gateway | 从 sensor 中移除 Internet stack | 低 | 经所有者批准的部署 |

## Direct shared NAT and carrier-grade NAT

**Mechanics：**多个用户共享一个 public address；access provider 将 subscriber-side address 和 port 映射到 public tuple。

**Pros：**速度快；无需特殊 client；仅凭 destination-side IP 可能只能识别家庭、场所或 carrier pool。

**Cons：**供应商可以保留 subscriber/port/time 映射；账户和 fingerprint 仍然存在；其他用户可能损害该 address 的 reputation。

**Procedure：**(1) 确认获授权访问是否使用 NAT/CGNAT；(2) 在自有 endpoint 记录准确的 public IP 和 source port；(3) 分离 application identity；(4) 不要将共享 address 当作 privacy control；(5) 如果 ISP 不应了解 destination，则使用更强的路径。

**Detection：**destination 应保留 source port 和精确时间，而不只是 IP。供应商关联 NAT allocation logs；调查人员将其与 account/device/browser 证据关联。

## Commercial VPN

**Mechanics：**加密的 full-tunnel connection 在 VPN 处终止；destination 看到 VPN 的 egress。VPN 通常可以关联 source、timing 和 destination。

**Pros：**速度快；简单；防止本地被动观察；提供稳定或共享的 exit；适合受控的 red-team egress。

**Cons：**信任集中；billing/login telemetry；kill-switch/DNS/IPv6 故障；共享 exit 经常因 reputation 被阻断。

**Procedure：**(1) 确认供应商、所有者、jurisdiction、retention 和 assessment policy；(2) 安装经过签名的官方 client；(3) 启用 full tunnel、always-on 和 fail-closed 行为；(4) 有意配置 DNS 和 IPv6；(5) 在自有 endpoint 验证实际观察到的 IPv4/IPv6/DNS；(6) 停止并重新连接 tunnel，确认没有明文 fallback。<sup>[[1]](#references)</sup>

**Detection：**本地网络可看到发往 VPN 基础设施的长时间加密流；供应商拥有 authentication/connection records；destination 使用 ASN/reputation，并结合 account、TLS/browser 和行为进行关联。

## Self-hosted VPN or rented VPS egress

**Mechanics：**操作者控制 WireGuard/OpenVPN gateway，或通过租用的 server 转发 traffic。

**Pros：**速度高且可预测；固定、可加入 allowlist 的 address；可自定义 logging/firewall；便于 incident control。

**Cons：**anonymity set 很小；cloud tenant、payment、source login、API 和 image history 都能关联操作者；特征明显的新 server 很容易被聚类。

**Procedure：**(1) 创建 engagement 专用的 organization project；(2) 部署受支持的 image 和固定 address；(3) 将 management 限制为 MFA/key-based administration；(4) 配置 full-tunnel egress 和 DNS；(5) 在可行时仅允许范围内的 destination；(6) 测试 leak/failure 行为；(7) 保留 controller audit records；(8) 在 teardown 时销毁 credentials 和 resources。

**Detection：**关联 hosting ASN、首次出现的 address、certificate/service fingerprint 和 scanning behavior；cloud owner 使用 control-plane、console、billing 和 flow logs。

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics：**application 请求 proxy 打开 TCP stream；SOCKS 还可根据版本传递 name resolution 和 UDP；SSH 在一个加密 session 中转发 stream。

**Pros：**轻量；按 application 使用；速度快；适合 chaining 和访问分段网络。

**Cons：**application 可能绕过它；DNS 可能泄漏；proxy 可看到相邻 endpoint；browser state 仍然存在；open proxy 可能是陷阱或已被入侵的系统。

**Procedure：**(1) 在自有 host 部署 proxy；(2) 要求 authentication 并限制 source/destination；(3) 配置一个一次性 application profile；(4) 必要时确保使用 remote DNS resolution；(5) 使用自有 DNS/HTTP endpoint 验证；(6) 阻止 workload 的 direct egress；(7) 检查并轮换 proxy credentials。

**Detection：**识别具备 tunnel 能力的 process、CONNECT/SOCKS negotiation、长期 SSH session，以及与 application 不一致的 destination；proxy logs 可重建 streams。

## URL-rewriting web proxy and browser proxy extension

**Mechanics：**网站获取 destination 并通过自身 origin 重写 links/forms，或 extension 将 browser requests 指向 proxy。destination 看到的是该 service；service 可在 TLS termination 后读取明文，并注入或保留 content。

**Pros：**无需 system-wide client；适合简单 browsing 且速度快；VPN 无法安装时仍可使用。

**Cons：**proxy 可读取 credentials/content、重写 downloads 并 fingerprint 用户；scripts/WebSockets/downloads 可能绕过；browser extension 具有广泛权限；anonymity set 小且经常被阻断。

**Procedure：**(1) 仅使用组织运营的 proxy 进行获授权测试；(2) 在 disposable browser 中隔离，禁止 personal accounts；(3) 禁止输入 password 和下载敏感内容；(4) 在自有页面确认每个 subresource 都通过 proxy 解析；(5) 测试 WebSocket、download 和 form 行为；(6) 使用后移除 extension/profile。

**Detection：**destination 记录 proxy；enterprise proxy/DNS 和 extension inventory 可识别该 service；content-security/reporting 或自有 canary subresources 可发现 direct bypass；proxy logs 将 user session 映射到 target。

## Multi-hop proxy or provider multi-hop VPN

**Mechanics：**entry 看到 source，一个或多个 traversal relay 将其与看到 destination 的 exit 分离。

**Pros：**普通 relay 无需同时知道两端；一个 node 故障或被扣押时暴露的信息更少；地理位置灵活。

**Cons：**共享 administration/logs 会破坏分离；存在 latency、timing correlation、更多 failure 和 DNS route；相同的 account/payment 可将所有 hop 关联起来。

**Procedure：**(1) 明确每个 hop 要移除的 observer；(2) 在分离重要时，使用独立管理的自有/批准 relay；(3) 对 workload 强制 entry-only access；(4) 确保每个 relay 只能访问下一个 hop；(5) 验证每一层的 logs；(6) 停止每个 hop，确认 fail-closed 行为。使用 [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) 复现。

**Detection：**关联相邻 NetFlow 的 timing/volume、重复的 proxy handshake 和共同的 controller infrastructure；不要根据 exit 推断 operator geography。

## Split-knowledge application relay and OHTTP

**Mechanics：**client 将无状态 HTTP message 加密到 gateway，并通过 relay 发送。relay 可看到 client IP 但看不到 request；gateway 可看到 request，但通常只能看到 relay IP。

**Pros：**对受支持 request 提供强而可审计的 privacy partition；开销低于通用 anonymity network。

**Cons：**不是任意 browsing；cookies/authentication 可能重新关联；relay/gateway collusion 和 traffic analysis 仍然存在；application 必须实现该功能。

**Procedure：**(1) 选择明确支持 RFC 9458 的 application；(2) 通过官方 configuration path 验证 gateway keys；(3) 避免稳定的 per-user fields；(4) 仅发送受支持的 stateless request；(5) 比较 relay、gateway 和 target logs；(6) 测试 key rotation/failure，确保没有 direct fallback。<sup>[[2]](#references)</sup>

**Detection：**enterprise endpoint 可暴露 initiating process 和 OHTTP relay；gateway 可检测 malformed/replayed traffic；timing 和稳定的 payload/account fields 可关联 requests。

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics：**HTTP Extended CONNECT over TLS/QUIC 通过 proxy 携带 UDP 或 IP packets。它可以实现现代 VPN-like tunnel，并将 transport 融入 HTTP/3，但 proxy 仍是 observer。<sup>[[3]](#references)</sup>

**Pros：**multiplexing/roaming 高效；支持 UDP 或完整 IP；可通过现代 HTTP infrastructure 部署。

**Cons：**不是 anonymity network；proxy/account 可看到 source 和 destination；QUIC/HTTP fingerprints 与 well-known paths 对 endpoint/provider 可见。

**Procedure：**(1) 使用记录支持 RFC 9298/9484 的 client/service；(2) authentication proxy certificate/configuration；(3) 定义允许的 target routes；(4) 在 path 内启用 encrypted DNS；(5) 使用自有 endpoint 验证 UDP、TCP、IPv6 和 failover；(6) 检查 proxy request 和 flow logs。

**Detection：**endpoint 可看到 client process 和 virtual interface；网络可将持续的 QUIC/TLS 到 proxy 流量分类；proxy logs 暴露 CONNECT target/path 和 assigned routes。

## Tor Browser

**Mechanics：**Tor 选择 guard、middle 和 exit relay；分层加密限制每个 relay 能看到的内容。Tor Browser 提供旨在抵抗 fingerprinting 的标准化 browser。

**Pros：**大型公共 anonymity set；普通 relay 不会同时知道两端；无需运行 server 即可实现 destination unlinkability。

**Cons：**速度较慢；以 TCP 为主；exit reputation/blocks；login 和主动披露会识别用户；低延迟 timing correlation 仍然存在。

**Procedure：**(1) 从项目官方来源下载并验证 Tor Browser；(2) 保持默认设置并避免 extensions；(3) 选择适当的 security level；(4) 创建独立 identity/session；(5) 避免 identifying accounts 和外部 active documents；(6) 使用 HTTPS 或 authenticated onion services；(7) 仅使用自有 endpoint 验证 exit。<sup>[[4]](#references)</sup>

**Detection：**除非使用 bridge/transport，否则本地网络可识别已知 guard traffic；destination 可看到 exits 和 Tor Browser behavior；端到端 observer 可关联 timing/volume。

## Tor bridges and pluggable transports

**Mechanics：**非公开 bridge 取代 public guard；obfs4、Snowflake 或 WebTunnel 改变 first-hop transport，以抵抗简单 blocking/probing。

**Pros：**绕过 censorship，并隐藏明显的 public-relay destination；进入后仍保留 Tor circuit。

**Cons：**transport patterns/bridge discovery 仍可能发生；性能可变；无法额外防护 accounts 或 global timing。

**Procedure：**(1) 先尝试 direct Tor；(2) 在 Tor Browser Connection settings 中选择内置的受支持 transport，或请求官方 bridge；(3) 不要使用随机 binaries/lists；(4) 连接并运行无害测试；(5) 测试 reconnect 和 clock；(6) 保持其他 browser settings 为标准设置。<sup>[[5]](#references)</sup>

**Detection：**censor 使用 destination discovery、protocol/flow classification 和 active probing；defender 应区分 circumvention use 与 compromise，并依赖 endpoint process/context。

## VPN before Tor and Tor before VPN

**Mechanics：**VPN-before-Tor 将 direct Tor use 隐藏于 access ISP，但向 VPN 暴露 source。Tor-before-VPN 将 post-Tor traffic 和通常稳定的 customer/tunnel identity 交给 VPN。

**Pros：**设计正确时可移除特定 observer；可访问阻止其中一层的网络。

**Cons：**复杂度、罕见 fingerprint、leaks、较小 anonymity set 和虚假信心；Tor Project 将这些组合视为 advanced。<sup>[[6]](#references)</sup>

**Procedure：**(1) 写明移除的 observer 和引入的新 observer；(2) 使用 disposable environment；(3) 仅建立预期的 outer path；(4) 强制 firewall routes；(5) 验证 DNS/IPv4/IPv6 和每种 failure order；(6) 比较两个 provider 的可见性；(7) 如果没有可测量优势，则放弃该 stack。

**Detection：**local/VPN/Tor observers 可看到不同的相邻层；timing 仍然是端到端的；不寻常的嵌套 tunnel fingerprints 和 provider accounts 可能关联 sessions。

## Onion service

**Mechanics：**client 和 service 都构建 Tor circuits 到 rendezvous，从而隐藏 service IP 并避免 exit。

**Pros：**保护 source 和 service location；端到端 onion authentication；没有 public inbound port；可选 client authorization。

**Cons：**updates/analytics/errors 可能泄漏 origin；onion key 至关重要；application identity/timing 和 host compromise 仍然存在。

**Procedure：**(1) 隔离 application，并仅绑定到 loopback/socket；(2) 安装受支持的 Tor；(3) 按官方说明配置 v3 onion service；(4) 仅在需要稳定 identity 时保护/备份 key；(5) 对封闭使用添加 client authorization；(6) 移除 third-party fetches；(7) 从外部验证 origin 不可达。<sup>[[7]](#references)</sup>

**Detection：**host/network defender 可发现 Tor process/configuration 和 outbound circuits；application errors、DNS、certificates 或 third-party resources 可能暴露 origin。

## I2P internal services

**Mechanics：**I2P 为 overlay 内的 destination 使用独立的单向 inbound/outbound tunnels；public-Internet outproxy 会增加 trust point。

**Pros：**去中心化的 internal publishing；不依赖官方 exit；独立的 inbound/outbound paths。

**Cons：**不是通用 web 替代品；生态较小；存在长期 peer behavior；outproxy 可观察 public browsing。

**Procedure：**(1) 从官方来源安装；(2) 使用 dedicated context；(3) 允许 integration/bandwidth stabilization；(4) 访问自有的 I2P-native service；(5) 除非明确需要，否则避免 outproxy；(6) 验证 shutdown 不会出现 direct fallback；(7) 检查本地 peer 和 service logs。<sup>[[8]](#references)</sup>

**Detection：**本地网络可看到长期 peer traffic 和 bootstrap behavior；endpoint 暴露 router/application processes；outproxy 记录 exits。

## Mixnets

**Mechanics：**fixed-size packets、batching、delay、reordering 和 cover traffic 降低 timing correlation；gateway 为 applications 提供桥接。

**Pros：**比 low-latency proxy 更能抵抗 timing analysis；适用于 asynchronous messages/transactions。

**Cons：**latency、bandwidth overhead、部署规模较小和 application 限制；gateway/account metadata 可能持久存在。

**Procedure：**(1) 选择维护中的 client 和受支持的 application；(2) 阅读实际 threat model；(3) 在独立 compartment 中安装；(4) 向自有 endpoint 发送无害数据；(5) 测量 latency/reliability 和 reply path；(6) 测试 gateway failure；(7) 不要仅为提速而禁用 delays/cover traffic。<sup>[[9]](#references)</sup>

**Detection：**endpoint 可识别 client；access network 可对 gateway/packet cadence 分类；gateway 和 exit 观察相邻角色，而更广泛的 correlation 需要更长的统计窗口。

## GNUnet anonymous file sharing

**Mechanics：**GNUnet 可通过 peers 路由 publish/search/download requests，并根据 anonymity level 添加 cover traffic。其文档警告，默认 level 1 不要求 cover traffic，强大的 traffic analysis 可能识别 origin。<sup>[[10]](#references)</sup>

**Pros：**去中心化、application-native 的 anonymous sharing；可调节 cover-traffic 要求。

**Cons：**不是普通 anonymous web access；性能和存储成本；peer 与 traffic-analysis 限制；GNUnet VPN 文档指出其 IP overlay 不提供良好的 anonymity。

**Procedure：**(1) 安装维护中的官方 build；(2) 隔离 test peer；(3) 限制 bandwidth/storage；(4) 使用选定的 anonymity level 发布无害且唯一的 test file；(5) 从另一个自有 peer 获取；(6) 记录 cover-traffic 和 latency；(7) 不要声称 IP VPN component 提供等效 anonymity。

**Detection：**peer bootstrap、overlay traffic、本地 datastore/process 和 file identifiers；广泛的 observer 可将 traffic volume 与 cover traffic 对比分析。

## Encrypted DNS, ODoH and ECH

**Mechanics：**DoH/DoT/DoQ 将 traffic 加密到 resolver；ODoH 在 proxy 和 resolver 之间分离 client address 与 query；ECH 加密 inner TLS ClientHello/server name。

**Pros：**从部分本地 observer 移除明文 DNS/SNI；ODoH 分割 source/query knowledge。

**Cons：**不是 IP-anonymity path；resolver/proxy/server 仍保留各自角色；destination IP/timing/volume 和 endpoint 仍然存在；fallback 可能泄漏。

**Procedure：**(1) 决定由 OS、application 或 tunnel 负责 DNS；(2) 启用 strict encrypted mode 或受支持的 ODoH；(3) 测试唯一的自有 domain；(4) 在本地 capture，确认没有明文 query；(5) 使 resolver 失效并验证预期行为；(6) 对 ECH，确认 server diagnostics 显示接受 inner ClientHello。<sup>[[11]](#references)</sup>

**Detection：**endpoint/resolver logs 暴露 queries；网络可识别 encrypted-resolver endpoints 和 destination flows；即使在 path 上隐藏，ECH state 仍对 endpoint/CDN 可见。

## Split-provider privacy relay

**Mechanics：**iCloud Private Relay 等产品使用知道 client 的 ingress 和知道 destination 的独立 egress，并进行粗略区域处理。

**Pros：**低摩擦的 split knowledge；速度快；为受支持的 traffic 集成 DNS/web protection。

**Cons：**product/application scope 有限；account/platform provider 仍可识别 customer；不是任意的 system anonymity；存在 collusion/legal 和 timing 风险。

**Procedure：**(1) 确认具体支持的 applications 和 traffic types；(2) 在适当时使用 dedicated platform context 启用功能；(3) 选择 region behavior；(4) 分别测试 Safari/DNS 和不受支持的 applications；(5) 检查 destination address；(6) 测试 network switching/failure。<sup>[[12]](#references)</sup>

**Detection：**access 看到 ingress；destination 看到 egress；platform/relay logs 和 account records 覆盖各自层；不受支持的 applications 暴露普通路径。

## Remote browser, VDI, RDP or organization jump host

**Mechanics：**browsing/tool execution 在 remote system 上执行；destination 看到其 egress，而 workspace provider 看到 operator connection 和 control plane。

**Pros：**速度快；隔离危险内容；稳定且受控的 egress；disposable state 和强大的组织审计。

**Cons：**provider/admin 可观察 session/account；screen/clipboard/file channels 可能泄漏；remote browser fingerprint 可能独特；对 workspace owner 并不 anonymous。

**Procedure：**(1) 为每个 engagement 创建一个 organization-owned workspace；(2) 要求 MFA 并限制 administration；(3) 禁用或限制 clipboard/upload/download；(4) 通过批准的固定 egress 路由；(5) 不使用 personal IdP/sync；(6) 仅导出经过审查的 evidence；(7) 按计划销毁 workspace 和 credentials。

**Detection：**provider 和 IdP logs 将 user 映射到 session；destination 对 workspace egress/browser 进行聚类；enterprise defender 识别 remote-control protocols 和异常 cloud sessions。

## Public or guest Wi-Fi

**Mechanics：**traffic 通过场所 NAT 或在那里启动的 tunnel 退出。

**Pros：**速度高且使用共享的非家庭 address；无需专用基础设施。

**Cons：**venue association/DHCP/portal、camera、purchase 和 location evidence；恶意 peers/AP；terms；物理风险。

**Procedure：**(1) 获取向 guest 提供的 access，并向 staff 验证 SSID；(2) 使用已修补的 low-trust device；(3) 禁用 sharing/auto-join 并启用 private MAC；(4) 不使用复用 identity 完成 portal；(5) 启动 fail-closed VPN/Tor path；(6) 验证 tethered traffic；(7) 忘记该 network。

**Detection：**venue 关联 AP、MAC、DHCP、portal 和 time；destination 看到 venue/tunnel；调查人员结合 physical 和 device evidence。绝不绕过 access control。

## Travel router

**Mechanics：**operator-owned router 加入 venue Wi-Fi/Ethernet，并通过强制 tunnel policy 提供隔离的内部网络。

**Pros：**隔离 workstations；集中式 kill switch/DNS；一致的 client network；保护 privileged endpoints 免受本地 broadcasts。

**Cons：**router 形成稳定的 radio/DHCP fingerprint；增加 attack surface；captive portal 和 tethering 可能绕过 tunnel。

**Procedure：**(1) 更新受支持的 firmware；(2) 设置唯一 management credentials，并禁用 WAN admin/WPS/UPnP；(3) 在允许时配置 private upstream MAC；(4) 创建独立 internal SSID；(5) 强制 full-tunnel DNS/IPv6 firewall policy；(6) 测试 portal、reconnect 和 tunnel failure。

**Detection：**venue 看到 router association 和 traffic shape；本地 RF/DHCP fingerprinting 可识别它；VPN provider 看到 venue source。

## Cellular, prepaid SIM and eSIM

**Mechanics：**modem 使用 carrier radio access，通常位于 carrier NAT 后；VPN/Tor layer 可改变 destination-visible exit。

**Pros：**独立于本地 wired/Wi-Fi network；移动；速度高；适合授权 drop 的 backhaul。

**Cons：**carrier 知道 subscriber/eSIM、IMSI、IMEI、cells、time 和 assigned ports；registration laws 各不相同；与个人 phone 共处会关联 devices。

**Procedure：**(1) 按法律要求并使用准确资料获得 service；(2) 使用 organization-owned 的独立 modem/device；(3) 向 exercise controller 登记；(4) 禁用无关 radios/accounts；(5) 建立批准的 tunnel；(6) 测试 tethered clients 是否确实通过该 tunnel；(7) 出行前验证 provider 和 retention 假设。<sup>[[13]](#references)</sup>

**Detection：**carrier records 和 RF location；enterprise USB/PCI/MDM inventory 与 rogue-hotspot surveys；destination/tunnel timing。

## Satellite Internet and satellite downlink abuse

**Mechanics：**正常 service 使用 registered terminal/provider。过去的一种单向 DVB-S abuse 允许 beam 内的 receiver 观察发往合法 subscriber 的未加密 downlink traffic，同时使用另一条路径发送 outbound requests。

**Pros：**覆盖范围广；独立的 last mile；历史上的单向 abuse 可将 C2 错误归因于 subscriber geography。

**Cons：**equipment/RF/provider records；latency 和 coverage；现代双向系统有所不同；outbound path 和 asymmetric routing 仍是 evidence。

**Procedure：**对于合法访问，注册自有 terminal，并按需要通过 tunnel 传输 traffic。要仿真历史 Turla behavior，应在无 RF 实验室中重放 synthetic one-way packet captures，测试 analyst 是否能检测到未发出 request 的 host 却收到 reply；不要拦截 live satellite traffic。<sup>[[14]](#references)</sup>

**Detection：**provider/terminal telemetry、RF direction finding、impossible/asymmetric flow、RTT/routing inconsistency 和 malware configuration。

## Residential/mobile proxy or consented proxyware

**Mechanics：**backconnect gateway 分配 consumer broadband/mobile exits，可为 sticky 或 rotating。来源可能是经同意、欺骗性捆绑或恶意的。

**Pros：**速度高；可选择地理位置；consumer ASN 可避开部分 hosting blocks；pool 较大。

**Cons：**来源/同意和法律风险；broker 可看到 customer；受感染 exit 会伤害 victims；rotation 会产生 anomalies；昂贵且不可靠。

**Procedure：**仅使用有记录且取得知情同意的 organization-owned agents 进行仿真：(1) 注册 test endpoints；(2) 清点 owners/IPs；(3) 配置 gateway；(4) 轮换 sticky/per-request modes；(5) 仅向自有 target 发送 traffic；(6) 比较 gateway/exit/target logs；(7) 移除所有 agents。

**Detection：**impossible travel、rapid IP/ASN changes 中保持稳定的 browser/account、backconnect protocols、proxyware process/network artifacts 和 broker/controller relations。

## ORB, botnet and compromised edge-device relays

**Mechanics：**租用或被入侵的 routers/IoT/servers 组成 access、traversal 和 exit roles，并作为 fleet 管理。多个 APT customer 可能共享该 fleet。

**Pros：**借用 reputation/geography；短期 exits；有弹性的 multi-hop mesh；actor 与 IP 的直接关联较弱。

**Cons：**criminal victimization；implant/controller 和 fleet patterns；intermediary seizure；性能不一致；operator/customer service records。

**Procedure：**绝不入侵真实 devices。使用 [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain)：(1) 创建隔离的 entry/transit/target networks；(2) 连接自有的 dual-homed relay containers；(3) 仅转发一个 test port；(4) 发送无害 request；(5) 验证 target 只看到 exit；(6) 轮换 exit；(7) 拆除所有已命名 assets。<sup>[[15]](#references)</sup>

**Detection：**跟踪 topology、ports/services、controller relations、implant fingerprints 和 node lifecycle；集中 edge configuration/flow/integrity telemetry；不要将 exit IP 等同于 actor。

## CDN redirector, domain fronting and domainless fronting

**Mechanics：**public edge 仅转发匹配 grammar 的 traffic；fronting 在 intermediary 允许时使用 benign outer SNI 和不同的 inner HTTP authority，或使用 blank SNI。

**Pros：**隐藏/保护 backend；快速的 global edge；将 destination 融入共享 service；可快速切换。

**Cons：**CDN 看到所有 routing 和 tenant；许多 provider 禁止 cross-tenant fronting；SNI/Host/process/flow 和 account artifacts；配置复用会聚类 campaigns。

**Procedure：**仅在自有 reverse proxy 上使用 [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging) 复现：创建 local certificate/edge，将一个 mismatched Host 路由到自有 target，记录 SNI 和 Host，发送 normal/mismatched requests，然后移除 containers。<sup>[[16]](#references)</sup>

**Detection：**在 endpoint 或 terminating edge 比较 SNI/ECH/Host/`:authority`；关联 initiating process、tenant/origin、request grammar 和 flow cadence。

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics：**DDNS 更新稳定 name；DGA 生成不断变化的 candidate names；fast flux 以低 TTL 轮换 service addresses；double flux 还会轮换 name servers。

**Pros：**具有弹性的 discovery；可快速替换 infrastructure；通过多个 nodes 隐藏 controller。

**Cons：**DNS 生成集中式 telemetry；entropy/NXDOMAIN/churn；低 TTL 和广泛的 ASN patterns；registration 和 authoritative infrastructure 仍然存在。

**Procedure：**使用 [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry)：运行一个返回 RFC 5737 addresses、TTL 为五秒的自有 zone，反复 query，改变 synthetic epoch，并验证 analytics。绝不要将 test records 指向第三方。<sup>[[17]](#references)</sup>

**Detection：**滑动窗口中的 unique answers/ASNs、median TTL、geography、authoritative churn、DGA NXDOMAIN/lexical/temporal clusters 和 process follow-on；结合 context 排除合法 CDN。

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics：**public post、repository、document、object 或 feed 包含 encoded current endpoint 或 task。client 可能通过另一条 channel 返回结果。

**Pros：**使用高 reputation service；TLS；无需更改 binary 即可轮换 endpoint；asymmetric tasking 使简单 flow correlation 更困难。

**Cons：**稳定的 object/account/API identifiers；provider records；endpoint decode/follow-on sequence；content 可能被扣押或修改。

**Procedure：**使用 [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence)：在一个自有 container 上托管 encoded pointer，由 short-lived client 获取/解码，联系第二个自有 service，保留两端 logs，然后 teardown。

**Detection：**关联异常的 process → stable object read → decode → new destination；hash/preserve content，并保留完整 object paths，而不只是 domain。

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics：**functions/short-lived jobs 在 provider NAT 或 front 后运行；logical service 保持稳定，而 instances 和 addresses 轮换。

**Pros：**部署/销毁迅速；provider-scale shared egress；本地磁盘少；区域路由弹性。

**Cons：**tenant、role、API、image、secret、invocation、billing 和 front-to-origin logs 都是持久的；cold-start 和 platform fingerprints；provider policy。

**Procedure：**(1) 使用 organization-owned exercise tenant；(2) 部署仅请求自有 endpoint 的 benign function；(3) 记录 project/role/image/config；(4) 在多个 instances 中调用；(5) 将 target IPs 与 audit/request IDs 比较；(6) 测试 log retention；(7) 移除 function、roles 和 secrets。

**Detection：**cloud audit/invocation logs、异常 role creation、shared egress 与稳定 request grammar、image/layer 和 secret reuse，以及 front-origin correlation。

## Authorized on-site drop

**Mechanics：**inventoried small computer 使用 local wired/Wi-Fi 和 outbound VPN/cellular rendezvous，并呈现 local source。

**Pros：**真实的 internal-origin testing；速度高；可测试 NAC、physical inventory 和 egress controls。

**Cons：**physical discovery/theft；serial/MAC/USB/DHCP/PoE/RF 和 camera evidence；丢失可能暴露 credentials。

**Procedure：**遵循 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md)：(1) 获取确切的书面 placement authority；(2) 记录 serial、MAC、photo、location 和 retrieval time；(3) 使用 signed minimal image 和短期 mutual credentials；(4) 限制 outbound-only destinations/capabilities；(5) 添加 server-side quarantine 和 bandwidth limits；(6) 测试 SOC visibility 和 loss response；(7) 按约定的 lifecycle policy 取回、保留所需 evidence，然后 sanitize。绝不要将其藏在未同意的场所。

**Detection：**NAC/802.1X、switchport/PoE/DHCP、USB inventory、RF survey、recurring tunnel、receiving/camera 和 physical inspection。

## Nearest-neighbor wireless pivot

**Mechanics：**actor 控制目标 radio range 内的 host，然后使用目标 Wi-Fi credentials 远程跨越边界。APT28 曾以这种方式使用附近的 compromised organizations。<sup>[[18]](#references)</sup>

**Pros：**无需 operator travel；target 看到 local radio source；绕过仅应用于 Internet entry 的 controls。

**Cons：**需要附近的 compromised/owned dual-radio host 和有效 access；存在 RADIUS/NAC/AP 与 neighbor endpoint evidence；可能出现 signal/device anomalies。

**Procedure：**仅使用 [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) 复现：将自有 pivot 加入 neighbor 和 target lab SSIDs，仅转发一个 service，收集两个 AP/pivot logs，然后启用 EAP-TLS/device posture 并确认第二次尝试失败。

**Detection：**关联 RADIUS identity、managed certificate/posture、first-seen device、AP edge/signal、concurrent login 和 physical presence；在附近 endpoints 搜索 simultaneous radios、forwarding 和 tunnels。

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics：**traffic 通过 local peers、asynchronous gateways、removable media 或 scheduled queues，而不是一条 interactive Internet session。

**Pros：**网络中断/censorship 期间仍可工作；delayed/batched delivery 削弱简单 timing；本地通信无需 central last mile。

**Cons：**latency 高；anonymity set 小；custody/physical metadata；恶意 peers；数据最终仍会到达能够观察它的 gateway。

**Procedure：**(1) 构建隔离的自有 three-node mesh 或 file queue；(2) 端到端加密/authenticate content；(3) 从 origin 移除 direct Internet routes；(4) 在受控 delay 后 relay benign file；(5) 验证只有 gateway 联系自有 destination；(6) 比较 custody/timestamps；(7) 保留所需 evidence，然后在批准的 closeout 中 sanitize temporary media/queues。

**Detection：**endpoint file/process activity、peer-radio links、removable-media audit、queue/gateway periodicity 和 content identifiers。更长的 correlation windows 取代 interactive-flow analysis。

## TURN relay and forced-relay WebRTC

**Mechanics：**Traversal Using Relays around NAT (TURN) 分配 public relay address，并在 client 与 peers 之间承载 UDP、TCP 或 TLS traffic。ICE policy 可强制使用 relay，而不暴露 direct candidate。TURN 解决的是 reachability，不是通用 anonymity：server authentication client，并观察 allocations、peers、time 和 volume。<sup>[[19]](#references)</sup>

**Pros：**广泛实现；处理 restrictive NAT；支持 mobile WebRTC；正确强制 relay-only policy 时，peer 不会收到 client 的 direct transport address。

**Cons：**TURN operator 可看到两侧相邻信息；application identity、media fingerprint 和 signaling 仍存在；relay-only 消耗 bandwidth 和 latency；配置错误仍可能收集 host 或 server-reflexive candidates。

**Procedure：**(1) 部署 organization-owned TURN service，使用 TLS 和 short-lived credentials；(2) 限制 realms、peers、ports、quotas 和 expiration；(3) 将 test application 的 ICE 设置为 relay-only；(4) 呼叫自有 peer；(5) 检查 `getStats()` 和 packet capture，确认仅 relay candidates 承载 media；(6) 使 relay 失效，确认没有 direct fallback；(7) 为 engagement 保留 allocation logs。

**Detection：**signaling、browser process 和 TURN allocations 可将 session 与 relay 关联；网络可观察发往 TURN ports 或 TLS endpoints 的持续 flows；peer 看到 allocated relay。**Captured node：**application state 和临时 TURN credentials 可能暴露 realm 和 rendezvous service。使用 per-device、short-lived credentials 降低暴露，并仅在 controller 保存 operator authentication。

## Outbound-only rendezvous or reverse overlay

**Mechanics：**NAT 后的 node 向 organization-controlled broker 发起 authenticated connection。operator 单独向 broker authentication，broker 授权狭窄的 management channel；不需要 inbound port forwarding 或 direct operator-to-node route。

**Pros：**在 NAT 和 captive last miles 后稳定；集中式 revocation 和 audit；field-node address 变化无需 operator discovery；清晰分离 operator identity 与 node credential。

**Cons：**broker 成为高价值 correlation point；periodic keepalives 易被识别；宽泛的 tunnel 可能变成不安全的 pivot；broker 丢失会终止 management。

**Procedure：**遵循 [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous)：签发一个 scoped device identity，仅允许自有 broker 和批准的 management service，使用 authenticated keepalive，强制 fail-closed routing，测试 address changes 和 reboot recovery，并在 loss drill 中撤销 identity。WireGuard 文档指出，在确实需要时，25 秒 persistent keepalive 是广泛适用的 NAT interval。<sup>[[20]](#references)</sup>

**Detection：**broker 和 identity-provider logs 映射双方；access network 看到重复的 encrypted destination/cadence；endpoint inventory 显示 overlay agent。**Captured node：**假定其 device key、broker name、tunnel addresses 和 cached task data 均已暴露。不得包含 operator private key、personal account 或可复用的 controller token。

## Pull mailbox, message queue or object-store rendezvous

**Mechanics：**field workload 轮询 authenticated mailbox，获取 signed、pre-approved jobs，并提交受限 results。operator 通过独立 control plane 写入 queue；两者之间没有 interactive socket。

**Pros：**可容忍间歇性 links；解耦 timing 和 addressing；quotas 与 schemas 可限制 capability；易于集中 audit 和 revocation。

**Cons：**polling cadence 和稳定 object/queue names 会 fingerprint system；provider logs 将 producer 与 consumer 关联；control 延迟；捕获的 queued data 可能暴露 exercise。

**Procedure：**(1) 创建一个 engagement queue 和一个 device identity；(2) 定义 benign、明确受限的 signed schema jobs；(3) 设置 message TTL、maximum result size 和 rate；(4) 允许 node 仅 pull 自己的 queue，并仅写入自己的 result prefix；(5) 测试 offline accumulation、duplicate delivery 和 revocation；(6) 集中 immutable access logs；(7) 满足 retention requirements 后删除 queue。

**Detection：**搜索异常 process 的 periodic API calls、稳定 bucket/object/queue paths、相同 user-agent 或 TLS behavior，以及 fetch-then-new-connection sequence。**Captured node：**local cache 可能暴露 pending jobs 和 object names；保持 cache encrypted、bounded 和 disposable，同时保留 authoritative controller logs。

## Dual-uplink failover and connection migration

**Mechanics：**批准的 field node 有两个独立 uplinks，例如 venue Ethernet/Wi-Fi 和 organization cellular，并通过 overlay 或 message broker 在 routes 变化时保持 control session。这是 availability engineering，不是 anonymity。

**Pros：**可承受一个 provider、AP 或 captive-portal failure；支持计划维护；可快速隔离可疑 path。

**Cons：**两个 providers 会生成两套 location/account records；同时使用会使 correlation 更容易；failover 期间可能出现 route 和 DNS leaks；cellular co-location evidence 仍然存在。

**Procedure：**(1) 登记两个 organization-owned interfaces 和 providers；(2) 为自有 endpoints 分配确定的 route priorities 和 health checks；(3) 将 DNS 和 management 绑定到 overlay；(4) 禁止 secondary path 接受 inbound traffic；(5) 逐一断开 paths，验证 session recovery、source policy 和没有 direct destination access；(6) 对未计划的 path change 告警；(7) 记录 data use 和 roaming limits。

**Detection：**通过 ASNs 关联相同 device certificate、request grammar 和 timing；local inventory 看到两个 radios；carriers/venues 保留各自 records。**Captured node：**两个 SIM/device identifiers 和已知 SSIDs 可能可见；使用 organization assets，绝不将 node 与个人 devices 共处或配对。

## Organization private APN or managed cellular tunnel

**Mechanics：**carrier private APN 将 enrolled SIMs 放入 private routed domain，或将 traffic tunnel 到 enterprise gateway。它把 device 与 public mobile Internet 分离，但不能将其隐藏于 carrier 或 contracting organization。

**Pros：**稳定的 private addressing；carrier-level enrollment 和 traffic policy；避免 public inbound exposure；适合获授权的 remote appliances。

**Cons：**subscriber、IMSI/IMEI、cell 和 billing attribution 很强；采购周期和成本；carrier/gateway outage；对 operator 并不 anonymous。

**Procedure：**(1) 以 assessment organization 名义签订 APN；(2) 仅 allowlist registered SIMs 和 gateway prefixes；(3) 添加 application-layer mutual authentication；(4) 将 APN route 限制为 rendezvous 和 update services；(5) 测试 SIM removal、roaming、public-Internet breakout 和 revocation；(6) 监控 carrier 和 gateway records；(7) 在 closeout 时取消或 quarantine 每个 SIM。

**Detection：**carrier inventory 和 cell telemetry、APN gateway flows、SIM/IMEI mismatch 和 enterprise asset records。**Captured node：**即使 storage 加密，SIM 和 modem 也能识别 contract；因此 capture resilience 意味着快速 suspension 和狭窄 authorization，而不是 deniability。

## Long-range point-to-point wireless bridge

**Mechanics：**directional Wi-Fi 或其他 licensed/unlicensed point-to-point radio 连接两个 owner-approved sites，并在 remote site 提供 Internet egress。无需 commercial proxy 即可移动 apparent IP location。

**Pros：**throughput 高；独立于中间 wired carriers；RF 和 routing 可控；适合测试 segmentation 和 remote-site monitoring。

**Cons：**需要 line-of-sight、spectrum、landlord 和 regulatory 许可；RF emissions 和 hardware 具有特征；两个 endpoints 都是 physical evidence；weather/power/alignment 会影响稳定性。

**Procedure：**(1) 获得两个 sites 的书面许可，并验证 spectrum/power 规则；(2) 在 approved parameters 外不发射地 survey path；(3) 使用 authenticated encryption 和 management VLAN；(4) 将 bridge 限制为自有 rendezvous 或 test subnet；(5) 测试 failover、alignment、power recovery 和 RF containment；(6) 标记并清点两个 radios；(7) 移除它们，并在 exercise 后验证 configuration reset。

**Detection：**RF surveys、spectrum analysis、rooftop/site inspection、bridge MAC/OUI、management traffic 和 remote-site egress logs。**Captured node：**configuration 会暴露 peer 和 management domain；使用独特的 exercise credentials，不使用个人 management accounts，并快速撤销 peer-key。

## Consented cooperative or community exit

**Mechanics：**volunteers 或 partner organizations 根据公开 policy 知情运行 relays。traffic 从共享 community pool exit，而 coordination layer 负责 abuse 和 revocation。

**Pros：**多样的 non-cloud networks；明确同意比 proxyware 更安全；shared governance 可分散 trust；适合 research 和 censorship-resilience studies。

**Cons：**小型 pool 和 membership records 会降低 anonymity；exit operators 接收投诉并观察 traffic metadata；存在恶意参与者、uptime 不稳定和 jurisdiction 差异。

**Procedure：**(1) 发布 acceptable-use 和 logging policy；(2) 获取每位 operator 的 informed opt-in；(3) 签发唯一 relay identity，并限制 destinations/rates；(4) 提供 abuse handling 和 one-action revocation；(5) 测试期间仅向自有 endpoints 发送获授权 traffic；(6) 测量 churn 和 correlation exposure；(7) consent 结束时干净地移除 relay。

**Detection：**membership/control-plane records、relay certificates、common software fingerprint 和 exit behavior 可识别 pool。**Captured node：**relay configuration 可能识别 cooperative，但不应包含 client identities；在 access control 下由 authorized controller 保存 client-to-session accountability。

## IPv6 temporary addresses and prefix rotation

**Mechanics：**IPv6 privacy extensions 创建临时 interface identifiers，使 stable address 不会用于每个 outbound connection。Provider prefix changes 可增加 rotation，但 delegated prefix、subscriber record 和 upper-layer fingerprint 仍然存在。<sup>[[21]](#references)</sup>

**Pros：**降低通过稳定 interface identifier 进行的长期被动 tracking；常见 operating systems 内置；无需 relay overhead。

**Cons：**不是 source anonymity；ISP 和 local network 仍知道 prefix/device；DNS、accounts 和 browser state 会关联 sessions；address churn 使 allowlists 和 logging 更复杂。

**Procedure：**(1) 在自有 client 检查当前 stable 和 temporary addresses；(2) 启用 OS 支持的 privacy-address default，而不是第三方 spoofing；(3) 在不同 address lifetimes 期间反复请求自有 IPv6 endpoint；(4) 确认 inbound services 仅绑定预期的 stable addresses；(5) 保留 DHCPv6/RA/neighbor 和精确 endpoint logs；(6) 测试每个 IPv6 address 的 VPN/firewall behavior。

**Detection：**关联 delegated prefix、layer-2 identity、neighbor discovery、account 和 endpoint telemetry，而不是把一个 address 当作一个 device。**Captured node：**network profiles 和 interface identifiers 仍存在；temporary addressing 只能阻止一个 passive identifier，不能阻止 forensic attribution。

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics：**pluggable transport 改变 first Tor connection 的外观，或改变到 bridge 的方式。Snowflake 使用短期 volunteer WebRTC proxies，WebTunnel 类似普通 HTTPS，obfs4 抵抗简单 protocol identification 和 active probing，meek 通过受支持的 web infrastructure relay。它们是进入 Tor 的 censorship-circumvention transports，不是额外的端到端 anonymity layers。<sup>[[22]](#references)</sup>

**Pros：**direct Tor 或已知 relays 被阻止时有用；Snowflake 避免稳定的 public bridge address；集成于维护中的 Tor clients；destination 仍接收普通 Tor properties。

**Cons：**性能较低或可变；broker/front/bridge 和 local network 观察不同 metadata；transport fingerprints 和 blocking 仍可能存在；volunteer proxy 不会替代 Tor，也不应被信任为 application plaintext 的保护者。

**Procedure：**(1) 安装并验证官方 Tor Browser 或受支持的 Tor client；(2) 在 Connection/Bridges 中选择内置 transport；(3) 仅连接自有 diagnostic page；(4) 确认页面看到的是 Tor exit，而不是 Snowflake/WebTunnel peer；(5) 比较 bootstrap 和 performance；(6) 使 transport 失效，确认 client 不会静默 direct connect；(7) 测试后返回标准受支持配置。

**Detection：**censor 可结合 destination allowlists、TLS/WebRTC behavior、broker discovery 和 flow analysis；endpoint 暴露 Tor 和 transport configuration。**Capture-resilient OPSEC：**使用 standard client，绝不将个人 browser state 复制到其中，并假定 bridge/broker history 可恢复。**Monitoring：**监控 Tor bootstrap logs、意外 direct DNS/connection attempts 和 controller-side owned-page observations；transport failure 不证明已被发现。

## Refraction networking or decoy routing

**Mechanics：**合作的 network operator 检测看似发往 allowed decoy 的 traffic 中的 covert signal，并将 flow 转移到 circumvention proxy。部署需要 network path 中的 infrastructure；client 不能仅通过选择一个无害 website 来创建它。<sup>[[23]](#references)</sup>

**Pros：**若不造成 collateral damage，censor 可能难以阻止 apparent destination；无需分发 public bridge address；适用于 on-path-assisted circumvention 的研究模型。

**Cons：**需要专门的 ISP/transit participation；deployability 和 performance 取决于 routing；client-to-decoy flow 与 proxy-side activity 仍存在；global 或 cooperating observer 可关联 timing。

**Procedure：**不要通过无关网络发送 signal。在隔离实验室复现：(1) 创建自有 client、router、decoy 和 proxy namespaces；(2) 使用 benign tagged test request；(3) 让自有 router 仅将该 tag 重定向到 proxy；(4) 记录 pre/post-routing tuples 和 request IDs；(5) 比较 ordinary 和 signaled flows；(6) 测试 false positives 和 removal；(7) 销毁实验室 routes。

**Detection：**授权 network operators 可检查 routing divergence、异常 client hello/tag behavior 和 decoy-versus-back-end flow discrepancies。**Capture-resilient OPSEC：**research client 仅应保存 test keys 和 documentation addresses。**Monitoring：**将 signed lab-router decisions 与 proxy arrivals 比较；不要探测 production transit providers 来判断它们是否检测到 signaling。

## Content-addressed gateway or cached peer retrieval

**Mechanics：**HTTP gateway 获取 IPFS content identifier (CID)，可能来自 cache 或 peers，并将可验证 content 返回给 client。原始 publisher 可能看到 gateway 或其他 peers，而不是最终 reader；gateway 看到 reader IP 和 requested CID。Native peer-to-peer retrieval 会将 client 暴露给 peers 和 DHT/routing participants。<sup>[[24]](#references)</sup>

**Pros：**publisher 与 reader 可由 caches 分离；不可变 content 可通过 hash 验证；replicated data 可在一个 host 失效时继续存在；HTTP clients 不需要 native peer stack。

**Cons：**public CIDs 和 gateway logs 暴露 interests；首次 retrieval timing 可关联 publisher 和 reader；恶意 web content 和 path-style same-origin hazards；public gateways 仅提供 best-effort service 且禁止 abuse。

**Procedure：**(1) 将无害 test file 发布到自有 private IPFS swarm 或自有 gateway；(2) 记录 CID；(3) 通过独立的自有 HTTP gateway 并使用 subdomain isolation 获取；(4) 根据 CID 验证 bytes；(5) caching 后重复获取；(6) 比较 publisher、peer 和 gateway logs；(7) retention 结束时 unpin 并移除 test content。

**Detection：**gateway 记录 source/CID；DHT 和 peer connections 暴露 retrieval；endpoint history 和 file hashes 可识别 content。**Capture-resilient OPSEC：**不要在 read-only field client 上存储 private publishing key，并在 content addressing 前加密敏感 content。**Monitoring：**对 unexpected pinning、peer-set change、allowlist 外的 CID requests 或 gateway account notices 告警。

## Private information retrieval service

**Mechanics：**Private Information Retrieval (PIR) 允许 client 从 database 获取一条 record，同时根据声明的 single- 或 multi-server threat model，以 cryptographic 方式隐藏所选 index。它保护受限 dataset 中的 query selection；不是通用 web access 或 IP anonymity。<sup>[[25]](#references)</sup>

**Pros：**强大的 application-specific query privacy；可测量的 leakage model；适用于 key directories、blocklists 或小型 public databases；可减少暴露精确 lookup terms 的需要。

**Cons：**computation/bandwidth overhead；除非结合 relay，否则 server 仍知道 connection time/IP；dataset version、response size 和 application state 可区分 users；实现成熟度不一。

**Procedure：**(1) 针对 synthetic owned database 部署 audited PIR implementation；(2) 发布 dataset version 和 parameters；(3) 通过相同 request sizes 获取多个 indices；(4) 在本地验证 correctness；(5) 比较 server logs，确认 index 不存在；(6) 测试 malicious/truncated responses 和 version mismatch；(7) 记录准确的 privacy assumption，而不是称其为 anonymous browsing。

**Detection：**network 可看到 service use 和 volume；endpoint telemetry 暴露 client 和最终 record use；compromised server 可操纵 datasets 或 timing。**Capture-resilient OPSEC：**client 仅保留 public database parameters 和受限 cache。**Monitoring：**验证 signed dataset roots、fixed request shapes、error-rate changes 和 server-key rotations。

## Constrained server-side fetcher, preview or rendering service

**Mechanics：**remote service 获取或渲染 URL，并返回 screenshot、metadata 或 sanitized content。destination 看到 fetcher address；service 看到 requester、URL 和 result。滥用 link-preview bots、security scanners 或第三方 URL fetchers 不属于获授权的 proxy use。

**Pros：**将 active content 与 workstation 隔离；destination 收到受控 fetcher fingerprint；可限制 file type、size、destination 和 rendering；提供 disposable execution environment。

**Cons：**service 拥有完整 request knowledge；存在 account/API/billing records；SSRF 和 data-exfiltration 风险；scripts、authentication 和 interactive sites 可能无法工作；unique URLs 会关联 requester 与 fetch。

**Procedure：**(1) 部署 organization-owned fetcher，仅允许自有 test domains；(2) 阻止 private、link-local、metadata 和 redirect-to-unapproved addresses；(3) 限制 methods、redirects、bytes 和 render time；(4) 清除 credentials/cookies；(5) 提交自有 URL；(6) 比较 requester、fetcher 和 target logs；(7) 销毁 render instance，并按 policy 保留 central audit。

**Detection：**target 看到 service ASN/fingerprint；provider 和 controller logs 将 requester 映射到 URL；endpoint process/API calls 显示 submission。**Capture-resilient OPSEC：**使用一个没有 arbitrary destination authority 的 short-lived project token。**Monitoring：**对 allowlist denials、redirect violations、没有 controller job ID 的 fetches 和 provider abuse notices 告警。

## Anycast rendezvous pool

**Mechanics：**多个 organization-controlled nodes 宣布或 front 一个稳定的 service address，routing 选择附近的 instance。Anycast 提高 availability，并向 client 隐藏单个 backend，但 operator 仍控制所有 instances，且 service address 保持稳定。<sup>[[26]](#references)</sup>

**Pros：**有弹性的 regional ingress；一个 instance 失效时无需 field reconfiguration；DDoS/load distribution；central policy 可在已知 nodes 间移动 sessions。

**Cons：**BGP/CDN 和 provider records 可识别 organization；path changes 可能破坏 stateful sessions；不同 client location 的 monitoring 不同；单一稳定 address 易被阻断或进行 reputation clustering。

**Procedure：**使用 provider-supported organization project 或隔离的 routing lab：(1) 部署两个相同的 authenticated health endpoints；(2) 暴露一个 documented service address；(3) 将 session state 保存在 broker 而不是 edge；(4) 撤回一个 node 并验证 reconnection；(5) 测试 certificate、policy 和 log consistency；(6) 对 unauthorized origin/region 告警；(7) closeout 时移除 advertisements 和 credentials。

**Detection：**BGP/RPKI/history、provider tenancy、certificates 和 identical service behavior 可识别 pool。**Capture-resilient OPSEC：**edge 仅保存 regional service identity，不保存 operator 或 fleet-enrollment key。**Monitoring：**从 authorized monitors 探测每个 region，比较 route origin 和 configuration digest，并将 unexpected origin 视为 incident。

## QUIC migration and Multipath TCP continuity

**Mechanics：**QUIC connection IDs 可在 NAT rebinding 或 address changes 后保持 client session；Multipath TCP 可通过多个 subflows 承载一个可靠 byte stream。它们提升 Wi-Fi/cellular transition 的 continuity，但会向 common peer 暴露旧路径和新路径，并可能使 cross-path correlation 更容易。<sup>[[27]](#references)</sup>

**Pros：**uplink changes 期间恢复更快；application session 无需重启；MPTCP 可结合 resilience 与 throughput；适合批准的 field nodes。

**Cons：**不是 anonymity；peer 看到 migration/subflows；connection identifiers 和 simultaneous traffic 可关联 paths；middlebox/carrier support 不一；provider records 增多。

**Procedure：**(1) 仅在自有 field client 与 rendezvous 之间启用受支持 transport；(2) 独立于 IP 对 application 进行 authentication；(3) 在批准的 Wi-Fi 上开始受限 transfer；(4) 切换到 organization cellular；(5) 确认 path validation、data integrity 和没有 clear/direct fallback；(6) 测试 idle timeout 和 return；(7) 保留 broker 对每次 path transition 的 records。

**Detection：**peer 直接观察 address migration 或 MPTCP subflows；access providers 看到各自部分；connection IDs、TLS identity 和 timing 将两者关联。**Capture-resilient OPSEC：**仅存储 device-scoped session material，并快速过期 resumable state。**Monitoring：**对 impossible path changes、同时出现的未批准 networks、migration storms 和 quarantine 后 resumption 告警。

## Managed CI/CD or ephemeral automation runner egress

**Mechanics：**organization-owned workflow 在 hosted runner 上执行受限 network check。destination 看到 cloud runner address，而 platform 保留 repository、actor、workflow、token、log 和 billing attribution。这是具有 accountable egress 的 remote execution，不是对 provider 的 anonymity。<sup>[[28]](#references)</sup>

**Pros：**disposable clean environment；可复现 job definition；无 inbound connection；适合 geographically distributed availability checks；controller audit 强。

**Cons：**platform 和 organization 可识别 initiator；宽泛 workflow tokens 和 untrusted pull requests 很危险；shared IP reputation；logs/artifacts 可能保留 secrets 或 target data。

**Procedure：**(1) 为 assessment 创建 private organization repository 和 environment；(2) 仅允许针对自有 endpoints 的、手动批准的固定 benign jobs；(3) 使用最小 read-only workflow permissions，不使用 production secrets；(4) 运行 check；(5) 比较 workflow、provider 和 target records；(6) 验证 artifacts 不含 credentials；(7) 删除 environment token，并保留所需 audit。

**Detection：**provider audit 和 workflow logs 提供直接 attribution；target 识别 runner ASNs/ranges 和稳定 request grammar。**Capture-resilient OPSEC：**绝不要将 field-device、signing、wallet 或 cloud-administrator secrets 放入 runner variables。**Monitoring：**要求 branch/environment approval，并对 workflow edits、fork execution、secret reads 和 unexpected destinations 告警。

## Non-IP local first hop to an owned gateway

**Mechanics：**Bluetooth mesh、Wi-Fi Aware/Direct、low-power radio 或 serial/optical link 将附近 sensor 的受限 messages 传递到 owner-approved Internet gateway。field device 本身没有 Internet route；gateway 是唯一 egress。radio range 和 protocol limits 使其成为 telemetry/store-and-forward design，而不是 interactive anonymous Internet。

**Pros：**从最小的 field device 移除 Internet stack 和 credentials；低功耗；gateway 集中 policy；可跨越临时 dead zones。

**Cons：**RF/physical discovery、pairing 和 device identifiers；bandwidth 和 range 小；gateway 仍关联所有 messages；spectrum 和 encryption restrictions 各不相同；capture 可能暴露 queued data。

**Procedure：**(1) 获得 site 和 spectrum approval；(2) 使用 unique keys 将一个自有 sensor 与一个自有 gateway 配对；(3) 定义 signed fixed-size message types、TTL 和 rate；(4) 不向 sensor 提供 default IP route；(5) 让 gateway 仅转发到自有 collector；(6) 测试 replay、range loss 和 gateway outage；(7) 清点并取回两个 devices。

**Detection：**RF survey、pairing database、physical inspection 和 gateway process/flow logs 可暴露该 path。**Capture-resilient OPSEC：**sensor 仅保存 pairwise key 和受限的 encrypted queue，绝不保存 operator、Wi-Fi、cellular 或 controller credentials。**Monitoring：**对 new peers、sequence rollback、key failure、异常 RF rate 和来自 unregistered gateway 的 messages 告警。

## Capture/compromise exposure matrix

此表对上述每个类别执行 capture-resilience 检查。“Minimize”表示减少获授权资产上的 secrets 和 blast radius；绝不表示清除 evidence 或躲避调查。

| Technique family | 被捕获的 endpoint/relay 可暴露 | Minimum authorized control |
|---|---|---|
| NAT/CGNAT、public Wi-Fi、travel router | known networks、DHCP/portal history、MACs、tunnel peer | 独立 organization device；在支持时使用 private MAC；不使用 personal accounts；controller inventory |
| VPN、VPS、HTTP/SOCKS/SSH、multi-hop | provider/hostnames、keys、routes、logs 和 adjacent hop | 每个 engagement 一个 identity；short TTL；narrow routes；broker-side revocation；不使用 master keys |
| OHTTP/ODoH、MASQUE、split-provider relay | relay/gateway configuration、application identifiers 和 cached requests | 减少 payload identifiers；pin approved config；bounded cache；严格 no-direct fallback |
| Tor、bridge、onion service、I2P、mixnet、GNUnet | installed software、bridge/onion material、local state 和 peer history | standard client；separate service keys；encrypted minimal state；轮换已泄露的 service identity |
| Remote browser/VDI/jump host | workspace token、clipboard/files 和 remote tenant | phishing-resistant MFA at gateway；disabled transfer channels；快速 session revocation |
| Cellular、satellite、private APN | SIM/eSIM、IMEI/terminal identity、provider 和 approximate location | organization contract；不与个人设备共处；narrow APN/overlay policy；provider suspension runbook |
| Residential/cooperative proxy、ORB lab | agent identity、controller/next hop、cached traffic | 仅使用 consented/owned nodes；signed agent；per-node credential；controller-held participant mapping |
| CDN/fronting、fast flux、serverless | tenant/origin/config、API tokens、deployment 和 billing references | dedicated project；least-privilege role；short-lived deploy token；provider audit 集中保留 |
| Dead drop、pull mailbox、store-and-forward | object names、queue、cached jobs/results 和 custody data | signed bounded jobs；TTL；encrypted cache；separate producer identity；immutable server logs |
| Drop、nearest-neighbor、long-range bridge | serial/radio/SSID/peer、device key、physical placement artifacts | written placement；unique device identity；不保存 operator secret；tamper/state telemetry；revoke and recover |
| TURN、reverse overlay、dual-uplink | realm/broker、device credential、peer/route 和 uplink profiles | outbound-only narrow service；short-lived device credential；independent operator login；fail-closed paths |
| IPv6 temporary addressing | profiles、prefix history 和 endpoint/application state | 仅视为 anti-tracking；保留 network logs；配合 endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings、Tor state 和 research keys | standard client 或 isolated lab；不使用 personal browser state；不进行 production signaling |
| IPFS/PIR/fetcher | requested CID/query client、cached content、gateway 或 service token | encrypted bounded cache；public-only parameters；short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes、connection IDs、resumable state 和所有已知 paths | regional identity only；short resumption lifetime；central route/session revocation |
| Managed CI/CD runner | repository、workflow、provider token、logs 和 artifacts | least-privilege workflow；不使用 production/field/wallet secrets；environment approval |
| Non-IP local hop | radio peer、pairwise key、queued messages 和 gateway identity | unique pairwise key；fixed message schema；不保存 Wi-Fi/cellular/operator credential |

## Monitoring possible discovery for every access family

客户端测试无法证明 investigator 或 defender 正在观察。监控 engagement 所有者拥有的 systems 中的变化，用 controller/client 进行佐证，并停止操作，而不是探测 observer。以下各行覆盖上述所有 techniques；将其与 [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise) 结合使用。

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT、public/guest Wi-Fi、travel router、cellular/eSIM、satellite、private APN | lease/portal/carrier session、public tuple、BSSID/cell/path change、provider notice | 未批准的 network/SIM/device、无法解释的 relocation 或 provider/SOC escalation |
| VPN/VPS、HTTP/SOCKS/SSH、multi-hop、residential/cooperative proxy | peer authentication、tunnel state、route/DNS leaks、新 admin/API event、complaint | 重复/被盗 credential、未知 administrator、direct fallback 或超范围 egress |
| OHTTP/ODoH/ECH、MASQUE、split-provider relay、TURN | relay/gateway allocation、key/config version、unsupported direct connection、error/replay rate | key mismatch、direct fallback、未知 realm/peer 或 provider abuse notice |
| Tor Browser、bridges、Snowflake/WebTunnel/obfs4/meek、VPN±Tor、onion service | bootstrap state、circuit failure、onion descriptor/service health 和 owned canary page | personal-account crossover、unexpected non-Tor connection 或 compromised service key |
| I2P、mixnet、GNUnet、mesh/store-forward、non-IP local hop | peer set、queue age/sequence、gateway arrival、radio association 和 content hash | unknown peer/gateway、sequence rollback、unauthorized content 或 missing custody record |
| Remote browser/VDI/jump host、CI/CD runner、serverless | IdP session、workflow/image/config change、new token use、artifact/export 和 cloud audit | unknown login/workflow edit、secret read、unexpected destination 或 project-role escalation |
| ORB lab、fast flux/DGA、CDN/fronting、dead drop/pull mailbox | owned node inventory、DNS/edge/object access、controller graph、job signature 和 TTL | unknown node/origin/object writer、unsigned/replayed job、topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat、boot/config hash、enclosure state、AP/switch context、duplicate identity | moved/opened node、unexpected boot/hash/path、sentinel use 或 site report |
| IPv6 temporary addresses、QUIC migration、MPTCP | delegated prefix、connection ID/subflows、path-validation 和 broker session | impossible migration、同时出现的未批准 paths 或 revoke 后 session resumption |
| IPFS/cache、PIR、constrained fetcher | CID/query-shape/root version、peer/gateway change、redirect/allowlist denial | unexpected pin/query/destination、unsigned dataset root 或 provider abuse notice |
| Refraction/decoy-routing lab、anycast rendezvous | owned diversion decision、proxy arrival、BGP/RPKI origin、regional config digest | production-path signal、unknown route origin、region/config inconsistency |

## Choosing and testing a path

1. 明确要移除的 observer 和要隐藏的数据。
2. 选择能够移除该 observer 的最简单类别。
3. 绘制 source、entry、traversal、exit、DNS、account 和 payment observers。
4. 使用独立的 endpoint/application identity。
5. 验证 IPv4、IPv6、DNS、WebRTC/application bypass 和 destination view。
6. 破坏每个 hop，确认 failure 是 closed。
7. 比较所控制的每个 component 的 logs。
8. 记录残余的 timing、provider、endpoint 和 physical links。

## References

- [1] [EFF — 选择适合你的 VPN](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
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
